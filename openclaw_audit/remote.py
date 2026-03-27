"""Remote scanning via SSH — fetch files locally, scan, optionally push fixes back.

Uses ssh+tar instead of rsync so that interactive password prompts work
natively. No special tools required on the remote host beyond ssh and tar.
"""

from __future__ import annotations

import getpass
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class RemoteTarget:
    user: str
    host: str
    port: int
    path: str

    @property
    def ssh_target(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    @property
    def display(self) -> str:
        port_str = f":{self.port}" if self.port != 22 else ""
        return f"{self.ssh_target}{port_str}:{self.path}"


def parse_remote_target(target: str, default_port: int = 22) -> Optional[RemoteTarget]:
    """Parse user@host:/path or host:/path into a RemoteTarget.

    Returns None if this doesn't look like a remote target (i.e., it's a local path).
    """
    m = re.match(
        r'^(?:([^@:]+)@)?'       # optional user@
        r'([^:/]+)'               # host (no colons, no slashes)
        r'(?::(\d+))?'            # optional :port
        r':(/\S+)$',              # :/absolute/path
        target,
    )
    if not m:
        return None

    user = m.group(1) or "root"
    host = m.group(2)
    port = int(m.group(3)) if m.group(3) else default_port
    path = m.group(4)

    return RemoteTarget(user=user, host=host, port=port, path=path)


def _build_ssh_cmd(remote: RemoteTarget, ssh_key: Optional[str] = None,
                   password: Optional[str] = None) -> list[str]:
    """Build the base SSH command list."""
    cmd: list[str] = []

    # If password provided and sshpass is available, use it
    if password and shutil.which("sshpass"):
        cmd = ["sshpass", "-p", password]

    cmd.extend(["ssh", "-p", str(remote.port)])

    if ssh_key:
        cmd.extend(["-i", ssh_key])

    cmd.extend([
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
    ])

    # If password auth and no sshpass, SSH will prompt interactively — that's fine
    return cmd


def fetch_remote(remote: RemoteTarget, local_dir: Path,
                 ssh_key: Optional[str] = None,
                 password: Optional[str] = None,
                 quiet: bool = False) -> None:
    """Fetch a remote OpenClaw directory to a local temp directory via ssh+tar."""
    if not quiet:
        print(f"  Fetching {remote.display} ...")

    ssh_base = _build_ssh_cmd(remote, ssh_key=ssh_key, password=password)

    # Use tar over SSH: remote tars the directory, local untars it
    # Excludes large/irrelevant dirs to keep it fast
    remote_cmd = (
        f"tar czf - -C {remote.path} "
        f"--exclude='node_modules' "
        f"--exclude='.git' "
        f"--exclude='__pycache__' "
        f"--exclude='*.log' "
        f"."
    )

    cmd = ssh_base + [remote.ssh_target, remote_cmd]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Pipe SSH stdout (the tar stream) into local tar to extract
    extract = subprocess.Popen(
        ["tar", "xzf", "-", "-C", str(local_dir)],
        stdin=proc.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Allow proc to receive SIGPIPE if extract exits early
    if proc.stdout:
        proc.stdout.close()

    extract_out, extract_err = extract.communicate(timeout=120)
    proc.wait(timeout=30)

    if proc.returncode != 0:
        stderr = proc.stderr.read().decode() if proc.stderr else ""
        # Filter out tar warnings (non-fatal)
        errors = [l for l in stderr.splitlines()
                  if l and "tar:" not in l.lower()]
        if errors or extract.returncode != 0:
            raise RuntimeError(
                f"SSH fetch failed (ssh exit {proc.returncode}): "
                f"{stderr.strip()}"
            )

    if not quiet:
        file_count = sum(1 for _ in local_dir.rglob("*") if _.is_file())
        print(f"  Fetched {file_count} files")


def push_fixes(remote: RemoteTarget, local_dir: Path,
               ssh_key: Optional[str] = None,
               password: Optional[str] = None,
               quiet: bool = False) -> None:
    """Push locally-applied fixes back to the remote host via ssh+tar."""
    if not quiet:
        print(f"  Pushing fixes to {remote.display} ...")

    ssh_base = _build_ssh_cmd(remote, ssh_key=ssh_key, password=password)

    # Tar local dir, pipe to remote, extract at remote path
    tar_cmd = [
        "tar", "czf", "-", "-C", str(local_dir),
        "--exclude", "node_modules",
        "--exclude", ".git",
        "--exclude", "__pycache__",
        "--exclude", ".quarantine",
        ".",
    ]

    remote_extract = f"tar xzf - -C {remote.path}"
    ssh_cmd = ssh_base + [remote.ssh_target, remote_extract]

    tar_proc = subprocess.Popen(
        tar_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    ssh_proc = subprocess.Popen(
        ssh_cmd,
        stdin=tar_proc.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if tar_proc.stdout:
        tar_proc.stdout.close()

    ssh_out, ssh_err = ssh_proc.communicate(timeout=120)
    tar_proc.wait(timeout=30)

    if ssh_proc.returncode != 0:
        raise RuntimeError(
            f"Push failed (exit {ssh_proc.returncode}): "
            f"{ssh_err.decode().strip()}"
        )


def scan_remote(remote: RemoteTarget, ssh_key: Optional[str] = None,
                password: Optional[str] = None,
                quiet: bool = False) -> Path:
    """Fetch remote files to a temp directory and return the local path."""
    local_dir = Path(tempfile.mkdtemp(prefix="openclaw-audit-"))
    fetch_remote(remote, local_dir, ssh_key=ssh_key, password=password,
                 quiet=quiet)
    return local_dir


def prompt_password(remote: RemoteTarget) -> str:
    """Securely prompt for SSH password."""
    return getpass.getpass(f"  Password for {remote.ssh_target}: ")


def scan_hosts_file(hosts_file: Path) -> list[RemoteTarget]:
    """Parse a hosts file into RemoteTarget list.

    Format: one target per line, blank lines and # comments ignored.
    """
    targets = []
    for line in hosts_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        remote = parse_remote_target(line)
        if remote:
            targets.append(remote)
        else:
            if re.match(r'^[\w.\-]+$', line):
                targets.append(RemoteTarget(
                    user="root", host=line, port=22, path="/home/openclaw",
                ))
    return targets
