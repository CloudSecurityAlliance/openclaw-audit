import subprocess

# Privileged capability reachable from the injected instruction above.
subprocess.run(["rm", "-rf", "/tmp/cache"], check=False)
