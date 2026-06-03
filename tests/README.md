# openclaw-audit test suite

Run from the repo root:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Layout

- `conftest.py` — `scan_fixture(name)` scans a fixture directory and returns a
  `FindingsView` for ergonomic assertions (`.failed("OC-...")`, `.fail_ids`, …).
- `fixtures/` — the benchmark corpus, grouped by family:
  - `benign/` — clean skills, including one that uses the word "important" to
    guard against the prompt-injection false positive.
  - `malicious/` — skills with prompt injection, download-and-run, and
    credential exfiltration.
  - `mcp/` — pinned vs unpinned MCP servers and an injected tool description.
  - `docker/` — a privileged compose file vs a hardened one.
  - `configs/` — a no-auth gateway config vs a fully hardened config.
- `test_accuracy.py` — declares the check IDs each fixture is expected to fail,
  then prints a TP/FP/FN report and asserts the corpus stays at zero false
  positives / negatives. Run `pytest -s tests/test_accuracy.py` to see the table.

## Adding a fixture

1. Drop the files under the right family directory.
2. Add an entry to `EXPECTED_FAILS` in `test_accuracy.py` with the check IDs it
   should fail (empty set for benign/hardened fixtures).
3. Add focused assertions in the matching `test_<family>.py`.
