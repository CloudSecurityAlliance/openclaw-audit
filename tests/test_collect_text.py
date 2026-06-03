"""Bounds tests for capabilities.collect_text (cron hang guard)."""

from openclaw_audit.capabilities import collect_text, _MAX_TOTAL_BYTES


def test_skips_vendored_dirs(tmp_path):
    (tmp_path / "skill.py").write_text("import os\n")
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("SHOULD_NOT_APPEAR = 1\n")
    text = collect_text(tmp_path)
    assert "import os" in text
    assert "SHOULD_NOT_APPEAR" not in text


def test_skips_oversized_and_minified(tmp_path):
    (tmp_path / "ok.js").write_text("normal();\n")
    (tmp_path / "huge.json").write_text("x" * (300 * 1024))  # > 256KB cap
    (tmp_path / "lib.min.js").write_text("minified();\n")
    text = collect_text(tmp_path)
    assert "normal()" in text
    assert "x" * 1000 not in text
    assert "minified()" not in text


def test_total_cap_enforced(tmp_path):
    for i in range(60):
        (tmp_path / f"f{i}.py").write_text("a" * (100 * 1024))  # 60 * 100KB = 6MB
    text = collect_text(tmp_path)
    assert len(text) <= _MAX_TOTAL_BYTES + 4096
