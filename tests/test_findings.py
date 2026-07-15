from app.analyzer.findings import merge_findings


def test_merge_findings_dedupes_same_file_same_key():
    a = [{"message": "eval bad", "severity": "HIGH", "line": 1, "filename": "a.py"}]
    b = [{"issue": "eval bad", "severity": "HIGH", "line": 1, "filename": "a.py"}]
    merged = merge_findings(a, b)
    assert len(merged) == 1


def test_merge_findings_keeps_same_line_different_files():
    a = [{"message": "x", "severity": "HIGH", "line": 42, "filename": "foo.py"}]
    b = [{"message": "x", "severity": "HIGH", "line": 42, "filename": "bar.py"}]
    merged = merge_findings(a, b)
    assert len(merged) == 2
    paths = {m["filename"] for m in merged}
    assert paths == {"foo.py", "bar.py"}


def test_merge_findings_different_line_same_file_both_kept():
    a = [{"message": "one", "severity": "LOW", "line": 1, "filename": "f.py"}]
    b = [{"message": "two", "severity": "LOW", "line": 2, "filename": "f.py"}]
    merged = merge_findings(a, b)
    assert len(merged) == 2
