from app.analyzer.diff_parser import extract_added_lines


def test_extract_added_lines_collects_plus_lines_only():
    patch = """@@ -0,0 +1,3 @@
+line one
+line two
 context
-not removed
"""
    assert extract_added_lines(patch) == ["line one", "line two"]


def test_extract_added_lines_skips_file_headers():
    patch = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1 +1,2 @@
+added only
"""
    assert extract_added_lines(patch) == ["added only"]


def test_extract_added_lines_empty_without_plus_content():
    assert extract_added_lines("") == []
    assert extract_added_lines("@@ -1,1 +1,1 @@\n unchanged\n") == []
