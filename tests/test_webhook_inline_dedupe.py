from app.github.webhook import (
    _existing_inline_dedupe_keys,
    _is_our_review_comment,
    _normalize_inline_issue_key,
    _parse_issue_from_review_body,
)


def test_parse_issue_from_review_body():
    body = """**Exploit pattern confirmed in isolation**

**Issue:** Use of eval() is risky

**Sandbox evidence:** x
"""
    assert _parse_issue_from_review_body(body) == "Use of eval() is risky"


def test_is_our_review_comment_recognizes_current_formats():
    assert _is_our_review_comment("**Issue:** x\n**Sandbox evidence:** y")
    assert _is_our_review_comment("⚠️ **Potential Issue**\n\n**Issue:** x")
    assert not _is_our_review_comment("Random **Issue:** text without markers")


def test_existing_inline_dedupe_keys_from_api_shapes():
    comments = [
        {
            "path": "a.py",
            "line": 10,
            "body": "**Exploit pattern confirmed in isolation**\n\n**Issue:** Hello\n",
        },
        {"path": "b.py", "line": 2, "body": "not our bot"},
    ]
    keys = _existing_inline_dedupe_keys(comments)
    assert ("a.py", 10, _normalize_inline_issue_key("Hello")) in keys
    assert len(keys) == 1
