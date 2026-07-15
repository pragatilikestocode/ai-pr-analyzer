import json
import os
import re

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


SYSTEM = """You are a security engineer reviewing code changes.
- Only report real, concrete vulnerabilities in the diff
- If nothing is wrong, return []
- Return ONLY valid JSON, no explanation text"""

USER_TEMPLATE = """File: {filename}

Surrounding context:
{context}

Diff (added lines):
{diff}

Return JSON array: [{{"issue": str, "severity": "HIGH|MEDIUM|LOW", "line_hint": int, "explanation": str, "fix": str}}]"""


def _strip_markdown_fences(raw: str) -> str:
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"\s*```$", "", raw)
    return raw.strip()


def _normalize_findings(value) -> list[dict]:
    if not isinstance(value, list):
        return []

    findings = []
    for item in value:
        if not isinstance(item, dict):
            continue

        issue = item.get("issue") or item.get("message")
        severity = item.get("severity", "MEDIUM")
        line = item.get("line_hint", item.get("line"))
        explanation = item.get("explanation", "")
        fix = item.get("fix", "")

        if not isinstance(issue, str) or not issue.strip():
            continue

        if severity not in {"HIGH", "MEDIUM", "LOW", "ERROR", "WARNING", "INFO"}:
            severity = "MEDIUM"

        try:
            line = int(line)
        except (TypeError, ValueError):
            line = 1

        findings.append(
            {
                "issue": issue.strip(),
                "message": issue.strip(),
                "severity": severity,
                "line_hint": max(line, 1),
                "line": max(line, 1),
                "explanation": explanation if isinstance(explanation, str) else "",
                "fix": fix if isinstance(fix, str) else "",
            }
        )

    return findings


def _parse_ai_response(raw: str) -> list[dict]:
    raw = _strip_markdown_fences(raw)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []

    return _normalize_findings(parsed)


def ai_analyze(filename: str, diff: str, context: str = "") -> list[dict]:
    if OpenAI is None:
        print("OpenAI package is not installed; skipping AI analysis")
        return []

    if not os.getenv("OPENAI_API_KEY"):
        print("OPENAI_API_KEY is not set; skipping AI analysis")
        return []

    client = OpenAI()
    prompt = USER_TEMPLATE.format(filename=filename, diff=diff, context=context)

    try:
        resp = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            messages=[
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
    except Exception as error:
        print(f"OpenAI analysis failed: {error}")
        return []

    raw = resp.choices[0].message.content or ""
    return _parse_ai_response(raw)
