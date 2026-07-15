import hashlib
import hmac
import json
import os
import re

from fastapi import APIRouter, HTTPException, Request

from app.analyzer.ai_analyzer import ai_analyze
from app.analyzer.diff_parser import extract_added_lines, new_file_line_for_added_line
from app.analyzer.findings import format_github_summary_comment, merge_findings, score
from app.analyzer.semgrep_runner import run_semgrep
from app.exploit_sim.sandbox import simulate_all
from app.github.client import (
    get_installation_token,
    get_pr_files,
    list_pull_review_comments,
    post_pr_inline_comment,
    upsert_pr_summary_comment,
)


router = APIRouter()

_ISSUE_LINE_RE = re.compile(r"\*\*Issue:\*\*\s*([^\n]+)", re.IGNORECASE)


def _normalize_inline_issue_key(message: str) -> str:
    return " ".join(message.strip().lower().split())[:300]


def _parse_issue_from_review_body(body: str) -> str | None:
    match = _ISSUE_LINE_RE.search(body or "")
    if not match:
        return None
    return match.group(1).strip()


def _is_our_review_comment(body: str) -> bool:
    if "**Issue:**" not in (body or ""):
        return False
    b = body or ""
    return (
        "Exploit pattern confirmed in isolation" in b
        or "⚠️ **Potential Issue**" in b
        or "**Sandbox evidence:**" in b
        or "CONFIRMED EXPLOIT" in b
    )


def _existing_inline_dedupe_keys(comments: list[dict]) -> set[tuple[str, int, str]]:
    keys: set[tuple[str, int, str]] = set()
    for comment in comments:
        body = comment.get("body") or ""
        if not _is_our_review_comment(body):
            continue
        path = comment.get("path")
        line = comment.get("line")
        if not path or line is None:
            continue
        try:
            line_int = int(line)
        except (TypeError, ValueError):
            continue
        issue = _parse_issue_from_review_body(body)
        if not issue:
            continue
        keys.add((path, line_int, _normalize_inline_issue_key(issue)))
    return keys


def verify_signature(body: bytes, signature: str):
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()

    expected = "sha256=" + hmac.new(
        secret, body, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")


# def _inline_comment_body(issue: dict) -> str:
#     body = issue["message"]

#     if issue.get("explanation"):
#         body = f"{body}\n\nWhy: {issue['explanation']}"

#     if issue.get("fix"):
#         body = f"{body}\n\nFix: {issue['fix']}"

#     return body
def _inline_comment_body(issue: dict) -> str:
    if issue.get("exploit_confirmed"):
        body = f"""**Exploit pattern confirmed in isolation**

**Issue:** {issue['message']}

**Sandbox evidence:** {issue.get('simulation_evidence', 'Canned payload ran in Docker.')}

**What this means:** A generic proof-of-concept ran in an isolated container. It does **not** prove this exact PR change is exploitable in your application.
"""
        return body

    # ⚠️ fallback for non-confirmed issues
    body = f"""⚠️ **Potential Issue**

**Issue:** {issue['message']}
"""

    if issue.get("explanation"):
        body += f"\n**Why:** {issue['explanation']}"

    if issue.get("fix"):
        body += f"\n**Fix:** {issue['fix']}"

    return body

def _post_inline_comments(
    repo,
    pr_number,
    token,
    commit_id,
    filename,
    patch,
    findings,
    inline_dedupe_keys: set[tuple[str, int, str]],
):
    for issue in findings:
        if issue.get("exploit_confirmed"):
            print(
                f"Isolated pattern match [{issue['severity']}] {issue['message']} "
                f"(line {issue['line']})"
            )
        else:
            print(f"⚠️ {issue['severity']} {issue['message']} (line {issue['line']})")

        if issue["severity"] == "INFO":
            continue

        comment_line = new_file_line_for_added_line(patch, issue["line"])
        if comment_line is None:
            print(f"Could not map finding to file line: {filename}:{issue['line']}")
            continue

        dedupe_key = (
            filename,
            comment_line,
            _normalize_inline_issue_key(issue["message"]),
        )
        if dedupe_key in inline_dedupe_keys:
            print(
                f"Skipping inline comment (already on PR): {filename}:{comment_line} "
                f"— {issue['message'][:80]}"
            )
            continue

        try:
            post_pr_inline_comment(
                repo=repo,
                pr_number=pr_number,
                token=token,
                body=_inline_comment_body(issue),
                path=filename,
                line=comment_line,
                commit_id=commit_id,
            )
            inline_dedupe_keys.add(dedupe_key)
            print(f"Posted inline comment on {filename} at file line {comment_line}")
        except Exception as error:
            response_body = ""
            if getattr(error, "response", None) is not None:
                response_body = f" | response: {error.response.text}"
            print(f"Failed to post inline comment on {filename}:{issue['line']}: {error}{response_body}")


@router.post("/webhook")
async def webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    verify_signature(body, signature)

    payload = json.loads(body)

    action = payload.get("action")
    print("Webhook received:", action)

    if action in ["opened", "synchronize"]:
        repo = payload["repository"]["full_name"]
        pr_number = payload["pull_request"]["number"]
        commit_id = payload["pull_request"]["head"]["sha"]
        installation_id = payload["installation"]["id"]

        print("Repo:", repo)
        print("PR Number:", pr_number)
        print("Installation ID:", installation_id)

        token = get_installation_token(installation_id)
        files = get_pr_files(repo, pr_number, token)
        inline_dedupe_keys = _existing_inline_dedupe_keys(
            list_pull_review_comments(repo, pr_number, token)
        )

        print("\n--- ADDED LINES ---")
        pr_findings = []

        for f in files:
            filename = f["filename"]
            patch = f.get("patch", "")
            added_lines = extract_added_lines(patch)

            if not added_lines:
                continue

            code = "\n".join(added_lines)

            print(f"\nFile: {filename}")
            print("Code:\n", code)

            static_findings = run_semgrep(code, filename)
            ai_findings = ai_analyze(filename, code, context=patch)
            for item in static_findings:
                item["filename"] = filename
            for item in ai_findings:
                item["filename"] = filename
            findings = merge_findings(static_findings, ai_findings)
            findings = simulate_all(findings, added_lines)
            pr_findings.extend(findings)

            confirmed = sum(1 for x in findings if x.get("exploit_confirmed"))
            high = sum(1 for x in findings if x.get("severity") == "HIGH")

            print(
                f"File: {filename} | Score: {score(findings)}/100 | "
                f"Confirmed: {confirmed} | High: {high}"
            )
            _post_inline_comments(
                repo,
                pr_number,
                token,
                commit_id,
                filename,
                patch,
                findings,
                inline_dedupe_keys,
            )

        pr_findings = merge_findings(pr_findings, [])
        security_score = score(pr_findings)
        # print(f"\nOverall PR security score: {security_score}/100")
        total_confirmed = sum(1 for f in pr_findings if f.get("exploit_confirmed"))

        print(
            f"\n🚨 PR Summary | Score: {security_score}/100 | "
            f"Isolated pattern matches: {total_confirmed}"
        )
        summary = format_github_summary_comment(pr_findings, security_score)
        try:
            upsert_pr_summary_comment(repo, pr_number, token, summary)
            print("Upserted security summary comment")
        except Exception as error:
            print(f"Failed to post security summary comment: {error}")

    return {"ok": True}
