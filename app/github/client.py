import time

import jwt
import requests

from app.analyzer.findings import SUMMARY_COMMENT_MARKER
from app.utils.config import GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH

def get_jwt_token():
    with open(GITHUB_PRIVATE_KEY_PATH, "r") as f:
        private_key = f.read()

    now = int(time.time())

    payload = {
        "iat": now - 60,
        "exp": now + 600,
        "iss": GITHUB_APP_ID
    }

    return jwt.encode(payload, private_key, algorithm="RS256")


def get_installation_token(installation_id):
    jwt_token = get_jwt_token()

    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"

    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json"
        },
        timeout=60,
    )

    response.raise_for_status()
    return response.json()["token"]


def get_pr_files(repo, pr_number, token):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    per_page = 100
    page = 1
    all_files = []

    while True:
        response = requests.get(
            url,
            headers=headers,
            params={"per_page": per_page, "page": page},
            timeout=60,
        )
        response.raise_for_status()
        batch = response.json()
        if not batch:
            break
        all_files.extend(batch)
        if len(batch) < per_page:
            break
        page += 1

    return all_files


def list_pull_review_comments(repo, pr_number, token):
    """All pull request review (inline) comments, for deduping new inline posts."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    per_page = 100
    page = 1
    all_comments = []

    while True:
        response = requests.get(
            url,
            headers=headers,
            params={"per_page": per_page, "page": page},
            timeout=60,
        )
        response.raise_for_status()
        batch = response.json()
        if not batch:
            break
        all_comments.extend(batch)
        if len(batch) < per_page:
            break
        page += 1

    return all_comments


def list_issue_comments(repo, pr_number, token):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    per_page = 100
    page = 1
    all_comments = []

    while True:
        response = requests.get(
            url,
            headers=headers,
            params={"per_page": per_page, "page": page},
            timeout=60,
        )
        response.raise_for_status()
        batch = response.json()
        if not batch:
            break
        all_comments.extend(batch)
        if len(batch) < per_page:
            break
        page += 1

    return all_comments


def post_pr_comment(repo, pr_number, token, body):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"

    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"body": body},
        timeout=60,
    )

    response.raise_for_status()
    return response.json()


def update_issue_comment(repo, comment_id, token, body):
    url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"

    response = requests.patch(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"body": body},
        timeout=60,
    )

    response.raise_for_status()
    return response.json()


def upsert_pr_summary_comment(repo, pr_number, token, body):
    """Create or replace the bot summary comment (identified by SUMMARY_COMMENT_MARKER)."""
    for comment in reversed(list_issue_comments(repo, pr_number, token)):
        existing = (comment.get("body") or "").lstrip()
        if existing.startswith(SUMMARY_COMMENT_MARKER):
            return update_issue_comment(repo, comment["id"], token, body)
    return post_pr_comment(repo, pr_number, token, body)


def post_pr_inline_comment(repo, pr_number, token, body, path, line, commit_id):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/comments"

    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "body": body,
            "path": path,
            "line": line,
            "side": "RIGHT",
            "commit_id": commit_id,
        },
        timeout=60,
    )

    response.raise_for_status()
    return response.json()
