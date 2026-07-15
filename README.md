<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/71f5aaf1-04ee-455a-99d8-a26702e769f1" />
# AI PR Security Analyzer

AI PR Security Analyzer is a FastAPI webhook service that reviews GitHub pull requests for risky code changes. It combines static analysis, custom Semgrep rules, lightweight fallback checks, and optional OpenAI analysis to produce security findings, PR scores, summary comments, and inline comments on vulnerable lines.

## Features

- Receives GitHub pull request webhooks.
- Extracts added lines from changed files.
- Runs Semgrep with local Python security rules.
- Falls back to built-in Python checks when Semgrep is unavailable.
- Optionally sends the diff and surrounding context to OpenAI for deeper review.
- Merges and deduplicates static and AI findings.
- Runs high-severity findings through a Docker-based exploit simulation sandbox.
- Scores each file and the overall PR from `0` to `100`.
- Posts a Markdown summary comment on the PR.
- Posts inline comments on exact vulnerable diff lines.
- Marks confirmed exploitability in the PR summary when simulation succeeds.

## Current Checks

The analyzer currently detects:

- `eval(...)` and `exec(...)`
- `os.system(...)`
- common `subprocess.*` calls
- hardcoded secrets
- SQL f-strings in query execution calls
- debug `print(...)` statements
- insecure `random.*` usage where `secrets` should be preferred

## Project Structure

```text
app/
  analyzer/
    ai_analyzer.py       # OpenAI-powered diff review and safe JSON parsing
    diff_parser.py       # Added-line extraction and diff position mapping
    findings.py          # Merge, dedupe, scoring, and summary formatting
    semgrep_runner.py    # Semgrep runner and fallback static checks
  exploit_sim/
    payload_gen.py       # Generates safe proof-of-concept simulation payloads
    sandbox.py           # Runs high-severity findings in the Docker sandbox
    harness/
      Dockerfile         # Container image for exploit simulations
      runner.py          # Isolated simulation runner
  github/
    client.py            # GitHub API helpers
    webhook.py           # GitHub webhook handler
  main.py                # FastAPI app entrypoint
semgrep_rules/
  python-security.yml    # Local Semgrep security rules
requirements.txt
```

## Requirements

- Python 3.11+
- GitHub App with webhook access
- GitHub App private key
- Docker Desktop, for exploit simulation
- Semgrep installed and available on `PATH`
- OpenAI API key, optional but recommended

Install dependencies:

```powershell
python -m pip install -r requirements.txt
python -m pip install fastapi uvicorn python-dotenv pyjwt requests semgrep docker
```

If `python` is not recognized on Windows, try:

```powershell
py -m pip install -r requirements.txt
py -m pip install fastapi uvicorn python-dotenv pyjwt requests semgrep docker
```

Build the exploit simulation sandbox image:

```powershell
docker build -t pr-exploit-sandbox:latest app/exploit_sim/harness
```

Verify the image exists:

```powershell
docker images pr-exploit-sandbox
```

Expected output includes:

```text
pr-exploit-sandbox   latest
```

## Environment Variables

Create a `.env` file in the project root.

```env
GITHUB_APP_ID=your_github_app_id
GITHUB_WEBHOOK_SECRET=your_webhook_secret
GITHUB_PRIVATE_KEY_PATH=path/to/your-github-app-private-key.pem
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4o
ENABLE_EXPLOIT_SIMULATION=true
EXPLOIT_SIM_TIMEOUT=12
```

Notes:

- Do not commit `.env`.
- Do not commit your GitHub App private key.
- `OPENAI_MODEL` is optional. If omitted, the app defaults to `gpt-4o`.
- `ENABLE_EXPLOIT_SIMULATION=false` disables Docker simulation and keeps static/AI review running.
- `EXPLOIT_SIM_TIMEOUT` controls Docker client timeout for exploit simulation.
- If OpenAI quota is unavailable or the SDK fails, AI analysis is skipped and static analysis still runs.

## GitHub App Setup

Your GitHub App needs these permissions:

- Pull requests: read
- Contents: read
- Issues: write, for PR summary comments
- Pull requests: write, for inline review comments

Webhook events:

- Pull request

Webhook URL:

```text
https://your-public-url/webhook
```

For local development, expose your FastAPI server with a tunnel such as ngrok and use the public tunnel URL.

## Running Locally

Start the FastAPI server:

```powershell
uvicorn app.main:app --reload
```

Health check:

```text
GET /
```

Expected response:

```json
{ "status": "running" }
```

Webhook endpoint:

```text
POST /webhook
```

## How It Works

1. GitHub sends a pull request webhook.
2. The app verifies the webhook signature.
3. The app gets the PR files from GitHub.
4. For each changed file, it extracts added lines from the patch.
5. Static analysis runs through Semgrep and fallback Python checks.
6. OpenAI analysis runs with filename, added lines, and surrounding patch context.
7. Static and AI findings are normalized, merged, and deduplicated.
8. High-severity findings are sent to the Docker exploit simulation sandbox.
9. The analyzer calculates file and PR security scores.
10. The app posts inline comments on vulnerable changed lines.
11. The app posts a summary comment on the PR, including exploit confirmation evidence when available.

## Security Score

The score starts at `100` and subtracts points for findings:

```text
HIGH   -15
MEDIUM -7
LOW    -2
```

Example:

```text
1 HIGH + 1 MEDIUM + 1 LOW = 100 - 15 - 7 - 2 = 76
```

`100` means clean. `0` means very risky.

## Summary Comment Format

The PR summary comment looks like this:

```md
## Security Scan Results

**Security Score: 78/100**

🔴 **HIGH** - Use of eval()/exec() can execute untrusted code (line 2)
   🔥 **EXPLOIT CONFIRMED**
   Evidence: `Payload executed in eval context. Output: EXPLOITED`
🟡 **MEDIUM** - random used (line 5)
```

## Inline Comments

Inline comments use GitHub's PR review comments API:

```text
POST /repos/{repo}/pulls/{pr_number}/comments
```

GitHub requires a diff `position`, not the source file line number. The app maps the finding's added-line number back to the unified diff position before posting.

## Exploit Simulation

High-severity findings are passed to `simulate_all()` after static and AI results are merged. The simulator generates safe proof-of-concept payloads and runs them inside the `pr-exploit-sandbox:latest` Docker image with:

- no network access
- memory limits
- CPU limits
- read-only filesystem
- non-root sandbox user

Simulation results are attached to findings:

```python
{
    "simulated": True,
    "exploit_confirmed": True,
    "simulation_evidence": "Payload executed in eval context. Output: EXPLOITED"
}
```

Run a local smoke test:

```powershell
@'
from app.exploit_sim.sandbox import simulate_all

findings = [
    {"issue": "Use of eval()/exec() can execute untrusted code", "severity": "HIGH", "line_hint": 1},
    {"issue": "Possible hardcoded secret", "severity": "HIGH", "line_hint": 2},
    {"issue": "SQL query built with an f-string may allow injection", "severity": "HIGH", "line_hint": 3},
    {"issue": "Use of os.system() can execute shell commands", "severity": "HIGH", "line_hint": 4},
]

lines = [
    "eval(user_input)",
    "DB_PASSWORD = \"admin123\"",
    "query = f\"SELECT * FROM users WHERE id={uid}\"",
    "os.system(f\"rm -rf {path}\")",
]

for result in simulate_all(findings, lines):
    status = "CONFIRMED" if result.get("exploit_confirmed") else "not triggered"
    print(f"{status} - {result['issue']}")
    if result.get("simulation_evidence"):
        print(f"  Evidence: {result['simulation_evidence'][:100]}")
'@ | python -
```

## Troubleshooting

### OpenAI returns 429 quota error

The app logs the error and continues with static analysis. Add billing/quota to the OpenAI project or change `OPENAI_API_KEY`.

### GitHub returns 403 when posting comments

Check GitHub App permissions. Summary comments need issue comment write access. Inline comments need pull request write access.

### Semgrep does not run

Install Semgrep:

```powershell
python -m pip install semgrep
```

Verify:

```powershell
semgrep --version
```

If Semgrep still fails, the app uses fallback checks for critical patterns.

### Exploit simulation does not run

Install the Docker Python SDK:

```powershell
python -m pip install docker
```

Rebuild the sandbox image:

```powershell
docker build -t pr-exploit-sandbox:latest app/exploit_sim/harness
```

Verify Docker Desktop is running and the image exists:

```powershell
docker images pr-exploit-sandbox
```

## Safety Notes

- Rotate any API key or private key that was committed, shared, or printed in logs.
- Keep `.env` and `.pem` files out of Git.
- Treat AI findings as assistant output; static checks remain the deterministic baseline.
