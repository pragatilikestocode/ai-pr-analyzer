import ast
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


LOCAL_RULES = Path(__file__).resolve().parents[2] / "semgrep_rules" / "python-security.yml"
SEMGREP_CONFIGS = [str(LOCAL_RULES), "p/python"]
SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|auth[_-]?token|access[_-]?token|secret|password|passwd|private[_-]?key)",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(r"['\"][A-Za-z0-9_./+=:@$%!-]{8,}['\"]")
SQL_METHODS = {"execute", "executemany", "raw", "query"}
SUBPROCESS_CALLS = {"run", "call", "check_call", "check_output", "Popen"}


def _issue(message: str, severity: str, line: int) -> dict:
    return {"message": message, "severity": severity, "line": line}


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    deduped = []
    seen = set()

    for finding in findings:
        key = (finding["message"], finding["severity"], finding["line"])
        if key in seen:
            continue

        seen.add(key)
        deduped.append(finding)

    return sorted(deduped, key=lambda finding: finding["line"])


def _line_fallback_findings(code: str) -> list[dict]:
    findings = []

    for line_number, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()

        if re.search(r"\b(eval|exec)\s*\(", stripped):
            findings.append(_issue("Use of eval()/exec() can execute untrusted code", "ERROR", line_number))

        if re.search(r"\bos\.system\s*\(", stripped):
            findings.append(_issue("Use of os.system() can execute shell commands", "ERROR", line_number))

        if re.search(r"\bsubprocess\.(run|call|check_call|check_output|Popen)\s*\(", stripped):
            findings.append(_issue("Subprocess call can execute external commands", "WARNING", line_number))

        if SECRET_NAME_RE.search(stripped) and SECRET_VALUE_RE.search(stripped):
            findings.append(_issue("Possible hardcoded secret", "ERROR", line_number))

        if re.search(r"\.(execute|executemany|raw|query)\s*\(\s*f['\"]", stripped):
            findings.append(_issue("SQL query built with an f-string may allow injection", "ERROR", line_number))

        if re.search(r"\bprint\s*\(", stripped):
            findings.append(_issue("Debug print left in code", "INFO", line_number))

        if re.search(r"\brandom\.(random|randint|randrange|choice|choices|shuffle|sample|uniform|token_bytes|bytes)\s*\(", stripped):
            findings.append(_issue("Use secrets instead of random for security-sensitive values", "WARNING", line_number))

    return _dedupe_findings(findings)


def _ast_fallback_findings(code: str) -> list[dict]:
    """Catch key Python risks even when Semgrep is unavailable or misconfigured."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return _line_fallback_findings(code)

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            findings.append(_issue("Use of eval()/exec() can execute untrusted code", "ERROR", node.lineno))

        if isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
            owner = node.func.value

            if isinstance(owner, ast.Name) and owner.id == "os" and call_name == "system":
                findings.append(_issue("Use of os.system() can execute shell commands", "ERROR", node.lineno))

            if isinstance(owner, ast.Name) and owner.id == "subprocess" and call_name in SUBPROCESS_CALLS:
                findings.append(_issue("Subprocess call can execute external commands", "WARNING", node.lineno))

            if call_name in SQL_METHODS and node.args and isinstance(node.args[0], ast.JoinedStr):
                findings.append(_issue("SQL query built with an f-string may allow injection", "ERROR", node.lineno))

            if isinstance(owner, ast.Name) and owner.id == "random":
                findings.append(
                    _issue("Use secrets instead of random for security-sensitive values", "WARNING", node.lineno)
                )

        if isinstance(node.func, ast.Name) and node.func.id == "print":
            findings.append(_issue("Debug print left in code", "INFO", node.lineno))

    return _dedupe_findings(findings + _line_fallback_findings(code))


def _semgrep_command(tmp: str) -> list[str]:
    command = ["semgrep", "--json"]
    for config in SEMGREP_CONFIGS:
        command.append(f"--config={config}")
    command.append(tmp)
    return command


def run_semgrep(code: str, filename: str) -> list[dict]:
    suffix = os.path.splitext(filename)[1] or ".py"

    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp = f.name

    try:
        try:
            result = subprocess.run(
                _semgrep_command(tmp),
                capture_output=True,
                timeout=60,
            )

            stdout = result.stdout.decode("utf-8", errors="ignore")
            stderr = result.stderr.decode("utf-8", errors="ignore")

            if not stdout.strip():
                print("Semgrep returned empty output")

        except subprocess.TimeoutExpired:
            print("Semgrep timed out")
            return _ast_fallback_findings(code)
        except OSError as error:
            print(f"Could not run Semgrep ({error}); using built-in fallback checks")
            return _ast_fallback_findings(code)

        if result.returncode not in [0, 1]:
            print("Semgrep error:", stderr)
            return _ast_fallback_findings(code)

        data = json.loads(stdout or "{}")

        findings = [
            {
                "message": r["extra"]["message"],
                "severity": r["extra"]["severity"],
                "line": r["start"]["line"],
            }
            for r in data.get("results", [])
        ]

        return findings or _ast_fallback_findings(code)

    finally:
        os.unlink(tmp)
