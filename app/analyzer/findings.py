SEVERITY_ALIASES = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "INFO",
}

ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

# Hidden marker so we can upsert the PR summary comment instead of spamming new ones.
SUMMARY_COMMENT_MARKER = "<!-- ai-pr-security-analyzer -->"


def normalize_finding(finding: dict) -> dict:
    issue = finding.get("issue") or finding.get("message") or ""
    message = finding.get("message") or issue

    severity = str(finding.get("severity", "LOW")).upper()
    severity = SEVERITY_ALIASES.get(severity, severity)

    if severity not in ORDER:
        severity = "LOW"

    line = finding.get("line", finding.get("line_hint", 1))
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = 1

    line = max(line, 1)

    filename = finding.get("filename") or finding.get("path") or ""
    filename = str(filename).strip()

    return {
        **finding,
        "issue": str(issue).strip(),
        "message": str(message).strip(),
        "severity": severity,
        "line": line,
        "line_hint": line,
        "filename": filename,
    }


def merge_findings(static: list[dict], ai: list[dict]) -> list[dict]:
    seen = set()
    merged = []

    for finding in static + ai:
        normalized = normalize_finding(finding)

        key = (
            normalized.get("filename", ""),
            normalized.get("issue", ""),
            normalized.get("message", ""),
            normalized.get("severity", ""),
            normalized.get("line", ""),
        )

        if key in seen:
            continue

        seen.add(key)
        merged.append(normalized)

    return sorted(
        merged,
        key=lambda item: ORDER.get(item.get("severity", "LOW").upper(), 3),
    )


def score(findings: list[dict]) -> int:
    normalized = [normalize_finding(finding) for finding in findings]

    high = sum(1 for f in normalized if f.get("severity") == "HIGH")
    medium = sum(1 for f in normalized if f.get("severity") == "MEDIUM")
    low = sum(1 for f in normalized if f.get("severity") == "LOW")

    raw = high * 15 + medium * 7 + low * 2
    return max(0, 100 - raw)


def _finding_location(f: dict) -> str:
    loc = ""
    fn = f.get("filename") or ""
    line = f.get("line")
    if fn and line is not None:
        loc = f"`{fn}` line {line}"
    elif fn:
        loc = f"`{fn}`"
    elif line is not None:
        loc = f"line {line}"
    return loc


def format_summary(findings: list[dict], security_score: int) -> str:
    normalized = [normalize_finding(f) for f in findings]

    confirmed = [f for f in normalized if f.get("exploit_confirmed")]
    high = [
        f for f in normalized
        if f.get("severity") == "HIGH" and not f.get("exploit_confirmed")
    ]
    medium = [f for f in normalized if f.get("severity") == "MEDIUM"]
    low = [f for f in normalized if f.get("severity") == "LOW"]

    lines = [
        "## 🔐 PR Security Report",
        "",
        f"**Security Score: {security_score}/100**",
        "",
        "---",
        "",
        f"### Exploit pattern confirmed in isolation ({len(confirmed)})",
        "",
        "_Canned sandbox payloads ran in Docker; this does not prove the PR line is exploitable in your app._",
    ]

    if confirmed:
        for f in confirmed:
            issue = f.get("issue") or f.get("message")
            evidence = f.get("simulation_evidence", "")
            loc = _finding_location(f)
            suffix = f" ({loc})" if loc else ""

            lines.append(f"- **{issue}**{suffix}")

            if evidence:
                lines.append(f"  - Sandbox evidence: `{evidence[:150]}`")
    else:
        lines.append("None")

    # ⚠️ HIGH
    lines += [
        "",
        "---",
        "",
        f"### High risk (no isolated pattern match) ({len(high)})",
    ]

    if high:
        for f in high:
            issue = f.get("issue") or f.get("message")
            loc = _finding_location(f)
            suffix = f" ({loc})" if loc else ""
            lines.append(f"- {issue}{suffix}")
    else:
        lines.append("None")

    # ℹ️ MEDIUM
    lines += [
        "",
        "---",
        "",
        f"### ℹ️ Medium Risk ({len(medium)})",
    ]

    if medium:
        for f in medium:
            issue = f.get("issue") or f.get("message")
            loc = _finding_location(f)
            suffix = f" ({loc})" if loc else ""
            lines.append(f"- {issue}{suffix}")
    else:
        lines.append("None")

    # 🟢 LOW
    lines += [
        "",
        "---",
        "",
        f"### 🟢 Low Risk ({len(low)})",
    ]

    if low:
        for f in low:
            issue = f.get("issue") or f.get("message")
            loc = _finding_location(f)
            suffix = f" ({loc})" if loc else ""
            lines.append(f"- {issue}{suffix}")
    else:
        lines.append("None")

    return "\n".join(lines)


def format_github_summary_comment(findings: list[dict], security_score: int) -> str:
    return f"{SUMMARY_COMMENT_MARKER}\n\n{format_summary(findings, security_score)}"

# SEVERITY_ALIASES = {
#     "ERROR": "HIGH",
#     "WARNING": "MEDIUM",
#     "INFO": "INFO",
# }
# ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


# def normalize_finding(finding: dict) -> dict:
#     issue = finding.get("issue") or finding.get("message") or ""
#     message = finding.get("message") or issue
#     severity = str(finding.get("severity", "LOW")).upper()
#     severity = SEVERITY_ALIASES.get(severity, severity)

#     if severity not in ORDER:
#         severity = "LOW"

#     line = finding.get("line", finding.get("line_hint", 1))
#     try:
#         line = int(line)
#     except (TypeError, ValueError):
#         line = 1

#     line = max(line, 1)

#     return {
#         **finding,
#         "issue": str(issue).strip(),
#         "message": str(message).strip(),
#         "severity": severity,
#         "line": line,
#         "line_hint": line,
#     }


# def merge_findings(static: list[dict], ai: list[dict]) -> list[dict]:
#     seen = set()
#     merged = []

#     for finding in static + ai:
#         normalized = normalize_finding(finding)
#         key = (
#             normalized.get("issue", ""),
#             normalized.get("message", ""),
#             normalized.get("severity", ""),
#             normalized.get("line", ""),
#         )

#         if key in seen:
#             continue

#         seen.add(key)
#         merged.append(normalized)

#     return sorted(merged, key=lambda item: ORDER.get(item.get("severity", "LOW").upper(), 3))


# def score(findings: list[dict]) -> int:
#     normalized = [normalize_finding(finding) for finding in findings]
#     high = sum(1 for finding in normalized if finding.get("severity") == "HIGH")
#     medium = sum(1 for finding in normalized if finding.get("severity") == "MEDIUM")
#     low = sum(1 for finding in normalized if finding.get("severity") == "LOW")
#     raw = high * 15 + medium * 7 + low * 2
#     return max(0, 100 - raw)


# # def format_summary(findings: list[dict], security_score: int) -> str:
# #     sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
# #     normalized = [normalize_finding(finding) for finding in findings]
# #     lines = [
# #         "## Security Scan Results",
# #         "",
# #         f"**Security Score: {security_score}/100**",
# #         "",
# #     ]

# #     if not normalized:
# #         lines.append("No issues found.")
# #     else:
# #         for finding in normalized:
# #             severity = finding.get("severity", "LOW").upper()
# #             icon = sev_icon.get(severity, "⚪")
# #             issue = finding.get("issue") or finding.get("message")
# #             line = finding.get("line_hint") or finding.get("line")

# #             if finding.get("simulated"):
# #                 if finding.get("exploit_confirmed"):
# #                     lines.append(f"{icon} **{severity}** - {issue} (line {line})")
# #                     lines.append("   🔥 **EXPLOIT CONFIRMED**")
# #                     evidence = finding.get("simulation_evidence", "")
# #                     if evidence:
# #                         lines.append(f"   Evidence: `{evidence[:150]}`")
# #                 else:
# #                     lines.append(f"{icon} **{severity}** - {issue} (line {line}) _(simulated - not triggered)_")
# #             else:
# #                 lines.append(f"{icon} **{severity}** - {issue} (line {line})")

# #             if finding.get("explanation"):
# #                 lines.append(f"   *Why:* {finding['explanation']}")
# #             if finding.get("fix"):
# #                 lines.append(f"   *Fix:* {finding['fix']}")

# #     return "\n".join(lines)
# def format_summary(findings: list[dict], security_score: int) -> str:
#     normalized = [normalize_finding(f) for f in findings]

#     confirmed = [f for f in normalized if f.get("exploit_confirmed")]
#     high = [f for f in normalized if f.get("severity") == "HIGH" and not f.get("exploit_confirmed")]
#     medium = [f for f in normalized if f.get("severity") == "MEDIUM"]
#     low = [f for f in normalized if f.get("severity") == "LOW"]

#     lines = [
#         "## PR Security Report",
#         "",
#         f"**Security Score: {security_score}/100**",
#         "",
#         "---",
#         "",
#         f"###  Confirmed Exploits ({len(confirmed)})",
#     ]

#     if confirmed:
#         for f in confirmed:
#             issue = f.get("issue") or f.get("message")
#             line = f.get("line")
#             evidence = f.get("simulation_evidence", "")

#             lines.append(f"- **{issue}** (line {line})")
#             if evidence:
#                 lines.append(f"  - Evidence: `{evidence[:150]}`")
#     else:
#         lines.append("None")

#     lines += [
#         "",
#         "---",
#         "",
#         f"### ⚠️ High Risk (Not Confirmed) ({len(high)})",
#     ]

#     if high:
#         for f in high:
#             issue = f.get("issue") or f.get("message")
#             line = f.get("line")
#             lines.append(f"- {issue} (line {line})")
#     else:
#         lines.append("None")

#     lines += [
#         "",
#         "---",
#         "",
#         f"###  Medium Risk ({len(medium)})",
#     ]

#     if medium:
#         for f in medium:
#             issue = f.get("issue") or f.get("message")
#             line = f.get("line")
#             lines.append(f"- {issue} (line {line})")
#     else:
#         lines.append("None")

#     lines += [
#         "",
#         "---",
#         "",
#         f"### 🟢 Low Risk ({len(low)})",
#     ]

#     if low:
#         for f in low:
#             issue = f.get("issue") or f.get("message")
#             line = f.get("line")
#             lines.append(f"- {issue} (line {line})")
#     else:
#         lines.append("None")

#     return "\n".join(lines)