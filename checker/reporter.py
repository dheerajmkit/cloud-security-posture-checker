"""JSON and Markdown report rendering."""
import json
from datetime import datetime, timezone


def to_dict(findings):
    return [
        {"check": f.check, "resource": f.resource,
         "severity": f.severity, "message": f.message}
        for f in findings
    ]


def write_json(findings, path="report.json"):
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": to_dict(findings),
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
    return path


def write_markdown(findings, path="report.md"):
    lines = ["# Posture Check Report", "",
             f"Findings: {len(findings)}", "",
             "| Severity | Check | Resource | Message |",
             "|---|---|---|---|"]
    for f in sorted(findings, key=lambda x: x.severity):
        lines.append(f"| {f.severity} | {f.check} | {f.resource} | {f.message} |")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return path
