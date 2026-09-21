"""Check runner framework.

Each check is a function taking an AWS session/client bundle and returning
a list of finding dicts: {"check", "resource", "severity", "message"}.
"""
from dataclasses import dataclass, field


@dataclass
class Finding:
    check: str
    resource: str
    severity: str  # low | medium | high
    message: str


class Engine:
    def __init__(self):
        self._checks = []

    def register(self, fn):
        self._checks.append(fn)
        return fn

    def run(self, ctx) -> list[Finding]:
        findings: list[Finding] = []
        for check in self._checks:
            try:
                findings.extend(check(ctx) or [])
            except Exception as exc:  # a failing check must not kill the run
                findings.append(Finding(
                    check=getattr(check, "__name__", "unknown"),
                    resource="-",
                    severity="low",
                    message=f"check errored: {exc}",
                ))
        return findings
