"""CloudTrail posture checks (read-only)."""
from .engine import Finding


def check_cloudtrail_enabled(ctx) -> list[Finding]:
    """Flag the absence of an active multi-region CloudTrail trail."""
    ct = ctx["cloudtrail"]
    findings = []
    trails = ct.describe_trails().get("trailList", [])
    ok = False
    for trail in trails:
        arn = trail["TrailARN"]
        try:
            status = ct.get_trail_status(Name=arn)
        except Exception:
            continue
        if status.get("IsLogging") and trail.get("IsMultiRegionTrail"):
            ok = True
            break
    if not ok:
        findings.append(Finding("cloudtrail_enabled", "cloudtrail", "high",
                                "no active multi-region trail logging"))
    return findings


CHECKS = [check_cloudtrail_enabled]
