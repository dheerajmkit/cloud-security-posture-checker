"""S3 posture checks (read-only)."""
from .engine import Finding


def check_s3_public_access_block(ctx) -> list[Finding]:
    """Flag buckets without an account/bucket-level public access block."""
    s3 = ctx["s3"]
    findings = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            blocked = all(cfg.get(k) for k in (
                "BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets"))
        except Exception:
            blocked = False
        if not blocked:
            findings.append(Finding(
                check="s3_public_access_block",
                resource=f"s3://{name}",
                severity="high",
                message="bucket lacks a full public access block",
            ))
    return findings


CHECKS = [check_s3_public_access_block]
