"""Toggles and severity overrides for checks."""
ENABLED_CHECKS = {
    "s3_public_access_block": True,
    "iam_password_policy": True,
    "iam_mfa": True,
    "cloudtrail_enabled": True,
}

SEVERITY_OVERRIDE = {
    # "iam_password_policy": "high",
}
