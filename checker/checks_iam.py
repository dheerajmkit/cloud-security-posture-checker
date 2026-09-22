"""IAM posture checks (read-only)."""
from .engine import Finding


def check_iam_password_policy(ctx) -> list[Finding]:
    """Flag weak or missing account password policy."""
    iam = ctx["iam"]
    findings = []
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except Exception:
        return [Finding("iam_password_policy", "iam-account", "medium",
                        "no account password policy configured")]
    if policy.get("MinimumPasswordLength", 0) < 14:
        findings.append(Finding("iam_password_policy", "iam-account", "medium",
                                "minimum password length below 14"))
    for flag, label in (("RequireSymbols", "symbols"), ("RequireNumbers", "numbers"),
                        ("RequireUppercaseCharacters", "uppercase"),
                        ("RequireLowercaseCharacters", "lowercase")):
        if not policy.get(flag):
            findings.append(Finding("iam_password_policy", "iam-account", "low",
                                    f"password policy does not require {label}"))
    return findings


def check_iam_mfa(ctx) -> list[Finding]:
    """Flag IAM users with console access but no MFA device."""
    iam = ctx["iam"]
    findings = []
    for user in iam.list_users().get("Users", []):
        name = user["UserName"]
        try:
            has_login = bool(iam.get_login_profile(UserName=name))
        except Exception:
            has_login = False
        if not has_login:
            continue
        mfa = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
        if not mfa:
            findings.append(Finding("iam_mfa", f"iam-user:{name}", "high",
                                    "console user has no MFA device"))
    return findings


CHECKS = [check_iam_password_policy, check_iam_mfa]
