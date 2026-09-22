"""Run all registered checks and print a summary. Usage: python run.py"""
import boto3
import config
from checker.engine import Engine
from checker import checks_s3, checks_iam, checks_cloudtrail


def main():
    session = boto3.Session()
    ctx = {
        "s3": session.client("s3"),
        "iam": session.client("iam"),
        "cloudtrail": session.client("cloudtrail"),
    }
    engine = Engine()
    for module in (checks_s3, checks_iam, checks_cloudtrail):
        for check in module.CHECKS:
            if config.ENABLED_CHECKS.get(check.__name__, True):
                engine.register(check)
    findings = engine.run(ctx)
    for f in findings:
        sev = config.SEVERITY_OVERRIDE.get(f.check, f.severity)
        print(f"[{sev.upper():6}] {f.check:28} {f.resource} - {f.message}")
    print(f"\n{len(findings)} finding(s)")


if __name__ == "__main__":
    main()
