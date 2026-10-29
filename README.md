# Cloud Security Posture Checker

A lightweight, sample AWS security posture checker. It runs a set of
read-only configuration checks (S3 public access, IAM password policy,
CloudTrail logging, and more) and produces a findings report.

> Sample / educational project. Checks are read-only and make no changes
> to your AWS environment.

## Layout

- `checker/engine.py` — check runner framework
- `checker/checks_s3.py` — S3 checks (day 1)
- `checker/checks_iam.py` — IAM checks (day 2)
- `checker/checks_cloudtrail.py` — CloudTrail checks (day 2)
- `checker/reporter.py` — JSON and Markdown reporting (day 3)
- `config.py` — severity thresholds and check toggles (day 2)
- `tests/` — unit tests (day 3)
