# Cloud Security Posture Checker

A lightweight, sample AWS security posture checker. It runs a set of
read-only configuration checks (S3 public access, IAM password policy,
MFA coverage, CloudTrail logging) and produces JSON and Markdown findings
reports.

> Sample / educational project. Checks are read-only and make no changes
> to your AWS environment.

## Quick start

```bash
pip install -r requirements.txt
python run.py                 # prints findings to stdout
```

Reports are written with `checker/reporter.py`:

```python
from checker.reporter import write_json, write_markdown
write_json(findings)       # -> report.json
write_markdown(findings)   # -> report.md
```

## Layout

- `checker/engine.py` — check runner framework
- `checker/checks_s3.py` — S3 public access block check
- `checker/checks_iam.py` — IAM password policy and MFA checks
- `checker/checks_cloudtrail.py` — CloudTrail logging check
- `checker/reporter.py` — JSON and Markdown reporting
- `config.py` — severity thresholds and check toggles
- `tests/` — unit tests (run with `pytest`)
