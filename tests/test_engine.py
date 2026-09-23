"""Unit tests for the engine and S3 checks (no AWS calls)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checker.engine import Engine, Finding


class FakeS3:
    def list_buckets(self):
        return {"Buckets": [{"Name": "demo-bucket"}]}

    def get_public_access_block(self, Bucket):
        return {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}


def test_engine_collects_findings():
    engine = Engine()
    engine.register(lambda ctx: [Finding("c1", "r1", "low", "m1")])
    findings = engine.run({})
    assert len(findings) == 1 and findings[0].check == "c1"


def test_engine_isolates_check_errors():
    engine = Engine()
    def boom(ctx):
        raise RuntimeError("nope")
    engine.register(boom)
    findings = engine.run({})
    assert len(findings) == 1 and "check errored" in findings[0].message


def test_s3_check_passes_with_block():
    from checker.checks_s3 import check_s3_public_access_block
    findings = check_s3_public_access_block({"s3": FakeS3()})
    assert findings == []
