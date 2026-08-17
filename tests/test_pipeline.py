import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("run_pipeline", ROOT / "workspace/scripts/run_pipeline.py")
pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipeline)


class PipelineTest(unittest.TestCase):
    def test_octobus_response_is_the_report_verdict(self):
        remote = {
            "cveId": "CVE-TEST",
            "ghsaId": "GHSA-TEST",
            "alertNumber": 7,
            "package": "g:a",
            "installedVersion": "1.0",
            "affectedVersions": "< 2.0",
            "fixedVersion": "2.0",
            "ruleId": "rule-test",
            "sourceCommit": "abc",
            "snapshotId": "snapshot-1",
            "scope": "component API boundary",
            "checks": {
                "versionMatch": "pass",
                "sinkPresent": "pass",
                "preconditions": [{"id": "input_controlled", "status": "pass"}],
            },
            "verdict": "reachable",
            "confidence": "high",
            "reason": "all required conditions are established",
            "reachabilityLevel": "L3",
            "levelReason": "external input reaches the dangerous sink",
            "governanceAction": "high-priority remediation",
            "levelChecks": {
                "componentUsage": "pass",
                "dangerousSink": "pass",
                "externalInputToSink": "pass",
                "completeAttackPath": "unknown",
            },
            "evidence": [{
                "ruleId": "rule-test", "check": "sink_call", "status": "pass",
                "detail": "matched sink", "file": "Example.java", "line": 42,
            }],
            "limitations": ["network exposure is unknown"],
            "fix": ["upgrade"],
        }

        verdict = pipeline.normalize_verdict(remote)

        self.assertEqual(verdict["verdict"], "reachable")
        self.assertEqual(verdict["rule_id"], "rule-test")
        self.assertEqual(verdict["reachability_level"], "L3")
        self.assertEqual(verdict["level_checks"]["complete_attack_path"], "unknown")
        self.assertEqual(verdict["checks"]["preconditions"], {"input_controlled": "pass"})
        report = pipeline.build_markdown(
            [verdict], {"snapshotId": "snapshot-1", "resolvedCommit": "abc"}, "2026-01-01T00:00:00Z"
        )
        self.assertIn("CVE-TEST — REACHABLE", report)
        self.assertIn("level: **L3**", report)
        self.assertIn("high-priority remediation", report)
        self.assertIn("Example.java:42", report)


if __name__ == "__main__":
    unittest.main()
