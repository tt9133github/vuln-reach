import copy
import importlib.util
import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/workspace"
SPEC = importlib.util.spec_from_file_location("reachability", ROOT / "workspace/scripts/reachability.py")
reachability = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reachability)


def alert(cve):
    return json.loads((ROOT / f"inputs/alerts/{cve}.json").read_text(encoding="utf-8"))


def rules():
    result = {}
    for name in ("fastjson.yaml", "velocity.yaml"):
        for rule in yaml.safe_load((ROOT / "workspace/rules" / name).read_text(encoding="utf-8"))["rules"]:
            result[rule["cve"]] = rule
    return result


class ReachabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dep_doc = json.loads((FIXTURE / "repo/dependencies.json").read_text(encoding="utf-8"))
        cls.source = dep_doc["source"]
        cls.deps = {item["package"]: item for item in dep_doc["dependencies"]}
        cls.usage = json.loads((FIXTURE / "repo/usage.json").read_text(encoding="utf-8"))["evidence"]
        cls.rules = rules()

    def evaluate(self, cve):
        current_alert = alert(cve)
        package = current_alert["vulnerability"]["package"]
        return reachability.judge(current_alert, self.rules[cve], self.deps[package], self.usage[package], self.source)

    def test_fixed_analysis_fixtures(self):
        self.assertEqual("reachable", self.evaluate("CVE-2025-70974")["verdict"])
        self.assertEqual("reachable", self.evaluate("CVE-2022-25845")["verdict"])
        self.assertEqual("unknown", self.evaluate("CVE-2020-13936")["verdict"])

    def test_invalid_version_is_unknown(self):
        current_alert = alert("CVE-2025-70974")
        package = current_alert["vulnerability"]["package"]
        dep = copy.deepcopy(self.deps[package])
        dep["version"] = "not-a-version"
        result = reachability.judge(current_alert, self.rules["CVE-2025-70974"], dep, self.usage[package], self.source)
        self.assertEqual("unknown", result["verdict"])
        self.assertIsNone(result["checks"]["version_match"])

    def test_incomplete_sink_scan_is_unknown(self):
        current_alert = alert("CVE-2025-70974")
        package = current_alert["vulnerability"]["package"]
        evidence = {"sinks": [], "entry_points": [{"sink_argument_controlled": True}]}
        result = reachability.judge(current_alert, self.rules["CVE-2025-70974"], self.deps[package], evidence, self.source)
        self.assertEqual("unknown", result["verdict"])


if __name__ == "__main__":
    unittest.main()
