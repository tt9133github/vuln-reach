import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


class DeploymentConfigTest(unittest.TestCase):
    def test_report_directory_is_a_writable_persistent_bind(self):
        config = yaml.safe_load((ROOT / "agent-compose.yml").read_text(encoding="utf-8"))
        agent = config["agents"]["reach-analyzer"]

        self.assertEqual(agent["workspace"], {"provider": "local", "path": "./workspace"})
        report_mounts = [
            mount
            for mount in agent.get("volumes", [])
            if mount.get("target") == "/workspace/report"
        ]
        self.assertEqual(
            report_mounts,
            [
                {
                    "type": "bind",
                    "source": "./workspace/report",
                    "target": "/workspace/report",
                    "read_only": False,
                }
            ],
        )
        self.assertTrue((ROOT / "workspace" / "report").is_dir())


if __name__ == "__main__":
    unittest.main()
