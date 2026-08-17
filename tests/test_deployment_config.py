import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


class DeploymentConfigTest(unittest.TestCase):
    def test_generated_directories_have_explicit_mount_contracts(self):
        config = yaml.safe_load((ROOT / "agent-compose.yml").read_text(encoding="utf-8"))
        agent = config["agents"]["reach-analyzer"]

        self.assertEqual(agent["workspace"], {"provider": "local", "path": "./workspace"})
        mounts = {mount["target"]: mount for mount in agent.get("volumes", [])}
        self.assertEqual(mounts["/workspace/runtime"], {
            "type": "bind",
            "source": "./workspace/runtime",
            "target": "/workspace/runtime",
            "read_only": True,
        })
        self.assertEqual(mounts["/workspace/report"], {
            "type": "bind",
            "source": "./workspace/report",
            "target": "/workspace/report",
            "read_only": False,
        })
        self.assertTrue((ROOT / "workspace" / "runtime").is_dir())
        self.assertTrue((ROOT / "workspace" / "report").is_dir())


if __name__ == "__main__":
    unittest.main()
