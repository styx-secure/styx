from pathlib import Path
import unittest


class SkillContractTests(unittest.TestCase):
    def test_skill_uses_one_pre_state_runner_command(self):
        root = Path(__file__).resolve().parents[3]
        skill = (root / ".claude/skills/styx-run/SKILL.md").read_text(encoding="utf-8")
        command = "python3 tools/agent-runner/styx-agent run --issue N --execution-id issue-N"
        self.assertEqual(skill.count(command), 1)
        self.assertNotIn("styx-agent check --execution-id", skill)
        self.assertNotIn("set -eu", skill)


if __name__ == "__main__":
    unittest.main()
