"""Tests for agent-config-scan.

Run: python3 -m unittest discover -s tests -v
"""

import os
import subprocess
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A clearly fake token used only as a test fixture. It is not a real
# credential and must never be treated as one.
FAKE_OPENAI_KEY = "sk-TESTFIXTURE00000000000000"


def run_scan(target):
    """Run the scanner as a subprocess; return (returncode, stdout)."""
    result = subprocess.run(
        [sys.executable, "-m", "agent_config_scan", target],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout


class ScanTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content):
        path = os.path.join(self.root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_high_skip_permissions_flag(self):
        self.write("agent.json",
                   '{"dangerously-skip-permissions": true}\n')
        code, out = run_scan(self.root)
        self.assertEqual(code, 1)
        self.assertIn("HIGH", out)
        self.assertIn("skip-permissions-flag", out)
        self.assertIn("high: 1", out)

    def test_high_secret_without_leaking_value(self):
        self.write("config.yaml",
                   f'api_key: "{FAKE_OPENAI_KEY}"\n')
        code, out = run_scan(self.root)
        self.assertEqual(code, 1)
        self.assertIn("secret-openai-key", out)
        # The secret value itself must never appear in the output.
        self.assertNotIn(FAKE_OPENAI_KEY, out)
        self.assertNotIn("TESTFIXTURE", out)

    def test_medium_unrestricted_fetch_tool(self):
        self.write("tools.json",
                   '{"name": "web_fetch", '
                   '"description": "Fetch any URL with curl."}\n')
        code, out = run_scan(self.root)
        self.assertEqual(code, 0)  # no HIGH findings
        self.assertIn("MEDIUM", out)
        self.assertIn("fetch-no-allowlist", out)
        self.assertIn("high: 0", out)
        self.assertIn("medium: 1", out)

    def test_low_undocumented_tool(self):
        self.write("tools.json", '{"name": "read_file"}\n')
        code, out = run_scan(self.root)
        self.assertEqual(code, 0)
        self.assertIn("LOW", out)
        self.assertIn("undocumented-tool", out)
        self.assertIn("low: 1", out)

    def test_clean_config_exits_zero(self):
        self.write("agent.json",
                   '{\n'
                   '  "tools": [\n'
                   '    {"name": "read_file", '
                   '"description": "Read a file the user names.", '
                   '"scope": ["docs/"]},\n'
                   '    {"name": "web_fetch", '
                   '"description": "Fetch a URL from the allowlist.", '
                   '"allowlist": ["example.com"]}\n'
                   '  ]\n'
                   '}\n')
        code, out = run_scan(self.root)
        self.assertEqual(code, 0)
        self.assertIn("findings: 0 (high: 0, medium: 0, low: 0)", out)

    def test_missing_directory_exits_two(self):
        code, out = run_scan(os.path.join(self.root, "does-not-exist"))
        self.assertEqual(code, 2)

    def test_usage_error_exits_two(self):
        result = subprocess.run(
            [sys.executable, "-m", "agent_config_scan"],
            cwd=PROJECT_ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

    def test_allowlisted_fetch_is_not_flagged(self):
        self.write("tools.json",
                   '{"name": "web_fetch", '
                   '"description": "Fetch a URL.", '
                   '"allowlist": ["example.com"]}\n')
        code, out = run_scan(self.root)
        self.assertEqual(code, 0)
        self.assertNotIn("fetch-no-allowlist", out)


if __name__ == "__main__":
    unittest.main()
