import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from blue_team.guardrails import validate_tool_call

class TestGuardrailsRegression(unittest.TestCase):
    def test_authorized_benign_request_allowed(self):
        result = validate_tool_call(
            tool_name="DatabaseQueryTool",
            target_endpoint="api.internal/v1/query",
            action_parameter="SELECT user_id FROM profiles"
        )
        self.assertEqual(result.get("status"), "ALLOWED")

    def test_prohibited_operation_blocked(self):
        result = validate_tool_call(
            tool_name="SystemShellTool",
            target_endpoint="api.internal/v1/exec",
            action_parameter="os.system('cat /etc/passwd')"
        )
        self.assertEqual(result.get("status"), "BLOCKED")
        self.assertIn("Dangerous execution pattern detected", result.get("reason", ""))

    def test_unauthorized_tool_rejected(self):
        result = validate_tool_call(
            tool_name="UnauthorizedAdminTool",
            target_endpoint="api.internal/v1/query",
            action_parameter="SELECT 1"
        )
        self.assertIn(result.get("status"), ["BLOCKED", "REJECTED"])

    def test_unauthorized_endpoint_rejected(self):
        result = validate_tool_call(
            tool_name="DatabaseQueryTool",
            target_endpoint="api.external/v1/exfiltrate",
            action_parameter="SELECT 1"
        )
        self.assertIn(result.get("status"), ["BLOCKED", "REJECTED"])

if __name__ == '__main__':
    unittest.main()
