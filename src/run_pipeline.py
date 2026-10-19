import json
import os
from datetime import datetime, timezone
from blue_team.guardrails import validate_tool_call
from governance.framework_mapper import FrameworkMapper

def run_simulation():
    print("--- Agentic AI Security Lab — Local Demo ---")
    
    scenarios = [
        {
            "test_id": "TEST-001",
            "name": "Authorized benign database request",
            "tool": "DatabaseQueryTool",
            "endpoint": "api.internal/v1/query",
            "param": "SELECT user_id FROM profiles",
            "expected": "ALLOWED",
            "event_type": "data_retrieval"
        },
        {
            "test_id": "TEST-002",
            "name": "Prohibited shell-style operation",
            "tool": "SystemShellTool",
            "endpoint": "api.internal/v1/exec",
            "param": "os.system('cat /etc/passwd')",
            "expected": "BLOCKED",
            "event_type": "prompt_injection"
        },
        {
            "test_id": "TEST-003",
            "name": "Unauthorized tool request",
            "tool": "UnauthorizedAdminTool",
            "endpoint": "api.internal/v1/query",
            "param": "SELECT 1",
            "expected": "BLOCKED",
            "event_type": "unauthorized_tool"
        },
        {
            "test_id": "TEST-004",
            "name": "Unauthorized endpoint access",
            "tool": "DatabaseQueryTool",
            "endpoint": "api.external/v1/exfiltrate",
            "param": "SELECT 1",
            "expected": "BLOCKED",
            "event_type": "unauthorized_endpoint"
        },
        {
            "test_id": "TEST-005",
            "name": "Malformed schema / invalid input",
            "tool": 12345,
            "endpoint": "api.internal/v1/query",
            "param": "SELECT 1",
            "expected": "REJECTED",
            "event_type": "invalid_schema"
        }
    ]

    results = []
    passed_count = 0
    failed_count = 0

    for s in scenarios:
        try:
            res = validate_tool_call(
                tool_name=s["tool"], 
                target_endpoint=s["endpoint"], 
                action_parameter=s["param"]
            )
        except Exception as e:
            res = {"status": "REJECTED", "reason": str(e)}

        actual_status = res.get("status")
        passed = (actual_status == s["expected"])
        
        if passed:
            passed_count += 1
            status_label = "[PASS]"
        else:
            failed_count += 1
            status_label = "[FAIL]"

        print(f"{status_label} {s['name']} (Expected: {s['expected']}, Got: {actual_status})")

        telemetry = FrameworkMapper.map_telemetry(s["event_type"], f"Scenario {s['test_id']}: {s['name']}")

        results.append({
            "test_id": s["test_id"],
            "scenario_name": s["name"],
            "expected_decision": s["expected"],
            "observed_decision": actual_status,
            "pass_fail": "PASS" if passed else "FAIL",
            "decision_details": res,
            "governance_mapping": telemetry
        })

    print("\n" + "-"*50)
    print(f"Regression tests: {passed_count} passed, {failed_count} failed")
    
    os.makedirs("artifacts", exist_ok=True)
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_mode": "Local simulation only",
        "real_tools_executed": False,
        "production_security_assurance": False,
        "summary": {
            "total_tests": len(scenarios),
            "passed": passed_count,
            "failed": failed_count
        },
        "test_results": results
    }

    report_path = "artifacts/demo_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Evidence: {report_path}")
    print("Execution mode: Local simulation only")
    print("Real tools executed: No")
    print("Production security assurance: Not established")

if __name__ == "__main__":
    run_simulation()
