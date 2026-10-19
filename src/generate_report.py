import json
import os
import sys
import argparse

REQUIRED_TEST_IDS = {"TEST-001", "TEST-002", "TEST-003", "TEST-004", "TEST-005", "TEST-006"}
VALID_DECISIONS = {"ALLOWED", "BLOCKED", "REJECTED"}
VALID_PASS_FAIL = {"PASS", "FAIL"}

def generate_executive_report(artifacts_dir: str = "artifacts"):
    report_path = os.path.join(artifacts_dir, "demo_report.json")
    if not os.path.exists(report_path):
        print(f"[ERROR] {report_path} not found. Run simulation pipeline first.")
        sys.exit(1)

    try:
        with open(report_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Evidence validation failed: Invalid JSON format: {e}")
        sys.exit(2)

    if not isinstance(data, dict):
        print("[ERROR] Evidence validation failed: Root JSON must be an object.")
        sys.exit(2)

    if not isinstance(data.get("timestamp"), str) or not isinstance(data.get("execution_mode"), str) or not isinstance(data.get("real_tools_executed"), bool):
        print("[ERROR] Evidence validation failed: Invalid top-level metadata types.")
        sys.exit(2)

    summary = data.get("summary")
    if not isinstance(summary, dict):
        print("[ERROR] Evidence validation failed: 'summary' must be a dictionary.")
        sys.exit(2)

    for sum_key in ["total_tests", "passed", "failed"]:
        if not isinstance(summary.get(sum_key), int):
            print(f"[ERROR] Evidence validation failed: Summary field '{sum_key}' must be an integer.")
            sys.exit(2)

    if summary.get("overall_status") not in VALID_PASS_FAIL:
        print("[ERROR] Evidence validation failed: Invalid summary 'overall_status'.")
        sys.exit(2)

    test_results = data.get("test_results")
    if not isinstance(test_results, list) or len(test_results) == 0:
        print("[ERROR] Evidence validation failed: 'test_results' must be a non-empty list.")
        sys.exit(2)

    recorded_ids_list = []
    for t in test_results:
        if not isinstance(t, dict):
            print("[ERROR] Evidence validation failed: Result record must be an object.")
            sys.exit(2)
        for subfield in ["test_id", "scenario_name", "expected_decision", "gateway_decision", "observed_decision", "pass_fail", "reason"]:
            if subfield not in t or not isinstance(t[subfield], str):
                print(f"[ERROR] Evidence validation failed: Result record missing or invalid string field '{subfield}'.")
                sys.exit(2)

        if t["expected_decision"] not in VALID_DECISIONS or t["gateway_decision"] not in VALID_DECISIONS or t["observed_decision"] not in VALID_DECISIONS:
            print(f"[ERROR] Evidence validation failed: Invalid decision value in test {t['test_id']}.")
            sys.exit(2)

        if t["pass_fail"] not in VALID_PASS_FAIL:
            print(f"[ERROR] Evidence validation failed: Invalid pass_fail value in test {t['test_id']}.")
            sys.exit(2)

        recorded_ids_list.append(t["test_id"])

    recorded_ids_set = set(recorded_ids_list)
    if len(recorded_ids_list) != len(recorded_ids_set):
        print("[ERROR] Evidence validation failed: Duplicate test IDs in evidence records.")
        sys.exit(2)
    if recorded_ids_set != REQUIRED_TEST_IDS:
        print(f"[ERROR] Evidence validation failed: Test ID set mismatch. Got {recorded_ids_set}, expected {REQUIRED_TEST_IDS}")
        sys.exit(2)

    recomputed_passed = 0
    recomputed_failed = 0

    for t in test_results:
        expected = t.get("expected_decision")
        observed = t.get("observed_decision")
        pass_fail = t.get("pass_fail")

        expected_pass_fail = "PASS" if expected == observed else "FAIL"
        if pass_fail != expected_pass_fail:
            print(f"[ERROR] Evidence integrity violation: Test {t.get('test_id')} pass_fail status contradicts expected/observed decision.")
            sys.exit(2)

        if pass_fail == "PASS":
            recomputed_passed += 1
        else:
            recomputed_failed += 1

    total_tests = len(test_results)
    recomputed_status = "PASS" if (recomputed_passed == total_tests and recomputed_failed == 0) else "FAIL"

    if summary.get("overall_status") != recomputed_status or summary.get("passed") != recomputed_passed or summary.get("failed") != recomputed_failed or summary.get("total_tests") != total_tests:
        print("[ERROR] Evidence integrity violation: Stored summary metrics contradict recomputed values.")
        sys.exit(2)

    proposed_framework_alignments = {
        "TEST-001": "NIST AI RMF 1.0 (MAP 1.1: Context Understanding) & OWASP LLM Top 10 2025 (LLM06: Excessive Agency / Data Access): Least-privilege data access mapping.",
        "TEST-002": "NIST AI RMF 1.0 (MEASURE 2.1: TEVV Procedures) & OWASP LLM Top 10 2025 (LLM01: Prompt Injection / Injection Interception): Proactive command interception.",
        "TEST-003": "NIST AI RMF 1.0 (MANAGE 1.1: Risk Response) & OWASP LLM Top 10 2025 (LLM06: Excessive Agency): Explicit tool allowlist verification.",
        "TEST-004": "NIST AI RMF 1.0 (MAP 1.1 Boundary Context) & OWASP LLM Top 10 2025 (LLM06): Network and endpoint boundary enforcement.",
        "TEST-005": "Strict Type Validation Standard & NIST AI RMF 1.0 (MEASURE 2.1): Fail-closed schema parsing and boundary defense.",
        "TEST-006": "NIST AI RMF 1.0 (MEASURE 2.1) & OWASP LLM Top 10 2025 (LLM01: Prompt Injection): Simulated gateway handling of adversarial policy override."
    }

    markdown = "# Executive AI-GRC Assurance Report\n\n"
    markdown += f"**Evaluation Timestamp:** {data['timestamp']}  \n"
    markdown += f"**Execution Mode:** {data['execution_mode']} | **Real Tools Executed:** {data['real_tools_executed']}\n\n"

    markdown += "## Executive Summary\n"
    markdown += f"* **Total Scenarios Audited:** {total_tests}\n"
    markdown += f"* **Passed / Defended:** {recomputed_passed}\n"
    markdown += f"* **Failed / Unmatched:** {recomputed_failed}\n"
    markdown += f"* **Overall Posture Status:** **{recomputed_status}** (Independently recomputed from validated execution evidence)\n\n"

    markdown += "> **Important Legal & Compliance Disclaimer:** *This report reflects technical control alignment with published governance frameworks (including NIST AI RMF 1.0 and OWASP LLM Top 10 2025) under local simulation conditions. It does NOT constitute legal compliance, formal third-party audit certification, or production security assurance.*\n\n"

    markdown += "## Proposed Control Alignment & Reference\n\n"
    markdown += "| Scenario / Test ID | Outcome | Gateway Decision | Observed Decision | Proposed Authoritative Framework Alignment & Reference |\n"
    markdown += "| :--- | :--- | :--- | :--- | :--- |\n"

    for t in test_results:
        tid = t['test_id']
        name = t['scenario_name']
        outcome = t['pass_fail']
        gw_dec = t['gateway_decision']
        obs_dec = t['observed_decision']
        alignment = proposed_framework_alignments.get(tid, "Proposed internal control alignment.")

        if gw_dec != obs_dec:
            alignment = f"**[Test Harness Override]** Gateway returned `{gw_dec}`, harness forced `{obs_dec}`. {alignment}"

        markdown += f"| **{tid}**: {name} | **{outcome}** | `{gw_dec}` | `{obs_dec}` | {alignment} |\n"

    os.makedirs(artifacts_dir, exist_ok=True)
    exec_path = os.path.join(artifacts_dir, "executive_summary.md")
    with open(exec_path, "w") as f:
        f.write(markdown)

    print(f"[SUCCESS] Executive report dynamically generated: {exec_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Executive AI-GRC Assurance Report Generator")
    parser.add_argument("--artifacts-dir", type=str, default="artifacts", help="Directory to read evidence and store executive report")
    args = parser.parse_args()

    generate_executive_report(artifacts_dir=args.artifacts_dir)
