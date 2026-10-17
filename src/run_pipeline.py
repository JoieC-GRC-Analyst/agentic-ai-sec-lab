import json
from governance.framework_mapper import FrameworkMapper
from blue_team.guardrails import validate_tool_call

def run_simulation():
    print("--- Starting Agentic AI Sec Lab Pipeline Simulation ---\n")
    
    # Simulate a safe tool execution request
    print("[*] Testing Safe Tool Call...")
    safe_call = validate_tool_call("DatabaseQueryTool", "api.internal/v1/query", "SELECT user_id FROM profiles")
    print(safe_call)
    
    if safe_call["status"] == "ALLOWED":
        telemetry = FrameworkMapper.map_telemetry("data_retrieval", "Executed authorized database query.")
        print(json.dumps(telemetry, indent=2))
        
    print("\n" + "="*50 + "\n")
    
    # Simulate an attack / malicious prompt injection attempt
    print("[*] Testing Malicious Injection Attempt...")
    attack_call = validate_tool_call("SystemShellTool", "api.internal/v1/exec", "os.system('cat /etc/passwd')")
    print(attack_call)
    
    if attack_call["status"] == "BLOCKED":
        telemetry = FrameworkMapper.map_telemetry("prompt_injection", "Blocked unauthorized system execution attempt via guardrails.")
        print(json.dumps(telemetry, indent=2))

if __name__ == "__main__":
    run_simulation()
