import json
from datetime import datetime

class FrameworkMapper:
    @staticmethod
    def map_telemetry(action_type: str, description: str) -> dict:
        telemetry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action_type": action_type,
            "description": description,
            "taxonomies": {},
            "governance_alignment": {}
        }
        
        if "injection" in action_type.lower() or "prompt" in action_type.lower():
            telemetry["taxonomies"] = {
                "mitre_atlas": "AML.T0051 (LLM Prompt Injection)",
                "owasp_llm": "LLM01: Prompt Injection",
                "owasp_agentic": "ASI-01: Excessive Agency"
            }
            telemetry["governance_alignment"] = {
                "nist_ai_rmf": ["MEASURE 2.6", "MANAGE 2.4"],
                "status": "DEFENSIVE_CONTROL_TRIGGERED"
            }
        else:
            telemetry["taxonomies"] = {
                "mitre_atlas": "AML.T0043 (Craft Adversarial Data)",
                "owasp_llm": "LLM06: Sensitive Information Disclosure"
            }
            telemetry["governance_alignment"] = {
                "nist_ai_rmf": ["MAP 1.5"],
                "status": "AUDIT_LOGGED"
            }
            
        return telemetry

if __name__ == "__main__":
    mapper = FrameworkMapper()
    sample_event = mapper.map_telemetry("prompt_injection", "Attempted indirect prompt injection via data retrieval layer.")
    print(json.dumps(sample_event, indent=2))
