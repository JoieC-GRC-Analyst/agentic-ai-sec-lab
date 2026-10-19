from pydantic import BaseModel, Field, ConfigDict, ValidationError
from typing import Any, Dict

ALLOWED_TOOLS = {"database_query", "read_customer_records"}
ALLOWED_ENDPOINTS = {"internal_db_v1", "secure_cache_v1"}
PROHIBITED_PATTERNS = {"rm -rf", "exec(", "drop table", "cat /etc/passwd", "system("}

class AgentRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    test_id: str = Field(..., description="Test scenario identifier")
    tool_name: str = Field(..., description="Requested tool name")
    endpoint: str = Field(..., description="Target endpoint")
    payload: str = Field(..., description="Input payload or query string")

class PolicyViolationError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

def evaluate_gateway_request(raw_data: Any) -> Dict[str, str]:
    """
    Evaluates raw agentic requests.
    Step 1: Pydantic schema validation -> REJECTED (malformed input / unexpected fields).
    Step 2: Explicit policy checks -> BLOCKED (allowlist / blocklist violations).
    """
    test_id = raw_data.get("test_id", "UNKNOWN") if isinstance(raw_data, dict) else "UNKNOWN"

    if not isinstance(raw_data, dict):
        return {
            "status": "REJECTED",
            "reason": "Malformed Input: Request payload must be a structured JSON dictionary.",
            "test_id": test_id
        }

    # Step 1: Schema & Type Validation (Pydantic)
    try:
        req = AgentRequest(**raw_data)
    except ValidationError as e:
        return {
            "status": "REJECTED",
            "reason": f"Malformed Input / Schema Validation Error: {str(e)}",
            "test_id": test_id
        }
    except Exception:
        return {
            "status": "REJECTED",
            "reason": "Internal Gateway Error: Request failed closed due to an unexpected parsing exception.",
            "test_id": test_id
        }

    # Step 2: Explicit Policy Enforcement
    try:
        if req.tool_name not in ALLOWED_TOOLS:
            raise PolicyViolationError(f"Policy Violation: Unauthorized tool invocation '{req.tool_name}' blocked by explicit allowlist.")

        if req.endpoint not in ALLOWED_ENDPOINTS:
            raise PolicyViolationError(f"Policy Violation: Unauthorized endpoint access '{req.endpoint}' blocked by boundary protection.")

        lower_payload = req.payload.lower()
        for pattern in PROHIBITED_PATTERNS:
            if pattern in lower_payload:
                raise PolicyViolationError(f"Policy Violation: Prohibited injection pattern detected: '{pattern}'")

        return {
            "status": "ALLOWED",
            "reason": "Request successfully passed strict schema validation, allowlists, and boundary checks.",
            "test_id": req.test_id
        }
    except PolicyViolationError as pve:
        return {
            "status": "BLOCKED",
            "reason": str(pve),
            "test_id": req.test_id
        }
