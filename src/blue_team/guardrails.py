from pydantic import BaseModel, Field, ValidationError

class ToolExecutionRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the tool being invoked")
    target_endpoint: str = Field(..., description="Target URI or resource identifier")
    action_parameter: str = Field(..., description="Payload or parameter passed to the tool")
    max_retries: int = Field(default=3, le=5)

# Explicit security allowlists
ALLOWED_TOOLS = {"DatabaseQueryTool", "SystemShellTool"}
ALLOWED_ENDPOINTS = {"api.internal/v1/query", "api.internal/v1/exec"}

def validate_tool_call(tool_name: str, target_endpoint: str, action_parameter: str) -> dict:
    try:
        # Enforce schema validation via Pydantic
        request = ToolExecutionRequest(
            tool_name=tool_name,
            target_endpoint=target_endpoint,
            action_parameter=action_parameter
        )

        # Check tool allowlist (Fail-closed)
        if request.tool_name not in ALLOWED_TOOLS:
            return {
                "status": "BLOCKED",
                "reason": f"Unauthorized tool invocation: '{request.tool_name}'"
            }

        # Check endpoint allowlist (Fail-closed)
        if request.target_endpoint not in ALLOWED_ENDPOINTS:
            return {
                "status": "BLOCKED",
                "reason": f"Unauthorized endpoint access: '{request.target_endpoint}'"
            }

        # Blocklist for dangerous execution patterns
        blocked_patterns = ["eval", "exec", "os.system", "subprocess", "rm -rf"]
        for pattern in blocked_patterns:
            if pattern in request.action_parameter.lower():
                return {
                    "status": "BLOCKED",
                    "reason": f"Dangerous execution pattern detected: '{pattern}' found in parameter"
                }

        return {"status": "ALLOWED", "validated_request": request.model_dump()}

    except ValidationError as e:
        return {"status": "REJECTED", "reason": str(e)}

if __name__ == "__main__":
    print("Testing safe call:")
    print(validate_tool_call("DatabaseQueryTool", "api.internal/v1/query", "SELECT user_id FROM profiles"))
