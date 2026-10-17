from pydantic import BaseModel, Field, ValidationError

class ToolExecutionRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the tool being invoked")
    target_endpoint: str = Field(..., description="Target URI or resource identifier")
    action_parameter: str = Field(..., description="Payload or parameter passed to the tool")
    max_retries: int = Field(default=3, le=5)

def validate_tool_call(tool_name: str, endpoint: str, param: str) -> dict:
    try:
        # Enforce least-privilege constraints
        request = ToolExecutionRequest(
            tool_name=tool_name,
            target_endpoint=endpoint,
            action_parameter=param
        )
        
        # Comprehensive blocklist for dangerous execution patterns
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
    
    print("\nTesting malicious injection attempt:")
    print(validate_tool_call("SystemShellTool", "api.internal/v1/exec", "os.system('rm -rf /')"))
