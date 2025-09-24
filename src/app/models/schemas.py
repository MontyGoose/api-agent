from typing import List, Optional

from pydantic import BaseModel, Field


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class User(BaseModel):
    username: str
    roles: List[str] = []


class AgentStatusResponse(BaseModel):
    """Response model for agent status information."""
    
    id: str = Field(
        ..., 
        description="Agent unique identifier",
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9\-_]+$"
    )
    agent_name: str = Field(
        ..., 
        description="Human-readable agent name",
        min_length=1,
        max_length=255
    )
    status: str = Field(
        ..., 
        description="Current agent status",
        min_length=1,
        max_length=50
    )
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "agent-123",
                "agent_name": "Customer Support Bot",
                "status": "active"
            }
        }
    }


class ErrorDetail(BaseModel):
    """Detailed error information."""
    
    message: str = Field(
        ..., 
        description="Human-readable error message",
        min_length=1
    )
    code: str = Field(
        ..., 
        description="Machine-readable error code",
        min_length=1,
        max_length=100
    )
    details: Optional[dict] = Field(
        None, 
        description="Additional error context and details"
    )
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "message": "Agent not found",
                "code": "AGENT_NOT_FOUND",
                "details": {
                    "agent_id": "invalid-agent-123",
                    "timestamp": "2024-01-15T10:30:00Z"
                }
            }
        }
    }


class ErrorResponse(BaseModel):
    """Standard error response format."""
    
    error: ErrorDetail = Field(
        ..., 
        description="Error details"
    )
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "error": {
                    "message": "Agent not found",
                    "code": "AGENT_NOT_FOUND",
                    "details": {
                        "agent_id": "invalid-agent-123"
                    }
                }
            }
        }
    }
