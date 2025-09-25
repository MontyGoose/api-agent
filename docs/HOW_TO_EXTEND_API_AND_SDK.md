# How to Extend the Agent SDK API and SDK Integration

This guide provides step-by-step instructions for extending the codebase with new API endpoints and SDK functionality.

## Table of Contents

1. [Overview](#overview)
2. [Adding a New API Endpoint](#adding-a-new-api-endpoint)
3. [Extending SDK Functionality](#extending-sdk-functionality)
4. [Testing Your Extensions](#testing-your-extensions)
5. [Best Practices](#best-practices)
6. [Example: Adding Agent Chat Endpoint](#example-adding-agent-chat-endpoint)

## Overview

The codebase follows a layered architecture:

```
API Layer (FastAPI Routes) 
    ↓
Service Layer (Business Logic)
    ↓
SDK Layer (Mock/Concrete Implementation)
    ↓
External Agent Service
```

## Adding a New API Endpoint

### Step 1: Define Response Models

First, create Pydantic models for your API request/response in `src/app/models/schemas.py`:

```python
from pydantic import BaseModel, Field
from typing import Optional, List

class ChatRequest(BaseModel):
    message: str = Field(..., description="Message to send to agent")
    session_id: Optional[str] = Field(None, description="Chat session ID")

class ChatResponse(BaseModel):
    response: str = Field(..., description="Agent's response")
    session_id: str = Field(..., description="Chat session ID")
    timestamp: str = Field(..., description="Response timestamp")
```

### Step 2: Create API Route

Create or update a route file in `src/app/api/routes/v1/`:

```python
# src/app/api/routes/v1/agents.py (or create new file)

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Annotated
import structlog

from app.api.deps import get_current_user, get_agent_service
from app.models.schemas import User, ChatRequest, ChatResponse, ErrorResponse
from app.services.agent_service import AgentService

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/agent", tags=["agents"])

@router.post(
    "/{agent_id}/chat",
    response_model=ChatResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
        404: {"model": ErrorResponse, "description": "Agent not found"},
        502: {"model": ErrorResponse, "description": "Agent service error"},
    },
    summary="Send message to agent",
    description="Send a chat message to a specific agent and receive response",
)
async def chat_with_agent(
    agent_id: Annotated[str, Path(description="Agent unique identifier")],
    request: ChatRequest,
    user: Annotated[User, Depends(get_current_user)],
    agent_service: Annotated[AgentService, Depends(get_agent_service)]
) -> ChatResponse:
    """Send a message to an agent and get response."""
    
    logger.info(
        "Agent chat request received",
        agent_id=agent_id,
        user=user.username,
        message_length=len(request.message)
    )
    
    try:
        response = await agent_service.send_message(agent_id, request)
        
        logger.info(
            "Agent chat request completed successfully",
            agent_id=agent_id,
            user=user.username,
            session_id=response.session_id
        )
        
        return response
        
    except Exception as e:
        logger.error(
            "Agent chat request failed",
            agent_id=agent_id,
            user=user.username,
            error=str(e)
        )
        raise
```

### Step 3: Register Route in Main App

Update `src/app/main.py` to include your new route:

```python
from app.api.routes.v1 import agents  # or your new route file

def create_app() -> FastAPI:
    app = FastAPI(...)
    
    # Include routers
    app.include_router(agents.router)
    
    return app
```

## Extending SDK Functionality

### Step 1: Update SDK Interface

Add new method to the SDK interface in `src/app/services/interfaces.py`:

```python
from abc import ABC, abstractmethod
from typing import Dict, Any

class AgentSDKInterface(ABC):
    """Interface for Agent SDK implementations."""
    
    @abstractmethod
    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """Get agent information."""
        pass
    
    @abstractmethod
    async def send_message(self, agent_id: str, message: str, session_id: str = None) -> Dict[str, Any]:
        """Send message to agent and get response."""
        pass
```

### Step 2: Update Mock SDK Implementation

Add the new functionality to `src/app/services/mock_sdk.py`:

```python
class MockAgentSDK(AgentSDKInterface):
    
    # Mock chat sessions for testing
    MOCK_SESSIONS = {
        "session-123": {
            "agent_id": "agent-123",
            "messages": []
        }
    }
    
    async def send_message(self, agent_id: str, message: str, session_id: str = None) -> Dict[str, Any]:
        """Mock implementation of message sending."""
        logger.debug(
            "MockAgentSDK.send_message called",
            agent_id=agent_id,
            message_length=len(message),
            session_id=session_id
        )
        
        # Simulate network delay
        if self.simulate_delays:
            await asyncio.sleep(0.1)
        
        # Check if agent exists
        if agent_id not in self.MOCK_AGENTS:
            raise AgentNotFoundError(agent_id)
        
        # Generate session ID if not provided
        if not session_id:
            session_id = f"session-{len(self.MOCK_SESSIONS) + 1}"
        
        # Mock response based on message content
        if "hello" in message.lower():
            response_text = f"Hello! I'm {self.MOCK_AGENTS[agent_id]['name']}. How can I help you?"
        else:
            response_text = f"I received your message: '{message}'. How else can I assist you?"
        
        return {
            "response": response_text,
            "session_id": session_id,
            "timestamp": "2024-01-01T12:00:00Z"
        }
```

### Step 3: Update Concrete SDK Implementation

Add the new functionality to `src/app/services/concrete_sdk.py`:

```python
class ConcreteAgentSDK(AgentSDKInterface):
    
    async def send_message(self, agent_id: str, message: str, session_id: str = None) -> Dict[str, Any]:
        """Send message to agent using AsyncAgent."""
        logger.info("Sending message via ConcreteAgentSDK", agent_id=agent_id)
        
        try:
            # Create AsyncAgent instance
            async_agent = await self._create_async_agent(agent_id)
            
            # Call the chat method (assuming AsyncAgent has this method)
            chat_response = await self._call_agent_chat_with_retry(
                async_agent, agent_id, message, session_id
            )
            
            # Transform response to expected format
            return self._transform_chat_response(chat_response, agent_id)
            
        except Exception as e:
            logger.error(
                "Failed to send message via ConcreteAgentSDK",
                agent_id=agent_id,
                error=str(e)
            )
            mapped_error = self._map_sdk_exceptions(e, agent_id, "send_message")
            raise mapped_error
    
    async def _call_agent_chat_with_retry(
        self, async_agent: AsyncAgent, agent_id: str, message: str, session_id: str = None
    ) -> Dict[str, Any]:
        """Call AsyncAgent chat method with retry logic."""
        last_exception = None
        
        for attempt in range(self.config.retry_count + 1):
            try:
                # Call chat method with timeout
                chat_response = await asyncio.wait_for(
                    async_agent.chat(message, session_id),
                    timeout=self.config.request_timeout
                )
                return chat_response
                
            except asyncio.TimeoutError:
                raise SDKTimeoutError(self.config.request_timeout, "agent_chat")
                
            except (AgentNotFoundError, AuthenticationError):
                raise
                
            except Exception as e:
                mapped_error = self._map_sdk_exceptions(e, agent_id, "agent_chat")
                
                if isinstance(mapped_error, (AgentNotFoundError, AuthenticationError)):
                    raise mapped_error
                
                last_exception = mapped_error
                if attempt < self.config.retry_count:
                    wait_time = 2 ** attempt
                    logger.warning(
                        "AsyncAgent chat() call failed, retrying",
                        agent_id=agent_id,
                        attempt=attempt + 1,
                        wait_time=wait_time,
                        error=str(e)
                    )
                    await asyncio.sleep(wait_time)
        
        raise SDKError(
            f"Agent chat call failed after {self.config.retry_count + 1} attempts",
            original_error=last_exception
        )
    
    def _transform_chat_response(self, chat_response: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        """Transform chat response to expected format."""
        try:
            return {
                "response": chat_response.get("response", ""),
                "session_id": chat_response.get("session_id", ""),
                "timestamp": chat_response.get("timestamp", "")
            }
        except Exception as e:
            raise SDKError(f"Invalid chat response format: {str(e)}", original_error=e)
```

### Step 4: Update Service Layer

Add the new functionality to `src/app/services/agent_service.py`:

```python
class AgentService:
    
    async def send_message(self, agent_id: str, request: ChatRequest) -> ChatResponse:
        """Send message to agent and get response."""
        
        # Validate agent ID
        self._validate_agent_id(agent_id)
        
        logger.info("Sending message to agent", agent_id=agent_id)
        
        try:
            # Call SDK with retry logic
            response_data = await self._call_sdk_send_message_with_retry(
                agent_id, request.message, request.session_id
            )
            
            # Transform SDK response to our model
            response = self._transform_chat_response(response_data, agent_id)
            
            logger.info(
                "Successfully sent message to agent",
                agent_id=agent_id,
                session_id=response.session_id
            )
            
            return response
            
        except Exception as e:
            logger.error("Failed to send message to agent", agent_id=agent_id, error=str(e))
            # Handle errors similar to get_agent_status method
            raise self._handle_sdk_error(e)
    
    async def _call_sdk_send_message_with_retry(
        self, agent_id: str, message: str, session_id: str = None
    ) -> Dict[str, Any]:
        """Call SDK send_message with retry logic."""
        last_exception = None
        
        for attempt in range(self.retry_count):
            try:
                response_data = await asyncio.wait_for(
                    self.sdk.send_message(agent_id, message, session_id),
                    timeout=self.timeout_seconds
                )
                return response_data
                
            except asyncio.TimeoutError:
                raise SDKTimeoutError(self.timeout_seconds)
                
            except (AgentNotFoundError, AuthenticationError, InvalidAgentIdError):
                raise
                
            except Exception as e:
                last_exception = e
                if attempt < self.retry_count - 1:
                    wait_time = 2 ** attempt
                    logger.warning(
                        "SDK send_message call failed, retrying",
                        agent_id=agent_id,
                        attempt=attempt + 1,
                        wait_time=wait_time,
                        error=str(e)
                    )
                    await asyncio.sleep(wait_time)
        
        raise SDKError(
            f"SDK send_message call failed after {self.retry_count} attempts",
            original_error=last_exception
        )
    
    def _transform_chat_response(self, response_data: Dict[str, Any], agent_id: str) -> ChatResponse:
        """Transform SDK response to ChatResponse model."""
        try:
            return ChatResponse(
                response=response_data["response"],
                session_id=response_data["session_id"],
                timestamp=response_data["timestamp"]
            )
        except (KeyError, TypeError, ValueError) as e:
            raise SDKError(f"Invalid chat response format: {str(e)}", original_error=e)
```

## Testing Your Extensions

### Step 1: Unit Tests

Create unit tests for your new functionality:

```python
# tests/test_agent_chat.py

import pytest
from unittest.mock import AsyncMock, patch
from app.services.agent_service import AgentService
from app.services.mock_sdk import MockAgentSDK
from app.models.schemas import ChatRequest, ChatResponse

class TestAgentChat:
    
    @pytest.fixture
    def mock_sdk(self):
        return MockAgentSDK()
    
    @pytest.fixture
    def agent_service(self, mock_sdk):
        return AgentService(sdk=mock_sdk, timeout_seconds=30, retry_count=3)
    
    @pytest.mark.asyncio
    async def test_send_message_success(self, agent_service):
        """Test successful message sending."""
        request = ChatRequest(message="Hello", session_id="test-session")
        
        response = await agent_service.send_message("agent-123", request)
        
        assert isinstance(response, ChatResponse)
        assert "Hello" in response.response
        assert response.session_id == "test-session"
    
    @pytest.mark.asyncio
    async def test_send_message_agent_not_found(self, agent_service):
        """Test message sending to non-existent agent."""
        request = ChatRequest(message="Hello")
        
        with pytest.raises(HTTPException) as exc_info:
            await agent_service.send_message("nonexistent-agent", request)
        
        assert exc_info.value.status_code == 404
```

### Step 2: Integration Tests

Add integration tests to your comprehensive test suite:

```python
# tests/test_comprehensive_integration.py

class TestChatIntegration:
    """Integration tests for chat functionality."""
    
    def test_chat_endpoint_success(self, client, valid_jwt_token, auth_headers):
        """Test successful chat endpoint."""
        agent_id = "agent-123"
        chat_request = {
            "message": "Hello, how are you?",
            "session_id": "test-session"
        }
        
        response = client.post(
            f"/api/v1/agent/{agent_id}/chat",
            json=chat_request,
            headers=auth_headers(valid_jwt_token)
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert "response" in response_data
        assert "session_id" in response_data
        assert "timestamp" in response_data
```

## Best Practices

### 1. Error Handling

Always follow the established error handling patterns:

```python
try:
    # Your SDK call
    result = await sdk.your_method()
    return result
except AgentNotFoundError as e:
    raise self._handle_not_found_error(e)
except SDKTimeoutError as e:
    raise self._handle_timeout_error(e)
except SDKError as e:
    raise self._handle_sdk_error(e)
except Exception as e:
    logger.error("Unexpected error", error=str(e))
    raise HTTPException(status_code=500, detail="Internal server error")
```

### 2. Structured Logging

Use structured logging throughout:

```python
logger.info(
    "Operation started",
    agent_id=agent_id,
    user=user.username,
    operation="send_message"
)
```

### 3. Input Validation

Always validate inputs using Pydantic models:

```python
class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000, description="Message text")
    session_id: Optional[str] = Field(None, regex=r"^[a-zA-Z0-9\-_]+$")
```

### 4. Response Models

Define clear response models:

```python
class ChatResponse(BaseModel):
    response: str = Field(..., description="Agent's response")
    session_id: str = Field(..., description="Chat session ID")
    timestamp: str = Field(..., description="ISO timestamp")
    
    class Config:
        schema_extra = {
            "example": {
                "response": "Hello! How can I help you?",
                "session_id": "session-123",
                "timestamp": "2024-01-01T12:00:00Z"
            }
        }
```

## Example: Adding Agent Chat Endpoint

Here's a complete example of adding a chat endpoint following all the steps above:

### 1. Models (src/app/models/schemas.py)

```python
class ChatMessage(BaseModel):
    role: str = Field(..., description="Message role: 'user' or 'agent'")
    content: str = Field(..., description="Message content")
    timestamp: str = Field(..., description="Message timestamp")

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    session_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

class ChatResponse(BaseModel):
    response: str
    session_id: str
    timestamp: str
    context: Optional[Dict[str, Any]] = None
```

### 2. Route (src/app/api/routes/v1/agents.py)

```python
@router.post("/{agent_id}/chat", response_model=ChatResponse)
async def chat_with_agent(
    agent_id: str,
    request: ChatRequest,
    user: Annotated[User, Depends(get_current_user)],
    agent_service: Annotated[AgentService, Depends(get_agent_service)]
) -> ChatResponse:
    return await agent_service.send_message(agent_id, request)
```

### 3. Service Method (src/app/services/agent_service.py)

```python
async def send_message(self, agent_id: str, request: ChatRequest) -> ChatResponse:
    self._validate_agent_id(agent_id)
    
    try:
        response_data = await self.sdk.send_message(
            agent_id, 
            request.message, 
            request.session_id
        )
        return ChatResponse(**response_data)
    except Exception as e:
        logger.error("Chat failed", agent_id=agent_id, error=str(e))
        raise self._handle_sdk_error(e)
```

### 4. SDK Implementation (both mock and concrete)

```python
# Mock SDK
async def send_message(self, agent_id: str, message: str, session_id: str = None):
    # Mock implementation as shown above
    
# Concrete SDK  
async def send_message(self, agent_id: str, message: str, session_id: str = None):
    # Real implementation as shown above
```

### 5. Tests

```python
def test_chat_endpoint_integration(client, auth_headers, valid_jwt_token):
    response = client.post(
        "/api/v1/agent/agent-123/chat",
        json={"message": "Hello"},
        headers=auth_headers(valid_jwt_token)
    )
    assert response.status_code == 200
```

## Summary

When extending the API and SDK:

1. **Define models first** - Clear request/response models
2. **Update SDK interface** - Add abstract method
3. **Implement in both SDKs** - Mock and concrete versions
4. **Add service layer logic** - Business logic and error handling
5. **Create API endpoint** - FastAPI route with proper validation
6. **Write comprehensive tests** - Unit and integration tests
7. **Follow established patterns** - Error handling, logging, validation

This approach ensures consistency, maintainability, and reliability across your extensions.