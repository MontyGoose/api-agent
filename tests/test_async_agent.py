"""Unit tests for AsyncAgent class."""

import pytest
import uuid
import jwt
import httpx
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from unittest.mock import patch, AsyncMock, MagicMock

from src.app.models.async_agent import AsyncAgent, FileDetail, MemoryConfig
from src.app.models.session import Session, SessionManager
from src.app.services.exceptions import SDKError, AgentNotFoundError, AuthenticationError


class TestAsyncAgent:
    """Test cases for AsyncAgent initialization and validation."""
    
    def test_async_agent_default_initialization(self):
        """Test AsyncAgent initialization with default values."""
        agent = AsyncAgent()
        
        # Check that agent_id is generated as UUID
        assert agent.agent_id is not None
        assert isinstance(agent.agent_id, str)
        # Validate it's a proper UUID
        uuid.UUID(agent.agent_id)
        
        # Check default agent_name format
        assert agent.agent_name is not None
        assert agent.agent_name.startswith("Agent: ")
        assert len(agent.agent_name.split(": ")[1]) == 4  # 4-digit number
        
        # Check default values
        assert agent.env is None
        assert agent.base_url is None
        assert agent.session is None
        assert agent.request_timeout == 180
        assert agent.auth_headers is None
        assert agent.llm_model is None
        assert agent.agent_description == ""
        assert agent.prompt == ""
        assert agent.role == ""
        assert agent.welcome_message == "Hi! How can I assist you today?"
        assert agent.retriever_strategy is None
        assert agent.reasoning_algorithm is None
        assert agent.questions == []
        assert agent.file_details is None
        assert agent.request_url is None
        assert agent.root_url is None
        assert agent.request_id is None
        assert agent.app_id is None
        assert agent.commit_id is None
        assert agent.initiative_id is None
        assert agent.metadata is None
        assert agent.control_flags == []
        assert agent.memory_config is not None
        assert agent.guardrail_config is None
        assert agent.agent_type == "BYOD"
        assert agent.stomp_client is None
        assert agent.http_client is None
    
    def test_async_agent_with_provided_agent_id(self):
        """Test AsyncAgent initialization with provided agent_id."""
        test_agent_id = "test-agent-123"
        agent = AsyncAgent(agent_id=test_agent_id)
        
        assert agent.agent_id == test_agent_id
    
    def test_async_agent_with_all_parameters(self):
        """Test AsyncAgent initialization with all parameters provided."""
        test_data = {
            "agent_id": "test-agent-456",
            "agent_name": "Test Agent",
            "env": "DEV",
            "base_url": "https://test.example.com",
            "request_timeout": 300,
            "auth_headers": {"Authorization": "Bearer token"},
            "llm_model": "gpt-4",
            "agent_description": "Test agent description",
            "prompt": "You are a helpful assistant",
            "role": "assistant",
            "welcome_message": "Welcome to the test agent",
            "retriever_strategy": "NUGGET",
            "reasoning_algorithm": "GPT_FUNCTION_REASONING",
            "questions": ["What can you do?", "How can I help?"],
            "request_url": "https://test.example.com/chat",
            "root_url": "https://test.example.com/",
            "request_id": "req-123",
            "app_id": "app-456",
            "commit_id": "commit-789",
            "initiative_id": "init-001",
            "metadata": {"key": "value"},
            "control_flags": ["USE_HYBRID_RAG", "ADD_KNOWLEDGE"],
            "agent_type": "CUSTOM"
        }
        
        agent = AsyncAgent(**test_data)
        
        # Verify all fields are set correctly
        assert agent.agent_id == test_data["agent_id"]
        assert agent.agent_name == test_data["agent_name"]
        assert agent.env == test_data["env"]
        assert agent.base_url == test_data["base_url"]
        assert agent.request_timeout == test_data["request_timeout"]
        assert agent.auth_headers == test_data["auth_headers"]
        assert agent.llm_model == test_data["llm_model"]
        assert agent.agent_description == test_data["agent_description"]
        assert agent.prompt == test_data["prompt"]
        assert agent.role == test_data["role"]
        assert agent.welcome_message == test_data["welcome_message"]
        assert agent.retriever_strategy == test_data["retriever_strategy"]
        assert agent.reasoning_algorithm == test_data["reasoning_algorithm"]
        assert agent.questions == test_data["questions"]
        assert agent.request_url == test_data["request_url"]
        assert agent.root_url == test_data["root_url"]
        assert agent.request_id == test_data["request_id"]
        assert agent.app_id == test_data["app_id"]
        assert agent.commit_id == test_data["commit_id"]
        assert agent.initiative_id == test_data["initiative_id"]
        assert agent.metadata == test_data["metadata"]
        assert agent.control_flags == test_data["control_flags"]
        assert agent.agent_type == test_data["agent_type"]


class TestAsyncAgentValidation:
    """Test cases for AsyncAgent field validation."""
    
    def test_agent_id_validation_empty_string(self):
        """Test agent_id validation with empty string."""
        with pytest.raises(ValueError, match="agent_id must be a non-empty string"):
            AsyncAgent(agent_id="")
    
    def test_agent_id_validation_whitespace_only(self):
        """Test agent_id validation with whitespace-only string."""
        with pytest.raises(ValueError, match="agent_id must be a non-empty string"):
            AsyncAgent(agent_id="   ")
    
    def test_agent_id_validation_strips_whitespace(self):
        """Test agent_id validation strips whitespace."""
        agent = AsyncAgent(agent_id="  test-agent  ")
        assert agent.agent_id == "test-agent"
    
    def test_env_validation_valid_values(self):
        """Test env validation with valid values."""
        valid_envs = ["DEV", "QA", "PROD", "LOCAL", "TEST"]
        
        for env in valid_envs:
            agent = AsyncAgent(env=env)
            assert agent.env == env.upper()
            
            # Test lowercase versions
            agent_lower = AsyncAgent(env=env.lower())
            assert agent_lower.env == env.upper()
    
    def test_env_validation_invalid_value(self):
        """Test env validation with invalid value."""
        with pytest.raises(ValueError, match="env must be one of"):
            AsyncAgent(env="INVALID")
    
    def test_request_timeout_validation_positive(self):
        """Test request_timeout validation with positive values."""
        agent = AsyncAgent(request_timeout=300)
        assert agent.request_timeout == 300
    
    def test_request_timeout_validation_zero(self):
        """Test request_timeout validation with zero."""
        with pytest.raises(ValueError, match="request_timeout must be positive"):
            AsyncAgent(request_timeout=0)
    
    def test_request_timeout_validation_negative(self):
        """Test request_timeout validation with negative value."""
        with pytest.raises(ValueError, match="request_timeout must be positive"):
            AsyncAgent(request_timeout=-1)
    
    def test_uuid_generation_when_agent_id_none(self):
        """Test UUID generation when agent_id is None."""
        agent = AsyncAgent(agent_id=None)
        
        # Should generate a valid UUID
        assert agent.agent_id is not None
        uuid.UUID(agent.agent_id)  # This will raise if not a valid UUID
    
    def test_uuid_generation_multiple_agents(self):
        """Test that multiple agents get different UUIDs."""
        agent1 = AsyncAgent()
        agent2 = AsyncAgent()
        
        assert agent1.agent_id != agent2.agent_id
        # Both should be valid UUIDs
        uuid.UUID(agent1.agent_id)
        uuid.UUID(agent2.agent_id)


class TestAsyncAgentMethods:
    """Test cases for AsyncAgent methods."""
    
    def test_to_dict_method(self):
        """Test to_dict method returns proper dictionary."""
        agent = AsyncAgent(
            agent_id="test-123",
            agent_name="Test Agent",
            env="DEV"
        )
        
        result = agent.to_dict()
        
        assert isinstance(result, dict)
        assert result["agent_id"] == "test-123"
        assert result["agent_name"] == "Test Agent"
        assert result["env"] == "DEV"
        # Should exclude None values
        assert "base_url" not in result or result["base_url"] is None
    
    def test_str_representation(self):
        """Test string representation of agent."""
        agent = AsyncAgent(
            agent_id="test-123",
            agent_name="Test Agent",
            env="DEV"
        )
        
        str_repr = str(agent)
        assert "AsyncAgent" in str_repr
        assert "test-123" in str_repr
        assert "Test Agent" in str_repr
        assert "DEV" in str_repr
    
    def test_repr_representation(self):
        """Test detailed string representation of agent."""
        agent = AsyncAgent(
            agent_id="test-123",
            agent_name="Test Agent",
            env="DEV",
            base_url="https://test.com"
        )
        
        repr_str = repr(agent)
        assert "AsyncAgent" in repr_str
        assert "agent_id='test-123'" in repr_str
        assert "agent_name='Test Agent'" in repr_str
        assert "env='DEV'" in repr_str
        assert "base_url='https://test.com'" in repr_str
    



class TestFileDetail:
    """Test cases for FileDetail model."""
    
    def test_file_detail_initialization(self):
        """Test FileDetail initialization."""
        file_detail = FileDetail(filename="test.txt")
        
        assert file_detail.filename == "test.txt"
        assert file_detail.content is None
        assert file_detail.file_type is None
    
    def test_file_detail_with_all_fields(self):
        """Test FileDetail with all fields."""
        file_detail = FileDetail(
            filename="test.txt",
            content="file content",
            file_type="text/plain"
        )
        
        assert file_detail.filename == "test.txt"
        assert file_detail.content == "file content"
        assert file_detail.file_type == "text/plain"


class TestMemoryConfig:
    """Test cases for MemoryConfig model."""
    
    def test_memory_config_defaults(self):
        """Test MemoryConfig default values."""
        config = MemoryConfig()
        
        assert config.enabled is True
        assert config.max_tokens == 4000
    
    def test_memory_config_custom_values(self):
        """Test MemoryConfig with custom values."""
        config = MemoryConfig(enabled=False, max_tokens=2000)
        
        assert config.enabled is False
        assert config.max_tokens == 2000
    
    def test_memory_config_dict_method(self):
        """Test MemoryConfig dict method."""
        config = MemoryConfig(enabled=False, max_tokens=2000)
        result = config.dict()
        
        assert isinstance(result, dict)
        assert result == {"enabled": False, "max_tokens": 2000}


class TestAsyncAgentWithFileDetails:
    """Test cases for AsyncAgent with file details."""
    
    def test_agent_with_file_details(self):
        """Test AsyncAgent with file details."""
        file_details = [
            FileDetail(filename="doc1.txt", content="content1"),
            FileDetail(filename="doc2.pdf", file_type="application/pdf")
        ]
        
        agent = AsyncAgent(file_details=file_details)
        
        assert len(agent.file_details) == 2
        assert agent.file_details[0].filename == "doc1.txt"
        assert agent.file_details[0].content == "content1"
        assert agent.file_details[1].filename == "doc2.pdf"
        assert agent.file_details[1].file_type == "application/pdf"


class TestAsyncAgentNameGeneration:
    """Test cases for agent name generation."""
    
    @patch('random.randint')
    def test_agent_name_generation_format(self, mock_randint):
        """Test agent name generation format."""
        mock_randint.return_value = 1234
        
        agent = AsyncAgent()
        
        assert agent.agent_name == "Agent: 1234"
        mock_randint.assert_called_once_with(1000, 9999)
    
    def test_agent_name_generation_uniqueness(self):
        """Test that agent name generation produces different names."""
        agents = [AsyncAgent() for _ in range(10)]
        names = [agent.agent_name for agent in agents]
        
        # While not guaranteed, it's very unlikely all 10 would be the same
        # This test might occasionally fail due to randomness, but it's very unlikely
        assert len(set(names)) > 1, "Generated names should be different"


class TestAsyncAgentSessionManagement:
    """Test cases for AsyncAgent session management functionality."""
    
    def test_agent_initialization_with_session(self):
        """Test AsyncAgent initialization with session."""
        # Create a valid JWT token
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session = Session.connect(token)
        
        agent = AsyncAgent(session=session)
        
        assert agent.session == session
        assert agent._session_manager is not None
        assert agent._session_manager.jwt_token == token
    
    def test_agent_initialization_without_session(self):
        """Test AsyncAgent initialization without session."""
        agent = AsyncAgent()
        
        assert agent.session is None
        assert agent._session_manager is None
    
    def test_set_session_manager(self):
        """Test setting session manager."""
        agent = AsyncAgent()
        
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent.set_session_manager(session_manager)
        
        assert agent._session_manager == session_manager
    
    def test_get_session_manager(self):
        """Test getting session manager."""
        agent = AsyncAgent()
        
        # Initially None
        assert agent.get_session_manager() is None
        
        # After setting
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent.set_session_manager(session_manager)
        
        assert agent.get_session_manager() == session_manager
    
    @pytest.mark.asyncio
    async def test_ensure_authenticated_session_success(self):
        """Test successful authentication session creation."""
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent()
        agent.set_session_manager(session_manager)
        
        session = await agent.ensure_authenticated_session()
        
        assert session is not None
        assert session.jwt_token == token
        assert session.user_id == "user123"
    
    @pytest.mark.asyncio
    async def test_ensure_authenticated_session_no_manager(self):
        """Test authentication session fails without session manager."""
        agent = AsyncAgent()
        
        with pytest.raises(SDKError, match="No session manager available"):
            await agent.ensure_authenticated_session()
    
    @pytest.mark.asyncio
    async def test_ensure_authenticated_session_invalid_token(self):
        """Test authentication session fails with invalid token."""
        session_manager = SessionManager()  # No token
        
        agent = AsyncAgent()
        agent.set_session_manager(session_manager)
        
        with pytest.raises(SDKError, match="No JWT token available"):
            await agent.ensure_authenticated_session()
    
    def test_agent_initialization_creates_session_manager_from_session(self):
        """Test that agent initialization creates session manager from session JWT token."""
        # Create a valid JWT token and session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session = Session.connect(token)
        
        agent = AsyncAgent(session=session)
        
        assert agent.session == session
        assert agent._session_manager is not None
        assert agent._session_manager.jwt_token == token
    
    @pytest.mark.asyncio
    async def test_full_session_workflow(self):
        """Test complete session workflow with AsyncAgent."""
        # Create JWT token
        payload = {
            "sub": "user123",
            "roles": ["user"],
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        
        # Create agent and set up session management
        agent = AsyncAgent(agent_id="test-agent")
        session_manager = SessionManager(jwt_token=token)
        agent.set_session_manager(session_manager)
        
        # Ensure authenticated session
        session = await agent.ensure_authenticated_session()
        
        # Verify session properties
        assert session.user_id == "user123"
        assert session.roles == ["user"]
        assert not session.is_expired()
        
        # Get auth headers
        headers = session.get_auth_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == f"Bearer {token}"


class TestAsyncAgentViewMethod:
    """Test cases for AsyncAgent view() method and API integration."""
    
    def _setup_mock_client(self, mock_client, status_code=200, json_response=None, side_effect=None):
        """Helper to setup mock HTTP client."""
        mock_response = MagicMock()
        mock_response.status_code = status_code
        
        if json_response is not None:
            mock_response.json.return_value = json_response
        if side_effect is not None:
            if hasattr(side_effect, '__call__'):
                mock_response.json.side_effect = side_effect
            else:
                mock_client_instance = AsyncMock()
                mock_client_instance.get.side_effect = side_effect
                mock_client.return_value.__aenter__.return_value = mock_client_instance
                return
        
        # Setup async context manager
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
    
    @pytest.mark.asyncio
    async def test_view_method_no_agent_id(self):
        """Test view method fails when no agent_id is available."""
        # Create agent and manually set agent_id to None after initialization
        # We need to bypass the model validator that generates UUID
        agent = AsyncAgent()
        # Use model_dump and model_validate to bypass the validator
        data = agent.model_dump()
        data['agent_id'] = None
        agent = AsyncAgent.model_validate(data)
        # Override the validator by setting directly
        object.__setattr__(agent, 'agent_id', None)
        
        with pytest.raises(SDKError, match="No agent_id provided and current agent has no ID"):
            await agent.view()
    
    @pytest.mark.asyncio
    async def test_view_method_no_base_url(self):
        """Test view method fails when base_url is not configured."""
        agent = AsyncAgent(agent_id="test-agent")
        
        with pytest.raises(SDKError, match="base_url is required for API calls"):
            await agent.view()
    
    @pytest.mark.asyncio
    async def test_view_method_no_session_manager(self):
        """Test view method fails when no session manager is available."""
        agent = AsyncAgent(
            agent_id="test-agent",
            base_url="https://test.example.com"
        )
        
        with pytest.raises(AuthenticationError, match="Failed to establish authenticated session"):
            await agent.view()
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_successful_response(self, mock_client):
        """Test view method with successful API response."""
        # Setup mock response
        self._setup_mock_client(mock_client, 200, {
            "agentId": "test-agent",
            "agentName": "Test Agent",
            "status": "active"
        })
        
        # Create agent with session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="test-agent",
            base_url="https://test.example.com",
            request_timeout=30
        )
        agent.set_session_manager(session_manager)
        
        # Call view method
        result = await agent.view()
        
        # Verify result
        assert result["agentId"] == "test-agent"
        assert result["agentName"] == "Test Agent"
        assert result["status"] == "active"
        
        # Verify HTTP call was made correctly
        mock_client.assert_called_once_with(timeout=30)
        mock_client.return_value.__aenter__.return_value.get.assert_called_once_with(
            "https://test.example.com/agents/test-agent",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        )
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_with_different_agent_id(self, mock_client):
        """Test view method with different agent_id parameter."""
        # Setup mock response
        self._setup_mock_client(mock_client, 200, {
            "agentId": "other-agent",
            "agentName": "Other Agent"
        })
        
        # Create agent with session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="test-agent",
            base_url="https://test.example.com"
        )
        agent.set_session_manager(session_manager)
        
        # Call view method with different agent_id
        result = await agent.view("other-agent")
        
        # Verify result
        assert result["agentId"] == "other-agent"
        
        # Verify correct URL was called
        mock_client.return_value.__aenter__.return_value.get.assert_called_once_with(
            "https://test.example.com/agents/other-agent",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        )
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_404_response(self, mock_client):
        """Test view method with 404 response (agent not found)."""
        # Setup mock response
        self._setup_mock_client(mock_client, 404)
        
        # Create agent with session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="nonexistent-agent",
            base_url="https://test.example.com"
        )
        agent.set_session_manager(session_manager)
        
        # Call view method and expect AgentNotFoundError
        with pytest.raises(AgentNotFoundError):
            await agent.view()
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_403_response(self, mock_client):
        """Test view method with 403 response (access denied)."""
        # Setup mock response
        self._setup_mock_client(mock_client, 403)
        
        # Create agent with session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="restricted-agent",
            base_url="https://test.example.com"
        )
        agent.set_session_manager(session_manager)
        
        # Call view method and expect AgentNotFoundError (access denied treated as not found)
        with pytest.raises(AgentNotFoundError):
            await agent.view()
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_401_response(self, mock_client):
        """Test view method with 401 response (authentication failed)."""
        # Setup mock response
        self._setup_mock_client(mock_client, 401)
        
        # Create agent with session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="test-agent",
            base_url="https://test.example.com"
        )
        agent.set_session_manager(session_manager)
        
        # Call view method and expect AuthenticationError
        with pytest.raises(AuthenticationError, match="Authentication failed - invalid or expired JWT token"):
            await agent.view()
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_500_response(self, mock_client):
        """Test view method with 500 response (server error)."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.return_value = {"detail": "Internal server error"}
        mock_response.text = "Internal server error"
        
        # Setup async context manager
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        # Create agent with session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="test-agent",
            base_url="https://test.example.com"
        )
        agent.set_session_manager(session_manager)
        
        # Call view method and expect SDKError
        with pytest.raises(SDKError, match="API call failed with status 500"):
            await agent.view()
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_timeout_error(self, mock_client):
        """Test view method with timeout error."""
        # Setup mock to raise timeout exception
        self._setup_mock_client(mock_client, side_effect=httpx.TimeoutException("Request timed out"))
        
        # Create agent with session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="test-agent",
            base_url="https://test.example.com",
            request_timeout=5
        )
        agent.set_session_manager(session_manager)
        
        # Call view method and expect SDKTimeoutError
        from src.app.services.exceptions import SDKTimeoutError
        with pytest.raises(SDKTimeoutError):
            await agent.view()
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_request_error(self, mock_client):
        """Test view method with HTTP request error."""
        # Setup mock to raise request exception
        self._setup_mock_client(mock_client, side_effect=httpx.RequestError("Connection failed"))
        
        # Create agent with session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="test-agent",
            base_url="https://test.example.com"
        )
        agent.set_session_manager(session_manager)
        
        # Call view method and expect SDKError
        with pytest.raises(SDKError, match="HTTP request failed"):
            await agent.view()
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_json_parse_error(self, mock_client):
        """Test view method with JSON parsing error."""
        # Setup mock response with invalid JSON
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        
        # Setup async context manager
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        # Create agent with session
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="test-agent",
            base_url="https://test.example.com"
        )
        agent.set_session_manager(session_manager)
        
        # Call view method and expect SDKError
        with pytest.raises(SDKError, match="Failed to parse JSON response"):
            await agent.view()
    
    @pytest.mark.asyncio
    @patch('src.app.models.async_agent.httpx.AsyncClient')
    async def test_view_method_uses_default_timeout(self, mock_client):
        """Test view method uses default timeout when not specified."""
        # Setup mock response
        self._setup_mock_client(mock_client, 200, {"agentId": "test-agent"})
        
        # Create agent with session (no timeout specified)
        payload = {
            "sub": "user123",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")
        session_manager = SessionManager(jwt_token=token)
        
        agent = AsyncAgent(
            agent_id="test-agent",
            base_url="https://test.example.com"
            # request_timeout not specified, should use default 180
        )
        agent.set_session_manager(session_manager)
        
        # Call view method
        await agent.view()
        
        # Verify default timeout was used
        mock_client.assert_called_once_with(timeout=180)


class TestAsyncAgentURLConstruction:
    """Test cases for AsyncAgent URL construction helper."""
    
    def test_construct_api_url_basic(self):
        """Test basic URL construction."""
        agent = AsyncAgent(base_url="https://test.example.com")
        
        url = agent._construct_api_url("agents/123")
        assert url == "https://test.example.com/agents/123"
    
    def test_construct_api_url_with_trailing_slash(self):
        """Test URL construction with trailing slash in base_url."""
        agent = AsyncAgent(base_url="https://test.example.com/")
        
        url = agent._construct_api_url("agents/123")
        assert url == "https://test.example.com/agents/123"
    
    def test_construct_api_url_with_leading_slash(self):
        """Test URL construction with leading slash in endpoint."""
        agent = AsyncAgent(base_url="https://test.example.com")
        
        url = agent._construct_api_url("/agents/123")
        assert url == "https://test.example.com/agents/123"
    
    def test_construct_api_url_with_both_slashes(self):
        """Test URL construction with both trailing and leading slashes."""
        agent = AsyncAgent(base_url="https://test.example.com/")
        
        url = agent._construct_api_url("/agents/123")
        assert url == "https://test.example.com/agents/123"
    
    def test_construct_api_url_no_base_url(self):
        """Test URL construction fails without base_url."""
        agent = AsyncAgent()
        
        with pytest.raises(SDKError, match="base_url is required for API calls"):
            agent._construct_api_url("agents/123")
    
    def test_construct_api_url_complex_endpoint(self):
        """Test URL construction with complex endpoint."""
        agent = AsyncAgent(base_url="https://api.example.com/v1")
        
        url = agent._construct_api_url("agents/123/details?include=config")
        assert url == "https://api.example.com/v1/agents/123/details?include=config"