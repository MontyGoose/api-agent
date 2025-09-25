"""Tests for ConcreteAgentSDK response transformation integration."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

from src.app.services.concrete_sdk import ConcreteAgentSDK
from src.app.models.agent_config import AgentSDKConfig
from src.app.services.exceptions import SDKResponseError


class TestConcreteAgentSDKResponseTransformation:
    """Test response transformation in ConcreteAgentSDK."""
    
    @pytest.fixture
    def mock_config(self) -> AgentSDKConfig:
        """Create mock AgentSDKConfig for testing."""
        return AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token="mock.jwt.token",
            request_timeout=30,
            retry_count=2,
            mock_mode=False
        )
    
    @pytest.fixture
    def concrete_sdk(self, mock_config) -> ConcreteAgentSDK:
        """Create ConcreteAgentSDK instance for testing."""
        return ConcreteAgentSDK(mock_config)
    
    def test_parse_agent_response_valid_complete_response(self, concrete_sdk):
        """Test parsing a valid, complete agent response."""
        valid_response = {
            "agentId": "test-agent-123",
            "agentName": "Customer Support Bot",
            "orgId": "org-456",
            "tenantId": "tenant-789",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner-123",
                "agentType": "BYOD",
                "group": "Personal",
                "requestUrl": "https://api.example.com/agent/chat",
                "rootUrl": "https://api.example.com/agent/",
                "llmModel": "gpt-4",
                "status": "ACTIVE",
                "retrieverStrategy": "NUGGET",
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING",
                "welcomeMessage": "Hello! How can I help?",
                "controlFlags": ["USE_HYBRID_RAG"],
                "uiType": "chat"
            }
        }
        
        result = concrete_sdk._parse_agent_response(valid_response, "test-agent-123")
        
        assert result.agentId == "test-agent-123"
        assert result.agentName == "Customer Support Bot"
        assert result.tenantId == "tenant-789"
        assert result.agentConfig.status == "ACTIVE"
        assert result.agentConfig.llmModel == "gpt-4"
    
    def test_parse_agent_response_agent_id_mismatch(self, concrete_sdk):
        """Test parsing fails when agent ID doesn't match expected."""
        response_with_wrong_id = {
            "agentId": "different-agent-456",
            "agentName": "Test Agent",
            "tenantId": "tenant-123",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner-123",
                "requestUrl": "https://api.example.com/agent/chat",
                "rootUrl": "https://api.example.com/agent/",
                "llmModel": "gpt-4",
                "status": "ACTIVE",
                "retrieverStrategy": "NUGGET",
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING"
            }
        }
        
        with pytest.raises(SDKResponseError) as exc_info:
            concrete_sdk._parse_agent_response(response_with_wrong_id, "test-agent-123")
        
        assert "Response agent ID mismatch" in str(exc_info.value)
        assert "expected 'test-agent-123'" in str(exc_info.value)
        assert "got 'different-agent-456'" in str(exc_info.value)
    
    def test_parse_agent_response_invalid_type(self, concrete_sdk):
        """Test parsing fails for non-dictionary input."""
        invalid_inputs = [
            "string response",
            123,
            ["list", "response"],
            None,
            True
        ]
        
        for invalid_input in invalid_inputs:
            with pytest.raises(SDKResponseError) as exc_info:
                concrete_sdk._parse_agent_response(invalid_input, "test-agent-123")
            
            assert "Expected dictionary" in str(exc_info.value)
    
    def test_parse_agent_response_missing_required_fields(self, concrete_sdk):
        """Test parsing fails when required fields are missing."""
        incomplete_responses = [
            # Missing agentId
            {
                "agentName": "Test Agent",
                "tenantId": "tenant-123",
                "agentConfig": {"version": "3", "ownerId": "owner-123"}
            },
            # Missing agentName
            {
                "agentId": "test-agent-123",
                "tenantId": "tenant-123",
                "agentConfig": {"version": "3", "ownerId": "owner-123"}
            },
            # Missing tenantId
            {
                "agentId": "test-agent-123",
                "agentName": "Test Agent",
                "agentConfig": {"version": "3", "ownerId": "owner-123"}
            },
            # Missing agentConfig
            {
                "agentId": "test-agent-123",
                "agentName": "Test Agent",
                "tenantId": "tenant-123"
            }
        ]
        
        for incomplete_response in incomplete_responses:
            with pytest.raises(SDKResponseError):
                concrete_sdk._parse_agent_response(incomplete_response, "test-agent-123")
    
    def test_parse_agent_response_incomplete_agent_config(self, concrete_sdk):
        """Test parsing fails when agentConfig is incomplete."""
        response_with_incomplete_config = {
            "agentId": "test-agent-123",
            "agentName": "Test Agent",
            "tenantId": "tenant-123",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner-123",
                # Missing required fields like requestUrl, rootUrl, llmModel, status, etc.
            }
        }
        
        with pytest.raises(SDKResponseError):
            concrete_sdk._parse_agent_response(response_with_incomplete_config, "test-agent-123")
    
    def test_parse_agent_response_invalid_urls(self, concrete_sdk):
        """Test parsing fails when URLs are invalid."""
        response_with_invalid_urls = {
            "agentId": "test-agent-123",
            "agentName": "Test Agent",
            "tenantId": "tenant-123",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner-123",
                "requestUrl": "invalid-url",  # Invalid URL
                "rootUrl": "also-invalid",    # Invalid URL
                "llmModel": "gpt-4",
                "status": "ACTIVE",
                "retrieverStrategy": "NUGGET",
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING"
            }
        }
        
        with pytest.raises(SDKResponseError):
            concrete_sdk._parse_agent_response(response_with_invalid_urls, "test-agent-123")


class TestConcreteAgentSDKEndToEndTransformation:
    """Test end-to-end transformation in ConcreteAgentSDK.get_agent."""
    
    @pytest.fixture
    def mock_config(self) -> AgentSDKConfig:
        """Create mock AgentSDKConfig for testing."""
        return AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token="mock.jwt.token",
            request_timeout=30,
            retry_count=1,  # Reduce retries for faster tests
            mock_mode=False
        )
    
    @pytest.fixture
    def concrete_sdk(self, mock_config) -> ConcreteAgentSDK:
        """Create ConcreteAgentSDK instance for testing."""
        sdk = ConcreteAgentSDK(mock_config)
        # Mock the session manager to avoid authentication issues in tests
        sdk.session_manager = Mock()
        sdk.session_manager.is_authenticated.return_value = True
        return sdk
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_successful_transformation(self, mock_async_agent_class, concrete_sdk):
        """Test successful agent retrieval and transformation."""
        # Setup mock AsyncAgent
        mock_async_agent = AsyncMock()
        mock_async_agent_class.return_value = mock_async_agent
        
        # Mock the view() method to return a complete response
        mock_response = {
            "agentId": "test-agent-123",
            "agentName": "Customer Support Bot",
            "orgId": "org-456",
            "tenantId": "DEV",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner-123",
                "agentType": "BYOD",
                "group": "Personal",
                "requestUrl": "https://api.example.com/agent/chat",
                "rootUrl": "https://api.example.com/agent/",
                "llmModel": "gpt-4",
                "status": "ACTIVE",
                "retrieverStrategy": "NUGGET",
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING",
                "welcomeMessage": "Hello! How can I help?",
                "controlFlags": ["USE_HYBRID_RAG"],
                "uiType": "chat"
            }
        }
        mock_async_agent.view.return_value = mock_response
        
        # Call get_agent
        result = await concrete_sdk.get_agent("test-agent-123")
        
        # Verify the result is in simple format
        expected_simple_format = {
            "id": "test-agent-123",
            "name": "Customer Support Bot",
            "status": "active"  # Should be lowercase
        }
        
        assert result == expected_simple_format
        
        # Verify AsyncAgent was created and called correctly
        mock_async_agent_class.assert_called_once()
        mock_async_agent.view.assert_called_once_with("test-agent-123")
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_transformation_with_various_statuses(self, mock_async_agent_class, concrete_sdk):
        """Test transformation handles various status formats correctly."""
        status_test_cases = [
            ("ACTIVE", "active"),
            ("INACTIVE", "inactive"),
            ("BUSY", "busy"),
            ("ERROR", "error"),
            ("INDEXING", "indexing"),
            ("  READY  ", "ready")  # Test whitespace trimming
        ]
        
        for input_status, expected_status in status_test_cases:
            # Setup mock AsyncAgent for each test case
            mock_async_agent = AsyncMock()
            mock_async_agent_class.return_value = mock_async_agent
            
            mock_response = {
                "agentId": "test-agent-123",
                "agentName": "Test Agent",
                "tenantId": "DEV",
                "agentConfig": {
                    "version": "3",
                    "ownerId": "owner-123",
                    "requestUrl": "https://api.example.com/agent/chat",
                    "rootUrl": "https://api.example.com/agent/",
                    "llmModel": "gpt-4",
                    "status": input_status,
                    "retrieverStrategy": "NUGGET",
                    "reasoningAlgorithm": "GPT_FUNCTION_REASONING"
                }
            }
            mock_async_agent.view.return_value = mock_response
            
            result = await concrete_sdk.get_agent("test-agent-123")
            
            assert result["status"] == expected_status
            assert result["id"] == "test-agent-123"
            assert result["name"] == "Test Agent"
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_response_validation_failure(self, mock_async_agent_class, concrete_sdk):
        """Test get_agent handles response validation failures."""
        # Setup mock AsyncAgent
        mock_async_agent = AsyncMock()
        mock_async_agent_class.return_value = mock_async_agent
        
        # Mock invalid response (missing required fields)
        invalid_response = {
            "agentId": "test-agent-123",
            # Missing agentName, tenantId, agentConfig
        }
        mock_async_agent.view.return_value = invalid_response
        
        # Should raise SDKResponseError
        with pytest.raises(SDKResponseError):
            await concrete_sdk.get_agent("test-agent-123")
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_get_agent_agent_id_mismatch_in_response(self, mock_async_agent_class, concrete_sdk):
        """Test get_agent handles agent ID mismatch in response."""
        # Setup mock AsyncAgent
        mock_async_agent = AsyncMock()
        mock_async_agent_class.return_value = mock_async_agent
        
        # Mock response with different agent ID
        mismatched_response = {
            "agentId": "different-agent-456",
            "agentName": "Test Agent",
            "tenantId": "DEV",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner-123",
                "requestUrl": "https://api.example.com/agent/chat",
                "rootUrl": "https://api.example.com/agent/",
                "llmModel": "gpt-4",
                "status": "ACTIVE",
                "retrieverStrategy": "NUGGET",
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING"
            }
        }
        mock_async_agent.view.return_value = mismatched_response
        
        # Should raise SDKResponseError with specific message
        with pytest.raises(SDKResponseError) as exc_info:
            await concrete_sdk.get_agent("test-agent-123")
        
        assert "Response agent ID mismatch" in str(exc_info.value)


class TestConcreteAgentSDKBackwardCompatibility:
    """Test backward compatibility of ConcreteAgentSDK transformations."""
    
    @pytest.fixture
    def mock_config(self) -> AgentSDKConfig:
        """Create mock AgentSDKConfig for testing."""
        return AgentSDKConfig(
            env="DEV",
            base_url="https://api.example.com",
            jwt_token="mock.jwt.token",
            request_timeout=30,
            retry_count=1,
            mock_mode=False
        )
    
    @pytest.fixture
    def concrete_sdk(self, mock_config) -> ConcreteAgentSDK:
        """Create ConcreteAgentSDK instance for testing."""
        sdk = ConcreteAgentSDK(mock_config)
        sdk.session_manager = Mock()
        sdk.session_manager.is_authenticated.return_value = True
        return sdk
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_output_matches_mock_sdk_format(self, mock_async_agent_class, concrete_sdk):
        """Test that ConcreteAgentSDK output matches MockAgentSDK format exactly."""
        # Setup mock AsyncAgent
        mock_async_agent = AsyncMock()
        mock_async_agent_class.return_value = mock_async_agent
        
        # Mock response that should transform to match MockAgentSDK output
        mock_response = {
            "agentId": "agent-123",
            "agentName": "Customer Support Bot",
            "tenantId": "DEV",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner-123",
                "requestUrl": "https://api.example.com/agent/chat",
                "rootUrl": "https://api.example.com/agent/",
                "llmModel": "gpt-4",
                "status": "ACTIVE",
                "retrieverStrategy": "NUGGET",
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING"
            }
        }
        mock_async_agent.view.return_value = mock_response
        
        result = await concrete_sdk.get_agent("agent-123")
        
        # This should match exactly what MockAgentSDK returns
        expected_mock_format = {
            "id": "agent-123",
            "name": "Customer Support Bot",
            "status": "active"
        }
        
        assert result == expected_mock_format
        assert set(result.keys()) == {"id", "name", "status"}
        assert isinstance(result["id"], str)
        assert isinstance(result["name"], str)
        assert isinstance(result["status"], str)
    
    @pytest.mark.asyncio
    @patch('src.app.services.concrete_sdk.AsyncAgent')
    async def test_output_compatible_with_agent_service(self, mock_async_agent_class, concrete_sdk):
        """Test that ConcreteAgentSDK output is compatible with AgentService expectations."""
        # Setup mock AsyncAgent
        mock_async_agent = AsyncMock()
        mock_async_agent_class.return_value = mock_async_agent
        
        mock_response = {
            "agentId": "test-agent-456",
            "agentName": "Sales Assistant",
            "tenantId": "DEV",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner-123",
                "requestUrl": "https://api.example.com/agent/chat",
                "rootUrl": "https://api.example.com/agent/",
                "llmModel": "gpt-4",
                "status": "INACTIVE",
                "retrieverStrategy": "NUGGET",
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING"
            }
        }
        mock_async_agent.view.return_value = mock_response
        
        result = await concrete_sdk.get_agent("test-agent-456")
        
        # AgentService expects these exact fields to create AgentStatusResponse
        assert "id" in result
        assert "name" in result
        assert "status" in result
        
        # Values should be properly formatted for AgentService
        assert result["id"] == "test-agent-456"
        assert result["name"] == "Sales Assistant"
        assert result["status"] == "inactive"  # Lowercase for consistency
        
        # No extra fields that might confuse AgentService
        assert len(result) == 3