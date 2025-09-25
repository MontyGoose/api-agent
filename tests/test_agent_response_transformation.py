"""Tests for agent response transformation and validation."""

import pytest
from typing import Dict, Any

from src.app.models.agent_config import AgentDetailsResponse, AgentConfig


class TestAgentDetailsResponseValidation:
    """Test validation functionality in AgentDetailsResponse."""
    
    def test_valid_response_creation(self):
        """Test creating AgentDetailsResponse with valid data."""
        valid_data = {
            "agentId": "test-agent-123",
            "agentName": "Test Agent",
            "orgId": "org-123",
            "tenantId": "tenant-123",
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
        
        response = AgentDetailsResponse(**valid_data)
        
        assert response.agentId == "test-agent-123"
        assert response.agentName == "Test Agent"
        assert response.tenantId == "tenant-123"
        assert response.agentConfig.status == "ACTIVE"
    
    def test_agent_id_validation_empty(self):
        """Test validation fails for empty agentId."""
        invalid_data = {
            "agentId": "",
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
        
        # Pydantic's built-in validation catches this first
        with pytest.raises(Exception):  # Could be ValidationError or ValueError
            AgentDetailsResponse(**invalid_data)
    
    def test_agent_id_validation_whitespace(self):
        """Test validation trims whitespace from agentId."""
        data = {
            "agentId": "  test-agent-123  ",
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
        
        response = AgentDetailsResponse(**data)
        assert response.agentId == "test-agent-123"
    
    def test_agent_name_validation_empty(self):
        """Test validation fails for empty agentName."""
        invalid_data = {
            "agentId": "test-agent-123",
            "agentName": "",
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
        
        # Pydantic's built-in validation catches this first
        with pytest.raises(Exception):  # Could be ValidationError or ValueError
            AgentDetailsResponse(**invalid_data)
    
    def test_tenant_id_validation_empty(self):
        """Test validation fails for empty tenantId."""
        invalid_data = {
            "agentId": "test-agent-123",
            "agentName": "Test Agent",
            "tenantId": "",
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
        
        # Pydantic's built-in validation catches this first
        with pytest.raises(Exception):  # Could be ValidationError or ValueError
            AgentDetailsResponse(**invalid_data)


class TestAgentDetailsResponseTransformation:
    """Test transformation functionality in AgentDetailsResponse."""
    
    @pytest.fixture
    def valid_agent_response(self) -> AgentDetailsResponse:
        """Create a valid AgentDetailsResponse for testing."""
        return AgentDetailsResponse(
            agentId="test-agent-123",
            agentName="Customer Support Bot",
            orgId="org-456",
            tenantId="tenant-789",
            agentConfig=AgentConfig(
                version="3",
                ownerId="owner-123",
                agentType="BYOD",
                group="Personal",
                requestUrl="https://api.example.com/agent/chat",
                rootUrl="https://api.example.com/agent/",
                llmModel="gpt-4",
                status="ACTIVE",
                retrieverStrategy="NUGGET",
                reasoningAlgorithm="GPT_FUNCTION_REASONING",
                welcomeMessage="Hello! How can I help?",
                controlFlags=["USE_HYBRID_RAG"],
                uiType="chat"
            )
        )
    
    def test_to_simple_format_basic(self, valid_agent_response):
        """Test basic transformation to simple format."""
        result = valid_agent_response.to_simple_format()
        
        expected = {
            "id": "test-agent-123",
            "name": "Customer Support Bot",
            "status": "active"
        }
        
        assert result == expected
    
    def test_to_simple_format_status_normalization(self):
        """Test that status is normalized to lowercase."""
        test_cases = [
            ("ACTIVE", "active"),
            ("INACTIVE", "inactive"),
            ("BUSY", "busy"),
            ("ERROR", "error"),
            ("Active", "active"),
            ("InActive", "inactive"),
            ("  ACTIVE  ", "active")
        ]
        
        for input_status, expected_status in test_cases:
            response = AgentDetailsResponse(
                agentId="test-agent",
                agentName="Test Agent",
                tenantId="tenant-123",
                agentConfig=AgentConfig(
                    version="3",
                    ownerId="owner-123",
                    requestUrl="https://api.example.com/agent/chat",
                    rootUrl="https://api.example.com/agent/",
                    llmModel="gpt-4",
                    status=input_status,
                    retrieverStrategy="NUGGET",
                    reasoningAlgorithm="GPT_FUNCTION_REASONING"
                )
            )
            
            result = response.to_simple_format()
            assert result["status"] == expected_status
    
    def test_to_simple_format_missing_agent_id(self):
        """Test transformation fails when agentId is missing."""
        # Create a valid response first, then manually set agentId to empty to test transformation
        response = AgentDetailsResponse(
            agentId="test-agent",
            agentName="Test Agent",
            tenantId="tenant-123",
            agentConfig=AgentConfig(
                version="3",
                ownerId="owner-123",
                requestUrl="https://api.example.com/agent/chat",
                rootUrl="https://api.example.com/agent/",
                llmModel="gpt-4",
                status="ACTIVE",
                retrieverStrategy="NUGGET",
                reasoningAlgorithm="GPT_FUNCTION_REASONING"
            )
        )
        
        # Manually set agentId to empty to test transformation validation
        response.agentId = ""
        
        with pytest.raises(ValueError, match="agentId is required"):
            response.to_simple_format()
    
    def test_to_simple_format_empty_status(self):
        """Test transformation fails when status is empty."""
        # Create response with valid status first, then modify it
        response = AgentDetailsResponse(
            agentId="test-agent",
            agentName="Test Agent",
            tenantId="tenant-123",
            agentConfig=AgentConfig(
                version="3",
                ownerId="owner-123",
                requestUrl="https://api.example.com/agent/chat",
                rootUrl="https://api.example.com/agent/",
                llmModel="gpt-4",
                status="ACTIVE",
                retrieverStrategy="NUGGET",
                reasoningAlgorithm="GPT_FUNCTION_REASONING"
            )
        )
        
        # Manually set status to empty to test transformation validation
        response.agentConfig.status = ""
        
        with pytest.raises(ValueError, match="agentConfig.status is required"):
            response.to_simple_format()


class TestAgentDetailsResponseCompleteValidation:
    """Test complete validation functionality."""
    
    def test_validate_response_completeness_valid(self):
        """Test validation passes for complete response."""
        response = AgentDetailsResponse(
            agentId="test-agent-123",
            agentName="Test Agent",
            tenantId="tenant-123",
            agentConfig=AgentConfig(
                version="3",
                ownerId="owner-123",
                requestUrl="https://api.example.com/agent/chat",
                rootUrl="https://api.example.com/agent/",
                llmModel="gpt-4",
                status="ACTIVE",
                retrieverStrategy="NUGGET",
                reasoningAlgorithm="GPT_FUNCTION_REASONING"
            )
        )
        
        # Should not raise any exception
        response.validate_response_completeness()
    
    def test_validate_response_completeness_missing_config(self):
        """Test validation fails when agentConfig is missing."""
        # This test is more theoretical since Pydantic would catch this first
        response = AgentDetailsResponse(
            agentId="test-agent-123",
            agentName="Test Agent",
            tenantId="tenant-123",
            agentConfig=AgentConfig(
                version="3",
                ownerId="owner-123",
                requestUrl="https://api.example.com/agent/chat",
                rootUrl="https://api.example.com/agent/",
                llmModel="gpt-4",
                status="ACTIVE",
                retrieverStrategy="NUGGET",
                reasoningAlgorithm="GPT_FUNCTION_REASONING"
            )
        )
        
        # Manually set to None to test validation
        response.agentConfig = None
        
        with pytest.raises(ValueError, match="Agent response missing agentConfig"):
            response.validate_response_completeness()
    
    def test_validate_response_completeness_missing_status(self):
        """Test validation fails when status is missing."""
        response = AgentDetailsResponse(
            agentId="test-agent-123",
            agentName="Test Agent",
            tenantId="tenant-123",
            agentConfig=AgentConfig(
                version="3",
                ownerId="owner-123",
                requestUrl="https://api.example.com/agent/chat",
                rootUrl="https://api.example.com/agent/",
                llmModel="gpt-4",
                status="",  # Empty status
                retrieverStrategy="NUGGET",
                reasoningAlgorithm="GPT_FUNCTION_REASONING"
            )
        )
        
        with pytest.raises(ValueError, match="Agent response missing or empty agentConfig.status"):
            response.validate_response_completeness()
    
    def test_validate_response_completeness_invalid_url(self):
        """Test validation fails for invalid URLs."""
        response = AgentDetailsResponse(
            agentId="test-agent-123",
            agentName="Test Agent",
            tenantId="tenant-123",
            agentConfig=AgentConfig(
                version="3",
                ownerId="owner-123",
                requestUrl="invalid-url",  # Invalid URL
                rootUrl="https://api.example.com/agent/",
                llmModel="gpt-4",
                status="ACTIVE",
                retrieverStrategy="NUGGET",
                reasoningAlgorithm="GPT_FUNCTION_REASONING"
            )
        )
        
        with pytest.raises(ValueError, match="agentConfig.requestUrl must be a valid URL"):
            response.validate_response_completeness()


class TestAgentDetailsResponseFromDict:
    """Test from_dict_with_validation functionality."""
    
    def test_from_dict_with_validation_valid(self):
        """Test creating response from valid dictionary."""
        data = {
            "agentId": "test-agent-123",
            "agentName": "Test Agent",
            "orgId": "org-123",
            "tenantId": "tenant-123",
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
                "reasoningAlgorithm": "GPT_FUNCTION_REASONING"
            }
        }
        
        response = AgentDetailsResponse.from_dict_with_validation(data)
        
        assert response.agentId == "test-agent-123"
        assert response.agentName == "Test Agent"
        assert response.agentConfig.status == "ACTIVE"
    
    def test_from_dict_with_validation_agent_id_match(self):
        """Test validation with matching agent ID."""
        data = {
            "agentId": "test-agent-123",
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
        
        response = AgentDetailsResponse.from_dict_with_validation(data, "test-agent-123")
        assert response.agentId == "test-agent-123"
    
    def test_from_dict_with_validation_agent_id_mismatch(self):
        """Test validation fails with mismatched agent ID."""
        data = {
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
        
        with pytest.raises(ValueError, match="Response agent ID mismatch"):
            AgentDetailsResponse.from_dict_with_validation(data, "test-agent-123")
    
    def test_from_dict_with_validation_invalid_type(self):
        """Test validation fails for non-dictionary input."""
        invalid_inputs = [
            "string",
            123,
            ["list"],
            None,
            True
        ]
        
        for invalid_input in invalid_inputs:
            with pytest.raises(TypeError, match="Expected dictionary"):
                AgentDetailsResponse.from_dict_with_validation(invalid_input)
    
    def test_from_dict_with_validation_missing_required_fields(self):
        """Test validation fails for missing required fields."""
        incomplete_data = {
            "agentId": "test-agent-123",
            # Missing agentName, tenantId, agentConfig
        }
        
        with pytest.raises(ValueError):
            AgentDetailsResponse.from_dict_with_validation(incomplete_data)
    
    def test_from_dict_with_validation_incomplete_config(self):
        """Test validation fails for incomplete agentConfig."""
        data = {
            "agentId": "test-agent-123",
            "agentName": "Test Agent",
            "tenantId": "tenant-123",
            "agentConfig": {
                "version": "3",
                "ownerId": "owner-123",
                # Missing required fields like requestUrl, rootUrl, etc.
            }
        }
        
        with pytest.raises(ValueError):
            AgentDetailsResponse.from_dict_with_validation(data)


class TestBackwardCompatibility:
    """Test backward compatibility with existing AgentStatusResponse format."""
    
    def test_simple_format_matches_mock_sdk(self):
        """Test that simple format matches what MockAgentSDK returns."""
        # This is the format that MockAgentSDK returns
        mock_sdk_format = {
            "id": "agent-123",
            "name": "Customer Support Bot",
            "status": "active"
        }
        
        # Create AgentDetailsResponse and transform it
        response = AgentDetailsResponse(
            agentId="agent-123",
            agentName="Customer Support Bot",
            tenantId="tenant-123",
            agentConfig=AgentConfig(
                version="3",
                ownerId="owner-123",
                requestUrl="https://api.example.com/agent/chat",
                rootUrl="https://api.example.com/agent/",
                llmModel="gpt-4",
                status="ACTIVE",  # Uppercase in SDK
                retrieverStrategy="NUGGET",
                reasoningAlgorithm="GPT_FUNCTION_REASONING"
            )
        )
        
        simple_format = response.to_simple_format()
        
        # Should match exactly what MockAgentSDK returns
        assert simple_format == mock_sdk_format
    
    def test_simple_format_compatible_with_agent_service(self):
        """Test that simple format is compatible with AgentService expectations."""
        response = AgentDetailsResponse(
            agentId="test-agent-456",
            agentName="Sales Assistant",
            tenantId="tenant-123",
            agentConfig=AgentConfig(
                version="3",
                ownerId="owner-123",
                requestUrl="https://api.example.com/agent/chat",
                rootUrl="https://api.example.com/agent/",
                llmModel="gpt-4",
                status="INACTIVE",
                retrieverStrategy="NUGGET",
                reasoningAlgorithm="GPT_FUNCTION_REASONING"
            )
        )
        
        simple_format = response.to_simple_format()
        
        # AgentService expects these exact fields
        required_fields = ["id", "name", "status"]
        for field in required_fields:
            assert field in simple_format
        
        # Values should be properly formatted
        assert simple_format["id"] == "test-agent-456"
        assert simple_format["name"] == "Sales Assistant"
        assert simple_format["status"] == "inactive"  # Lowercase
    
    def test_various_status_formats(self):
        """Test transformation handles various status formats correctly."""
        status_test_cases = [
            ("ACTIVE", "active"),
            ("INACTIVE", "inactive"),
            ("BUSY", "busy"),
            ("ERROR", "error"),
            ("INDEXING", "indexing"),
            ("READY", "ready"),
            ("STOPPED", "stopped")
        ]
        
        for input_status, expected_output in status_test_cases:
            response = AgentDetailsResponse(
                agentId="test-agent",
                agentName="Test Agent",
                tenantId="tenant-123",
                agentConfig=AgentConfig(
                    version="3",
                    ownerId="owner-123",
                    requestUrl="https://api.example.com/agent/chat",
                    rootUrl="https://api.example.com/agent/",
                    llmModel="gpt-4",
                    status=input_status,
                    retrieverStrategy="NUGGET",
                    reasoningAlgorithm="GPT_FUNCTION_REASONING"
                )
            )
            
            result = response.to_simple_format()
            assert result["status"] == expected_output