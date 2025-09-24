"""Unit tests for agent-related Pydantic models."""

import pytest
from pydantic import ValidationError

from app.models.schemas import AgentStatusResponse, ErrorDetail, ErrorResponse


class TestAgentStatusResponse:
    """Test cases for AgentStatusResponse model."""

    def test_valid_agent_status_response(self):
        """Test creating a valid AgentStatusResponse."""
        data = {
            "id": "agent-123",
            "agent_name": "Customer Support Bot",
            "status": "active"
        }
        
        response = AgentStatusResponse(**data)
        
        assert response.id == "agent-123"
        assert response.agent_name == "Customer Support Bot"
        assert response.status == "active"

    def test_agent_status_response_serialization(self):
        """Test JSON serialization of AgentStatusResponse."""
        response = AgentStatusResponse(
            id="agent-456",
            agent_name="Sales Assistant",
            status="inactive"
        )
        
        json_data = response.model_dump()
        expected = {
            "id": "agent-456",
            "agent_name": "Sales Assistant",
            "status": "inactive"
        }
        
        assert json_data == expected

    def test_agent_status_response_from_json(self):
        """Test creating AgentStatusResponse from JSON data."""
        json_data = {
            "id": "agent-789",
            "agent_name": "Technical Support",
            "status": "busy"
        }
        
        response = AgentStatusResponse.model_validate(json_data)
        
        assert response.id == "agent-789"
        assert response.agent_name == "Technical Support"
        assert response.status == "busy"

    def test_agent_id_validation_valid_patterns(self):
        """Test valid agent ID patterns."""
        valid_ids = [
            "agent-123",
            "AGENT_456",
            "agent123",
            "a",
            "123",
            "agent-test_123",
            "A1B2C3"
        ]
        
        for agent_id in valid_ids:
            response = AgentStatusResponse(
                id=agent_id,
                agent_name="Test Agent",
                status="active"
            )
            assert response.id == agent_id

    def test_agent_id_validation_invalid_patterns(self):
        """Test invalid agent ID patterns that should fail validation."""
        invalid_ids = [
            "",  # Empty string
            "agent with spaces",  # Contains spaces
            "agent@123",  # Contains special characters
            "agent.123",  # Contains dots
            "agent#123",  # Contains hash
            "agent/123",  # Contains slash
            "a" * 256,  # Too long (over 255 chars)
        ]
        
        for agent_id in invalid_ids:
            with pytest.raises(ValidationError) as exc_info:
                AgentStatusResponse(
                    id=agent_id,
                    agent_name="Test Agent",
                    status="active"
                )
            
            # Verify the error is related to the id field
            errors = exc_info.value.errors()
            assert any(error["loc"] == ("id",) for error in errors)

    def test_agent_name_validation(self):
        """Test agent name field validation."""
        # Valid names
        valid_names = [
            "Customer Support Bot",
            "A",
            "Agent with Numbers 123",
            "Special-Characters_Allowed!@#$%^&*()",
            "a" * 255  # Max length
        ]
        
        for name in valid_names:
            response = AgentStatusResponse(
                id="agent-123",
                agent_name=name,
                status="active"
            )
            assert response.agent_name == name

    def test_agent_name_validation_invalid(self):
        """Test invalid agent names that should fail validation."""
        invalid_names = [
            "",  # Empty string
            "a" * 256,  # Too long (over 255 chars)
        ]
        
        for name in invalid_names:
            with pytest.raises(ValidationError) as exc_info:
                AgentStatusResponse(
                    id="agent-123",
                    agent_name=name,
                    status="active"
                )
            
            errors = exc_info.value.errors()
            assert any(error["loc"] == ("agent_name",) for error in errors)

    def test_status_validation(self):
        """Test status field validation."""
        # Valid statuses
        valid_statuses = [
            "active",
            "inactive",
            "busy",
            "error",
            "a",
            "a" * 50  # Max length
        ]
        
        for status in valid_statuses:
            response = AgentStatusResponse(
                id="agent-123",
                agent_name="Test Agent",
                status=status
            )
            assert response.status == status

    def test_status_validation_invalid(self):
        """Test invalid status values that should fail validation."""
        invalid_statuses = [
            "",  # Empty string
            "a" * 51,  # Too long (over 50 chars)
        ]
        
        for status in invalid_statuses:
            with pytest.raises(ValidationError) as exc_info:
                AgentStatusResponse(
                    id="agent-123",
                    agent_name="Test Agent",
                    status=status
                )
            
            errors = exc_info.value.errors()
            assert any(error["loc"] == ("status",) for error in errors)

    def test_missing_required_fields(self):
        """Test that all required fields must be provided."""
        # Missing id
        with pytest.raises(ValidationError) as exc_info:
            AgentStatusResponse(
                agent_name="Test Agent",
                status="active"
            )
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("id",) and error["type"] == "missing" for error in errors)

        # Missing agent_name
        with pytest.raises(ValidationError) as exc_info:
            AgentStatusResponse(
                id="agent-123",
                status="active"
            )
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("agent_name",) and error["type"] == "missing" for error in errors)

        # Missing status
        with pytest.raises(ValidationError) as exc_info:
            AgentStatusResponse(
                id="agent-123",
                agent_name="Test Agent"
            )
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("status",) and error["type"] == "missing" for error in errors)

    def test_extra_fields_ignored(self):
        """Test that extra fields are ignored during validation."""
        data = {
            "id": "agent-123",
            "agent_name": "Test Agent",
            "status": "active",
            "extra_field": "should be ignored",
            "another_extra": 123
        }
        
        response = AgentStatusResponse(**data)
        
        # Only the defined fields should be present
        assert response.id == "agent-123"
        assert response.agent_name == "Test Agent"
        assert response.status == "active"
        
        # Extra fields should not be in the serialized output
        json_data = response.model_dump()
        assert "extra_field" not in json_data
        assert "another_extra" not in json_data


class TestErrorDetail:
    """Test cases for ErrorDetail model."""

    def test_valid_error_detail(self):
        """Test creating a valid ErrorDetail."""
        error = ErrorDetail(
            message="Agent not found",
            code="AGENT_NOT_FOUND",
            details={"agent_id": "invalid-123"}
        )
        
        assert error.message == "Agent not found"
        assert error.code == "AGENT_NOT_FOUND"
        assert error.details == {"agent_id": "invalid-123"}

    def test_error_detail_without_details(self):
        """Test ErrorDetail without optional details field."""
        error = ErrorDetail(
            message="Validation failed",
            code="VALIDATION_ERROR"
        )
        
        assert error.message == "Validation failed"
        assert error.code == "VALIDATION_ERROR"
        assert error.details is None

    def test_error_detail_serialization(self):
        """Test JSON serialization of ErrorDetail."""
        error = ErrorDetail(
            message="SDK timeout",
            code="SDK_TIMEOUT",
            details={"timeout_seconds": 30, "retry_count": 3}
        )
        
        json_data = error.model_dump()
        expected = {
            "message": "SDK timeout",
            "code": "SDK_TIMEOUT",
            "details": {"timeout_seconds": 30, "retry_count": 3}
        }
        
        assert json_data == expected

    def test_error_detail_serialization_exclude_none(self):
        """Test JSON serialization excluding None values."""
        error = ErrorDetail(
            message="Simple error",
            code="SIMPLE_ERROR"
        )
        
        json_data = error.model_dump(exclude_none=True)
        expected = {
            "message": "Simple error",
            "code": "SIMPLE_ERROR"
        }
        
        assert json_data == expected
        assert "details" not in json_data

    def test_message_validation(self):
        """Test message field validation."""
        # Valid message
        error = ErrorDetail(
            message="This is a valid error message",
            code="TEST_ERROR"
        )
        assert error.message == "This is a valid error message"

        # Empty message should fail
        with pytest.raises(ValidationError) as exc_info:
            ErrorDetail(
                message="",
                code="TEST_ERROR"
            )
        
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("message",) for error in errors)

    def test_code_validation(self):
        """Test code field validation."""
        # Valid codes
        valid_codes = [
            "ERROR_CODE",
            "SIMPLE",
            "A",
            "a" * 100  # Max length
        ]
        
        for code in valid_codes:
            error = ErrorDetail(
                message="Test message",
                code=code
            )
            assert error.code == code

        # Invalid codes
        invalid_codes = [
            "",  # Empty string
            "a" * 101,  # Too long
        ]
        
        for code in invalid_codes:
            with pytest.raises(ValidationError) as exc_info:
                ErrorDetail(
                    message="Test message",
                    code=code
                )
            
            errors = exc_info.value.errors()
            assert any(error["loc"] == ("code",) for error in errors)

    def test_details_field_types(self):
        """Test that details field accepts various dict types."""
        valid_details = [
            None,
            {},
            {"key": "value"},
            {"number": 123, "boolean": True, "list": [1, 2, 3]},
            {"nested": {"inner": "value"}},
        ]
        
        for details in valid_details:
            error = ErrorDetail(
                message="Test message",
                code="TEST_ERROR",
                details=details
            )
            assert error.details == details

    def test_missing_required_fields(self):
        """Test that required fields must be provided."""
        # Missing message
        with pytest.raises(ValidationError) as exc_info:
            ErrorDetail(code="TEST_ERROR")
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("message",) and error["type"] == "missing" for error in errors)

        # Missing code
        with pytest.raises(ValidationError) as exc_info:
            ErrorDetail(message="Test message")
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("code",) and error["type"] == "missing" for error in errors)


class TestErrorResponse:
    """Test cases for ErrorResponse model."""

    def test_valid_error_response(self):
        """Test creating a valid ErrorResponse."""
        error_detail = ErrorDetail(
            message="Agent not found",
            code="AGENT_NOT_FOUND",
            details={"agent_id": "invalid-123"}
        )
        
        error_response = ErrorResponse(error=error_detail)
        
        assert error_response.error == error_detail
        assert error_response.error.message == "Agent not found"
        assert error_response.error.code == "AGENT_NOT_FOUND"

    def test_error_response_serialization(self):
        """Test JSON serialization of ErrorResponse."""
        error_response = ErrorResponse(
            error=ErrorDetail(
                message="Validation failed",
                code="VALIDATION_ERROR",
                details={"field": "agent_id", "value": "invalid"}
            )
        )
        
        json_data = error_response.model_dump()
        expected = {
            "error": {
                "message": "Validation failed",
                "code": "VALIDATION_ERROR",
                "details": {"field": "agent_id", "value": "invalid"}
            }
        }
        
        assert json_data == expected

    def test_error_response_from_dict(self):
        """Test creating ErrorResponse from nested dict."""
        data = {
            "error": {
                "message": "SDK error",
                "code": "SDK_ERROR",
                "details": {"timeout": True}
            }
        }
        
        error_response = ErrorResponse.model_validate(data)
        
        assert error_response.error.message == "SDK error"
        assert error_response.error.code == "SDK_ERROR"
        assert error_response.error.details == {"timeout": True}

    def test_error_response_nested_validation(self):
        """Test that nested ErrorDetail validation is enforced."""
        # Invalid nested error (missing required fields)
        with pytest.raises(ValidationError) as exc_info:
            ErrorResponse(
                error={"message": "Missing code field"}  # Missing 'code'
            )
        
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("error", "code") for error in errors)

    def test_missing_error_field(self):
        """Test that error field is required."""
        with pytest.raises(ValidationError) as exc_info:
            ErrorResponse()
        
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("error",) and error["type"] == "missing" for error in errors)

    def test_error_response_with_none_details(self):
        """Test ErrorResponse with ErrorDetail that has None details."""
        error_response = ErrorResponse(
            error=ErrorDetail(
                message="Simple error",
                code="SIMPLE_ERROR"
            )
        )
        
        json_data = error_response.model_dump()
        assert json_data["error"]["details"] is None
        
        # Test excluding None values
        json_data_exclude_none = error_response.model_dump(exclude_none=True)
        assert "details" not in json_data_exclude_none["error"]


class TestModelIntegration:
    """Integration tests for model interactions."""

    def test_complete_error_flow(self):
        """Test complete error creation and serialization flow."""
        # Create a complete error response as would be used in the API
        error_response = ErrorResponse(
            error=ErrorDetail(
                message="The specified agent could not be found",
                code="AGENT_NOT_FOUND",
                details={
                    "agent_id": "nonexistent-agent-123",
                    "timestamp": "2024-01-15T10:30:00Z",
                    "request_id": "req-456"
                }
            )
        )
        
        # Serialize to JSON (as would be returned by FastAPI)
        json_data = error_response.model_dump()
        
        # Verify structure
        assert "error" in json_data
        assert "message" in json_data["error"]
        assert "code" in json_data["error"]
        assert "details" in json_data["error"]
        
        # Verify content
        assert json_data["error"]["message"] == "The specified agent could not be found"
        assert json_data["error"]["code"] == "AGENT_NOT_FOUND"
        assert json_data["error"]["details"]["agent_id"] == "nonexistent-agent-123"

    def test_agent_status_and_error_response_compatibility(self):
        """Test that both success and error responses can be serialized consistently."""
        # Success response
        success_response = AgentStatusResponse(
            id="agent-123",
            agent_name="Test Agent",
            status="active"
        )
        
        # Error response
        error_response = ErrorResponse(
            error=ErrorDetail(
                message="Agent not found",
                code="AGENT_NOT_FOUND"
            )
        )
        
        # Both should serialize to valid JSON
        success_json = success_response.model_dump()
        error_json = error_response.model_dump()
        
        # Verify they have different structures (no overlap)
        assert set(success_json.keys()) != set(error_json.keys())
        assert "error" not in success_json
        assert "id" not in error_json
        assert "agent_name" not in error_json
        assert "status" not in error_json