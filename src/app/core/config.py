from functools import lru_cache
from typing import List, Union, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator, model_validator

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ENV: str = Field("local", description="Environment: local|dev|prod")
    DEBUG: bool = Field(True, description="Debug mode: affects logging and reload")
    PROJECT_NAME: str = "fastapi-starter"
    VERSION: str = "0.1.0"
    API_PREFIX: str = "/api"

    SECRET_KEY: str = Field(..., description="JWT signing key (use RS256 in prod)")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15

    ALLOWED_ORIGINS: Union[str, List[str]] = Field(default_factory=list, description="CORS origins")

    # Agent SDK Configuration
    AGENT_SDK_ENV: str = Field("DEV", description="Agent SDK environment")
    AGENT_SDK_BASE_URL: str = Field("https://lm.qa.example.net", description="Agent SDK base URL")
    AGENT_SDK_JWT_TOKEN: Optional[str] = Field(None, description="JWT token for agent authentication")
    AGENT_SDK_TIMEOUT: int = Field(180, description="Agent SDK call timeout in seconds")
    AGENT_SDK_RETRY_COUNT: int = Field(3, description="Number of retry attempts for SDK calls")
    AGENT_SDK_MOCK_MODE: bool = Field(False, description="Force mock mode even in production")

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def split_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @model_validator(mode="after")
    def validate_production_config(self):
        """Validate required configuration for production mode."""
        # Only validate critical security settings in production
        if self.is_prod:
            # Validate JWT secret key is not default
            if self.SECRET_KEY == "CHANGE_ME":
                raise ValueError("SECRET_KEY must be changed from default value in production")
        
        return self
    
    def validate_agent_sdk_config(self) -> tuple[bool, list[str]]:
        """
        Validate Agent SDK configuration and return validation status and reasons.
        
        Returns:
            Tuple of (is_valid, list_of_validation_errors)
        """
        errors = []
        
        if self.is_prod and not self.AGENT_SDK_MOCK_MODE:
            if not self.AGENT_SDK_JWT_TOKEN or self.AGENT_SDK_JWT_TOKEN.strip() == "":
                errors.append("AGENT_SDK_JWT_TOKEN is required in production when not using mock mode")
            
            if self.AGENT_SDK_JWT_TOKEN == "your-jwt-token-here":
                errors.append("AGENT_SDK_JWT_TOKEN must be changed from default value in production")
            
            if self.AGENT_SDK_BASE_URL == "https://lm.qa.example.net":
                errors.append("AGENT_SDK_BASE_URL must be changed from default value in production")
        
        return len(errors) == 0, errors

    @property
    def is_prod(self) -> bool:
        return self.ENV.lower() == "prod"
    
    @property
    def requires_real_sdk(self) -> bool:
        """Check if configuration requires real SDK (not mock mode)."""
        return not self.AGENT_SDK_MOCK_MODE and not self.ENV.lower() in ["local", "test"]

@lru_cache
def get_settings() -> "Settings":
    return Settings()  # type: ignore[call-arg]
