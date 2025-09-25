"""AgentHelper bridge class following SDK patterns from documentation."""

import re
from typing import Optional, Dict, Any
import structlog

from .async_agent import AsyncAgent
from .session import Session, SessionManager
from ..services.exceptions import SDKError, AuthenticationError

logger = structlog.get_logger(__name__)


class AgentHelper:
    """
    AgentHelper bridge class that follows the SDK patterns from documentation.
    
    This class provides a bridge between the high-level agent operations
    and the underlying AsyncAgent implementation, following the patterns
    described in the Agent SDK documentation.
    
    Example usage:
        agent_helper = AgentHelper(
            env="DEV",
            agent_id="my-agent-id", 
            jwt_token="jwt-token-here",
            agent_name="My Agent",
            prompt="You are a helpful assistant",
            role="assistant"
        )
        agent_helper.set_session()
        agent = await agent_helper.get_agent()
    """
    
    # Class-level constants following SDK patterns
    RE_AGENT_DOC_ID = re.compile(r'agentDocId=[^&]+&')
    agent_doc_url_prefix = 'https://cognitive-engine.dev.net/cog/'
    
    def __init__(
        self,
        env: str,
        agent_id: str,
        jwt_token: str,
        **kwargs
    ):
        """
        Initialize AgentHelper with required and optional parameters.
        
        Args:
            env: Environment (DEV, QA, PROD)
            agent_id: Agent identifier
            jwt_token: JWT token for authentication
            **kwargs: Optional parameters including:
                - agent_name: Agent display name
                - welcome: Welcome message
                - prompt: System prompt
                - role: Agent role
                - strategy: Retrieval strategy
                - llm_model: LLM model identifier
                - control_flags: List of control flags
        
        Raises:
            ValueError: If required parameters are missing or invalid
        """
        # Validate required parameters
        if not env or not isinstance(env, str):
            raise ValueError("env must be a non-empty string")
        
        if not agent_id or not isinstance(agent_id, str):
            raise ValueError("agent_id must be a non-empty string")
        
        if not jwt_token or not isinstance(jwt_token, str):
            raise ValueError("jwt_token must be a non-empty string")
        
        # Set core properties
        self.env = env.upper()
        self.agent_id = agent_id
        self.jwt_token = jwt_token
        
        # Initialize session-related properties
        self.session: Optional[Session] = None
        self.session_manager: Optional[SessionManager] = None
        
        # Set optional parameters with defaults
        self.agent_name: Optional[str] = kwargs.get('agent_name')
        self.welcome: Optional[str] = kwargs.get('welcome', "Hi! How can I assist you today?")
        self.prompt: Optional[str] = kwargs.get('prompt')
        self.role: Optional[str] = kwargs.get('role')
        self.strategy: Optional[str] = kwargs.get('strategy')
        self.llm_model: Optional[str] = kwargs.get('llm_model')
        self.control_flags: Optional[list] = kwargs.get('control_flags')
        
        # Determine base URL based on environment
        self.api_base = self._get_api_base_url(self.env)
        
        logger.info(
            "AgentHelper initialized",
            env=self.env,
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            api_base=self.api_base,
            has_jwt_token=bool(self.jwt_token)
        )
    
    def _get_api_base_url(self, env: str) -> str:
        """
        Get API base URL based on environment.
        
        Args:
            env: Environment string (DEV, QA, PROD)
            
        Returns:
            Base URL for the environment
        """
        env_urls = {
            'DEV': 'https://lm.qa.example.net',
            'QA': 'https://lm.qa.example.net', 
            'PROD': 'https://lm.prod.example.net',
            'LOCAL': 'http://localhost:8000',
            'TEST': 'http://localhost:8000'
        }
        
        return env_urls.get(env, 'https://lm.qa.example.net')
    
    def set_session(self) -> None:
        """
        Initialize session with JWT token.
        
        This method creates a new session using the provided JWT token
        and sets up the session manager for subsequent operations.
        
        Raises:
            AuthenticationError: If session creation fails
            SDKError: If JWT token is invalid
        """
        try:
            logger.info("Setting up session", agent_id=self.agent_id)
            
            # Create session using JWT token
            self.session = Session.connect(jwt_token=self.jwt_token)
            
            # Create session manager
            self.session_manager = SessionManager(jwt_token=self.jwt_token)
            
            logger.info(
                "Session established successfully",
                agent_id=self.agent_id,
                user_id=self.session.user_id,
                expires_at=self.session.expires_at
            )
            
        except Exception as e:
            logger.error(
                "Failed to set session",
                agent_id=self.agent_id,
                error=str(e),
                error_type=type(e).__name__
            )
            
            if isinstance(e, (SDKError, AuthenticationError)):
                raise
            else:
                raise AuthenticationError(f"Failed to establish session: {str(e)}", e)
    
    async def get_agent(self) -> AsyncAgent:
        """
        Create and configure AsyncAgent instance.
        
        This method creates an AsyncAgent with all the configured parameters
        and sets up the session manager for authentication.
        
        Returns:
            Configured AsyncAgent instance
            
        Raises:
            ValueError: If session is not set
            SDKError: If agent creation fails
        """
        if self.session is None or self.session_manager is None:
            raise ValueError(
                'Session is not set. Please set the session using set_session() method'
            )
        
        try:
            logger.info(
                "Creating agent",
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                env=self.env
            )
            
            # Create AsyncAgent with all configured parameters
            agent_params = {
                'agent_id': self.agent_id,
                'env': self.env,
                'base_url': self.api_base,
                'session': self.session
            }
            
            # Add optional parameters if provided
            if self.agent_name:
                agent_params['agent_name'] = self.agent_name
            
            if self.welcome:
                agent_params['welcome_message'] = self.welcome
            
            if self.prompt:
                agent_params['prompt'] = self.prompt
            
            if self.role:
                agent_params['role'] = self.role
            
            if self.strategy:
                agent_params['retriever_strategy'] = self.strategy
            
            if self.llm_model:
                agent_params['llm_model'] = self.llm_model
            
            if self.control_flags:
                agent_params['control_flags'] = self.control_flags
            
            # Create the AsyncAgent
            agent = AsyncAgent(**agent_params)
            
            # Set the session manager
            agent.set_session_manager(self.session_manager)
            
            logger.info(
                "Agent created successfully",
                agent_id=agent.agent_id,
                agent_name=agent.agent_name,
                env=agent.env
            )
            
            return agent
            
        except Exception as e:
            logger.error(
                "Failed to create agent",
                agent_id=self.agent_id,
                error=str(e),
                error_type=type(e).__name__
            )
            
            if isinstance(e, (ValueError, SDKError)):
                raise
            else:
                raise SDKError(f"Failed to create agent: {str(e)}", e)
    
    def is_session_active(self) -> bool:
        """
        Check if session is active and valid.
        
        Returns:
            True if session is active and valid, False otherwise
        """
        return (
            self.session is not None and
            self.session.is_valid() and
            self.session_manager is not None and
            self.session_manager.is_authenticated()
        )
    
    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the current session.
        
        Returns:
            Dictionary with session information or None if no session
        """
        if self.session is None:
            return None
        
        return {
            'user_id': self.session.user_id,
            'roles': self.session.roles,
            'created_at': self.session.created_at,
            'expires_at': self.session.expires_at,
            'is_valid': self.session.is_valid(),
            'is_expired': self.session.is_expired()
        }
    
    def clear_session(self) -> None:
        """
        Clear the current session and session manager.
        """
        logger.info("Clearing session", agent_id=self.agent_id)
        
        if self.session_manager:
            self.session_manager.clear_session()
        
        self.session = None
        self.session_manager = None
    
    def __str__(self) -> str:
        """String representation of AgentHelper."""
        return (
            f"AgentHelper(agent_id={self.agent_id}, env={self.env}, "
            f"agent_name={self.agent_name}, has_session={self.session is not None})"
        )
    
    def __repr__(self) -> str:
        """Detailed string representation of AgentHelper."""
        return (
            f"AgentHelper(agent_id={self.agent_id!r}, env={self.env!r}, "
            f"agent_name={self.agent_name!r}, api_base={self.api_base!r}, "
            f"has_session={self.session is not None})"
        )