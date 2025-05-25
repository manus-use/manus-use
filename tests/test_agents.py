"""Tests for agent implementations."""

import pytest
from unittest.mock import Mock, patch

from manus_use.agents import ManusAgent, BrowserAgent, DataAnalysisAgent
from manus_use.config import Config


def test_manus_agent_initialization():
    """Test ManusAgent initialization."""
    # Mock the model to avoid actual API calls
    with patch("manus_use.config.Config.get_model") as mock_model:
        mock_model.return_value = Mock()
        
        agent = ManusAgent()
        
        # Check that agent has tools
        assert hasattr(agent, "_tools") or hasattr(agent, "tools")
        
        # Check system prompt
        prompt = agent._get_default_system_prompt()
        assert "Manus" in prompt
        assert "assistant" in prompt.lower()


def test_browser_agent_initialization():
    """Test BrowserAgent initialization."""
    with patch("manus_use.config.Config.get_model") as mock_model:
        mock_model.return_value = Mock()
        
        agent = BrowserAgent()
        
        # Check browser-specific attributes
        assert hasattr(agent, "headless")
        
        # Check system prompt
        prompt = agent._get_default_system_prompt()
        assert "browsing" in prompt.lower()


def test_data_analysis_agent_initialization():
    """Test DataAnalysisAgent initialization."""
    with patch("manus_use.config.Config.get_model") as mock_model:
        mock_model.return_value = Mock()
        
        agent = DataAnalysisAgent()
        
        # Check system prompt
        prompt = agent._get_default_system_prompt()
        assert "data analysis" in prompt.lower()
        assert "visualization" in prompt.lower()


def test_agent_with_custom_config():
    """Test agent with custom configuration."""
    config = Config()
    config.llm.temperature = 0.5
    
    with patch("manus_use.config.Config.get_model") as mock_model:
        mock_model.return_value = Mock()
        
        agent = ManusAgent(config=config)
        
        # Verify config was used
        assert agent.config.llm.temperature == 0.5


def test_agent_add_tools():
    """Test adding tools to agent."""
    with patch("manus_use.config.Config.get_model") as mock_model:
        mock_model.return_value = Mock()
        
        # Create agent with no tools
        agent = ManusAgent(tools=[])
        
        # Mock tool
        mock_tool = Mock()
        mock_tool.__name__ = "test_tool"
        
        # Add tool
        agent.add_tools([mock_tool])
        
        # Verify tool was added
        if hasattr(agent, "_tools"):
            assert mock_tool in agent._tools