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
        
        # Verify that add_tools method is removed
        with pytest.raises(AttributeError):
            agent.add_tools([mock_tool])


def test_agent_constructor_tools():
    """Test tools passed to agent constructor."""
    with patch("manus_use.config.Config.get_model") as mock_model:
        mock_model.return_value = Mock()
        
        mock_tool = Mock()
        mock_tool.__name__ = "constructor_tool"
        
        agent = ManusAgent(tools=[mock_tool])
        
        # Verify tool is present
        # Accessing agent.tools is the public way for Strands
        assert mock_tool in agent.tools


# Need to import MCPAgent and MCPClient for the next test
from manus_use.agents.mcp import MCPAgent
from strands.tools.mcp import MCPClient


def test_mcp_agent_tool_initialization():
    """Test tool initialization and add_mcp_server for MCPAgent."""
    with patch("manus_use.config.Config.get_model") as mock_model_create:
        mock_model_create.return_value = Mock()

        # Mock tools
        mock_tool1 = Mock()
        mock_tool1.__name__ = "mcp_tool_1"
        mock_tool2 = Mock()
        mock_tool2.__name__ = "mcp_tool_2"

        # Mock MCPClient server 1
        mock_server1 = Mock(spec=MCPClient)
        mock_server1.list_tools_sync = Mock(return_value=[mock_tool1])

        # Instantiate MCPAgent with mock_server1
        agent = MCPAgent(mcp_servers=[mock_server1], tools=[]) # Pass empty tools list initially

        # Assert mock_tool1 is in agent's tools
        assert mock_tool1 in agent.tools
        assert mock_server1 in agent.mcp_servers

        # Mock MCPClient server 2
        mock_server2 = Mock(spec=MCPClient)
        mock_server2.list_tools_sync = Mock(return_value=[mock_tool2])

        # Call add_mcp_server with mock_server2
        agent.add_mcp_server(mock_server2)

        # Assert mock_tool2 is NOT in agent's tools (as add_tools was removed from add_mcp_server)
        assert mock_tool2 not in agent.tools
        
        # Assert mock_server2 IS in agent.mcp_servers
        assert mock_server2 in agent.mcp_servers
        
        # Assert mock_tool1 IS STILL in agent.tools
        assert mock_tool1 in agent.tools