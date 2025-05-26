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

# --- Tests for BrowserUseAgent ---
import asyncio
import logging
from unittest.mock import MagicMock # For async context manager

from manus_use.agents.browser_use_agent import BrowserUseAgent
# Assuming BROWSER_USE_AVAILABLE is True for most tests, will patch it for specific cases

@pytest.fixture
def mock_config():
    """Fixture for a mock Config object."""
    config = Mock(spec=Config)
    config.llm.provider = "openai"  # Default to openai for most tests
    config.llm.model = "test-model"
    config.llm.temperature = 0.5
    config.llm.max_tokens = 100
    config.llm.aws_region = "us-west-2"
    config.tools.browser_headless = True
    # Mock get_model for the dummy model in BrowserUseAgent
    config.get_model = Mock(return_value=Mock()) 
    return config

# Patch BROWSER_USE_AVAILABLE at the module level for most tests
# For the specific test where it's False, we'll patch it there.
@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.ChatBedrock', create=True) # create=True allows patching non-existent attrs
@patch('manus_use.agents.browser_use_agent.ChatOpenAI', create=True)
def test_browser_use_agent_init_defaults(MockChatOpenAI, MockChatBedrock, mock_config_fixture):
    """Test BrowserUseAgent initialization with default headless and memory."""
    agent = BrowserUseAgent(config=mock_config_fixture)
    assert agent.headless == mock_config_fixture.tools.browser_headless
    assert agent.enable_memory == False

@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.ChatBedrock', create=True)
@patch('manus_use.agents.browser_use_agent.ChatOpenAI', create=True)
def test_browser_use_agent_init_custom_settings(MockChatOpenAI, MockChatBedrock, mock_config_fixture):
    """Test BrowserUseAgent initialization with custom headless and memory."""
    agent = BrowserUseAgent(config=mock_config_fixture, headless=False, enable_memory=True)
    assert agent.headless == False
    assert agent.enable_memory == True

@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', False)
def test_browser_use_agent_init_unavailable(mock_config_fixture):
    """Test BrowserUseAgent raises ImportError if BROWSER_USE_AVAILABLE is False."""
    with pytest.raises(ImportError, match="Required package(s) for BrowserUseAgent missing"):
        BrowserUseAgent(config=mock_config_fixture)

# _get_browser_llm tests
@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.ChatOpenAI', create=True)
@patch('manus_use.agents.browser_use_agent.os.getenv') # Mock os.getenv for region
def test_browser_use_agent_get_llm_openai(mock_os_getenv, MockChatOpenAI, mock_config_fixture):
    mock_config_fixture.llm.provider = "openai"
    agent = BrowserUseAgent(config=mock_config_fixture)
    llm = agent._get_browser_llm()
    MockChatOpenAI.assert_called_once_with(
        model_name=mock_config_fixture.llm.model,
        temperature=mock_config_fixture.llm.temperature,
        max_tokens=mock_config_fixture.llm.max_tokens
    )
    assert llm == MockChatOpenAI.return_value

@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.ChatBedrock', create=True)
@patch('manus_use.agents.browser_use_agent.os.getenv')
def test_browser_use_agent_get_llm_bedrock(mock_os_getenv, MockChatBedrock, mock_config_fixture):
    mock_config_fixture.llm.provider = "bedrock"
    mock_os_getenv.return_value = "custom-region-from-env" # Simulate env var being set
    mock_config_fixture.llm.aws_region = None # Ensure env var is preferred if config is None

    agent = BrowserUseAgent(config=mock_config_fixture)
    llm = agent._get_browser_llm()
    
    mock_os_getenv.assert_called_once_with('AWS_DEFAULT_REGION', mock_config_fixture.llm.aws_region or 'us-east-1')
    MockChatBedrock.assert_called_once_with(
        model_id=mock_config_fixture.llm.model,
        model_kwargs={
            "temperature": mock_config_fixture.llm.temperature,
            "max_tokens": mock_config_fixture.llm.max_tokens
        },
        region_name="custom-region-from-env"
    )
    assert llm == MockChatBedrock.return_value

@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
def test_browser_use_agent_get_llm_unsupported(mock_config_fixture):
    mock_config_fixture.llm.provider = "unsupported_provider"
    agent = BrowserUseAgent(config=mock_config_fixture)
    with pytest.raises(ValueError, match="Unsupported LLM provider"):
        agent._get_browser_llm()

@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.ChatBedrock', None) # Simulate import failure
def test_browser_use_agent_get_llm_bedrock_import_error(mock_config_fixture):
    mock_config_fixture.llm.provider = "bedrock"
    agent = BrowserUseAgent(config=mock_config_fixture)
    with pytest.raises(ImportError, match="langchain-aws package is missing"):
        agent._get_browser_llm()

@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.ChatOpenAI', None) # Simulate import failure
def test_browser_use_agent_get_llm_openai_import_error(mock_config_fixture):
    mock_config_fixture.llm.provider = "openai"
    agent = BrowserUseAgent(config=mock_config_fixture)
    with pytest.raises(ImportError, match="langchain-openai package is missing"):
        agent._get_browser_llm()


# Task Execution Tests
@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.Controller', Mock()) # Mock at source
@patch('manus_use.agents.browser_use_agent.BrowserProfile', Mock()) # Mock at source
@patch('manus_use.agents.browser_use_agent.BrowserUse') # Mock at source (aliased as BrowserUse in module)
@patch('manus_use.agents.browser_use_agent.ChatOpenAI', create=True) # For LLM creation
@patch('manus_use.agents.browser_use_agent.logging.warning') # To check warnings
@pytest.mark.asyncio # Mark test as async
async def test_browser_use_agent_run_task_various_results(
    mock_logging_warning, MockChatOpenAI, MockBrowserUse, MockBrowserProfile, MockController, mock_config_fixture
):
    agent = BrowserUseAgent(config=mock_config_fixture, headless=True, enable_memory=True)
    mock_llm_instance = MockChatOpenAI.return_value 
    
    # Setup MockBrowserUse (the class) to return a mock instance
    mock_browser_use_instance = Mock()
    MockBrowserUse.return_value = mock_browser_use_instance
    
    # --- Test 1: extracted_content as callable ---
    mock_browser_use_instance.run = AsyncMock(return_value=Mock(extracted_content=Mock(return_value="callable_content")))
    result = await agent._run_browser_task("test task 1")
    MockBrowserUse.assert_called_with(
        task="test task 1",
        llm=mock_llm_instance,
        browser_profile=MockBrowserProfile.return_value,
        controller=MockController.return_value,
        enable_memory=True,
        validate_output=False
    )
    MockBrowserProfile.assert_called_with(headless=True)
    assert result == "callable_content"
    mock_logging_warning.assert_not_called()

    # --- Test 2: extracted_content as attribute ---
    mock_browser_use_instance.run = AsyncMock(return_value=Mock(extracted_content="direct_content", all_results=None)) # all_results=None to avoid that path
    # Reset warning mock for this specific test case
    mock_logging_warning.reset_mock()
    result = await agent._run_browser_task("test task 2")
    assert result == "direct_content"
    mock_logging_warning.assert_not_called()

    # --- Test 3: all_results list ---
    mock_result_item_done = Mock(is_done=True, extracted_content="from_all_results")
    mock_result_item_not_done = Mock(is_done=False, extracted_content="should_not_be_used")
    mock_browser_use_instance.run = AsyncMock(return_value=Mock(extracted_content=None, all_results=[mock_result_item_not_done, mock_result_item_done]))
    mock_logging_warning.reset_mock()
    result = await agent._run_browser_task("test task 3")
    assert result == "from_all_results"
    mock_logging_warning.assert_not_called()

    # --- Test 4: Fallback to str(result) ---
    final_fallback_result = Mock(spec=[]) # A mock that doesn't have any of the specific attributes
    final_fallback_result.__str__ = Mock(return_value="string_fallback")
    mock_browser_use_instance.run = AsyncMock(return_value=final_fallback_result)
    mock_logging_warning.reset_mock()
    result = await agent._run_browser_task("test task 4")
    assert result == "string_fallback"
    mock_logging_warning.assert_called_once()
    # Check that the log message contains the expected substring
    assert "Could not extract specific content" in mock_logging_warning.call_args[0][0]


# AsyncMock for Python 3.7 compatibility if needed, otherwise MagicMock for >=3.8
# For this environment, assume MagicMock is sufficient for async methods
if not hasattr(unittest.mock, 'AsyncMock'):
    class AsyncMock(MagicMock):
        async def __call__(self, *args, **kwargs):
            return super(AsyncMock, self).__call__(*args, **kwargs)
        # For async context managers if needed:
        # async def __aenter__(self):
        #     return self.__enter__()
        # async def __aexit__(self, *args):
        #     return self.__exit__(*args)

@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.BrowserUseAgent._run_browser_task', new_callable=AsyncMock)
@patch('manus_use.agents.browser_use_agent.asyncio')
def test_browser_use_agent_call_sync_context(mock_asyncio, mock_run_task, mock_config_fixture):
    """Test __call__ in a synchronous context."""
    mock_asyncio.get_running_loop.side_effect = RuntimeError("No running event loop")
    mock_asyncio.run = Mock(return_value="sync_result") # Mock asyncio.run
    
    agent = BrowserUseAgent(config=mock_config_fixture)
    result = agent(task="sync_task_str")
    
    mock_asyncio.get_running_loop.assert_called_once()
    mock_asyncio.run.assert_called_once_with(mock_run_task.return_value) # Check that run is called with the coroutine
    mock_run_task.assert_called_once_with("sync_task_str")
    assert result == "sync_result"

@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.BrowserUseAgent._run_browser_task', new_callable=AsyncMock)
@patch('manus_use.agents.browser_use_agent.asyncio')
def test_browser_use_agent_call_async_context(mock_asyncio, mock_run_task, mock_config_fixture):
    """Test __call__ in an asynchronous context."""
    mock_loop = Mock()
    mock_asyncio.get_running_loop.return_value = mock_loop # Simulate existing loop
    
    agent = BrowserUseAgent(config=mock_config_fixture)
    # Call the agent
    coroutine_result = agent(task="async_task_str_direct")
    
    mock_asyncio.get_running_loop.assert_called_once()
    mock_asyncio.run.assert_not_called() # asyncio.run should not be called
    mock_run_task.assert_called_once_with("async_task_str_direct")
    assert coroutine_result == mock_run_task.return_value # Should return the coroutine itself

@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
@patch('manus_use.agents.browser_use_agent.BrowserUseAgent._run_browser_task', new_callable=AsyncMock)
@patch('manus_use.agents.browser_use_agent.asyncio')
def test_browser_use_agent_call_list_input(mock_asyncio, mock_run_task, mock_config_fixture):
    """Test __call__ with a list of message dicts as input."""
    mock_asyncio.get_running_loop.side_effect = RuntimeError("No running event loop") # Test sync path
    
    agent = BrowserUseAgent(config=mock_config_fixture)
    task_list = [
        {"role": "user", "content": "ignore this"},
        {"role": "assistant", "content": "ignore this too"},
        {"role": "user", "content": "actual_task_from_list"}
    ]
    agent(task=task_list)
    mock_run_task.assert_called_once_with("actual_task_from_list")

# Test for stream_async (basic test to ensure it calls __call__ and yields)
@pytest.mark.asyncio
@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
async def test_browser_use_agent_stream_async(mock_config_fixture):
    agent = BrowserUseAgent(config=mock_config_fixture)
    
    # Mock the __call__ method to control its output
    # Since __call__ can return a coroutine or a direct result, we'll mock it to return a direct result for simplicity here.
    # A more complex mock might be needed if __call__ itself had more varied async behavior to test *through* stream_async.
    agent.__call__ = Mock(return_value="stream_output_from_call")
    
    results = [res async for res in agent.stream_async(task="stream_test_task")]
    
    agent.__call__.assert_called_once_with(task="stream_test_task")
    assert len(results) == 1
    assert results[0] == {"type": "text", "text": "stream_output_from_call"}

@pytest.mark.asyncio
@patch('manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE', True)
async def test_browser_use_agent_stream_async_with_awaitable_call(mock_config_fixture):
    agent = BrowserUseAgent(config=mock_config_fixture)
    
    # Mock __call__ to return an awaitable (coroutine)
    async def mock_async_call(*args, **kwargs):
        await asyncio.sleep(0) # Simulate some async work
        return "stream_output_from_awaited_call"

    agent.__call__ = Mock(side_effect=mock_async_call) # side_effect to make it behave like an async def

    results = [res async for res in agent.stream_async(task="stream_test_task_await")]
    
    agent.__call__.assert_called_once_with(task="stream_test_task_await")
    assert len(results) == 1
    assert results[0] == {"type": "text", "text": "stream_output_from_awaited_call"}
