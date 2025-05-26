"""Tests for CLI module."""

import sys
from unittest.mock import Mock, patch, MagicMock, call
import pytest

from manus_use.cli import is_complex_task, display_task_plan, main
from manus_use.multi_agents import TaskPlan, AgentType, ComplexityLevel


class TestIsComplexTask:
    """Test suite for is_complex_task function."""
    
    def test_simple_tasks(self):
        """Test that simple tasks are correctly identified."""
        simple_tasks = [
            "What is 2+2?",
            "Create a hello world program",
            "List files in directory",
            "Show me the weather",
            "Write a function to add two numbers",
        ]
        
        for task in simple_tasks:
            assert not is_complex_task(task), f"Task '{task}' should be simple"
    
    def test_complex_tasks_with_conjunctions(self):
        """Test detection of complex tasks with multiple conjunctions."""
        complex_tasks = [
            "Analyze the data and create a chart and write a report",
            "First download the file, then extract it, and finally process the data",
            "Research the topic and summarize findings and create presentation",
        ]
        
        for task in complex_tasks:
            assert is_complex_task(task), f"Task '{task}' should be complex"
    
    def test_complex_tasks_with_sequences(self):
        """Test detection of tasks with sequential operations."""
        complex_tasks = [
            "First research AI trends, then implement a demo",
            "After analyzing the data, create visualizations",
            "Download the data, then process it, finally generate report",
        ]
        
        for task in complex_tasks:
            assert is_complex_task(task), f"Task '{task}' should be complex"
    
    def test_complex_tasks_with_multiple_operations(self):
        """Test detection of tasks combining different operations."""
        complex_tasks = [
            "Analyze website performance and create visualization report",
            "Browse documentation, extract concepts, and generate summary",
            "Research market trends and implement trading strategy",
        ]
        
        for task in complex_tasks:
            assert is_complex_task(task), f"Task '{task}' should be complex"
    
    def test_long_tasks(self):
        """Test that very long tasks are considered complex."""
        long_task = " ".join(["word"] * 35)  # 35 words
        assert is_complex_task(long_task)
    
    def test_multiple_sentences(self):
        """Test that multiple sentences trigger complexity."""
        multi_sentence = "Do this task. Then do another task. Finally do a third task."
        assert is_complex_task(multi_sentence)
    
    def test_edge_cases(self):
        """Test edge cases for complexity detection."""
        # Empty string
        assert not is_complex_task("")
        
        # Single word
        assert not is_complex_task("help")
        
        # Just conjunctions without meaningful context should be complex
        # (multiple "and" triggers the conjunction pattern)
        assert is_complex_task("and and and")


class TestDisplayTaskPlan:
    """Test suite for display_task_plan function."""
    
    @patch('manus_use.cli.console')
    def test_display_empty_plan(self, mock_console):
        """Test displaying empty task plan."""
        display_task_plan([])
        
        # Should create and print a table
        mock_console.print.assert_called_once()
        printed_arg = mock_console.print.call_args[0][0]
        assert hasattr(printed_arg, 'title')
        assert printed_arg.title == "Execution Plan"
    
    @patch('manus_use.cli.console')
    def test_display_single_task(self, mock_console):
        """Test displaying single task."""
        task = TaskPlan(
            task_id="task1",
            description="Test task",
            agent_type=AgentType.MANUS,
            dependencies=[],
            inputs={},
            expected_output="Test output",
            priority=1,
            estimated_complexity=ComplexityLevel.LOW
        )
        
        display_task_plan([task])
        mock_console.print.assert_called_once()
    
    @patch('manus_use.cli.console')
    def test_display_tasks_with_dependencies(self, mock_console):
        """Test displaying tasks with dependencies."""
        tasks = [
            TaskPlan(
                task_id="task1",
                description="First task",
                agent_type=AgentType.BROWSER,
                dependencies=[],
                inputs={},
                expected_output="Data",
                priority=1,
                estimated_complexity=ComplexityLevel.MEDIUM
            ),
            TaskPlan(
                task_id="task2",
                description="Second task with very long description that should be truncated",
                agent_type=AgentType.DATA_ANALYSIS,
                dependencies=["task1"],
                inputs={},
                expected_output="Analysis",
                priority=2,
                estimated_complexity=ComplexityLevel.HIGH
            )
        ]
        
        display_task_plan(tasks)
        mock_console.print.assert_called_once()


class TestMain:
    """Test suite for main function."""
    
    @patch('sys.argv', ['cli.py'])
    @patch('manus_use.cli.Config')
    @patch('manus_use.cli.ManusAgent')
    @patch('manus_use.cli.Orchestrator')
    @patch('manus_use.cli.Prompt.ask')
    @patch('manus_use.cli.console')
    def test_single_agent_mode(self, mock_console, mock_prompt, mock_orchestrator_class, 
                              mock_agent_class, mock_config_class):
        """Test CLI in single agent mode."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_file.return_value = mock_config
        
        mock_agent = Mock()
        mock_agent.return_value = "Agent response"
        mock_agent_class.return_value = mock_agent
        
        mock_prompt.side_effect = ["Simple task", "exit"]
        
        # Run main
        with patch('sys.argv', ['cli.py', '--mode', 'single']):
            main()
        
        # Verify behavior
        mock_agent_class.assert_called_once_with(config=mock_config)
        mock_orchestrator_class.assert_not_called()
        mock_agent.assert_called_once_with("Simple task")
    
    @patch('sys.argv', ['cli.py', '--mode', 'multi'])
    @patch('manus_use.cli.Config')
    @patch('manus_use.cli.ManusAgent')
    @patch('manus_use.cli.Orchestrator')
    @patch('manus_use.cli.Prompt.ask')
    @patch('manus_use.cli.console')
    def test_multi_agent_mode(self, mock_console, mock_prompt, mock_orchestrator_class,
                             mock_agent_class, mock_config_class):
        """Test CLI in multi-agent mode."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_file.return_value = mock_config
        
        mock_agent = Mock()
        mock_agent_class.return_value = mock_agent
        
        mock_result = Mock()
        mock_result.success = True
        mock_result.output = "Multi-agent result"
        
        mock_orchestrator = Mock()
        mock_orchestrator.run.return_value = mock_result
        mock_orchestrator.agents = {}
        mock_orchestrator_class.return_value = mock_orchestrator
        
        mock_prompt.side_effect = ["Complex task", "exit"]
        
        # Run main
        with patch('sys.argv', ['cli.py', '--mode', 'multi']):
            main()
        
        # Verify behavior
        mock_orchestrator_class.assert_called_once_with(config=mock_config)
        mock_orchestrator.run.assert_called_once_with("Complex task")
    
    @patch('sys.argv', ['cli.py', '--mode', 'auto'])
    @patch('manus_use.cli.Config')
    @patch('manus_use.cli.ManusAgent')
    @patch('manus_use.cli.Orchestrator')
    @patch('manus_use.cli.Prompt.ask')
    @patch('manus_use.cli.console')
    def test_auto_mode_simple_task(self, mock_console, mock_prompt, mock_orchestrator_class,
                                   mock_agent_class, mock_config_class):
        """Test auto mode with simple task."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_file.return_value = mock_config
        
        mock_agent = Mock()
        mock_agent.return_value = "Simple response"
        mock_agent_class.return_value = mock_agent
        
        mock_orchestrator = Mock()
        mock_orchestrator_class.return_value = mock_orchestrator
        
        mock_prompt.side_effect = ["What is 2+2?", "exit"]
        
        # Run main
        main()
        
        # Should use single agent for simple task
        mock_agent.assert_called_once_with("What is 2+2?")
        mock_orchestrator.run.assert_not_called()
    
    @patch('sys.argv', ['cli.py', '--mode', 'auto'])
    @patch('manus_use.cli.Config')
    @patch('manus_use.cli.ManusAgent')
    @patch('manus_use.cli.Orchestrator')
    @patch('manus_use.cli.Prompt.ask')
    @patch('manus_use.cli.console')
    def test_auto_mode_complex_task(self, mock_console, mock_prompt, mock_orchestrator_class,
                                    mock_agent_class, mock_config_class):
        """Test auto mode with complex task."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_file.return_value = mock_config
        
        mock_agent = Mock()
        mock_agent_class.return_value = mock_agent
        
        mock_result = Mock()
        mock_result.success = True
        mock_result.output = "Complex result"
        
        mock_orchestrator = Mock()
        mock_orchestrator.run.return_value = mock_result
        mock_orchestrator.agents = {}
        mock_orchestrator_class.return_value = mock_orchestrator
        
        complex_task = "Analyze the website and create a report and generate visualizations"
        mock_prompt.side_effect = [complex_task, "exit"]
        
        # Run main
        main()
        
        # Should use orchestrator for complex task
        mock_orchestrator.run.assert_called_once_with(complex_task)
        mock_agent.assert_not_called()
    
    @patch('sys.argv', ['cli.py', '--show-plan'])
    @patch('manus_use.cli.Config')
    @patch('manus_use.cli.ManusAgent')
    @patch('manus_use.cli.Orchestrator')
    @patch('manus_use.cli.Prompt.ask')
    @patch('manus_use.cli.console')
    @patch('manus_use.cli.display_task_plan')
    def test_show_plan_option(self, mock_display_plan, mock_console, mock_prompt,
                             mock_orchestrator_class, mock_agent_class, mock_config_class):
        """Test --show-plan option."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_file.return_value = mock_config
        
        mock_agent = Mock()
        mock_agent_class.return_value = mock_agent
        
        # Create mock planner
        mock_planner = Mock()
        mock_tasks = [Mock(spec=TaskPlan), Mock(spec=TaskPlan)]
        mock_planner.create_plan.return_value = mock_tasks
        
        mock_result = Mock()
        mock_result.success = True
        mock_result.output = "Result"
        
        mock_orchestrator = Mock()
        mock_orchestrator.run.return_value = mock_result
        mock_orchestrator.agents = {"planner": mock_planner}
        mock_orchestrator_class.return_value = mock_orchestrator
        
        complex_task = "Research AI trends and create a report"
        mock_prompt.side_effect = [complex_task, "exit"]
        
        # Run main
        main()
        
        # Should display plan
        mock_planner.create_plan.assert_called_once_with(complex_task)
        mock_display_plan.assert_called_once_with(mock_tasks)
    
    @patch('sys.argv', ['cli.py'])
    @patch('manus_use.cli.Config')
    @patch('manus_use.cli.ManusAgent')
    @patch('manus_use.cli.Orchestrator')
    @patch('manus_use.cli.Prompt.ask')
    @patch('manus_use.cli.console')
    def test_keyboard_interrupt(self, mock_console, mock_prompt, mock_orchestrator_class,
                               mock_agent_class, mock_config_class):
        """Test handling keyboard interrupt."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_file.return_value = mock_config
        
        mock_agent = Mock()
        mock_agent_class.return_value = mock_agent
        
        mock_orchestrator = Mock()
        mock_orchestrator_class.return_value = mock_orchestrator
        
        mock_prompt.side_effect = KeyboardInterrupt()
        
        # Run main
        main()
        
        # Should exit gracefully
        mock_console.print.assert_any_call("\n\n[bold blue]Goodbye![/bold blue]")
    
    @patch('sys.argv', ['cli.py'])
    @patch('manus_use.cli.Config')
    @patch('manus_use.cli.ManusAgent')
    @patch('manus_use.cli.Orchestrator')
    @patch('manus_use.cli.Prompt.ask')
    @patch('manus_use.cli.console')
    def test_error_handling(self, mock_console, mock_prompt, mock_orchestrator_class,
                           mock_agent_class, mock_config_class):
        """Test error handling during execution."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_file.return_value = mock_config
        
        mock_agent = Mock()
        mock_agent.side_effect = Exception("Test error")
        mock_agent_class.return_value = mock_agent
        
        mock_orchestrator = Mock()
        mock_orchestrator_class.return_value = mock_orchestrator
        
        mock_prompt.side_effect = ["Task", "exit"]
        
        # Run main
        main()
        
        # Should handle error and continue
        mock_console.print.assert_any_call("\n[red]Error: Test error[/red]")
    
    @patch('sys.argv', ['cli.py'])
    @patch('manus_use.cli.Config')
    @patch('manus_use.cli.ManusAgent')
    @patch('manus_use.cli.console')
    def test_initialization_failure(self, mock_console, mock_agent_class, mock_config_class):
        """Test handling of agent initialization failure."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_file.return_value = mock_config
        
        mock_agent_class.side_effect = Exception("Init failed")
        
        # Run main
        with pytest.raises(SystemExit) as exc_info:
            main()
        
        assert exc_info.value.code == 1
        mock_console.print.assert_any_call("✗ Failed to initialize agents: Init failed", style="red")


class TestIntegration:
    """Integration tests for CLI."""
    
    @patch('sys.argv', ['cli.py'])
    @patch('manus_use.cli.Config')
    @patch('manus_use.cli.ManusAgent')
    @patch('manus_use.cli.Orchestrator')
    @patch('manus_use.cli.Prompt.ask')
    @patch('manus_use.cli.console')
    def test_full_workflow(self, mock_console, mock_prompt, mock_orchestrator_class,
                          mock_agent_class, mock_config_class):
        """Test a full workflow with multiple tasks."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_file.return_value = mock_config
        
        mock_agent = Mock()
        mock_agent.side_effect = ["Simple result 1", "Simple result 2"]
        mock_agent_class.return_value = mock_agent
        
        mock_result = Mock()
        mock_result.success = True
        mock_result.output = "Complex result"
        
        mock_orchestrator = Mock()
        mock_orchestrator.run.return_value = mock_result
        mock_orchestrator.agents = {}
        mock_orchestrator_class.return_value = mock_orchestrator
        
        # Simulate user interactions
        mock_prompt.side_effect = [
            "What is Python?",  # Simple task
            "Analyze website performance and create a report",  # Complex task
            "Tell me a joke",  # Simple task
            "exit"
        ]
        
        # Run main
        main()
        
        # Verify workflow
        assert mock_agent.call_count == 2
        assert mock_orchestrator.run.call_count == 1
        
        # Verify correct routing
        mock_agent.assert_any_call("What is Python?")
        mock_agent.assert_any_call("Tell me a joke")
        mock_orchestrator.run.assert_called_once_with("Analyze website performance and create a report")