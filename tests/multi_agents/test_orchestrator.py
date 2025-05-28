import asyncio
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

from src.manus_use.multi_agents.orchestrator import Orchestrator, AgentType, AGENT_SYSTEM_PROMPTS, ComplexityLevel, TaskPlan
from src.manus_use.config import Config # Assuming Config can be imported

# Mock StrandsAgentAlias if it's imported like 'from strands import Agent as StrandsAgentAlias'
# If 'strands.Agent' is used directly, patch that.
# Based on orchestrator.py, it's 'from strands import Agent as StrandsAgentAlias'
MODULE_PATH_FOR_STRANDS_AGENT = "src.manus_use.multi_agents.orchestrator.StrandsAgentAlias"

class TestOrchestratorGeneratePlan(unittest.IsolatedAsyncioTestCase):

    async def test_generate_plan_with_llm_success(self):
        # 1. Setup Orchestrator instance with mocks
        mock_config = MagicMock(spec=Config)
        mock_config.get_model.return_value = "test_model" # Mock model name

        # Mock LLM response
        mock_llm_json_output = """
        [
          {
            "task_id": "task1",
            "description": "First task",
            "agent_type": "manus",
            "dependencies": [],
            "inputs": {},
            "expected_output": "Output of task1",
            "priority": 1,
            "estimated_complexity": "low",
            "metadata": {"key": "value1"}
          },
          {
            "task_id": "task2",
            "description": "Second task depending on first",
            "agent_type": "browser",
            "dependencies": ["task1"],
            "inputs": {"data": "{{task1.output}}"},
            "expected_output": "Output of task2",
            "priority": 1,
            "estimated_complexity": "medium",
            "metadata": {}
          }
        ]
        """
        
        # Mock the response object that the LLM (main_agent) call returns
        mock_llm_response = MagicMock()
        mock_llm_response.content = mock_llm_json_output
        
        # Patch StrandsAgentAlias used to create self.main_agent
        with patch(MODULE_PATH_FOR_STRANDS_AGENT) as MockStrandsAgent:
            # Configure the instance of StrandsAgentAlias (self.main_agent)
            mock_main_agent_instance = MockStrandsAgent.return_value
            # The __call__ method of the agent should be an AsyncMock if it's called like 'await self.main_agent(...)'
            # or a MagicMock if called like 'self.main_agent(...)' and it's a coroutine
            # In orchestrator, it's:
            # llm_response = self.main_agent(full_prompt)
            # if asyncio.iscoroutine(llm_response):
            #     llm_response = await llm_response
            # So, we can make it return an awaitable (AsyncMock can do this, or a MagicMock returning a coroutine)
            # or just a plain MagicMock if the object itself is not awaitable but its methods are.
            # Let's assume the agent instance itself is callable and might return an awaitable or a direct response.
            # For simplicity, we'll make it return the mock_llm_response directly,
            # as the orchestrator code handles both awaitable and direct responses.
            
            # If self.main_agent is called directly (e.g. self.main_agent(prompt))
            # and that call is expected to return a response object (which might be a coroutine)
            # then mock_main_agent_instance itself should be an AsyncMock if it's `await self.main_agent(prompt)`
            # or MagicMock if it's `response = self.main_agent(prompt); if is_coroutine(response): await response`
            
            # The orchestrator code is:
            # llm_response = self.main_agent(full_prompt)
            # if asyncio.iscoroutine(llm_response):
            #    llm_response = await llm_response
            # So, self.main_agent(full_prompt) can return a non-coroutine.
            mock_main_agent_instance.return_value = mock_llm_response # For when main_agent instance is called

            orchestrator = Orchestrator(config=mock_config)
            
            # Ensure the mocked agent is used
            orchestrator.main_agent = mock_main_agent_instance

            # 3. Call _generate_plan_with_llm
            request_text = "test request for planning"
            generated_plan = await orchestrator._generate_plan_with_llm(request_text)

            # 4. Assertions
            self.assertIsInstance(generated_plan, list)
            self.assertEqual(len(generated_plan), 2)

            # Task 1 assertions
            task1 = generated_plan[0]
            self.assertEqual(task1['task_id'], "task1")
            self.assertEqual(task1['description'], "First task")
            self.assertEqual(task1['dependencies'], [])
            self.assertEqual(task1['system_prompt'], AGENT_SYSTEM_PROMPTS[AgentType.MANUS])
            self.assertEqual(task1['priority'], 1)
            self.assertIn('metadata', task1)
            self.assertEqual(task1['metadata'], {"key": "value1"})


            # Task 2 assertions
            task2 = generated_plan[1]
            self.assertEqual(task2['task_id'], "task2")
            self.assertEqual(task2['description'], "Second task depending on first")
            self.assertEqual(task2['dependencies'], ["task1"])
            self.assertEqual(task2['system_prompt'], AGENT_SYSTEM_PROMPTS[AgentType.BROWSER])
            self.assertEqual(task2['priority'], 1)
            self.assertIn('metadata', task2)
            self.assertEqual(task2['metadata'], {})
            
            # Check that the main_agent was called with the correct prompt structure
            mock_main_agent_instance.assert_called_once()
            args, _ = mock_main_agent_instance.call_args
            prompt_arg = args[0]
            self.assertIn("You are an expert task planning agent", prompt_arg)
            self.assertIn(request_text, prompt_arg)

    async def test_generate_plan_with_llm_fallback(self):
        # Test the fallback mechanism when LLM returns no JSON
        mock_config = MagicMock(spec=Config)
        mock_config.get_model.return_value = "test_model"

        mock_llm_response = MagicMock()
        mock_llm_response.content = "This is not a JSON response." # Invalid response

        with patch(MODULE_PATH_FOR_STRANDS_AGENT) as MockStrandsAgent:
            mock_main_agent_instance = MockStrandsAgent.return_value
            mock_main_agent_instance.return_value = mock_llm_response
            
            orchestrator = Orchestrator(config=mock_config)
            orchestrator.main_agent = mock_main_agent_instance

            request_text = "test request for fallback"
            generated_plan = await orchestrator._generate_plan_with_llm(request_text)

            self.assertIsInstance(generated_plan, list)
            self.assertEqual(len(generated_plan), 1)
            
            fallback_task = generated_plan[0]
            self.assertTrue(fallback_task['task_id'].startswith("fallback_task_"))
            self.assertEqual(fallback_task['description'], request_text)
            self.assertEqual(fallback_task['dependencies'], [])
            self.assertEqual(fallback_task['system_prompt'], AGENT_SYSTEM_PROMPTS[AgentType.MANUS])
            self.assertEqual(fallback_task['priority'], 1)
            self.assertEqual(fallback_task['metadata'], {"fallback": True})

    async def test_generate_plan_with_llm_parsing_error(self):
        # Test the fallback mechanism when LLM returns malformed JSON
        mock_config = MagicMock(spec=Config)
        mock_config.get_model.return_value = "test_model"

        mock_llm_response = MagicMock()
        # Malformed JSON (missing closing bracket for the array)
        mock_llm_response.content = """ 
        [
          {"task_id": "task1", "description": "First task", "agent_type": "manus"}
        """

        with patch(MODULE_PATH_FOR_STRANDS_AGENT) as MockStrandsAgent:
            mock_main_agent_instance = MockStrandsAgent.return_value
            mock_main_agent_instance.return_value = mock_llm_response
            
            orchestrator = Orchestrator(config=mock_config)
            orchestrator.main_agent = mock_main_agent_instance

            request_text = "test request for json error"
            generated_plan = await orchestrator._generate_plan_with_llm(request_text)
            
            # Should return empty list on JSONDecodeError
            self.assertIsInstance(generated_plan, list)
            self.assertEqual(len(generated_plan), 0)

    async def test_generate_plan_with_llm_task_validation(self):
        # Test that tasks are validated using TaskPlan and defaults are applied
        mock_config = MagicMock(spec=Config)
        mock_config.get_model.return_value = "test_model"

        mock_llm_json_output = """
        [
          {
            "task_id": "valid_task_1",
            "description": "Valid task with all fields",
            "agent_type": "manus",
            "dependencies": [],
            "inputs": {},
            "expected_output": "Output here",
            "priority": 2,
            "estimated_complexity": "high",
            "metadata": {"user_meta": "data"}
          },
          {
            "task_id": "task_missing_defaults",
            "description": "Task missing some optional fields that have defaults",
            "agent_type": "browser" 
            
          },
          {
            "task_id": "invalid_agent_type_task",
            "description": "Task with an agent_type not in Enum but should use default",
            "agent_type": "non_existent_agent",
            "expected_output": "some output"
          },
          {
            
            "description": "Task missing task_id and other required fields",
            "agent_type": "manus"
          }
        ]
        """
        # This last task should be skipped by Pydantic validation if task_id is required.
        # In current _generate_plan_with_llm, TaskPlan(**task_data) is called.
        # TaskPlan requires task_id, description, agent_type, expected_output.

        mock_llm_response = MagicMock()
        mock_llm_response.content = mock_llm_json_output
        
        with patch(MODULE_PATH_FOR_STRANDS_AGENT) as MockStrandsAgent:
            mock_main_agent_instance = MockStrandsAgent.return_value
            mock_main_agent_instance.return_value = mock_llm_response
            
            orchestrator = Orchestrator(config=mock_config)
            orchestrator.main_agent = mock_main_agent_instance

            generated_plan = await orchestrator._generate_plan_with_llm("test validation")
            
            self.assertIsInstance(generated_plan, list)
            # Expected: task1, task_missing_defaults (gets defaults), invalid_agent_type_task (agent_type becomes MANUS due to fallback in AGENT_SYSTEM_PROMPTS.get)
            # The last task (missing task_id, expected_output) will fail TaskPlan validation and be skipped.
            self.assertEqual(len(generated_plan), 3) 

            # Task 1 (valid_task_1)
            self.assertEqual(generated_plan[0]['task_id'], "valid_task_1")
            self.assertEqual(generated_plan[0]['description'], "Valid task with all fields")
            self.assertEqual(generated_plan[0]['agent_type'], AgentType.MANUS) # This is not in the output dict, system_prompt is
            self.assertEqual(generated_plan[0]['system_prompt'], AGENT_SYSTEM_PROMPTS[AgentType.MANUS])
            self.assertEqual(generated_plan[0]['priority'], 2)
            self.assertEqual(generated_plan[0]['metadata'], {"user_meta": "data"})
            # self.assertEqual(generated_plan[0]['estimated_complexity'], ComplexityLevel.HIGH) # This is not in output dict

            # Task 2 (task_missing_defaults)
            self.assertEqual(generated_plan[1]['task_id'], "task_missing_defaults")
            self.assertEqual(generated_plan[1]['description'], "Task missing some optional fields that have defaults")
            self.assertEqual(generated_plan[1]['system_prompt'], AGENT_SYSTEM_PROMPTS[AgentType.BROWSER])
            self.assertEqual(generated_plan[1]['priority'], 1) # Default from TaskPlan
            # self.assertEqual(generated_plan[1]['estimated_complexity'], ComplexityLevel.MEDIUM) # Default
            self.assertEqual(generated_plan[1]['dependencies'], []) # Default
            self.assertEqual(generated_plan[1]['metadata'], {}) # Default

            # Task 3 (invalid_agent_type_task)
            # The TaskPlan model will try to convert "non_existent_agent" to AgentType enum.
            # This will fail pydantic validation for agent_type if strict.
            # The code has: task_data['agent_type'] = AgentType(task_data['agent_type'].lower())
            # This will raise ValueError if not in enum.
            # Then `task_plan = TaskPlan(**task_data)` will fail.
            # So this task should be skipped.
            # Let's re-check the orchestrator's _generate_plan_with_llm:
            # It has a try-except around TaskPlan(**task_data)
            # logging.warning(f"Skipping task due to validation error: {e}. Task data: {task_data}")
            # So, tasks that fail pydantic validation for TaskPlan are skipped.
            # The current TaskPlan model makes agent_type required.
            # If agent_type="non_existent_agent" is passed, it will fail validation.
            #
            # The code snippet for handling agent_type:
            # if isinstance(task_data.get('agent_type'), str) and not isinstance(task_data.get('agent_type'), AgentType):
            #    task_data['agent_type'] = AgentType(task_data['agent_type'].lower())
            # This line itself will throw a ValueError if `task_data['agent_type'].lower()` is not a valid AgentType member.
            # This will be caught by `except Exception as e: logging.warning(...)`
            # So, this task will be skipped.
            #
            # The last task (missing task_id, description, expected_output) will also be skipped.
            # "expected_output" is required by TaskPlan.
            #
            # So, only the first two tasks should pass.

            # REVISING the expectation based on current implementation:
            # Task "invalid_agent_type_task" will fail validation because 'non_existent_agent' is not a valid AgentType.
            # Task "missing task_id" will fail validation because 'task_id' and 'expected_output' are required.
            self.assertEqual(len(generated_plan), 2) 


if __name__ == '__main__':
    unittest.main()
