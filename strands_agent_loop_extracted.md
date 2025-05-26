# Strands Agent Loop Documentation

Source: https://strandsagents.com/0.1.x/user-guide/concepts/agents/agent-loop/

## Overview

The agent loop is the central mechanism that orchestrates information flow in Strands Agents SDK. It processes messages, handles tool execution, manages conversation state, handles errors with retries, and collects metrics.

## The 7 Steps of the Agent Loop

### Step 1: Initialization
When an agent is created, it sets up the necessary components including:
- Tool registry
- Conversation manager
- Parallel processing capabilities
- Metrics collection

### Step 2: User Input Processing
The agent is called with a user input:
- Adds the message to conversation history
- Applies conversation management strategies
- Initializes a new event loop cycle

### Step 3: Model Processing
The model receives:
- System prompt
- Complete conversation history
- Configuration for available tools

The model then generates a response that can include text and tool use requests.

### Step 4: Response Analysis & Tool Execution
If the model returns a tool use request:
- The event loop extracts and validates the request
- Looks up the tool in the registry
- Executes it with error handling
- Captures the result

### Step 5: Tool Result Processing
- The tool result is formatted and added to the conversation history
- The model is invoked again to reason about the tool results

### Step 6: Recursive Processing
The agent loop can recursively continue if:
- The model requests more tool executions
- Further clarification is needed
- Multi-step reasoning is required

### Step 7: Completion
The loop completes when:
- The model generates a final text response
- An unhandled exception occurs

At completion:
- Metrics and traces are collected
- Conversation state is updated
- The final response is returned

## Code Examples

### Event Loop Cycle Function Signature
```python
def event_loop_cycle(
    model: Model,
    system_prompt: Optional[str],
    messages: Messages,
    tool_config: Optional[ToolConfig],
    callback_handler: Any,
    tool_handler: Optional[ToolHandler],
    tool_execution_handler: Optional[ParallelToolExecutorInterface] = None,
    **kwargs: Any,
) -> Tuple[StopReason, Message, EventLoopMetrics, Any]:
```

### Agent Initialization with Tools
```python
from strands import Agent
from strands_tools import calculator

# Initialize the agent with tools, model, and configuration
agent = Agent(
    tools=[calculator],
    system_prompt="You are a helpful assistant."
)
```

### Processing User Input
```python
# Process user input
result = agent("Calculate 25 * 48")
```

### Configuring Parallel Tool Execution
```python
# Configure maximum parallel tool execution
agent = Agent(
    max_parallel_tools=4  # Run up to 4 tools in parallel
)
```

### Tool Use Request Format
```json
{
  "role": "assistant",
  "content": [
    {
      "toolUse": {
        "toolUseId": "tool_123",
        "name": "calculator",
        "input": {
          "expression": "25 * 48"
        }
      }
    }
  ]
}
```

### Tool Result Format
```json
{
  "role": "user",
  "content": [
    {
      "toolResult": {
        "toolUseId": "tool_123",
        "status": "success",
        "content": [
          {"text": "1200"}
        ]
      }
    }
  ]
}
```

## Key Components

### Event Loop Cycle
Central mechanism that:
- Orchestrates information flow
- Processes messages
- Handles tool execution
- Manages conversation state
- Handles errors with retries
- Collects metrics

### Message Processing
Handles the flow of:
- User messages
- Assistant messages
- Tool result messages

All in a structured format through the agent loop.

### Tool Execution
System that:
- Validates tool requests
- Looks up tools in registry
- Executes tools with error handling
- Captures results
- Feeds them back to the model

### Tool Registry
Component that registers and manages available tools for the agent.

### Conversation Manager
Manages the conversation history and state throughout the agent loop.

### Parallel Processing
Capability to execute multiple tools simultaneously for improved efficiency.

### Metrics Collection
System for gathering performance data and traces for observability.

## Application to task_planner.py

Based on this agent loop architecture, the task_planner.py should:

1. **Follow the 7-step pattern**: Structure planning logic to mirror the agent loop steps
2. **Use structured messages**: Format task plans as structured messages similar to tool requests
3. **Enable parallel processing**: Identify tasks that can run in parallel
4. **Add metrics collection**: Track planning performance and task execution metrics
5. **Implement recursive processing**: Allow for iterative refinement of plans
6. **Manage state properly**: Track task dependencies and completion status
7. **Handle errors gracefully**: Include fallback mechanisms for failed tasks

## Best Practices

1. **Clear separation of concerns**: Each step should have a single responsibility
2. **Structured data formats**: Use well-defined schemas for all messages
3. **Error handling at each step**: Graceful degradation and recovery
4. **Observability throughout**: Emit events and collect metrics
5. **Efficient execution**: Leverage parallel processing where possible
6. **State management**: Maintain clear conversation and execution state