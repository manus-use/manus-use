"""Data analysis agent implementation."""

from typing import Any, List, Optional

from strands.types.tools import AgentTool

from .base import BaseManusAgent
from ..config import Config


class DataAnalysisAgent(BaseManusAgent):
    """Agent specialized for data analysis and visualization."""
    
    def __init__(
        self,
        tools: Optional[List[AgentTool]] = None,
        model: Optional[Any] = None,
        config: Optional[Config] = None,
        **kwargs
    ):
        """Initialize data analysis agent.
        
        Args:
            tools: List of tools to use
            model: Model instance or None to use config
            config: Configuration object
            **kwargs: Additional arguments for Agent
        """
        # Get data analysis tools if none provided
        if tools is None:
            tools = self._get_default_tools(config)
            
        super().__init__(
            tools=tools,
            model=model,
            config=config,
            system_prompt=self._get_default_system_prompt(),
            **kwargs
        )
        
    def _get_default_system_prompt(self) -> str:
        """Get data analysis agent system prompt."""
        return """You are a data analysis expert capable of:
- Loading and processing various data formats (CSV, JSON, Excel, etc.)
- Performing statistical analysis and calculations
- Creating insightful visualizations (charts, graphs, plots)
- Identifying patterns and trends in data
- Generating comprehensive reports

When analyzing data:
1. First understand the data structure and quality
2. Clean and preprocess data as needed
3. Choose appropriate analysis methods
4. Create clear, informative visualizations
5. Provide actionable insights and recommendations

Always explain your analysis process and findings clearly."""
        
    def _get_default_tools(self, config: Optional[Config] = None) -> List[AgentTool]:
        """Get default tools for data analysis."""
        from ..tools import get_tools_by_names
        
        config = config or Config.from_file()
        
        # Data analysis specific tools
        tool_names = [
            "file_read",
            "file_write", 
            "code_execute",  # For pandas, numpy operations
            "create_chart",
            "data_analyze",
            "statistical_test",
        ]
        
        return get_tools_by_names(tool_names, config=config)