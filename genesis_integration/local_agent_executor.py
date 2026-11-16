"""
Local Agent Executor with MCP Tool Calling.

Uses Genesis LLM API with agent prompts and local MCP server for tool execution.
This allows Gap Coverage and Determination agents to use execute_command locally
while Parser uses the deployed Genesis agent with OpenShift MCP.

Architecture:
- Load agent prompt as system prompt
- Call Genesis /v1/chat/completions with tools enabled
- Intercept tool calls and execute against local MCP server
- Return final agent response
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Genesis API configuration
GENESIS_API_BASE = os.environ.get("GENESIS_API_URL", "https://genesis-api.example.internal")
GENESIS_TOKEN = os.environ.get("GENESIS_API_TOKEN", "")
MCP_LOCAL_URL = os.environ.get("MCP_LOCAL_URL", "http://localhost:8000")

# SSL cert handling
SSL_CERT_FILE = os.environ.get("SSL_CERT_FILE", "")
if SSL_CERT_FILE and Path(SSL_CERT_FILE).exists():
    VERIFY_SSL = SSL_CERT_FILE
else:
    VERIFY_SSL = False
    if not SSL_CERT_FILE:
        logger.warning("No SSL_CERT_FILE set for local agent executor")


class LocalAgentExecutor:
    """
    Executes agent logic locally using Genesis LLM + local MCP tools.
    """
    
    def __init__(
        self,
        agent_prompt_file: str,
        model: str = "nemotron-3-ultra-550b-a55b",
        vector_store_id: Optional[str] = None,
        max_iterations: int = 10,
    ):
        """
        Initialize local agent executor.
        
        Args:
            agent_prompt_file: Path to agent prompt file (used as system prompt)
            model: Genesis model identifier
            vector_store_id: Genesis RAG vector store ID for STIG documents
            max_iterations: Max tool calling iterations to prevent infinite loops
        """
        self.model = model
        self.vector_store_id = vector_store_id
        self.max_iterations = max_iterations
        
        # Load agent prompt
        prompt_path = Path(agent_prompt_file)
        if not prompt_path.exists():
            raise FileNotFoundError(f"Agent prompt not found: {agent_prompt_file}")
        
        self.system_prompt = prompt_path.read_text(encoding="utf-8")
        logger.info(f"Loaded agent prompt from {agent_prompt_file} ({len(self.system_prompt)} chars)")
    
    def execute(
        self,
        user_input: str | Dict,
        timeout: int = 300,
    ) -> str:
        """
        Execute agent with user input, handling tool calls.
        
        Args:
            user_input: User message (string or dict that will be JSON-serialized)
            timeout: Request timeout in seconds
        
        Returns:
            Final agent response text
        """
        # Convert dict to JSON string
        if isinstance(user_input, dict):
            # Log the Check Text being sent
            vuln_id = user_input.get('vuln_id', 'unknown')
            check_text = user_input.get('check_text', '')
            if check_text:
                print(f"\n[AGENT INPUT] Vuln ID: {vuln_id}", flush=True)
                print(f"[AGENT INPUT] Check Text:", flush=True)
                print(f"{'-'*80}", flush=True)
                # Print first 500 chars of check text
                check_preview = check_text[:500].replace('\n', '\n  ')
                print(f"  {check_preview}", flush=True)
                if len(check_text) > 500:
                    print(f"  ... ({len(check_text)-500} more chars)", flush=True)
                print(f"{'-'*80}\n", flush=True)
            
            user_input = json.dumps(user_input, indent=2)
        
        messages = [
            {"role": "user", "content": user_input}
        ]
        
        # Tool calling loop
        for iteration in range(self.max_iterations):
            print(f"\n{'='*80}", flush=True)
            print(f"[ITERATION {iteration + 1}/{self.max_iterations}]", flush=True)
            print(f"{'='*80}", flush=True)
            logger.info(f"Agent iteration {iteration + 1}/{self.max_iterations}")
            
            # Call Genesis LLM
            response = self._call_llm(messages, timeout)
            
            # Extract and log any reasoning/content from LLM
            llm_content = self._extract_content(response)
            if llm_content and llm_content.strip():
                print(f"\n[LLM REASONING - Iteration {iteration + 1}]", flush=True)
                print(f"{'-'*80}", flush=True)
                # Show first 300 chars of reasoning
                reasoning_preview = llm_content[:300].strip()
                print(f"{reasoning_preview}", flush=True)
                if len(llm_content) > 300:
                    print(f"... ({len(llm_content)-300} more chars)", flush=True)
                print(f"{'-'*80}\n", flush=True)
            
            # Check for tool calls
            tool_calls = self._extract_tool_calls(response)
            
            if not tool_calls:
                # No more tool calls, return final response
                final_content = self._extract_content(response)
                print(f"\n[FINAL RESPONSE] Agent completed in {iteration + 1} iterations", flush=True)
                print(f"{'='*80}\n", flush=True)
                logger.info(f"Agent completed in {iteration + 1} iterations")
                return final_content
            
            # Execute tool calls via local MCP
            logger.info(f"Executing {len(tool_calls)} tool call(s)")
            tool_results = []
            
            for tool_call in tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["arguments"]
                tool_id = tool_call.get("id", f"call_{int(time.time() * 1000)}")
                
                logger.info(f"Tool call: {tool_name}")
                logger.info(f"Tool args: {json.dumps(tool_args, indent=2)}")
                
                if tool_name == "execute_command":
                    # Log command execution
                    command = tool_args.get("command", "")
                    rule_id = tool_args.get("rule_id", "")
                    use_sudo = tool_args.get("use_sudo", False)
                    
                    # DETAILED CONSOLE LOGGING
                    print(f"\n[EXECUTE_COMMAND]", flush=True)
                    print(f"  Command: {command}", flush=True)
                    print(f"  Rule ID: {rule_id}", flush=True)
                    print(f"  Use Sudo: {use_sudo}", flush=True)
                    print(f"  Calling MCP tool...", flush=True)
                    
                    logger.info(f"[CMD] Executing: {command}")
                    logger.info(f"[CMD] Rule ID: {rule_id}, Sudo: {use_sudo}")
                    
                    result = self._execute_command_local(tool_args)
                    
                    # Log result with FULL details
                    status = result.get("status", "unknown")
                    exit_code = result.get("exit_code", -1)
                    output = result.get("output", "")
                    error = result.get("error", "")
                    
                    # DETAILED CONSOLE LOGGING OF RESULTS
                    print(f"\n[COMMAND RESULT]", flush=True)
                    print(f"  Status: {status}", flush=True)
                    print(f"  Exit Code: {exit_code}", flush=True)
                    if output:
                        print(f"  Output:", flush=True)
                        print(f"{'-'*80}", flush=True)
                        # Show first 500 chars
                        output_preview = output[:500]
                        print(f"{output_preview}", flush=True)
                        if len(output) > 500:
                            print(f"... ({len(output)-500} more chars)", flush=True)
                        print(f"{'-'*80}", flush=True)
                    if error:
                        print(f"  Error: {error}", flush=True)
                    print(f"", flush=True)
                    
                    logger.info(f"[CMD] Status: {status}, Exit Code: {exit_code}")
                    if output:
                        preview = output[:200].replace('\n', ' ')
                        logger.info(f"[CMD] Output preview: {preview}...")
                    if error:
                        logger.error(f"[CMD] Error: {error[:200]}")
                else:
                    result = {"error": f"Unknown tool: {tool_name}"}
                
                tool_results.append({
                    "tool_call_id": tool_id,
                    "role": "tool",
                    "name": tool_name,
                    "content": json.dumps(result),
                })
            
            # Add assistant message with tool calls and tool results to conversation
            assistant_message = {
                "role": "assistant",
                "content": self._extract_content(response),
                "tool_calls": [
                    {
                        "id": tc.get("id", f"call_{i}"),
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": json.dumps(tc["arguments"]),
                        }
                    }
                    for i, tc in enumerate(tool_calls)
                ]
            }
            messages.append(assistant_message)
            
            # Add tool results
            for tool_result in tool_results:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_result["tool_call_id"],
                    "content": tool_result["content"],
                })
            
            # After tool execution, remind agent to return JSON only
            # This helps ensure the next iteration returns JSON verdict
            if len(tool_calls) > 0:
                messages.append({
                    "role": "system",
                    "content": "Now that you have command outputs, generate your final JSON verdict. Return ONLY the JSON object - no explanations, no markdown, no commentary. Start with { and end with }."
                })
        
        # Max iterations reached
        logger.warning(f"Max iterations ({self.max_iterations}) reached")
        return self._extract_content(response)
    
    def _call_llm(self, messages: List[Dict], timeout: int) -> Dict:
        """Call Genesis LLM API with tool definitions."""
        url = f"{GENESIS_API_BASE}/v1/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {GENESIS_TOKEN}",
            "Content-Type": "application/json",
        }
        
        # Build tools list: execute_command + file_search (if RAG enabled)
        tools = self._get_tool_definitions()
        if self.vector_store_id:
            tools.append({
                "type": "file_search"
            })
        
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                *messages,
            ],
            "tools": tools,
            "tool_choice": "auto",
        }
        
        # Add vector store for RAG access (if configured) - CORRECT FORMAT per Genesis API
        if self.vector_store_id:
            body["tool_resources"] = {
                "file_search": {
                    "vector_store_ids": [self.vector_store_id]  # Must be array
                }
            }
        
        resp = requests.post(
            url,
            headers=headers,
            json=body,
            timeout=timeout,
            verify=VERIFY_SSL,
        )
        
        if resp.status_code != 200:
            raise RuntimeError(
                f"Genesis LLM call failed (HTTP {resp.status_code}): {resp.text[:500]}"
            )
        
        return resp.json()
    
    def _get_tool_definitions(self) -> List[Dict]:
        """Get OpenAI-format tool definitions for execute_command."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "execute_command",
                    "description": (
                        "Execute a STIG validation command on the remote RHEL 8 target via SSH. "
                        "Use this to run Check Text commands and validate STIG findings. "
                        "Returns command output, exit code, and execution metadata."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Shell command to execute on target host",
                            },
                            "rule_id": {
                                "type": "string",
                                "description": "STIG rule identifier (e.g., V-230225) for audit logging",
                            },
                            "use_sudo": {
                                "type": "boolean",
                                "description": "Whether to use sudo for this command (default: true - most STIG checks need root)",
                                "default": True,
                            },
                        },
                        "required": ["command", "rule_id"],
                    },
                },
            }
        ]
    
    def _extract_tool_calls(self, response: Dict) -> List[Dict]:
        """Extract tool calls from Genesis LLM response."""
        choices = response.get("choices", [])
        if not choices:
            return []
        
        message = choices[0].get("message", {})
        tool_calls = message.get("tool_calls", [])
        
        if not tool_calls:
            return []
        
        # Convert to simplified format
        result = []
        for tc in tool_calls:
            if tc.get("type") != "function":
                continue
            
            func = tc.get("function", {})
            try:
                args = json.loads(func.get("arguments", "{}"))
            except json.JSONDecodeError:
                args = {}
            
            result.append({
                "id": tc.get("id"),
                "name": func.get("name"),
                "arguments": args,
            })
        
        return result
    
    def _extract_content(self, response: Dict) -> str:
        """Extract text content from Genesis LLM response."""
        choices = response.get("choices", [])
        if not choices:
            return ""
        
        message = choices[0].get("message", {})
        return message.get("content", "") or ""
    
    def _execute_command_local(self, args: Dict) -> Dict:
        """Execute command via local MCP server."""
        try:
            # Call local MCP server's execute_command endpoint
            # Note: We need to add a REST endpoint to MCP server for this
            # For now, we'll construct the response format the tool expects
            
            from cli_executor.ares_mcp_tool import ARESCliMcpTool
            
            tool = ARESCliMcpTool()
            result = tool.run(
                command=args.get("command", ""),
                rule_id=args.get("rule_id", ""),
                use_sudo=args.get("use_sudo", True),  # Default True - most STIG checks need root
            )
            
            logger.info(f"execute_command result: status={result.get('status')}, exit_code={result.get('exit_code')}")
            return result
            
        except Exception as e:
            logger.error(f"execute_command error: {e}", exc_info=True)
            return {
                "status": "error",
                "error": str(e),
                "exit_code": -1,
            }


class LocalAgentError(Exception):
    """Raised when local agent execution fails."""
