"""
Genesis Agent Client for ARES.

Calls Genesis agents via the OpenAI-compatible chat/completions endpoint.
Each agent is invoked at: POST /api/v1/agents/<agent-id>/chat/completions

Auth: Bearer token from Genesis Tokens page.
Docs: https://factory.example.internal/docs/genesis/agent-catalog
      https://factory.example.internal/docs/genesis/tokens
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

import requests
import urllib3

# Suppress SSL warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

GENESIS_API_BASE = os.environ.get(
    "GENESIS_API_URL",
    os.environ.get("GENESIS_API_BASE", "https://genesis-api.example.internal"),
)
GENESIS_TOKEN = os.environ.get(
    "GENESIS_API_TOKEN", os.environ.get("GENESIS_TOKEN", "")
)
GENESIS_ORG = os.environ.get("GENESIS_ORG", "")

# SSL cert bundle for corporate environments (internal CA)
SSL_CERT_FILE = os.environ.get(
    "SSL_CERT_FILE",
    os.environ.get("REQUESTS_CA_BUNDLE", ""),
)

# Agent IDs from the Genesis Panel (Discover > Agent Catalog or Build > Agents)
# Supports both ARES_*_AGENT_ID and shorter *_AGENT_ID env var names
AGENT_IDS = {
    "parser": os.environ.get(
        "ARES_PARSER_AGENT_ID",
        os.environ.get("PARSER_AGENT_ID", "d708cb3a-b2a9-49ae-a147-ebe8ad7af173"),
    ),
    "gap_coverage": os.environ.get(
        "ARES_GAP_COVERAGE_AGENT_ID",
        os.environ.get("GAP_COVERAGE_AGENT_ID", ""),
    ),
    "determination": os.environ.get(
        "ARES_DETERMINATION_AGENT_ID",
        os.environ.get("DETERMINATION_AGENT_ID", ""),
    ),
    "reporting": os.environ.get(
        "ARES_REPORTING_AGENT_ID",
        os.environ.get("REPORTING_AGENT_ID", ""),
    ),
}


class GenesisAgentClient:
    """Client for calling Genesis agents via chat/completions API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        organization: Optional[str] = None,
        verify_ssl: Optional[str] = None,
    ):
        self.base_url = (
            base_url
            or os.environ.get("GENESIS_AGENT_GATEWAY")
            or GENESIS_API_BASE
        ).rstrip("/")
        self.token = token or GENESIS_TOKEN
        self.organization = organization or GENESIS_ORG
        
        # SSL verification: use cert file if provided, otherwise disable verification
        # This allows Genesis API calls to work on corporate networks without proper cert setup
        if verify_ssl:
            self.verify = verify_ssl
        elif SSL_CERT_FILE:
            import pathlib
            cert_path = pathlib.Path(SSL_CERT_FILE)
            if cert_path.exists():
                self.verify = str(cert_path)
                logger.info(f"Using SSL cert: {self.verify}")
            else:
                logger.warning(f"SSL_CERT_FILE set but not found: {SSL_CERT_FILE}. Disabling SSL verification.")
                self.verify = False
        else:
            logger.warning("No SSL_CERT_FILE set. Disabling SSL verification for Genesis API calls.")
            self.verify = False

        if not self.token:
            logger.warning(
                "No GENESIS_TOKEN set. Agent calls will fail. "
                "Set GENESIS_TOKEN env var or pass token= to constructor."
            )

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        if self.organization:
            headers["OpenAI-Organization"] = self.organization
        return headers

    def call_agent(
        self,
        agent_id: str,
        prompt: str,
        auto_approve_tools: Optional[List[str]] = None,
        stream: bool = False,
        timeout: int = 300,
    ) -> str:
        """
        Send a message to a Genesis agent and return its text response.

        Args:
            agent_id: The UUID of the deployed agent.
            prompt: The user message content (typically JSON-serialized input).
            auto_approve_tools: MCP tool names to auto-approve for this request.
            stream: Whether to stream the response (False for simple use).
            timeout: Request timeout in seconds.

        Returns:
            The assistant's response text content.

        Raises:
            GenesisAgentError: On API errors or unexpected responses.
        """
        url = f"{self.base_url}/api/v1/agents/{agent_id}/chat/completions"

        body: Dict[str, Any] = {
            "stream": stream,
            "messages": [
                {"role": "user", "content": prompt},
            ],
        }

        if auto_approve_tools:
            body["metadata"] = {
                "tool_approval": json.dumps(
                    {"v": 1, "auto_approve": auto_approve_tools}
                )
            }

        logger.info(f"Calling agent {agent_id} at {url}")
        logger.debug(f"Prompt length: {len(prompt)} chars")

        resp = requests.post(
            url,
            headers=self._headers(),
            json=body,
            timeout=timeout,
            verify=self.verify,
        )

        if resp.status_code != 200:
            raise GenesisAgentError(
                f"Agent call failed (HTTP {resp.status_code}): {resp.text[:500]}"
            )

        data = resp.json()

        # OpenAI-compatible response: choices[0].message.content
        choices = data.get("choices", [])
        if not choices:
            # Check if tool approval is pending
            meta = data.get("metadata", {})
            tool_approval = meta.get("tool_approval", "")
            if "approval_required" in tool_approval:
                raise GenesisAgentError(
                    "Agent requires tool approval that was not auto-approved. "
                    f"Approval payload: {tool_approval}"
                )
            raise GenesisAgentError(
                f"No choices in agent response: {json.dumps(data)[:500]}"
            )

        message = choices[0].get("message", {})
        content = message.get("content", "")

        if not content:
            raise GenesisAgentError(
                f"Empty content in agent response: {json.dumps(data)[:500]}"
            )

        logger.info(f"Agent {agent_id} responded ({len(content)} chars)")
        return content

    def call_agent_json(
        self,
        agent_id: str,
        prompt: str,
        auto_approve_tools: Optional[List[str]] = None,
        timeout: int = 300,
    ) -> Any:
        """
        Call agent and parse the response as JSON.

        Same as call_agent() but parses the response text as JSON.
        Raises GenesisAgentError if the response isn't valid JSON.
        """
        raw = self.call_agent(
            agent_id, prompt, auto_approve_tools=auto_approve_tools, timeout=timeout
        )

        # Try to extract JSON from the response (agent might wrap in markdown)
        text = raw.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find the first JSON object or array in the response
        for start_char, end_char in [('{', '}'), ('[', ']')]:
            start = text.find(start_char)
            if start == -1:
                continue
            depth = 0
            for i in range(start, len(text)):
                if text[i] == start_char:
                    depth += 1
                elif text[i] == end_char:
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i + 1])
                        except json.JSONDecodeError:
                            break

        raise GenesisAgentError(
            f"Agent response is not valid JSON.\nRaw: {raw[:500]}"
        )


class GenesisAgentError(Exception):
    """Raised when a Genesis agent call fails."""
