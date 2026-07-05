"""
Generic AWS API tool — allows the LLM to call any read-only AWS API
via boto3.  Write operations are intentionally excluded here; they
go through the existing approval-gated remediation tools.

Requirements: Broad read access for diagnosis across all AWS services.
"""
import json
import logging
from typing import Dict, Any
from datetime import datetime, date

import boto3
from botocore.exceptions import ClientError, BotoCoreError, ParamValidationError

from src.models import ToolCall, ToolResult, ExecutionMode

logger = logging.getLogger(__name__)

# Actions that are considered safe read-only operations
READ_PREFIXES = (
    "describe", "list", "get", "lookup", "search",
    "check", "fetch", "read", "scan", "head",
    "batch_get", "batch_describe", "filter",
)

# Explicitly blocked actions that look like reads but mutate state
BLOCKED_ACTIONS = {
    "get_password_data",  # returns sensitive data
    "get_console_screenshot",  # expensive
}

# Services that should never be called
BLOCKED_SERVICES = {
    "iam",  # don't let LLM enumerate IAM
    "sts",  # handled separately
    "organizations",
}


def _is_read_only(action: str) -> bool:
    """Check if an action name is a safe read-only operation."""
    action_lower = action.lower()
    if action_lower in BLOCKED_ACTIONS:
        return False
    return any(action_lower.startswith(prefix) for prefix in READ_PREFIXES)


def _json_serial(obj: Any) -> str:
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return f"<{len(obj)} bytes>"
    if hasattr(obj, '__str__'):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


def _truncate(data: Any, max_items: int = 20, max_str_len: int = 2000) -> Any:
    """Truncate large responses to keep within reasonable size."""
    if isinstance(data, list):
        if len(data) > max_items:
            return data[:max_items] + [f"... and {len(data) - max_items} more items"]
        return [_truncate(item, max_items, max_str_len) for item in data]
    if isinstance(data, dict):
        return {k: _truncate(v, max_items, max_str_len) for k, v in data.items()}
    if isinstance(data, str) and len(data) > max_str_len:
        return data[:max_str_len] + "... [truncated]"
    return data


class AWSGenericReadTool:
    """
    Executes any read-only AWS API call via boto3.
    The LLM specifies the service, action, and parameters.
    """

    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE):
        self.execution_mode = execution_mode
        self._clients: Dict[str, Any] = {}

    def _get_client(self, service: str):
        """Get or create a boto3 client for the given service."""
        if service not in self._clients:
            self._clients[service] = boto3.client(service)
        return self._clients[service]

    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute a generic AWS read-only API call.

        Expected tool_call.args:
            service: str  — AWS service name (e.g. "ec2", "s3", "rds", "lambda")
            action: str   — API action (e.g. "describe_instances", "list_buckets")
            parameters: dict (optional) — kwargs to pass to the API call
        """
        service = tool_call.args.get("service", "").lower().strip()
        action = tool_call.args.get("action", "").strip()
        parameters = tool_call.args.get("parameters", {})

        # Validation
        if not service:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error="Missing required parameter: service",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id,
            )

        if not action:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error="Missing required parameter: action",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id,
            )

        if service in BLOCKED_SERVICES:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Service '{service}' is not accessible through this tool for security reasons",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id,
            )

        if not _is_read_only(action):
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Action '{action}' is not a read-only operation. Write operations require approval through the dedicated remediation tools.",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id,
            )

        # Mock mode
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={"mock": True, "service": service, "action": action, "message": f"Mock response for {service}.{action}"},
                execution_mode=self.execution_mode,
                correlation_id=correlation_id,
            )

        # Execute the API call
        try:
            client = self._get_client(service)
            api_method = getattr(client, action, None)

            if api_method is None:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"Action '{action}' does not exist on service '{service}'",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id,
                )

            logger.info(f"Executing {service}.{action} with params: {list(parameters.keys())}")
            response = api_method(**parameters) if parameters else api_method()

            # Remove ResponseMetadata (not useful for the user)
            if isinstance(response, dict):
                response.pop("ResponseMetadata", None)

            # Truncate large responses
            truncated = _truncate(response)

            # Serialize to ensure JSON compatibility
            serialized = json.loads(json.dumps(truncated, default=_json_serial))

            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data=serialized,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id,
            )

        except ParamValidationError as e:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Invalid parameters for {service}.{action}: {str(e)[:300]}",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id,
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            # Redact sensitive info
            if "credential" in error_msg.lower() or "token" in error_msg.lower():
                error_msg = f"Authentication error accessing {service}"
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"{service}.{action} failed ({error_code}): {error_msg}",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id,
            )
        except (BotoCoreError, Exception) as e:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Error calling {service}.{action}: {str(e)[:300]}",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id,
            )
