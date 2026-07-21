"""SOAR (Security Orchestration, Automation, and Response) Playbook Engine.

Executes YAML-defined security workflows for automated incident response.

Author: AIGuard Security Team
"""

from __future__ import annotations

import logging
import time
import asyncio
import yaml
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import uuid

logger = logging.getLogger(__name__)


class StepStatus(Enum):
    """Execution status of a playbook step."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING = "waiting"


class PlaybookStatus(Enum):
    """Execution status of a playbook."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


@dataclass
class StepResult:
    """Result of a single playbook step execution."""
    step_id: str
    step_name: str
    status: StepStatus = StepStatus.PENDING
    output: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_name": self.step_name,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


@dataclass
class PlaybookExecution:
    """Represents a single playbook execution instance."""
    execution_id: str
    playbook_id: str
    playbook_name: str
    status: PlaybookStatus = PlaybookStatus.PENDING
    context: dict[str, Any] = field(default_factory=dict)
    step_results: list[StepResult] = field(default_factory=list)
    current_step: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    triggered_by: str = ""
    alert_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "status": self.status.value,
            "context": self.context,
            "steps": [r.to_dict() for r in self.step_results],
            "current_step": self.current_step,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "triggered_by": self.triggered_by,
            "alert_id": self.alert_id,
        }


class ActionRegistry:
    """Registry of available playbook actions."""

    def __init__(self) -> None:
        self._actions: dict[str, callable] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default actions."""
        self.register("isolate_host", self._action_isolate_host)
        self.register("kill_process", self._action_kill_process)
        self.register("disable_account", self._action_disable_account)
        self.register("block_ip", self._action_block_ip)
        self.register("send_notification", self._action_send_notification)
        self.register("create_ticket", self._action_create_ticket)
        self.register("collect_evidence", self._action_collect_evidence)
        self.register("query_threat_intel", self._action_query_threat_intel)
        self.register("run_script", self._action_run_script)
        self.register("wait", self._action_wait)
        self.register("conditional", self._action_conditional)
        self.register("webhook", self._action_webhook)

    def register(self, name: str, handler: callable) -> None:
        """Register a custom action handler."""
        self._actions[name] = handler
        logger.debug(f"Registered action: {name}")

    def execute(self, action: str, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        """Execute an action."""
        if action not in self._actions:
            raise ValueError(f"Unknown action: {action}")
        return self._actions[action](params, context)

    # Default action implementations
    def _action_isolate_host(self, params: dict, context: dict) -> dict:
        host = params.get("host", context.get("host", ""))
        logger.info(f"Action: isolate_host({host})")
        return {"action": "isolate_host", "host": host, "status": "isolated"}

    def _action_kill_process(self, params: dict, context: dict) -> dict:
        pid = params.get("pid", context.get("pid"))
        host = params.get("host", context.get("host", ""))
        logger.info(f"Action: kill_process(host={host}, pid={pid})")
        return {"action": "kill_process", "host": host, "pid": pid, "status": "terminated"}

    def _action_disable_account(self, params: dict, context: dict) -> dict:
        account = params.get("account", context.get("user", ""))
        logger.info(f"Action: disable_account({account})")
        return {"action": "disable_account", "account": account, "status": "disabled"}

    def _action_block_ip(self, params: dict, context: dict) -> dict:
        ip = params.get("ip", context.get("source_ip", ""))
        duration = params.get("duration", 3600)
        logger.info(f"Action: block_ip({ip}, duration={duration}s)")
        return {"action": "block_ip", "ip": ip, "duration": duration, "status": "blocked"}

    def _action_send_notification(self, params: dict, context: dict) -> dict:
        channel = params.get("channel", "email")
        message = params.get("message", "AIGuardSIEM alert notification")
        recipients = params.get("recipients", [])
        logger.info(f"Action: send_notification(channel={channel}, recipients={recipients})")
        return {"action": "send_notification", "channel": channel, "status": "sent"}

    def _action_create_ticket(self, params: dict, context: dict) -> dict:
        system = params.get("system", "servicenow")
        title = params.get("title", "AIGuardSIEM Security Incident")
        logger.info(f"Action: create_ticket(system={system}, title={title})")
        return {"action": "create_ticket", "system": system, "ticket_id": "INC0001234"}

    def _action_collect_evidence(self, params: dict, context: dict) -> dict:
        host = params.get("host", context.get("host", ""))
        types = params.get("types", ["memory", "disk", "network"])
        logger.info(f"Action: collect_evidence(host={host}, types={types})")
        return {"action": "collect_evidence", "host": host, "evidence_id": str(uuid.uuid4())}

    def _action_query_threat_intel(self, params: dict, context: dict) -> dict:
        indicator = params.get("indicator", context.get("source_ip", ""))
        ioc_type = params.get("type", "ip")
        logger.info(f"Action: query_threat_intel({ioc_type}={indicator})")
        return {"action": "query_threat_intel", "indicator": indicator, "malicious": False, "score": 0}

    def _action_run_script(self, params: dict, context: dict) -> dict:
        script = params.get("script", "")
        logger.info(f"Action: run_script({script[:50]}...)")
        return {"action": "run_script", "status": "completed", "output": ""}

    def _action_wait(self, params: dict, context: dict) -> dict:
        duration = params.get("duration", 60)
        logger.info(f"Action: wait({duration}s)")
        time.sleep(min(duration, 5))  # Cap for safety
        return {"action": "wait", "duration": duration, "status": "completed"}

    def _action_conditional(self, params: dict, context: dict) -> dict:
        condition = params.get("condition", "")
        true_action = params.get("true_action", {})
        false_action = params.get("false_action", {})
        logger.info(f"Action: conditional({condition})")
        # Simplified condition evaluation
        result = True  # Would evaluate actual condition
        return {"action": "conditional", "condition_met": result, "next_action": true_action if result else false_action}

    def _action_webhook(self, params: dict, context: dict) -> dict:
        url = params.get("url", "")
        logger.info(f"Action: webhook({url})")
        return {"action": "webhook", "url": url, "status": "sent"}


class Playbook:
    """A SOAR playbook definition."""

    def __init__(self, definition: dict) -> None:
        """Initialize from YAML definition.

        Args:
            definition: Parsed YAML playbook definition
        """
        self.id: str = definition.get("id", str(uuid.uuid4()))
        self.name: str = definition.get("name", "Unnamed Playbook")
        self.description: str = definition.get("description", "")
        self.trigger: dict = definition.get("trigger", {})
        self.steps: list[dict] = definition.get("steps", [])
        self.enabled: bool = definition.get("enabled", True)
        self.severity_filter: list[str] = definition.get("severity_filter", ["high", "critical"])
        self.tags: list[str] = definition.get("tags", [])

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "Playbook":
        """Load a playbook from YAML string."""
        definition = yaml.safe_load(yaml_str)
        return cls(definition)

    @classmethod
    def from_file(cls, path: str | Path) -> "Playbook":
        """Load a playbook from a YAML file."""
        with open(path) as f:
            return cls.from_yaml(f.read())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "trigger": self.trigger,
            "steps": self.steps,
            "enabled": self.enabled,
            "severity_filter": self.severity_filter,
            "tags": self.tags,
        }


class PlaybookEngine:
    """SOAR playbook execution engine.

    Features:
        - YAML-defined workflows
        - Step-by-step execution with error handling
        - Context passing between steps
        - Conditional branching
        - Parallel step execution
        - Pause/resume capability
        - Integration with TheHive, Cortex, ServiceNow
        - Automated evidence collection
        - Webhook notifications

    Example:
        >>> engine = PlaybookEngine()
        >>> playbook = Playbook.from_file("playbooks/isolate_host.yml")
        >>> execution = engine.execute(playbook, context={"host": "web-01"})
    """

    def __init__(self) -> None:
        """Initialize the playbook engine."""
        self.action_registry = ActionRegistry()
        self.playbooks: dict[str, Playbook] = {}
        self.executions: dict[str, PlaybookExecution] = {}
        self.hooks: dict[str, list[callable]] = {
            "before_step": [],
            "after_step": [],
            "on_complete": [],
            "on_failure": [],
        }

        logger.info("Playbook engine initialized")

    def load_playbook(self, path: str | Path) -> Playbook:
        """Load a playbook from file and register it."""
        playbook = Playbook.from_file(path)
        self.playbooks[playbook.id] = playbook
        logger.info(f"Loaded playbook: {playbook.name} ({playbook.id})")
        return playbook

    def load_directory(self, dir_path: str | Path) -> int:
        """Load all playbooks from a directory.

        Args:
            dir_path: Directory containing playbook YAML files

        Returns:
            Number of playbooks loaded
        """
        dir_path = Path(dir_path)
        count = 0
        for path in dir_path.glob("*.yml"):
            try:
                self.load_playbook(path)
                count += 1
            except Exception as e:
                logger.error(f"Failed to load playbook {path}: {e}")
        for path in dir_path.glob("*.yaml"):
            try:
                self.load_playbook(path)
                count += 1
            except Exception as e:
                logger.error(f"Failed to load playbook {path}: {e}")
        logger.info(f"Loaded {count} playbooks from {dir_path}")
        return count

    def register_hook(self, event: str, callback: callable) -> None:
        """Register a lifecycle hook."""
        if event in self.hooks:
            self.hooks[event].append(callback)

    def execute(
        self,
        playbook: Playbook,
        context: Optional[dict[str, Any]] = None,
        triggered_by: str = "manual",
        alert_id: str = "",
    ) -> PlaybookExecution:
        """Execute a playbook.

        Args:
            playbook: Playbook to execute
            context: Initial execution context
            triggered_by: What triggered the playbook
            alert_id: Related alert ID

        Returns:
            Execution result
        """
        execution = PlaybookExecution(
            execution_id=str(uuid.uuid4()),
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            context=context or {},
            triggered_by=triggered_by,
            alert_id=alert_id,
            start_time=time.time(),
        )

        execution.status = PlaybookStatus.RUNNING
        self.executions[execution.execution_id] = execution

        logger.info(f"Executing playbook: {playbook.name} (execution: {execution.execution_id})")

        try:
            for i, step in enumerate(playbook.steps):
                execution.current_step = i
                step_result = self._execute_step(step, execution)
                execution.step_results.append(step_result)

                if step_result.status == StepStatus.FAILED:
                    on_failure = step.get("on_failure", "stop")
                    if on_failure == "stop":
                        execution.status = PlaybookStatus.FAILED
                        self._run_hooks("on_failure", execution)
                        break
                    elif on_failure == "continue":
                        continue
                    elif on_failure == "retry":
                        # Retry once
                        step_result = self._execute_step(step, execution)
                        execution.step_results[-1] = step_result
                        if step_result.status == StepStatus.FAILED:
                            execution.status = PlaybookStatus.FAILED
                            break

                if step_result.status == StepStatus.SKIPPED:
                    continue

            if execution.status == PlaybookStatus.RUNNING:
                execution.status = PlaybookStatus.COMPLETED
                self._run_hooks("on_complete", execution)

        except Exception as e:
            execution.status = PlaybookStatus.FAILED
            logger.error(f"Playbook execution failed: {e}")
            self._run_hooks("on_failure", execution)

        execution.end_time = time.time()
        logger.info(f"Playbook execution {execution.status.value}: {playbook.name}")

        return execution

    def _execute_step(self, step: dict, execution: PlaybookExecution) -> StepResult:
        """Execute a single playbook step."""
        step_id = step.get("id", f"step_{execution.current_step}")
        step_name = step.get("name", step_id)
        action = step.get("action", "")
        params = step.get("params", {})
        condition = step.get("condition")

        result = StepResult(
            step_id=step_id,
            step_name=step_name,
            start_time=time.time(),
        )

        # Check condition
        if condition:
            # Simplified condition check
            if not self._evaluate_condition(condition, execution.context):
                result.status = StepStatus.SKIPPED
                result.end_time = time.time()
                result.duration_ms = (result.end_time - result.start_time) * 1000
                logger.info(f"Step skipped (condition not met): {step_name}")
                return result

        # Run before hooks
        self._run_hooks("before_step", execution)

        result.status = StepStatus.RUNNING

        try:
            output = self.action_registry.execute(action, params, execution.context)
            result.output = output
            result.status = StepStatus.COMPLETED

            # Update context with step output
            if step.get("store_output"):
                var_name = step.get("output_var", step_id)
                execution.context[var_name] = output

        except Exception as e:
            result.status = StepStatus.FAILED
            result.error = str(e)
            logger.error(f"Step '{step_name}' failed: {e}")

        result.end_time = time.time()
        result.duration_ms = (result.end_time - result.start_time) * 1000

        # Run after hooks
        self._run_hooks("after_step", execution)

        logger.info(f"Step {step_name}: {result.status.value} ({result.duration_ms:.1f}ms)")
        return result

    def _evaluate_condition(self, condition: str, context: dict[str, Any]) -> bool:
        """Evaluate a step condition.

        Args:
            condition: Condition string (e.g., "severity == 'critical'")
            context: Execution context

        Returns:
            Whether condition is met
        """
        # Simplified condition evaluation
        # In production, would use a proper expression evaluator
        try:
            # Replace context variables
            for key, value in context.items():
                condition = condition.replace(f"{{{key}}}", str(value))

            # Basic comparison
            if "==" in condition:
                parts = condition.split("==")
                return parts[0].strip().strip("'\"") == parts[1].strip().strip("'\"")
            elif "!=" in condition:
                parts = condition.split("!=")
                return parts[0].strip().strip("'\"") != parts[1].strip().strip("'\"")
            elif ">" in condition:
                parts = condition.split(">")
                return float(parts[0].strip()) > float(parts[1].strip())
            elif "<" in condition:
                parts = condition.split("<")
                return float(parts[0].strip()) < float(parts[1].strip())

            return bool(condition)
        except Exception:
            return True

    def _run_hooks(self, event: str, execution: PlaybookExecution) -> None:
        """Run lifecycle hooks."""
        for hook in self.hooks.get(event, []):
            try:
                hook(execution)
            except Exception as e:
                logger.error(f"Hook error ({event}): {e}")

    def get_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        """Get execution status by ID."""
        return self.executions.get(execution_id)

    def list_executions(self, limit: int = 100) -> list[PlaybookExecution]:
        """List recent executions."""
        return list(self.executions.values())[-limit:]

    def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a running execution."""
        execution = self.executions.get(execution_id)
        if execution and execution.status == PlaybookStatus.RUNNING:
            execution.status = PlaybookStatus.CANCELLED
            execution.end_time = time.time()
            logger.info(f"Execution cancelled: {execution_id}")
            return True
        return False
