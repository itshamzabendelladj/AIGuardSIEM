"""API client for the SOC console — prefers live gateway, falls back to demo."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

API_BASE = os.getenv("AIGUARD_API_URL", "http://localhost:8080")
DEMO_USER = os.getenv("AIGUARD_DEMO_USER", "admin")
DEMO_PASS = os.getenv("AIGUARD_DEMO_PASS", "admin")

_token_lock = threading.Lock()
_cached_token: Optional[str] = None
_token_expires_at = 0.0


def api_request(method: str, path: str, token: Optional[str] = None, body: Any = None) -> Any:
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{API_BASE}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(req, timeout=2.5) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


def api_login(force: bool = False) -> Optional[str]:
    global _cached_token, _token_expires_at
    with _token_lock:
        if not force and _cached_token and time.time() < _token_expires_at - 30:
            return _cached_token
        try:
            data = api_request(
                "POST",
                "/api/v1/auth/login",
                body={"username": DEMO_USER, "password": DEMO_PASS},
            )
            token = data.get("token")
            if not token:
                return None
            _cached_token = token
            _token_expires_at = time.time() + float(data.get("expires_in") or 3600)
            return token
        except Exception as exc:  # noqa: BLE001
            logger.debug("API login unavailable: %s", exc)
            _cached_token = None
            return None


def _get(path: str, key: str, demo_fn) -> tuple[list[dict[str, Any]], str]:
    token = api_login()
    if not token:
        return demo_fn(), "demo"
    try:
        data = api_request("GET", path, token=token)
        items = data.get(key) or []
        return (items, "api") if items else (demo_fn(), "demo")
    except Exception as exc:  # noqa: BLE001
        logger.debug("GET %s failed: %s", path, exc)
        return demo_fn(), "demo"


def fetch_alerts() -> tuple[list[dict[str, Any]], str]:
    return _get("/api/v1/alerts", "alerts", demo_alerts)


def fetch_events(q: str = "", category: str = "") -> tuple[list[dict[str, Any]], str]:
    params = []
    if q:
        params.append(f"q={urllib.parse.quote(q)}")
    if category and category != "all":
        params.append(f"category={urllib.parse.quote(category)}")
    qs = ("?" + "&".join(params)) if params else ""
    return _get(f"/api/v1/events{qs}", "events", demo_events)


def fetch_cases() -> tuple[list[dict[str, Any]], str]:
    items, source = _get("/api/v1/cases", "cases", demo_cases)
    for c in items:
        if "alert_count" not in c:
            c["alert_count"] = len(c.get("alert_ids") or [])
        if "updated_at" not in c and c.get("UpdatedAt"):
            c["updated_at"] = c["UpdatedAt"]
    return items, source


def fetch_agents() -> tuple[list[dict[str, Any]], str]:
    return _get("/api/v1/agents", "agents", demo_agents)


def fetch_rules() -> tuple[list[dict[str, Any]], str]:
    return _get("/api/v1/rules", "rules", demo_rules)


def fetch_playbooks() -> tuple[list[dict[str, Any]], str]:
    return _get("/api/v1/playbooks", "playbooks", demo_playbooks)


def fetch_services() -> tuple[list[dict[str, Any]], str]:
    return _get("/api/v1/system/services", "services", demo_services)


def fetch_event_agg(field: str = "category") -> tuple[list[dict[str, Any]], str]:
    token = api_login()
    if not token:
        return demo_event_agg(), "demo"
    try:
        data = api_request("POST", "/api/v1/events/aggregate", token=token, body={"field": field})
        buckets = data.get("buckets") or []
        return (buckets, "api") if buckets else (demo_event_agg(), "demo")
    except Exception as exc:  # noqa: BLE001
        logger.debug("aggregate failed: %s", exc)
        return demo_event_agg(), "demo"


def ack_alert(alert_id: str) -> tuple[bool, str]:
    token = api_login()
    if not token:
        return False, "API offline"
    try:
        api_request("POST", f"/api/v1/alerts/{alert_id}/acknowledge", token=token)
        return True, f"Acknowledged {alert_id}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def resolve_alert(alert_id: str, resolution: str = "Resolved from SOC console") -> tuple[bool, str]:
    token = api_login()
    if not token:
        return False, "API offline"
    try:
        api_request(
            "POST",
            f"/api/v1/alerts/{alert_id}/resolve",
            token=token,
            body={"resolution": resolution, "notes": "Closed via dashboard"},
        )
        return True, f"Resolved {alert_id}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def create_case_from_alert(alert: dict[str, Any]) -> tuple[bool, str]:
    token = api_login()
    if not token:
        return False, "API offline"
    body = {
        "title": f"Case: {alert.get('rule_name') or alert.get('id')}",
        "description": alert.get("description") or "Opened from SOC console",
        "severity": alert.get("severity") or "medium",
        "assigned_to": DEMO_USER,
        "alert_ids": [alert.get("id")],
        "tags": alert.get("tags") or ["dashboard"],
    }
    try:
        created = api_request("POST", "/api/v1/cases", token=token, body=body)
        return True, f"Opened case {created.get('id')}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def set_agent_isolation(agent_id: str, isolate: bool) -> tuple[bool, str]:
    token = api_login()
    if not token:
        return False, "API offline"
    action = "isolate" if isolate else "unisolate"
    try:
        data = api_request("POST", f"/api/v1/agents/{agent_id}/{action}", token=token)
        return True, f"{agent_id} → {data.get('status')}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def execute_playbook(playbook_id: str) -> tuple[bool, str]:
    token = api_login()
    if not token:
        return False, "API offline"
    try:
        data = api_request("POST", f"/api/v1/playbooks/{playbook_id}/execute", token=token)
        return True, f"Started {data.get('name') or playbook_id} ({data.get('status')})"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def reload_rules() -> tuple[bool, str]:
    token = api_login()
    if not token:
        return False, "API offline"
    try:
        data = api_request("POST", "/api/v1/rules/reload", token=token)
        return True, data.get("message") or "Rules reloaded"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def health_ping() -> bool:
    try:
        api_request("GET", "/health")
        return True
    except Exception:  # noqa: BLE001
        return False


# --- Demo fallbacks (same shape as API) ---

def demo_alerts() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {"id": "alt-ssh-001", "severity": "high", "rule_name": "SSH Brute Force Attack", "source_ip": "203.0.113.45", "host_name": "bastion-01", "status": "open", "mitre_technique": "T1110", "timestamp": (now - timedelta(minutes=12)).isoformat()},
        {"id": "alt-scan-002", "severity": "medium", "rule_name": "Port Scan Detected", "source_ip": "198.51.100.10", "host_name": "fw-edge-01", "status": "open", "mitre_technique": "T1046", "timestamp": (now - timedelta(minutes=45)).isoformat()},
        {"id": "alt-ps-003", "severity": "critical", "rule_name": "Encoded PowerShell Command", "source_ip": "10.0.3.88", "host_name": "ws-finance-14", "status": "acknowledged", "mitre_technique": "T1059.001", "timestamp": (now - timedelta(hours=2)).isoformat()},
    ]


def demo_events() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {"id": "evt-1000", "timestamp": (now - timedelta(minutes=3)).isoformat(), "category": "authentication", "action": "ssh_login_failed", "source_ip": "203.0.113.45", "host_name": "bastion-01", "severity": "high", "source_type": "syslog"},
        {"id": "evt-1001", "timestamp": (now - timedelta(minutes=6)).isoformat(), "category": "network", "action": "port_scan", "source_ip": "198.51.100.10", "host_name": "fw-edge-01", "severity": "medium", "source_type": "network"},
        {"id": "evt-1002", "timestamp": (now - timedelta(minutes=9)).isoformat(), "category": "process", "action": "powershell_encoded", "source_ip": "10.0.3.88", "host_name": "ws-finance-14", "severity": "critical", "source_type": "endpoint"},
    ]


def demo_cases() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {"id": "CASE-1042", "title": "Suspected credential stuffing on bastion", "severity": "high", "status": "investigating", "assigned_to": "analyst", "alert_ids": ["alt-ssh-001"], "alert_count": 1, "updated_at": (now - timedelta(minutes=18)).isoformat()},
        {"id": "CASE-1041", "title": "Encoded PowerShell on finance workstation", "severity": "critical", "status": "open", "assigned_to": "admin", "alert_ids": ["alt-ps-003"], "alert_count": 1, "updated_at": (now - timedelta(hours=1)).isoformat()},
    ]


def demo_agents() -> list[dict[str, Any]]:
    return [
        {"id": "ag-01", "hostname": "bastion-01", "os": "Linux", "version": "1.0.4", "status": "active"},
        {"id": "ag-05", "hostname": "build-agent-2", "os": "Linux", "version": "1.0.2", "status": "isolated"},
    ]


def demo_rules() -> list[dict[str, Any]]:
    return [
        {"id": "ssh-brute-force", "name": "SSH Brute Force Attack", "severity": "high", "status": "active", "type": "sigma", "mitre_technique": "T1110"},
        {"id": "powershell-encoded", "name": "Encoded PowerShell Command", "severity": "critical", "status": "active", "type": "sigma", "mitre_technique": "T1059.001"},
    ]


def demo_playbooks() -> list[dict[str, Any]]:
    return [
        {"id": "isolate-compromised-host", "name": "Isolate Compromised Host", "description": "Block traffic and collect evidence", "enabled": True, "tags": ["host-isolation"]},
        {"id": "investigate-phishing", "name": "Investigate Phishing", "description": "Enrich and notify", "enabled": True, "tags": ["phishing"]},
    ]


def demo_services() -> list[dict[str, Any]]:
    return [
        {"name": "api-gateway", "port": 8080, "status": "registered", "health": "healthy"},
        {"name": "stream-processor", "port": 9090, "status": "registered", "health": "healthy"},
        {"name": "ml-inference", "port": 9092, "status": "registered", "health": "degraded"},
    ]


def demo_event_agg() -> list[dict[str, Any]]:
    return [
        {"key": "authentication", "count": 2},
        {"key": "network", "count": 2},
        {"key": "process", "count": 2},
        {"key": "dns", "count": 1},
        {"key": "file", "count": 1},
    ]
