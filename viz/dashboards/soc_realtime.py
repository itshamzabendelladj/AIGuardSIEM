"""AIGuardSIEM SOC Console — multi-page operations dashboard with sidebar."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import numpy as np

logger = logging.getLogger(__name__)

try:
    import dash
    from dash import dcc, html, Input, Output, State, ALL, ctx, no_update
    import plotly.graph_objects as go

    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False


API_BASE = os.getenv("AIGUARD_API_URL", "http://localhost:8080")
DEMO_USER = os.getenv("AIGUARD_DEMO_USER", "admin")
DEMO_PASS = os.getenv("AIGUARD_DEMO_PASS", "admin")

_RNG = np.random.default_rng(42)
_EPS_BASE = _RNG.integers(42000, 52000, size=30).astype(float)

PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="IBM Plex Sans, Segoe UI, sans-serif", color="#3d4a5c", size=12),
    margin=dict(l=48, r=20, t=12, b=40),
    hoverlabel=dict(bgcolor="#121a24", font_size=12, font_family="IBM Plex Sans"),
)

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#0369a1",
    "info": "#6b7a8d",
}

PAGES = {
    "/": ("Overview", "Live detection posture and pipeline health"),
    "/alerts": ("Alerts", "Triage, filter, and acknowledge detections"),
    "/events": ("Events", "Normalized security event stream"),
    "/cases": ("Cases", "Incident response caseboard"),
    "/mitre": ("MITRE ATT&CK", "Technique coverage and hit density"),
    "/agents": ("Agents", "Endpoint XDR agent inventory"),
    "/system": ("System", "Service registry and platform status"),
    "/settings": ("Settings", "Console and API configuration"),
}

NAV = [
    ("OPERATIONS", [
        ("/", "01", "Overview"),
        ("/alerts", "02", "Alerts"),
        ("/events", "03", "Events"),
        ("/cases", "04", "Cases"),
    ]),
    ("INTEL", [
        ("/mitre", "05", "MITRE"),
        ("/agents", "06", "Agents"),
    ]),
    ("PLATFORM", [
        ("/system", "07", "System"),
        ("/settings", "08", "Settings"),
    ]),
]


# ---------------------------------------------------------------------------
# API / demo data helpers
# ---------------------------------------------------------------------------

def _api_request(method: str, path: str, token: Optional[str] = None, body: Any = None) -> Any:
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


def _api_login() -> Optional[str]:
    try:
        data = _api_request("POST", "/api/v1/auth/login", body={"username": DEMO_USER, "password": DEMO_PASS})
        return data.get("token")
    except Exception as exc:  # noqa: BLE001
        logger.debug("API login unavailable: %s", exc)
        return None


def _fetch_alerts() -> tuple[list[dict[str, Any]], str]:
    token = _api_login()
    if not token:
        return _demo_alerts(), "demo"
    try:
        data = _api_request("GET", "/api/v1/alerts", token=token)
        alerts = data.get("alerts") or []
        return (alerts, "api") if alerts else (_demo_alerts(), "demo")
    except Exception as exc:  # noqa: BLE001
        logger.debug("API alerts unavailable: %s", exc)
        return _demo_alerts(), "demo"


def _fetch_services() -> tuple[list[dict[str, Any]], str]:
    token = _api_login()
    if not token:
        return _demo_services(), "demo"
    try:
        data = _api_request("GET", "/api/v1/system/services", token=token)
        services = data.get("services") or []
        return (services, "api") if services else (_demo_services(), "demo")
    except Exception as exc:  # noqa: BLE001
        logger.debug("API services unavailable: %s", exc)
        return _demo_services(), "demo"


def _ack_alert(alert_id: str) -> bool:
    token = _api_login()
    if not token:
        return False
    try:
        _api_request("POST", f"/api/v1/alerts/{alert_id}/acknowledge", token=token)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.debug("Ack failed: %s", exc)
        return False


def _demo_alerts() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "demo-ssh-001",
            "severity": "high",
            "rule_name": "SSH Brute Force Attack",
            "source_ip": "203.0.113.45",
            "host_name": "bastion-01",
            "user_name": "root",
            "status": "open",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110",
            "timestamp": (now - timedelta(minutes=12)).isoformat(),
        },
        {
            "id": "demo-scan-002",
            "severity": "medium",
            "rule_name": "Port Scan Detected",
            "source_ip": "198.51.100.10",
            "host_name": "fw-edge-01",
            "user_name": "",
            "status": "open",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1046",
            "timestamp": (now - timedelta(minutes=45)).isoformat(),
        },
        {
            "id": "demo-ps-003",
            "severity": "critical",
            "rule_name": "Encoded PowerShell Command",
            "source_ip": "10.0.3.88",
            "host_name": "ws-finance-14",
            "user_name": "jdoe",
            "status": "acknowledged",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059.001",
            "timestamp": (now - timedelta(hours=2)).isoformat(),
        },
        {
            "id": "demo-dns-004",
            "severity": "high",
            "rule_name": "Suspicious DNS Tunneling",
            "source_ip": "10.0.5.21",
            "host_name": "dev-laptop-09",
            "user_name": "asmith",
            "status": "open",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1048",
            "timestamp": (now - timedelta(minutes=8)).isoformat(),
        },
        {
            "id": "demo-lat-005",
            "severity": "medium",
            "rule_name": "Lateral Movement via RDP",
            "source_ip": "10.0.2.15",
            "host_name": "dc-01",
            "user_name": "svc_backup",
            "status": "open",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1021.001",
            "timestamp": (now - timedelta(minutes=33)).isoformat(),
        },
    ]


def _demo_events() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    rows = []
    samples = [
        ("authentication", "ssh_login_failed", "203.0.113.45", "bastion-01", "high"),
        ("network", "port_scan", "198.51.100.10", "fw-edge-01", "medium"),
        ("process", "powershell_encoded", "10.0.3.88", "ws-finance-14", "critical"),
        ("dns", "suspicious_query", "10.0.5.21", "dev-laptop-09", "high"),
        ("authentication", "rdp_login", "10.0.2.15", "dc-01", "medium"),
        ("file", "sensitive_file_access", "10.0.8.44", "fileserver-02", "low"),
        ("network", "egress_spike", "10.0.5.21", "proxy-01", "medium"),
        ("process", "rare_binary", "10.0.9.3", "build-agent-2", "high"),
    ]
    for i, (cat, action, sip, host, sev) in enumerate(samples):
        rows.append(
            {
                "id": f"evt-{1000 + i}",
                "timestamp": (now - timedelta(minutes=3 * i)).isoformat(),
                "category": cat,
                "action": action,
                "source_ip": sip,
                "host_name": host,
                "severity": sev,
                "source_type": "syslog" if i % 2 == 0 else "endpoint",
            }
        )
    return rows


def _demo_cases() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "CASE-1042",
            "title": "Suspected credential stuffing on bastion",
            "severity": "high",
            "status": "investigating",
            "assigned_to": "analyst",
            "alert_count": 12,
            "updated_at": (now - timedelta(minutes=18)).isoformat(),
        },
        {
            "id": "CASE-1041",
            "title": "Encoded PowerShell on finance workstation",
            "severity": "critical",
            "status": "open",
            "assigned_to": "admin",
            "alert_count": 3,
            "updated_at": (now - timedelta(hours=1)).isoformat(),
        },
        {
            "id": "CASE-1038",
            "title": "Outbound DNS anomaly cluster",
            "severity": "medium",
            "status": "contained",
            "assigned_to": "analyst",
            "alert_count": 7,
            "updated_at": (now - timedelta(hours=5)).isoformat(),
        },
    ]


def _demo_agents() -> list[dict[str, Any]]:
    return [
        {"id": "ag-01", "hostname": "bastion-01", "os": "Linux", "version": "1.0.4", "status": "active"},
        {"id": "ag-02", "hostname": "ws-finance-14", "os": "Windows", "version": "1.0.4", "status": "active"},
        {"id": "ag-03", "hostname": "dc-01", "os": "Windows", "version": "1.0.3", "status": "active"},
        {"id": "ag-04", "hostname": "dev-laptop-09", "os": "macOS", "version": "1.0.4", "status": "active"},
        {"id": "ag-05", "hostname": "build-agent-2", "os": "Linux", "version": "1.0.2", "status": "isolated"},
        {"id": "ag-06", "hostname": "fileserver-02", "os": "Linux", "version": "1.0.4", "status": "active"},
    ]


def _demo_services() -> list[dict[str, Any]]:
    return [
        {"name": "api-gateway", "port": 8080, "status": "registered", "health": "healthy"},
        {"name": "syslog-collector", "port": 514, "status": "registered", "health": "healthy"},
        {"name": "stream-processor", "port": 9090, "status": "registered", "health": "healthy"},
        {"name": "ml-inference", "port": 9092, "status": "registered", "health": "degraded"},
        {"name": "soar-engine", "port": 9096, "status": "registered", "health": "healthy"},
    ]


def _fmt_time(value: Any) -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return value[:19]
    return str(value)


def _apply_chart_style(fig: go.Figure, height: int = 300) -> go.Figure:
    fig.update_layout(height=height, **PLOT_LAYOUT)
    fig.update_xaxes(showgrid=True, gridcolor="#e8edf2", zeroline=False, linecolor="#d5dde7")
    fig.update_yaxes(showgrid=True, gridcolor="#e8edf2", zeroline=False, linecolor="#d5dde7")
    return fig


def _kpi(value_id: str, label: str, hint: str, tone: str = "") -> html.Div:
    classes = "kpi" + (f" {tone}" if tone else "")
    return html.Div(
        [
            html.P(label, className="kpi-label"),
            html.P("—", id=value_id, className="kpi-value"),
            html.P(hint, className="kpi-hint"),
        ],
        className=classes,
    )


def _sev_badge(sev: str) -> html.Span:
    key = (sev or "info").lower()
    cls = f"sev sev-{key}" if key in SEVERITY_COLORS else "sev sev-info"
    return html.Span((sev or "info").upper(), className=cls)


def _table(headers: list[str], rows: list[html.Tr]) -> html.Table:
    head = html.Tr([html.Th(h) for h in headers])
    if not rows:
        rows = [html.Tr([html.Td("No data", colSpan=len(headers), className="empty-state")])]
    return html.Table([head] + rows, className="alerts-table")


# ---------------------------------------------------------------------------
# Dashboard app
# ---------------------------------------------------------------------------

if DASH_AVAILABLE:

    class SOCRealtimeDashboard:
        def __init__(
            self,
            title: str = "AIGuardSIEM — SOC Console",
            host: str = "0.0.0.0",
            port: int = 8050,
            refresh_interval: int = 5000,
        ) -> None:
            assets = os.path.join(os.path.dirname(__file__), "assets")
            self.app = dash.Dash(
                __name__,
                title=title,
                assets_folder=assets,
                suppress_callback_exceptions=True,
                meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}],
            )
            self.app.index_string = """<!DOCTYPE html>
<html>
  <head>
    {%metas%}
    <title>{%title%}</title>
    {%favicon%}
    {%css%}
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&family=Sora:wght@500;600;700&display=swap" rel="stylesheet">
  </head>
  <body>
    {%app_entry%}
    <footer>{%config%}{%scripts%}{%renderer%}</footer>
  </body>
</html>"""
            self.host = host
            self.port = port
            self.refresh_interval = refresh_interval
            self._setup_layout()
            self._setup_callbacks()

        def _nav(self) -> list:
            items: list = []
            for section, links in NAV:
                items.append(html.P(section, className="nav-section-label"))
                for href, ico, label in links:
                    children = [
                        html.Span(ico, className="nav-ico"),
                        html.Span(label, className="label"),
                    ]
                    if href == "/alerts":
                        children.append(html.Span("0", id="nav-alert-badge", className="nav-badge"))
                    items.append(
                        dcc.Link(children, href=href, className="nav-link", id={"type": "nav", "href": href})
                    )
            return items

        def _setup_layout(self) -> None:
            self.app.layout = html.Div(
                [
                    dcc.Location(id="url", refresh=False),
                    dcc.Interval(id="refresh-interval", interval=self.refresh_interval),
                    dcc.Store(id="ack-toast"),
                    html.Div(
                        [
                            html.Aside(
                                [
                                    html.Div(
                                        [
                                            html.H1(["AIGuard", html.Span("SIEM")], className="sidebar-brand-mark"),
                                            html.P("SOC Console", className="sidebar-brand-sub"),
                                        ],
                                        className="sidebar-brand",
                                    ),
                                    html.Nav(self._nav(), className="sidebar-nav"),
                                    html.Div(className="sidebar-spacer"),
                                    html.Div(
                                        [
                                            html.P(DEMO_USER, className="sidebar-user-name"),
                                            html.P("Analyst session", className="sidebar-user-role"),
                                        ],
                                        className="sidebar-user",
                                    ),
                                ],
                                className="sidebar",
                            ),
                            html.Div(
                                [
                                    html.Header(
                                        [
                                            html.Div(
                                                [
                                                    html.H2(id="page-title", className="page-title"),
                                                    html.P(id="page-subtitle", className="page-subtitle"),
                                                ],
                                                className="topbar-left",
                                            ),
                                            html.Div(
                                                [
                                                    dcc.Input(
                                                        id="global-search",
                                                        type="text",
                                                        placeholder="Search hosts, IPs, rules…",
                                                        className="search-box",
                                                        debounce=True,
                                                    ),
                                                    html.Div(
                                                        [
                                                            html.Span(id="source-dot", className="live-dot demo"),
                                                            html.Span(id="source-label", children="…"),
                                                        ],
                                                        className="live-pill",
                                                    ),
                                                    html.Div(id="clock", className="clock"),
                                                ],
                                                className="topbar-right",
                                            ),
                                        ],
                                        className="topbar",
                                    ),
                                    html.Main(
                                        [
                                            self._page_overview(),
                                            self._page_alerts(),
                                            self._page_events(),
                                            self._page_cases(),
                                            self._page_mitre(),
                                            self._page_agents(),
                                            self._page_system(),
                                            self._page_settings(),
                                            html.Footer(
                                                [
                                                    html.Span("AIGuardSIEM v1.0 · SOC Console"),
                                                    html.Span("Synthetic panels labeled demo · alerts prefer live API"),
                                                ],
                                                className="soc-footer",
                                            ),
                                        ],
                                        className="content",
                                    ),
                                ],
                                className="main-col",
                            ),
                        ],
                        className="app-shell",
                    ),
                ]
            )

        def _page_overview(self) -> html.Div:
            return html.Div(
                [
                    html.Div(
                        [
                            _kpi("kpi-eps", "Events / sec", "Ingest throughput"),
                            _kpi("kpi-alerts", "Active alerts", "Open + acknowledged", "warn"),
                            _kpi("kpi-critical", "Critical", "Needs immediate review", "crit"),
                            _kpi("kpi-latency", "P99 latency", "Detection pipeline", "ok"),
                        ],
                        className="kpi-strip",
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Event volume", className="panel-title"),
                                            html.P("Last 30 minutes · demo stream", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    dcc.Graph(id="events-time-chart", config={"displayModeBar": False}),
                                ],
                                className="panel",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Severity mix", className="panel-title"),
                                            html.P("From current alert set", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    dcc.Graph(id="severity-pie-chart", config={"displayModeBar": False}),
                                ],
                                className="panel",
                            ),
                        ],
                        className="panel-grid",
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Priority queue", className="panel-title"),
                                            html.P("Top open alerts", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    html.Div(id="overview-alert-table", className="table-wrap"),
                                ],
                                className="panel pad-more",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Top source IPs", className="panel-title"),
                                            html.P("Demo stream", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    dcc.Graph(id="top-source-ips", config={"displayModeBar": False}),
                                ],
                                className="panel",
                            ),
                        ],
                        className="panel-grid",
                    ),
                ],
                id="page-overview",
                className="page active",
            )

        def _page_alerts(self) -> html.Div:
            return html.Div(
                [
                    html.Div(id="alerts-source"),
                    html.Div(
                        [
                            dcc.Dropdown(
                                id="alert-severity-filter",
                                options=[
                                    {"label": "All severities", "value": "all"},
                                    {"label": "Critical", "value": "critical"},
                                    {"label": "High", "value": "high"},
                                    {"label": "Medium", "value": "medium"},
                                    {"label": "Low", "value": "low"},
                                ],
                                value="all",
                                clearable=False,
                                style={"width": "180px"},
                            ),
                            dcc.Dropdown(
                                id="alert-status-filter",
                                options=[
                                    {"label": "All statuses", "value": "all"},
                                    {"label": "Open", "value": "open"},
                                    {"label": "Acknowledged", "value": "acknowledged"},
                                    {"label": "Resolved", "value": "resolved"},
                                ],
                                value="all",
                                clearable=False,
                                style={"width": "180px"},
                            ),
                            html.Button("Refresh", id="alerts-refresh-btn", className="btn"),
                        ],
                        className="toolbar",
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Alert inbox", className="panel-title"),
                                            html.P(id="alerts-count-label", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    html.Div(id="alerts-table", className="table-wrap"),
                                    html.Div(id="ack-feedback", style={"marginTop": "0.75rem", "fontSize": "0.8rem"}),
                                ],
                                className="panel pad-more",
                            )
                        ],
                        className="panel-full",
                    ),
                ],
                id="page-alerts",
                className="page",
            )

        def _page_events(self) -> html.Div:
            return html.Div(
                [
                    html.Div(
                        [
                            dcc.Input(
                                id="event-query",
                                type="text",
                                placeholder="Filter by host, IP, action…",
                                className="search-box",
                                style={"width": "280px"},
                                debounce=True,
                            ),
                            dcc.Dropdown(
                                id="event-category-filter",
                                options=[
                                    {"label": "All categories", "value": "all"},
                                    {"label": "Authentication", "value": "authentication"},
                                    {"label": "Network", "value": "network"},
                                    {"label": "Process", "value": "process"},
                                    {"label": "DNS", "value": "dns"},
                                    {"label": "File", "value": "file"},
                                ],
                                value="all",
                                clearable=False,
                                style={"width": "200px"},
                            ),
                        ],
                        className="toolbar",
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("Event stream", className="panel-title"),
                                    html.P("Normalized ECS-style demo events", className="panel-caption"),
                                ],
                                className="panel-head",
                            ),
                            html.Div(id="events-table", className="table-wrap"),
                        ],
                        className="panel pad-more panel-full",
                    ),
                ],
                id="page-events",
                className="page",
            )

        def _page_cases(self) -> html.Div:
            return html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [html.H3("Open", className=""), html.P("0", id="case-stat-open")],
                                className="stat-card",
                            ),
                            html.Div(
                                [html.H3("Investigating", className=""), html.P("0", id="case-stat-invest")],
                                className="stat-card",
                            ),
                            html.Div(
                                [html.H3("Contained", className=""), html.P("0", id="case-stat-contained")],
                                className="stat-card",
                            ),
                        ],
                        className="stat-cards",
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("Caseboard", className="panel-title"),
                                    html.P("Incident response tracking", className="panel-caption"),
                                ],
                                className="panel-head",
                            ),
                            html.Div(id="cases-table", className="table-wrap"),
                        ],
                        className="panel pad-more panel-full",
                    ),
                ],
                id="page-cases",
                className="page",
            )

        def _page_mitre(self) -> html.Div:
            return html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("ATT&CK heatmap", className="panel-title"),
                                    html.P("Technique hit density · demo matrix", className="panel-caption"),
                                ],
                                className="panel-head",
                            ),
                            dcc.Graph(id="mitre-heatmap", config={"displayModeBar": False}),
                        ],
                        className="panel panel-full",
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Threat geography", className="panel-title"),
                                            html.P("Illustrative regions", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    dcc.Graph(id="threat-map", config={"displayModeBar": False}),
                                ],
                                className="panel",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Top techniques", className="panel-title"),
                                            html.P("From current alerts", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    html.Div(id="mitre-technique-list", className="table-wrap"),
                                ],
                                className="panel pad-more",
                            ),
                        ],
                        className="panel-grid equal",
                    ),
                ],
                id="page-mitre",
                className="page",
            )

        def _page_agents(self) -> html.Div:
            return html.Div(
                [
                    html.Div(id="agents-grid", className="agent-grid"),
                ],
                id="page-agents",
                className="page",
            )

        def _page_system(self) -> html.Div:
            return html.Div(
                [
                    html.Div(id="system-source"),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Service health", className="panel-title"),
                                            html.P("Registered platform services", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    dcc.Graph(id="system-health", config={"displayModeBar": False}),
                                ],
                                className="panel",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Service registry", className="panel-title"),
                                            html.P("Name · port · health", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    html.Div(id="services-table", className="table-wrap"),
                                ],
                                className="panel pad-more",
                            ),
                        ],
                        className="panel-grid equal",
                    ),
                ],
                id="page-system",
                className="page",
            )

        def _page_settings(self) -> html.Div:
            return html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("Console settings", className="panel-title"),
                                    html.P("Read-only demo configuration", className="panel-caption"),
                                ],
                                className="panel-head",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [html.Label("API base URL"), html.Code(API_BASE)],
                                        className="settings-row",
                                    ),
                                    html.Div(
                                        [html.Label("Demo user"), html.Code(DEMO_USER)],
                                        className="settings-row",
                                    ),
                                    html.Div(
                                        [html.Label("Refresh interval"), html.Code(f"{self.refresh_interval} ms")],
                                        className="settings-row",
                                    ),
                                    html.Div(
                                        [
                                            html.Label("Auth"),
                                            html.Code("JWT via /api/v1/auth/login"),
                                        ],
                                        className="settings-row",
                                    ),
                                    html.Div(
                                        [
                                            html.Label("Data policy"),
                                            html.Code("Live alerts when API is up; else local demo"),
                                        ],
                                        className="settings-row",
                                    ),
                                ],
                                className="settings-list",
                            ),
                        ],
                        className="panel pad-more panel-full",
                    )
                ],
                id="page-settings",
                className="page",
            )

        def _setup_callbacks(self) -> None:
            page_ids = [
                "page-overview",
                "page-alerts",
                "page-events",
                "page-cases",
                "page-mitre",
                "page-agents",
                "page-system",
                "page-settings",
            ]
            path_to_page = {
                "/": "page-overview",
                "/alerts": "page-alerts",
                "/events": "page-events",
                "/cases": "page-cases",
                "/mitre": "page-mitre",
                "/agents": "page-agents",
                "/system": "page-system",
                "/settings": "page-settings",
            }

            @self.app.callback(
                [Output(pid, "className") for pid in page_ids]
                + [
                    Output("page-title", "children"),
                    Output("page-subtitle", "children"),
                    Output({"type": "nav", "href": ALL}, "className"),
                ],
                Input("url", "pathname"),
            )
            def route(pathname: str):
                pathname = pathname or "/"
                if pathname not in path_to_page:
                    pathname = "/"
                title, subtitle = PAGES[pathname]
                classes = ["page active" if path_to_page[pathname] == pid else "page" for pid in page_ids]
                nav_hrefs = [href for _, links in NAV for href, _, _ in links]
                nav_classes = ["nav-link active" if href == pathname else "nav-link" for href in nav_hrefs]
                return classes + [title, subtitle, nav_classes]

            @self.app.callback(
                [
                    Output("kpi-eps", "children"),
                    Output("kpi-alerts", "children"),
                    Output("kpi-critical", "children"),
                    Output("kpi-latency", "children"),
                    Output("source-label", "children"),
                    Output("source-dot", "className"),
                    Output("clock", "children"),
                    Output("nav-alert-badge", "children"),
                    Output("overview-alert-table", "children"),
                    Output("severity-pie-chart", "figure"),
                    Output("alerts-source", "children"),
                    Output("alerts-table", "children"),
                    Output("alerts-count-label", "children"),
                    Output("mitre-technique-list", "children"),
                ],
                [
                    Input("refresh-interval", "n_intervals"),
                    Input("alert-severity-filter", "value"),
                    Input("alert-status-filter", "value"),
                    Input("alerts-refresh-btn", "n_clicks"),
                    Input("global-search", "value"),
                ],
            )
            def update_alert_driven(n, sev_filter, status_filter, _refresh, search):
                alerts, source = _fetch_alerts()
                search = (search or "").strip().lower()

                openish = [
                    a
                    for a in alerts
                    if str(a.get("status", "open")).lower() in ("open", "acknowledged", "")
                ]
                critical = [a for a in alerts if str(a.get("severity", "")).lower() == "critical"]

                global _EPS_BASE
                _EPS_BASE = np.clip(_EPS_BASE + _RNG.normal(0, 400, size=_EPS_BASE.shape), 35000, 65000)
                eps = int(_EPS_BASE[-1])
                latency = f"{_RNG.uniform(2.1, 6.8):.1f} ms"

                is_api = source == "api"
                label = "LIVE · API" if is_api else "DEMO DATA"
                dot = "live-dot" if is_api else "live-dot demo"
                clock = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
                badge = str(len([a for a in alerts if str(a.get("status", "")).lower() == "open"]))

                overview_rows = []
                for a in sorted(openish, key=lambda x: str(x.get("severity")), reverse=True)[:5]:
                    overview_rows.append(
                        html.Tr(
                            [
                                html.Td(_sev_badge(str(a.get("severity", "")))),
                                html.Td(a.get("rule_name") or "—"),
                                html.Td(a.get("source_ip") or "—", className="mono"),
                                html.Td(a.get("host_name") or "—"),
                                html.Td(_fmt_time(a.get("timestamp"))[-8:], className="mono"),
                            ]
                        )
                    )
                overview_table = _table(["Sev", "Rule", "Source", "Host", "Time"], overview_rows)

                filtered = alerts
                if sev_filter and sev_filter != "all":
                    filtered = [a for a in filtered if str(a.get("severity", "")).lower() == sev_filter]
                if status_filter and status_filter != "all":
                    filtered = [a for a in filtered if str(a.get("status", "")).lower() == status_filter]
                if search:
                    filtered = [
                        a
                        for a in filtered
                        if search in json.dumps(a).lower()
                    ]

                banner = html.Div(
                    "Connected to API gateway."
                    if is_api
                    else "API offline — demo alerts. Start with: go run ./api",
                    className="source-banner" + ("" if is_api else " demo"),
                )

                alert_rows = []
                for a in filtered:
                    aid = str(a.get("id", ""))
                    alert_rows.append(
                        html.Tr(
                            [
                                html.Td(aid[:14], className="mono"),
                                html.Td(_sev_badge(str(a.get("severity", "")))),
                                html.Td(a.get("rule_name") or "—"),
                                html.Td(a.get("source_ip") or "—", className="mono"),
                                html.Td(a.get("host_name") or "—"),
                                html.Td(a.get("mitre_technique") or "—", className="mono"),
                                html.Td(str(a.get("status", "open")), className="status-chip"),
                                html.Td(_fmt_time(a.get("timestamp"))[-8:], className="mono"),
                                html.Td(
                                    html.Button(
                                        "Ack",
                                        id={"type": "ack-btn", "index": aid},
                                        className="btn btn-ghost",
                                        n_clicks=0,
                                        disabled=str(a.get("status", "")).lower() != "open",
                                    )
                                ),
                            ]
                        )
                    )
                alerts_table = _table(
                    ["ID", "Severity", "Rule", "Source", "Host", "MITRE", "Status", "Time", ""],
                    alert_rows,
                )

                tech_counts: dict[str, int] = {}
                for a in alerts:
                    t = str(a.get("mitre_technique") or "—")
                    tech_counts[t] = tech_counts.get(t, 0) + 1
                tech_rows = [
                    html.Tr([html.Td(k, className="mono"), html.Td(str(v))])
                    for k, v in sorted(tech_counts.items(), key=lambda kv: kv[1], reverse=True)
                ]
                tech_table = _table(["Technique", "Hits"], tech_rows)

                return (
                    f"{eps:,}",
                    str(len(openish)),
                    str(len(critical)),
                    latency,
                    label,
                    dot,
                    clock,
                    badge,
                    overview_table,
                    self._severity_figure(alerts),
                    banner,
                    alerts_table,
                    f"{len(filtered)} shown · {len(alerts)} total",
                    tech_table,
                )

            @self.app.callback(
                Output("ack-feedback", "children"),
                Input({"type": "ack-btn", "index": ALL}, "n_clicks"),
                prevent_initial_call=True,
            )
            def acknowledge(n_clicks_list):
                if not n_clicks_list or not any(n_clicks_list):
                    return no_update
                triggered = ctx.triggered_id
                if not triggered:
                    return no_update
                alert_id = triggered.get("index")
                ok = _ack_alert(alert_id)
                if ok:
                    return html.Span(f"Acknowledged {alert_id}", style={"color": "#15803d"})
                return html.Span(
                    f"Could not ack {alert_id} (API offline or already handled)",
                    style={"color": "#b45309"},
                )

            @self.app.callback(
                Output("events-time-chart", "figure"),
                Input("refresh-interval", "n_intervals"),
            )
            def events_chart(_n):
                now = datetime.now()
                times = [now - timedelta(minutes=30 - i) for i in range(30)]
                fig = go.Figure(
                    go.Scatter(
                        x=times,
                        y=_EPS_BASE.tolist(),
                        mode="lines",
                        fill="tozeroy",
                        line=dict(color="#0f6b6b", width=2.5),
                        fillcolor="rgba(15,107,107,0.12)",
                    )
                )
                fig.update_layout(showlegend=False, yaxis_title="Events/sec")
                return _apply_chart_style(fig, 280)

            @self.app.callback(
                Output("top-source-ips", "figure"),
                Input("refresh-interval", "n_intervals"),
            )
            def top_sources(_n):
                ips = ["203.0.113.45", "198.51.100.10", "10.0.3.88", "192.0.2.77", "10.0.1.14", "172.16.4.9"]
                counts = [c + int(_RNG.integers(-60, 60)) for c in [4200, 3100, 2800, 1900, 1500, 1200]]
                fig = go.Figure(go.Bar(x=counts, y=ips, orientation="h", marker_color="#0f6b6b"))
                fig.update_layout(yaxis=dict(autorange="reversed"), showlegend=False, xaxis_title="Events")
                return _apply_chart_style(fig, 280)

            @self.app.callback(
                Output("events-table", "children"),
                [
                    Input("refresh-interval", "n_intervals"),
                    Input("event-query", "value"),
                    Input("event-category-filter", "value"),
                    Input("global-search", "value"),
                ],
            )
            def events_table(_n, query, category, global_search):
                events = _demo_events()
                q = ((query or "") + " " + (global_search or "")).strip().lower()
                if category and category != "all":
                    events = [e for e in events if e.get("category") == category]
                if q.strip():
                    events = [e for e in events if q.strip() in json.dumps(e).lower()]
                rows = [
                    html.Tr(
                        [
                            html.Td(e["id"], className="mono"),
                            html.Td(_sev_badge(e["severity"])),
                            html.Td(e["category"]),
                            html.Td(e["action"], className="mono"),
                            html.Td(e["source_ip"], className="mono"),
                            html.Td(e["host_name"]),
                            html.Td(e["source_type"]),
                            html.Td(_fmt_time(e["timestamp"])[-8:], className="mono"),
                        ]
                    )
                    for e in events
                ]
                return _table(
                    ["ID", "Sev", "Category", "Action", "Source", "Host", "Type", "Time"],
                    rows,
                )

            @self.app.callback(
                [
                    Output("cases-table", "children"),
                    Output("case-stat-open", "children"),
                    Output("case-stat-invest", "children"),
                    Output("case-stat-contained", "children"),
                ],
                Input("refresh-interval", "n_intervals"),
            )
            def cases_page(_n):
                cases = _demo_cases()
                rows = [
                    html.Tr(
                        [
                            html.Td(c["id"], className="mono"),
                            html.Td(_sev_badge(c["severity"])),
                            html.Td(c["title"]),
                            html.Td(c["status"], className="status-chip"),
                            html.Td(c["assigned_to"]),
                            html.Td(str(c["alert_count"])),
                            html.Td(_fmt_time(c["updated_at"])[-8:], className="mono"),
                        ]
                    )
                    for c in cases
                ]
                return (
                    _table(["ID", "Sev", "Title", "Status", "Owner", "Alerts", "Updated"], rows),
                    str(sum(1 for c in cases if c["status"] == "open")),
                    str(sum(1 for c in cases if c["status"] == "investigating")),
                    str(sum(1 for c in cases if c["status"] == "contained")),
                )

            @self.app.callback(
                Output("mitre-heatmap", "figure"),
                Input("refresh-interval", "n_intervals"),
            )
            def mitre_heatmap(_n):
                tactics = [
                    "Initial Access", "Execution", "Persistence", "Priv Esc",
                    "Defense Evasion", "Cred Access", "Discovery", "Lateral",
                    "Collection", "C2", "Exfil", "Impact",
                ]
                techniques = [f"T1{i:03d}" for i in range(10)]
                base = np.array(
                    [
                        [2, 0, 1, 0, 0, 4, 1, 0, 0, 0, 0, 0],
                        [0, 5, 0, 1, 2, 0, 0, 0, 0, 1, 0, 0],
                        [1, 0, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0],
                        [0, 1, 0, 4, 1, 0, 0, 2, 0, 0, 0, 0],
                        [0, 2, 1, 0, 6, 1, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 2, 1],
                    ]
                )
                data = base + _RNG.integers(0, 2, size=base.shape)
                fig = go.Figure(
                    go.Heatmap(
                        z=data,
                        x=tactics,
                        y=techniques,
                        colorscale=[
                            [0.0, "#f8fafb"],
                            [0.35, "#c5e4e4"],
                            [0.7, "#0f6b6b"],
                            [1.0, "#083f3f"],
                        ],
                        colorbar=dict(thickness=10, len=0.7),
                    )
                )
                fig.update_layout(xaxis=dict(tickangle=-30))
                return _apply_chart_style(fig, 380)

            @self.app.callback(
                Output("threat-map", "figure"),
                Input("refresh-interval", "n_intervals"),
            )
            def threat_map(_n):
                sources = [
                    {"lat": 55.75, "lon": 37.62, "name": "Eastern Europe", "count": 150},
                    {"lat": 39.90, "lon": 116.41, "name": "East Asia", "count": 230},
                    {"lat": 51.5, "lon": -0.12, "name": "Western Europe", "count": 95},
                    {"lat": 28.61, "lon": 77.21, "name": "South Asia", "count": 80},
                    {"lat": -23.55, "lon": -46.63, "name": "South America", "count": 60},
                ]
                fig = go.Figure(
                    go.Scattergeo(
                        lat=[s["lat"] for s in sources],
                        lon=[s["lon"] for s in sources],
                        mode="markers",
                        marker=dict(
                            size=[max(10, s["count"] / 12) for s in sources],
                            color="#b45309",
                            opacity=0.85,
                        ),
                        text=[f"{s['name']}: {s['count']}" for s in sources],
                        hoverinfo="text",
                    )
                )
                fig.update_layout(
                    geo=dict(
                        showland=True,
                        landcolor="#f4f6f8",
                        showocean=True,
                        oceancolor="#d9e4ec",
                        showcountries=True,
                        countrycolor="#c5ced8",
                        showframe=False,
                        bgcolor="rgba(0,0,0,0)",
                        projection_type="natural earth",
                    ),
                    height=360,
                    margin=dict(l=0, r=0, t=0, b=0),
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=PLOT_LAYOUT["font"],
                )
                return fig

            @self.app.callback(
                Output("agents-grid", "children"),
                Input("refresh-interval", "n_intervals"),
            )
            def agents_page(_n):
                cards = []
                for a in _demo_agents():
                    status_cls = "agent-status isolated" if a["status"] == "isolated" else "agent-status"
                    cards.append(
                        html.Div(
                            [
                                html.H3(a["hostname"]),
                                html.P(f"{a['os']} · v{a['version']}", className="agent-meta"),
                                html.P(a["id"], className="agent-meta"),
                                html.Span(a["status"], className=status_cls),
                            ],
                            className="agent-card",
                        )
                    )
                return cards

            @self.app.callback(
                [
                    Output("system-source", "children"),
                    Output("services-table", "children"),
                    Output("system-health", "figure"),
                ],
                Input("refresh-interval", "n_intervals"),
            )
            def system_page(_n):
                services, source = _fetch_services()
                is_api = source == "api"
                banner = html.Div(
                    "Service registry from API."
                    if is_api
                    else "Showing demo service registry.",
                    className="source-banner" + ("" if is_api else " demo"),
                )
                rows = [
                    html.Tr(
                        [
                            html.Td(s.get("name"), className="mono"),
                            html.Td(str(s.get("port", ""))),
                            html.Td(s.get("status", ""), className="status-chip"),
                            html.Td(s.get("health", "")),
                        ]
                    )
                    for s in services
                ]
                names = [str(s.get("name", ""))[:16] for s in services]
                health_vals = []
                colors = []
                for s in services:
                    h = str(s.get("health", "")).lower()
                    if h == "healthy":
                        health_vals.append(98)
                        colors.append("#15803d")
                    elif h == "degraded":
                        health_vals.append(72)
                        colors.append("#a16207")
                    else:
                        health_vals.append(40)
                        colors.append("#b91c1c")
                fig = go.Figure(go.Bar(x=names, y=health_vals, marker_color=colors))
                fig.update_layout(yaxis=dict(range=[0, 100], title="Health %"), showlegend=False)
                return banner, _table(["Service", "Port", "Status", "Health"], rows), _apply_chart_style(fig, 300)

        def _severity_figure(self, alerts: list[dict[str, Any]]) -> go.Figure:
            buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for a in alerts:
                key = str(a.get("severity", "info")).lower()
                buckets[key if key in buckets else "info"] += 1
            labels = [k.title() for k, v in buckets.items() if v > 0]
            values = [v for v in buckets.values() if v > 0]
            colors = [SEVERITY_COLORS[k] for k, v in buckets.items() if v > 0]
            if not values:
                labels, values, colors = ["None"], [1], ["#d5dde7"]
            fig = go.Figure(
                go.Pie(
                    labels=labels,
                    values=values,
                    hole=0.62,
                    marker=dict(colors=colors, line=dict(color="#fff", width=2)),
                    textinfo="label+value",
                )
            )
            fig.update_layout(showlegend=False)
            return _apply_chart_style(fig, 280)

        def run(self, debug: bool = False) -> None:
            logger.info("Starting SOC console on %s:%s", self.host, self.port)
            logger.info("API base: %s", API_BASE)
            self.app.run(host=self.host, port=self.port, debug=debug)

else:

    class SOCRealtimeDashboard:  # type: ignore
        def __init__(self, *args, **kwargs) -> None:
            raise ImportError("Dash and Plotly are required. Install with: pip install dash plotly")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    SOCRealtimeDashboard().run(debug=False)
