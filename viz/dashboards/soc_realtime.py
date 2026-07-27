"""AIGuardSIEM SOC Console — multi-page operations dashboard with sidebar."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any

import numpy as np

from api_client import (
    API_BASE,
    DEMO_USER,
    DEMO_PASS,
    ack_alert,
    create_case_from_alert,
    execute_playbook,
    fetch_agents,
    fetch_alerts,
    fetch_cases,
    fetch_event_agg,
    fetch_events,
    fetch_playbooks,
    fetch_rules,
    fetch_services,
    health_ping,
    reload_rules,
    resolve_alert,
    set_agent_isolation,
)

logger = logging.getLogger(__name__)

try:
    import dash
    from dash import dcc, html, Input, Output, ALL, ctx, no_update
    import plotly.graph_objects as go

    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False


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
    "/alerts": ("Alerts", "Triage detections and open response cases"),
    "/events": ("Events", "Normalized security event stream from the API"),
    "/cases": ("Cases", "Incident response caseboard"),
    "/rules": ("Detection rules", "Sigma/correlation rules driving the engine"),
    "/response": ("Response", "SOAR playbooks linked to automated actions"),
    "/mitre": ("MITRE ATT&CK", "Technique coverage from live alerts"),
    "/agents": ("Agents", "Endpoint XDR agents — isolate / restore"),
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
    ("DETECT & RESPOND", [
        ("/rules", "05", "Rules"),
        ("/response", "06", "Response"),
        ("/mitre", "07", "MITRE"),
        ("/agents", "08", "Agents"),
    ]),
    ("PLATFORM", [
        ("/system", "09", "System"),
        ("/settings", "10", "Settings"),
    ]),
]


# ---------------------------------------------------------------------------
# Shared UI helpers
# ---------------------------------------------------------------------------

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
                                            self._page_rules(),
                                            self._page_response(),
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
                                            html.P("Top open alerts from API", className="panel-caption"),
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
                                            html.H3("Event categories", className="panel-title"),
                                            html.P("From /events/aggregate", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    dcc.Graph(id="event-category-chart", config={"displayModeBar": False}),
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
                                            html.H3("Top source IPs", className="panel-title"),
                                            html.P("Demo stream", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    dcc.Graph(id="top-source-ips", config={"displayModeBar": False}),
                                ],
                                className="panel",
                            ),
                            html.Div(
                                [
                                    html.Div(
                                        [
                                            html.H3("Pipeline link map", className="panel-title"),
                                            html.P("How console actions hit the platform", className="panel-caption"),
                                        ],
                                        className="panel-head",
                                    ),
                                    html.Div(
                                        [
                                            html.P("Alerts → Cases / Playbooks", className="kpi-hint"),
                                            html.P("Events → Aggregation & MITRE", className="kpi-hint"),
                                            html.P("Agents → Isolate (XDR response)", className="kpi-hint"),
                                            html.P("Rules → Sigma catalog reload", className="kpi-hint"),
                                            html.P("System → Orchestrator registry", className="kpi-hint"),
                                        ],
                                        style={"padding": "0.5rem 0.25rem 1rem"},
                                    ),
                                ],
                                className="panel pad-more",
                            ),
                        ],
                        className="panel-grid equal",
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
                    html.Div(id="cases-source"),
                    html.Div(
                        [
                            html.Div(
                                [html.H3("Open"), html.P("0", id="case-stat-open")],
                                className="stat-card",
                            ),
                            html.Div(
                                [html.H3("Investigating"), html.P("0", id="case-stat-invest")],
                                className="stat-card",
                            ),
                            html.Div(
                                [html.H3("Contained / closed"), html.P("0", id="case-stat-contained")],
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
                                    html.P("Cases linked to alert IDs from the API", className="panel-caption"),
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

        def _page_rules(self) -> html.Div:
            return html.Div(
                [
                    html.Div(id="rules-source"),
                    html.Div(
                        [
                            html.Button("Reload rules", id="rules-reload-btn", className="btn btn-primary", n_clicks=0),
                            html.Span(id="rules-action-feedback", style={"fontSize": "0.8rem"}),
                        ],
                        className="toolbar",
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("Detection rules", className="panel-title"),
                                    html.P("Sigma catalog exposed by /api/v1/rules", className="panel-caption"),
                                ],
                                className="panel-head",
                            ),
                            html.Div(id="rules-table", className="table-wrap"),
                        ],
                        className="panel pad-more panel-full",
                    ),
                ],
                id="page-rules",
                className="page",
            )

        def _page_response(self) -> html.Div:
            return html.Div(
                [
                    html.Div(id="playbooks-source"),
                    html.Div(id="playbook-action-feedback", style={"marginBottom": "0.75rem", "fontSize": "0.85rem"}),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("SOAR playbooks", className="panel-title"),
                                    html.P("Execute playbooks that drive host isolation / IR workflows", className="panel-caption"),
                                ],
                                className="panel-head",
                            ),
                            html.Div(id="playbooks-table", className="table-wrap"),
                        ],
                        className="panel pad-more panel-full",
                    ),
                ],
                id="page-response",
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
                    html.Div(id="agents-source"),
                    html.Div(id="agent-action-feedback", style={"marginBottom": "0.75rem", "fontSize": "0.85rem"}),
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
                "page-rules",
                "page-response",
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
                "/rules": "page-rules",
                "/response": "page-response",
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
                alerts, source = fetch_alerts()
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
                    "Connected to API gateway — alerts/cases/agents/rules share one store."
                    if is_api
                    else "API offline — local demo fallback. Start with: go run ./api",
                    className="source-banner" + ("" if is_api else " demo"),
                )

                alert_rows = []
                for a in filtered:
                    aid = str(a.get("id", ""))
                    status = str(a.get("status", "open")).lower()
                    alert_rows.append(
                        html.Tr(
                            [
                                html.Td(aid[:14], className="mono"),
                                html.Td(_sev_badge(str(a.get("severity", "")))),
                                html.Td(a.get("rule_name") or "—"),
                                html.Td(a.get("source_ip") or "—", className="mono"),
                                html.Td(a.get("host_name") or "—"),
                                html.Td(a.get("mitre_technique") or "—", className="mono"),
                                html.Td(status, className="status-chip"),
                                html.Td(_fmt_time(a.get("timestamp"))[-8:], className="mono"),
                                html.Td(
                                    html.Div(
                                        [
                                            html.Button(
                                                "Ack",
                                                id={"type": "ack-btn", "index": aid},
                                                className="btn btn-ghost",
                                                n_clicks=0,
                                                disabled=status != "open",
                                            ),
                                            html.Button(
                                                "Case",
                                                id={"type": "case-btn", "index": aid},
                                                className="btn btn-ghost",
                                                n_clicks=0,
                                            ),
                                            html.Button(
                                                "Resolve",
                                                id={"type": "resolve-btn", "index": aid},
                                                className="btn btn-ghost",
                                                n_clicks=0,
                                                disabled=status == "resolved",
                                            ),
                                        ],
                                        style={"display": "flex", "gap": "0.25rem", "flexWrap": "wrap"},
                                    )
                                ),
                            ]
                        )
                    )
                alerts_table = _table(
                    ["ID", "Severity", "Rule", "Source", "Host", "MITRE", "Status", "Time", "Actions"],
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
                [
                    Input({"type": "ack-btn", "index": ALL}, "n_clicks"),
                    Input({"type": "case-btn", "index": ALL}, "n_clicks"),
                    Input({"type": "resolve-btn", "index": ALL}, "n_clicks"),
                ],
                prevent_initial_call=True,
            )
            def alert_actions(_ack, _case, _resolve):
                if not ctx.triggered_id:
                    return no_update
                alert_id = ctx.triggered_id.get("index")
                action = ctx.triggered_id.get("type")
                alerts, _ = fetch_alerts()
                alert = next((a for a in alerts if str(a.get("id")) == str(alert_id)), {"id": alert_id})
                if action == "ack-btn":
                    ok, msg = ack_alert(alert_id)
                elif action == "case-btn":
                    ok, msg = create_case_from_alert(alert)
                else:
                    ok, msg = resolve_alert(alert_id)
                color = "#15803d" if ok else "#b45309"
                return html.Span(msg, style={"color": color})

            @self.app.callback(
                Output("event-category-chart", "figure"),
                Input("refresh-interval", "n_intervals"),
            )
            def event_category_chart(_n):
                buckets, _ = fetch_event_agg("category")
                keys = [str(b.get("key")) for b in buckets]
                vals = [int(b.get("count") or 0) for b in buckets]
                fig = go.Figure(go.Bar(x=keys, y=vals, marker_color="#0f6b6b"))
                fig.update_layout(showlegend=False, yaxis_title="Events")
                return _apply_chart_style(fig, 280)

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
                q = ((query or "") + " " + (global_search or "")).strip()
                events, source = fetch_events(q=q, category=category or "all")
                if category and category != "all":
                    events = [e for e in events if e.get("category") == category]
                if q:
                    events = [e for e in events if q.lower() in json.dumps(e).lower()]
                rows = [
                    html.Tr(
                        [
                            html.Td(e.get("id"), className="mono"),
                            html.Td(_sev_badge(str(e.get("severity", "")))),
                            html.Td(e.get("category")),
                            html.Td(e.get("action"), className="mono"),
                            html.Td(e.get("source_ip"), className="mono"),
                            html.Td(e.get("host_name")),
                            html.Td(e.get("source_type")),
                            html.Td(_fmt_time(e.get("timestamp"))[-8:], className="mono"),
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
                    Output("cases-source", "children"),
                ],
                Input("refresh-interval", "n_intervals"),
            )
            def cases_page(_n):
                cases, source = fetch_cases()
                rows = [
                    html.Tr(
                        [
                            html.Td(c.get("id"), className="mono"),
                            html.Td(_sev_badge(str(c.get("severity", "")))),
                            html.Td(c.get("title")),
                            html.Td(c.get("status"), className="status-chip"),
                            html.Td(c.get("assigned_to")),
                            html.Td(", ".join(c.get("alert_ids") or []) or str(c.get("alert_count", 0)), className="mono"),
                            html.Td(_fmt_time(c.get("updated_at"))[-8:], className="mono"),
                        ]
                    )
                    for c in cases
                ]
                banner = html.Div(
                    "Cases from API store (linked to alert IDs)."
                    if source == "api"
                    else "Demo cases (API offline).",
                    className="source-banner" + ("" if source == "api" else " demo"),
                )
                return (
                    _table(["ID", "Sev", "Title", "Status", "Owner", "Alerts", "Updated"], rows),
                    str(sum(1 for c in cases if c.get("status") == "open")),
                    str(sum(1 for c in cases if c.get("status") == "investigating")),
                    str(sum(1 for c in cases if c.get("status") in ("contained", "closed"))),
                    banner,
                )

            @self.app.callback(
                [
                    Output("rules-table", "children"),
                    Output("rules-source", "children"),
                    Output("rules-action-feedback", "children"),
                ],
                [
                    Input("refresh-interval", "n_intervals"),
                    Input("rules-reload-btn", "n_clicks"),
                ],
            )
            def rules_page(_n, reload_clicks):
                feedback = ""
                if ctx.triggered_id == "rules-reload-btn" and reload_clicks:
                    ok, msg = reload_rules()
                    feedback = html.Span(msg, style={"color": "#15803d" if ok else "#b45309"})
                rules, source = fetch_rules()
                rows = [
                    html.Tr(
                        [
                            html.Td(r.get("id"), className="mono"),
                            html.Td(r.get("name")),
                            html.Td(_sev_badge(str(r.get("severity", "")))),
                            html.Td(r.get("type") or "sigma"),
                            html.Td(r.get("status"), className="status-chip"),
                            html.Td(r.get("mitre_technique") or "—", className="mono"),
                            html.Td(", ".join(r.get("tags") or [])),
                        ]
                    )
                    for r in rules
                ]
                banner = html.Div(
                    "Rules mirror config/sigma_rules via API."
                    if source == "api"
                    else "Demo rules (API offline).",
                    className="source-banner" + ("" if source == "api" else " demo"),
                )
                return _table(["ID", "Name", "Sev", "Type", "Status", "MITRE", "Tags"], rows), banner, feedback

            @self.app.callback(
                [
                    Output("playbooks-table", "children"),
                    Output("playbooks-source", "children"),
                    Output("playbook-action-feedback", "children"),
                ],
                [
                    Input("refresh-interval", "n_intervals"),
                    Input({"type": "run-playbook", "index": ALL}, "n_clicks"),
                ],
            )
            def playbooks_page(_n, _clicks):
                feedback = ""
                if ctx.triggered_id and isinstance(ctx.triggered_id, dict) and ctx.triggered_id.get("type") == "run-playbook":
                    ok, msg = execute_playbook(ctx.triggered_id.get("index"))
                    feedback = html.Span(msg, style={"color": "#15803d" if ok else "#b45309"})
                playbooks, source = fetch_playbooks()
                rows = [
                    html.Tr(
                        [
                            html.Td(p.get("id"), className="mono"),
                            html.Td(p.get("name")),
                            html.Td(p.get("description")),
                            html.Td("yes" if p.get("enabled") else "no"),
                            html.Td(", ".join(p.get("tags") or [])),
                            html.Td(p.get("status") or "idle", className="status-chip"),
                            html.Td(
                                html.Button(
                                    "Run",
                                    id={"type": "run-playbook", "index": p.get("id")},
                                    className="btn btn-primary",
                                    n_clicks=0,
                                )
                            ),
                        ]
                    )
                    for p in playbooks
                ]
                banner = html.Div(
                    "Playbooks from /api/v1/playbooks (aligned with playbooks/*.yml)."
                    if source == "api"
                    else "Demo playbooks (API offline).",
                    className="source-banner" + ("" if source == "api" else " demo"),
                )
                return (
                    _table(["ID", "Name", "Description", "Enabled", "Tags", "Status", ""], rows),
                    banner,
                    feedback,
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
                [
                    Output("agents-grid", "children"),
                    Output("agents-source", "children"),
                    Output("agent-action-feedback", "children"),
                ],
                [
                    Input("refresh-interval", "n_intervals"),
                    Input({"type": "agent-iso", "index": ALL}, "n_clicks"),
                    Input({"type": "agent-uniso", "index": ALL}, "n_clicks"),
                ],
            )
            def agents_page(_n, _iso, _uniso):
                feedback = ""
                if ctx.triggered_id and isinstance(ctx.triggered_id, dict):
                    aid = ctx.triggered_id.get("index")
                    if ctx.triggered_id.get("type") == "agent-iso":
                        ok, msg = set_agent_isolation(aid, True)
                        feedback = html.Span(msg, style={"color": "#15803d" if ok else "#b45309"})
                    elif ctx.triggered_id.get("type") == "agent-uniso":
                        ok, msg = set_agent_isolation(aid, False)
                        feedback = html.Span(msg, style={"color": "#15803d" if ok else "#b45309"})
                agents, source = fetch_agents()
                cards = []
                for a in agents:
                    status = str(a.get("status", "active"))
                    status_cls = "agent-status isolated" if status == "isolated" else "agent-status"
                    cards.append(
                        html.Div(
                            [
                                html.H3(a.get("hostname")),
                                html.P(f"{a.get('os')} · v{a.get('version')}", className="agent-meta"),
                                html.P(a.get("id"), className="agent-meta"),
                                html.Span(status, className=status_cls),
                                html.Div(
                                    [
                                        html.Button(
                                            "Isolate",
                                            id={"type": "agent-iso", "index": a.get("id")},
                                            className="btn",
                                            n_clicks=0,
                                            disabled=status == "isolated",
                                        ),
                                        html.Button(
                                            "Restore",
                                            id={"type": "agent-uniso", "index": a.get("id")},
                                            className="btn btn-ghost",
                                            n_clicks=0,
                                            disabled=status != "isolated",
                                        ),
                                    ],
                                    style={"display": "flex", "gap": "0.4rem", "marginTop": "0.75rem"},
                                ),
                            ],
                            className="agent-card",
                        )
                    )
                banner = html.Div(
                    "XDR agents from API — isolate updates shared store for response workflows."
                    if source == "api"
                    else "Demo agents (API offline).",
                    className="source-banner" + ("" if source == "api" else " demo"),
                )
                return cards, banner, feedback

            @self.app.callback(
                [
                    Output("system-source", "children"),
                    Output("services-table", "children"),
                    Output("system-health", "figure"),
                ],
                Input("refresh-interval", "n_intervals"),
            )
            def system_page(_n):
                services, source = fetch_services()
                is_api = source == "api"
                banner = html.Div(
                    "Service registry from orchestrator API."
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
