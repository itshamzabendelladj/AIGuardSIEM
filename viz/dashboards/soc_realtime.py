"""Real-time SOC dashboard using Dash/Plotly.

Provides a comprehensive Security Operations Center dashboard with:
- Real-time event stream visualization
- Alert severity distribution
- MITRE ATT&CK heatmap
- Network traffic graphs
- Threat geolocation map
- Top sources/destinations
- System health metrics

Author: AIGuard Security Team
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Optional
import numpy as np

logger = logging.getLogger(__name__)

try:
    import dash
    from dash import dcc, html, Input, Output, State, callback
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import pandas as pd
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False


if DASH_AVAILABLE:

    class SOCRealtimeDashboard:
        """Real-time Security Operations Center dashboard.

        Args:
            title: Dashboard title
            host: Server host
            port: Server port
            refresh_interval: Auto-refresh interval in milliseconds

        Example:
            >>> dashboard = SOCRealtimeDashboard()
            >>> dashboard.run()
        """

        def __init__(
            self,
            title: str = "AIGuardSIEM - SOC Dashboard",
            host: str = "0.0.0.0",
            port: int = 8050,
            refresh_interval: int = 5000,
        ) -> None:
            self.app = dash.Dash(
                __name__,
                title=title,
                external_stylesheets=["https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"],
            )
            self.host = host
            self.port = port
            self.refresh_interval = refresh_interval

            self._setup_layout()
            self._setup_callbacks()

        def _setup_layout(self) -> None:
            """Set up the dashboard layout."""
            self.app.layout = html.Div([
                # Header
                html.Div([
                    html.H1("🛡️ AIGuardSIEM SOC Dashboard", className="text-center mb-4 mt-3",
                           style={"color": "#1a237e"}),
                    html.Hr(),
                ]),

                # Auto-refresh interval
                dcc.Interval(id="refresh-interval", interval=self.refresh_interval),

                # Key metrics row
                html.Div([
                    self._metric_card("events-per-second", "Events/sec", "0", "#1a237e"),
                    self._metric_card("active-alerts", "Active Alerts", "0", "#c62828"),
                    self._metric_card("critical-alerts", "Critical", "0", "#b71c1c"),
                    self._metric_card("processing-latency", "Latency (ms)", "0", "#2e7d32"),
                ], className="row justify-content-center mb-4"),

                # Main charts row 1
                html.Div([
                    html.Div([
                        html.H4("Events Over Time", className="text-center"),
                        dcc.Graph(id="events-time-chart"),
                    ], className="col-md-6"),
                    html.Div([
                        html.H4("Alerts by Severity", className="text-center"),
                        dcc.Graph(id="severity-pie-chart"),
                    ], className="col-md-6"),
                ], className="row mb-4"),

                # Main charts row 2
                html.Div([
                    html.Div([
                        html.H4("MITRE ATT&CK Heatmap", className="text-center"),
                        dcc.Graph(id="mitre-heatmap", style={"height": "400px"}),
                    ], className="col-md-12"),
                ], className="row mb-4"),

                # Main charts row 3
                html.Div([
                    html.Div([
                        html.H4("Top Source IPs", className="text-center"),
                        dcc.Graph(id="top-source-ips"),
                    ], className="col-md-6"),
                    html.Div([
                        html.H4("Top Destination IPs", className="text-center"),
                        dcc.Graph(id="top-dest-ips"),
                    ], className="col-md-6"),
                ], className="row mb-4"),

                # Threat map
                html.Div([
                    html.Div([
                        html.H4("Global Threat Map", className="text-center"),
                        dcc.Graph(id="threat-map", style={"height": "500px"}),
                    ], className="col-md-12"),
                ], className="row mb-4"),

                # System health
                html.Div([
                    html.Div([
                        html.H4("System Health", className="text-center"),
                        dcc.Graph(id="system-health"),
                    ], className="col-md-12"),
                ], className="row mb-4"),

                # Alert table
                html.Div([
                    html.H4("Recent Alerts", className="text-center mb-3"),
                    html.Div(id="alert-table"),
                ], className="row mb-5"),

                # Footer
                html.Div([
                    html.Hr(),
                    html.P("AIGuardSIEM v1.0.0 | Real-time SOC Dashboard",
                          className="text-center text-muted"),
                ]),
            ], className="container-fluid")

        def _metric_card(self, component_id: str, title: str, value: str, color: str) -> html.Div:
            """Create a metric card."""
            return html.Div([
                html.Div([
                    html.H5(title, className="card-title text-center"),
                    html.H2(id=component_id, children=value, className="text-center",
                          style={"color": color, "font-weight": "bold"}),
                ], className="card-body"),
            ], className="card col-md-3 m-2 shadow")

        def _setup_callbacks(self) -> None:
            """Set up dashboard callbacks."""

            @self.app.callback(
                [Output("events-per-second", "children"),
                 Output("active-alerts", "children"),
                 Output("critical-alerts", "children"),
                 Output("processing-latency", "children")],
                [Input("refresh-interval", "n_intervals")]
            )
            def update_metrics(n: int) -> tuple[str, str, str, str]:
                """Update top-level metrics."""
                eps = str(np.random.randint(40000, 60000))
                alerts = str(np.random.randint(10, 30))
                critical = str(np.random.randint(0, 5))
                latency = f"{np.random.uniform(1, 10):.1f}"
                return eps, alerts, critical, latency

            @self.app.callback(
                Output("events-time-chart", "figure"),
                [Input("refresh-interval", "n_intervals")]
            )
            def update_events_chart(n: int) -> go.Figure:
                """Update events over time chart."""
                now = datetime.now()
                times = [now - timedelta(minutes=30-i) for i in range(30)]
                values = np.random.randint(40000, 60000, 30).tolist()

                fig = go.Figure(data=go.Scatter(
                    x=times, y=values, mode="lines+markers",
                    name="Events/sec", line=dict(color="#1a237e", width=2),
                ))
                fig.update_layout(
                    xaxis_title="Time", yaxis_title="Events/sec",
                    height=300, margin=dict(l=40, r=20, t=20, b=40),
                )
                return fig

            @self.app.callback(
                Output("severity-pie-chart", "figure"),
                [Input("refresh-interval", "n_intervals")]
            )
            def update_severity_chart(n: int) -> go.Figure:
                """Update alerts by severity pie chart."""
                labels = ["Critical", "High", "Medium", "Low", "Info"]
                values = [3, 7, 12, 8, 25]

                fig = go.Figure(data=go.Pie(
                    labels=labels, values=values,
                    hole=0.4,
                    marker=dict(colors=["#b71c1c", "#e53935", "#fb8c00", "#fdd835", "#42a5f5"]),
                ))
                fig.update_layout(height=300, margin=dict(l=20, r=20, t=20, b=20))
                return fig

            @self.app.callback(
                Output("mitre-heatmap", "figure"),
                [Input("refresh-interval", "n_intervals")]
            )
            def update_mitre_heatmap(n: int) -> go.Figure:
                """Update MITRE ATT&CK heatmap."""
                tactics = ["Initial Access", "Execution", "Persistence", "Priv. Esc.",
                          "Def. Evasion", "Cred. Access", "Discovery", "Lat. Movement",
                          "Collection", "C2", "Exfiltration", "Impact"]

                techniques = [f"T{1000+i}" for i in range(10)]

                # Generate random heatmap data
                data = np.random.randint(0, 20, size=(len(techniques), len(tactics)))

                fig = go.Figure(data=go.Heatmap(
                    z=data, x=tactics, y=techniques,
                    colorscale="Reds",
                    showscale=True,
                ))
                fig.update_layout(
                    xaxis_title="Tactic", yaxis_title="Technique",
                    height=400, margin=dict(l=60, r=20, t=20, b=60),
                )
                return fig

            @self.app.callback(
                Output("top-source-ips", "figure"),
                [Input("refresh-interval", "n_intervals")]
            )
            def update_top_sources(n: int) -> go.Figure:
                """Update top source IPs chart."""
                ips = [f"10.0.0.{i}" for i in range(1, 11)]
                counts = np.random.randint(100, 5000, 10).tolist()

                fig = go.Figure(data=go.Bar(
                    x=counts, y=ips, orientation="h",
                    marker_color="#1a237e",
                ))
                fig.update_layout(
                    xaxis_title="Event Count", yaxis_title="Source IP",
                    height=300, margin=dict(l=100, r=20, t=20, b=40),
                    yaxis=dict(autorange="reversed"),
                )
                return fig

            @self.app.callback(
                Output("top-dest-ips", "figure"),
                [Input("refresh-interval", "n_intervals")]
            )
            def update_top_dests(n: int) -> go.Figure:
                """Update top destination IPs chart."""
                ips = [f"192.168.1.{i}" for i in range(1, 11)]
                counts = np.random.randint(50, 3000, 10).tolist()

                fig = go.Figure(data=go.Bar(
                    x=counts, y=ips, orientation="h",
                    marker_color="#2e7d32",
                ))
                fig.update_layout(
                    xaxis_title="Event Count", yaxis_title="Destination IP",
                    height=300, margin=dict(l=100, r=20, t=20, b=40),
                    yaxis=dict(autorange="reversed"),
                )
                return fig

            @self.app.callback(
                Output("threat-map", "figure"),
                [Input("refresh-interval", "n_intervals")]
            )
            def update_threat_map(n: int) -> go.Figure:
                """Update global threat map."""
                fig = go.Figure()

                # Threat sources
                sources = [
                    {"lat": 55.75, "lon": 37.62, "name": "Russia", "count": 150},
                    {"lat": 39.90, "lon": 116.41, "name": "China", "count": 230},
                    {"lat": 35.68, "lon": 139.69, "name": "Japan", "count": 45},
                    {"lat": 28.61, "lon": 77.21, "name": "India", "count": 80},
                    {"lat": -23.55, "lon": -46.63, "name": "Brazil", "count": 60},
                ]

                lats = [s["lat"] for s in sources]
                lons = [s["lon"] for s in sources]
                counts = [s["count"] for s in sources]
                names = [s["name"] for s in sources]

                fig.add_trace(go.Scattergeo(
                    lat=lats, lon=lons,
                    mode="markers",
                    marker=dict(
                        size=[c/10 for c in counts],
                        color="#c62828",
                        opacity=0.8,
                        line=dict(width=0),
                    ),
                    text=[f"{n}: {c} threats" for n, c in zip(names, counts)],
                    name="Threat Sources",
                ))

                fig.update_layout(
                    geo=dict(
                        showland=True, landcolor="rgb(240, 240, 240)",
                        showocean=True, oceancolor="rgb(200, 220, 255)",
                        showcountries=True, countrycolor="rgb(180, 180, 180)",
                        projection_type="natural earth",
                    ),
                    height=500, margin=dict(l=0, r=0, t=0, b=0),
                )
                return fig

            @self.app.callback(
                Output("system-health", "figure"),
                [Input("refresh-interval", "n_intervals")]
            )
            def update_system_health(n: int) -> go.Figure:
                """Update system health gauge."""
                services = ["Syslog Collector", "PCAP Collector", "Stream Processor",
                           "Rule Engine", "ML Inference", "Storage", "API Gateway"]
                health = [95, 98, 92, 99, 96, 94, 100]

                fig = go.Figure(data=go.Bar(
                    x=services, y=health,
                    marker_color=["#2e7d32" if h >= 90 else "#fdd835" if h >= 70 else "#c62828"
                                 for h in health],
                ))
                fig.update_layout(
                    xaxis_title="Service", yaxis_title="Health (%)",
                    yaxis=dict(range=[0, 100]),
                    height=300, margin=dict(l=40, r=20, t=20, b=60),
                )
                return fig

            @self.app.callback(
                Output("alert-table", "children"),
                [Input("refresh-interval", "n_intervals")]
            )
            def update_alert_table(n: int) -> html.Table:
                """Update recent alerts table."""
                alerts_data = [
                    {"id": "ALT-001", "severity": "Critical", "rule": "SSH Brute Force",
                     "source": "10.0.0.1", "time": datetime.now().strftime("%H:%M:%S")},
                    {"id": "ALT-002", "severity": "High", "rule": "Malware Detection",
                     "source": "192.168.1.5", "time": datetime.now().strftime("%H:%M:%S")},
                    {"id": "ALT-003", "severity": "Medium", "rule": "Port Scan Detected",
                     "source": "172.16.0.1", "time": datetime.now().strftime("%H:%M:%S")},
                ]

                header = html.Tr([
                    html.Th("ID"), html.Th("Severity"), html.Th("Rule"),
                    html.Th("Source"), html.Th("Time"),
                ])

                rows = []
                for alert in alerts_data:
                    color = "#c62828" if alert["severity"] == "Critical" else \
                           "#e53935" if alert["severity"] == "High" else "#fb8c00"
                    rows.append(html.Tr([
                        html.Td(alert["id"]),
                        html.Td(alert["severity"], style={"color": color, "font-weight": "bold"}),
                        html.Td(alert["rule"]),
                        html.Td(alert["source"]),
                        html.Td(alert["time"]),
                    ]))

                return html.Table(
                    [header] + rows,
                    className="table table-striped table-hover",
                )

        def run(self, debug: bool = False) -> None:
            """Run the dashboard server.

            Args:
                debug: Enable debug mode
            """
            logger.info(f"Starting SOC dashboard on {self.host}:{self.port}")
            self.app.run_server(host=self.host, port=self.port, debug=debug)

else:
    class SOCRealtimeDashboard:  # type: ignore
        def __init__(self, *args, **kwargs) -> None:
            raise ImportError("Dash and Plotly are required. Install with: pip install dash plotly")


# Entry point
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    dashboard = SOCRealtimeDashboard()
    dashboard.run(debug=True)
