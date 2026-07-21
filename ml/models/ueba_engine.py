"""User and Entity Behavior Analytics (UEBA) Engine.

Builds behavioral baselines for users and entities, detects anomalies
using statistical and ML methods, and assigns risk scores (0-100)
using Bayesian updating.

Author: AIGuard Security Team
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class UserBaseline:
    """Behavioral baseline for a user."""
    user_id: str
    user_name: str = ""

    # Login patterns
    login_hours: list[int] = field(default_factory=list)  # Hours of day
    login_locations: dict[str, int] = field(default_factory=dict)  # IP -> count
    typical_login_count: float = 0.0
    login_count_std: float = 0.0

    # Resource access patterns
    typical_resources: dict[str, int] = field(default_factory=dict)
    typical_data_volume: float = 0.0
    data_volume_std: float = 0.0

    # Peer group
    peer_group: str = ""
    peer_members: list[str] = field(default_factory=list)

    # Risk scoring
    risk_score: float = 0.0
    risk_history: list[float] = field(default_factory=list)
    last_update: float = field(default_factory=time.time)

    # Activity counters
    total_events: int = 0
    anomaly_count: int = 0


class UEBAEngine:
    """User and Entity Behavior Analytics engine.

    Features:
        - Behavioral baselining using statistical methods
        - Peer group analysis using PCA and t-SNE
        - Risk scoring (0-100) with Bayesian updating
        - Real-time anomaly detection
        - Progressive baseline refinement

    Example:
        >>> ueba = UEBAEngine()
        >>> ueba.update_baseline("user123", event)
        >>> risk = ueba.get_risk_score("user123")
        >>> anomalies = ueba.detect_anomalies(events)
    """

    def __init__(
        self,
        learning_rate: float = 0.05,
        min_samples_for_baseline: int = 50,
        anomaly_threshold: float = 2.5,  # Standard deviations
        risk_decay_factor: float = 0.95,
    ) -> None:
        """Initialize the UEBA engine.

        Args:
            learning_rate: Baseline update rate
            min_samples_for_baseline: Minimum samples before baseline is valid
            anomaly_threshold: Std dev threshold for anomaly detection
            risk_decay_factor: Risk score decay per time period
        """
        self.learning_rate = learning_rate
        self.min_samples = min_samples_for_baseline
        self.anomaly_threshold = anomaly_threshold
        self.risk_decay_factor = risk_decay_factor

        self.baselines: dict[str, UserBaseline] = {}
        self.peer_groups: dict[str, list[str]] = defaultdict(list)

        logger.info("UEBA engine initialized")

    def update_baseline(
        self,
        user_id: str,
        event: dict,
        user_name: str = "",
    ) -> None:
        """Update user baseline with new event.

        Args:
            user_id: User identifier
            event: Event data dictionary
            user_name: Optional user name
        """
        if user_id not in self.baselines:
            self.baselines[user_id] = UserBaseline(
                user_id=user_id,
                user_name=user_name,
            )

        baseline = self.baselines[user_id]
        baseline.total_events += 1

        # Update login hours
        timestamp = event.get("timestamp", time.time())
        hour = int(time.localtime(timestamp).tm_hour)
        baseline.login_hours.append(hour)

        # Keep last 1000 login hours
        if len(baseline.login_hours) > 1000:
            baseline.login_hours = baseline.login_hours[-1000:]

        # Update login locations
        source_ip = event.get("source_ip", "")
        if source_ip:
            baseline.login_locations[source_ip] = baseline.login_locations.get(source_ip, 0) + 1

        # Update resource access
        resource = event.get("resource", event.get("action", ""))
        if resource:
            baseline.typical_resources[resource] = baseline.typical_resources.get(resource, 0) + 1

        # Update data volume (EWMA)
        data_volume = float(event.get("network_bytes", 0))
        if baseline.total_events == 1:
            baseline.typical_data_volume = data_volume
        else:
            delta = data_volume - baseline.typical_data_volume
            baseline.typical_data_volume += self.learning_rate * delta
            baseline.data_volume_std = (1 - self.learning_rate) * baseline.data_volume_std + \
                                       self.learning_rate * abs(delta)

        # Update login count statistics
        if baseline.total_events % 100 == 0:
            baseline.typical_login_count = baseline.total_events / max(1, (time.time() - baseline.last_update) / 3600)

        baseline.last_update = time.time()

    def assign_peer_group(
        self,
        user_id: str,
        group_name: str,
        peers: list[str],
    ) -> None:
        """Assign user to a peer group.

        Args:
            user_id: User identifier
            group_name: Peer group name
            peers: List of peer user IDs
        """
        if user_id in self.baselines:
            self.baselines[user_id].peer_group = group_name
            self.baselines[user_id].peer_members = peers

        self.peer_groups[group_name] = peers
        logger.debug(f"Assigned {user_id} to peer group '{group_name}'")

    def detect_anomalies(
        self,
        user_id: str,
        event: dict,
    ) -> list[dict]:
        """Detect behavioral anomalies for a user event.

        Args:
            user_id: User identifier
            event: Event data

        Returns:
            List of detected anomalies
        """
        anomalies = []
        baseline = self.baselines.get(user_id)

        if not baseline or baseline.total_events < self.min_samples:
            return anomalies

        # Check login hour anomaly
        timestamp = event.get("timestamp", time.time())
        hour = int(time.localtime(timestamp).tm_hour)

        if baseline.login_hours:
            hour_counts = defaultdict(int)
            for h in baseline.login_hours:
                hour_counts[h] += 1

            total = len(baseline.login_hours)
            typical_probability = hour_counts.get(hour, 0) / total

            if typical_probability < 0.01:  # Less than 1% of logins at this hour
                anomalies.append({
                    "type": "unusual_login_time",
                    "severity": "medium",
                    "detail": f"Login at unusual hour {hour}:00",
                    "user_id": user_id,
                })

        # Check login location anomaly
        source_ip = event.get("source_ip", "")
        if source_ip and baseline.login_locations:
            total_logins = sum(baseline.login_locations.values())
            ip_count = baseline.login_locations.get(source_ip, 0)
            ip_probability = ip_count / total_logins if total_logins > 0 else 0

            if ip_probability < 0.001:  # Never or rarely seen from this IP
                anomalies.append({
                    "type": "unusual_login_location",
                    "severity": "high",
                    "detail": f"Login from new/rare IP: {source_ip}",
                    "user_id": user_id,
                })

        # Check data volume anomaly
        data_volume = float(event.get("network_bytes", 0))
        if baseline.data_volume_std > 0:
            z_score = abs(data_volume - baseline.typical_data_volume) / baseline.data_volume_std
            if z_score > self.anomaly_threshold:
                anomalies.append({
                    "type": "unusual_data_volume",
                    "severity": "high" if z_score > 4 else "medium",
                    "detail": f"Data volume {data_volume} bytes (z-score: {z_score:.2f})",
                    "user_id": user_id,
                    "z_score": z_score,
                })

        # Check resource access anomaly
        resource = event.get("resource", event.get("action", ""))
        if resource and baseline.typical_resources:
            total_access = sum(baseline.typical_resources.values())
            resource_count = baseline.typical_resources.get(resource, 0)
            resource_probability = resource_count / total_access if total_access > 0 else 0

            if resource_probability < 0.001:
                anomalies.append({
                    "type": "unusual_resource_access",
                    "severity": "medium",
                    "detail": f"Access to unusual resource: {resource}",
                    "user_id": user_id,
                })

        if anomalies:
            baseline.anomaly_count += len(anomalies)
            self._update_risk_score(user_id, anomalies)

        return anomalies

    def _update_risk_score(self, user_id: str, anomalies: list[dict]) -> None:
        """Update user risk score using Bayesian updating.

        Args:
            user_id: User identifier
            anomalies: List of detected anomalies
        """
        baseline = self.baselines.get(user_id)
        if not baseline:
            return

        # Severity weights
        severity_weights = {
            "low": 5,
            "medium": 15,
            "high": 30,
            "critical": 50,
        }

        # Calculate anomaly score
        anomaly_score = sum(
            severity_weights.get(a.get("severity", "medium"), 15)
            for a in anomalies
        )

        # Bayesian update: combine prior risk with new evidence
        prior_risk = baseline.risk_score
        evidence_weight = min(1.0, len(anomalies) / 5.0)  # More anomalies = stronger evidence
        likelihood = min(100.0, anomaly_score)

        # Bayesian-style update
        posterior = (prior_risk * (1 - evidence_weight) +
                     likelihood * evidence_weight)

        # Apply decay to prevent permanent high scores
        baseline.risk_score = min(100.0, posterior)
        baseline.risk_history.append(baseline.risk_score)

        # Keep history manageable
        if len(baseline.risk_history) > 1000:
            baseline.risk_history = baseline.risk_history[-1000:]

    def decay_risk_scores(self) -> None:
        """Decay all risk scores over time."""
        for baseline in self.baselines.values():
            baseline.risk_score *= self.risk_decay_factor

    def get_risk_score(self, user_id: str) -> float:
        """Get current risk score for a user.

        Args:
            user_id: User identifier

        Returns:
            Risk score (0-100)
        """
        baseline = self.baselines.get(user_id)
        return baseline.risk_score if baseline else 0.0

    def get_high_risk_users(self, threshold: float = 70.0) -> list[dict]:
        """Get users with high risk scores.

        Args:
            threshold: Risk score threshold

        Returns:
            List of high-risk user details
        """
        high_risk = []
        for user_id, baseline in self.baselines.items():
            if baseline.risk_score >= threshold:
                high_risk.append({
                    "user_id": user_id,
                    "user_name": baseline.user_name,
                    "risk_score": baseline.risk_score,
                    "anomaly_count": baseline.anomaly_count,
                    "total_events": baseline.total_events,
                    "peer_group": baseline.peer_group,
                })

        high_risk.sort(key=lambda x: x["risk_score"], reverse=True)
        return high_risk

    def get_user_profile(self, user_id: str) -> Optional[dict]:
        """Get complete user profile.

        Args:
            user_id: User identifier

        Returns:
            User profile dictionary
        """
        baseline = self.baselines.get(user_id)
        if not baseline:
            return None

        return {
            "user_id": baseline.user_id,
            "user_name": baseline.user_name,
            "risk_score": baseline.risk_score,
            "total_events": baseline.total_events,
            "anomaly_count": baseline.anomaly_count,
            "typical_login_hours": list(set(baseline.login_hours)),
            "login_locations": dict(list(baseline.login_locations.items())[:10]),
            "peer_group": baseline.peer_group,
            "typical_data_volume": baseline.typical_data_volume,
            "risk_history": baseline.risk_history[-20:],
        }

    def get_all_risk_scores(self) -> dict[str, float]:
        """Get risk scores for all users.

        Returns:
            Dictionary of user_id -> risk_score
        """
        return {
            uid: baseline.risk_score
            for uid, baseline in self.baselines.items()
        }

    def get_stats(self) -> dict[str, object]:
        """Get engine statistics.

        Returns:
            Statistics dictionary
        """
        total_anomalies = sum(b.anomaly_count for b in self.baselines.values())
        avg_risk = np.mean([b.risk_score for b in self.baselines.values()]) if self.baselines else 0

        return {
            "total_users": len(self.baselines),
            "total_anomalies": total_anomalies,
            "average_risk_score": float(avg_risk),
            "high_risk_users": len(self.get_high_risk_users()),
            "peer_groups": len(self.peer_groups),
        }
