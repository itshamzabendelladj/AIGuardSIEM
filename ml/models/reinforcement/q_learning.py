"""Q-Learning agent for adaptive detection threshold tuning.

Uses reinforcement learning to dynamically adjust detection thresholds
based on alert feedback, minimizing false positives while maintaining
high detection rates.

Author: AIGuard Security Team
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Optional
import numpy as np

logger = logging.getLogger(__name__)


class QLearningThresholdAgent:
    """Q-Learning agent for adaptive threshold tuning.

    The agent learns to adjust detection thresholds based on the
    trade-off between true positives and false positives. It uses
    a Q-table to learn optimal threshold adjustments for different
    alert volume and accuracy states.

    State Space:
        - Alert volume (low, medium, high)
        - False positive rate (low, medium, high)
        - Detection rate (low, medium, high)
        - Time of day (morning, afternoon, evening, night)

    Action Space:
        - Increase threshold
        - Decrease threshold
        - Maintain threshold

    Reward:
        - +1 for true positive detection
        - -1 for false positive
        - -0.5 for missed detection
        - +0.5 for maintaining good balance

    Example:
        >>> agent = QLearningThresholdAgent()
        >>> agent.train(episodes=10000)
        >>> optimal_threshold = agent.get_threshold(state)
    """

    # State discretization
    ALERT_VOLUME_BINS = [0, 10, 50, 100, float('inf')]  # low, medium, high, very_high
    FP_RATE_BINS = [0, 0.05, 0.15, 0.30, float('inf')]  # low, medium, high, very_high
    DETECTION_RATE_BINS = [0, 0.5, 0.7, 0.9, float('inf')]  # low, medium, high, very_high
    TIME_OF_DAY_BINS = [0, 6, 12, 18, 24]  # night, morning, afternoon, evening

    # Actions
    ACTIONS = ['increase', 'decrease', 'maintain']
    N_ACTIONS = 3

    # Threshold adjustment step
    THRESHOLD_STEP = 0.05
    MIN_THRESHOLD = 0.1
    MAX_THRESHOLD = 0.95

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        epsilon: float = 1.0,
        epsilon_min: float = 0.01,
        epsilon_decay: float = 0.995,
        initial_threshold: float = 0.5,
    ) -> None:
        """Initialize the Q-Learning agent.

        Args:
            learning_rate: Q-value update rate (alpha)
            discount_factor: Future reward discount (gamma)
            epsilon: Exploration rate
            epsilon_min: Minimum exploration rate
            epsilon_decay: Epsilon decay per episode
            initial_threshold: Starting detection threshold
        """
        self.alpha = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.current_threshold = initial_threshold

        # Q-table: state -> action values
        # State is (alert_vol, fp_rate, detection_rate, time_of_day)
        # Each dimension has 4 bins, so 4^4 = 256 states
        self.n_states = 256
        self.q_table: np.ndarray = np.zeros((self.n_states, self.N_ACTIONS))

        # Training history
        self.reward_history: list[float] = []
        self.threshold_history: list[float] = []
        self.fp_history: list[float] = []
        self.tp_history: list[float] = []

        logger.info("Q-Learning threshold agent initialized")

    def _discretize_state(
        self,
        alert_volume: float,
        fp_rate: float,
        detection_rate: float,
        time_of_day: float,
    ) -> int:
        """Discretize continuous state into discrete state index.

        Args:
            alert_volume: Current alert volume
            fp_rate: Current false positive rate
            detection_rate: Current detection rate
            time_of_day: Hour of day (0-23)

        Returns:
            Discrete state index
        """
        vol_bin = np.digitize(alert_volume, self.ALERT_VOLUME_BINS) - 1
        fp_bin = np.digitize(fp_rate, self.FP_RATE_BINS) - 1
        det_bin = np.digitize(detection_rate, self.DETECTION_RATE_BINS) - 1
        time_bin = np.digitize(time_of_day, self.TIME_OF_DAY_BINS) - 1

        # Clamp to valid range
        vol_bin = max(0, min(3, vol_bin))
        fp_bin = max(0, min(3, fp_bin))
        det_bin = max(0, min(3, det_bin))
        time_bin = max(0, min(3, time_bin))

        # Combine into single state index
        state = vol_bin * 64 + fp_bin * 16 + det_bin * 4 + time_bin
        return state

    def get_action(self, state: int, training: bool = True) -> int:
        """Get action using epsilon-greedy policy.

        Args:
            state: Current state index
            training: Whether in training mode

        Returns:
            Action index (0=increase, 1=decrease, 2=maintain)
        """
        if training and np.random.random() < self.epsilon:
            return np.random.randint(self.N_ACTIONS)

        return int(np.argmax(self.q_table[state]))

    def apply_action(self, action: int) -> float:
        """Apply action to adjust threshold.

        Args:
            action: Action index

        Returns:
            New threshold value
        """
        if action == 0:  # increase
            self.current_threshold = min(
                self.MAX_THRESHOLD,
                self.current_threshold + self.THRESHOLD_STEP
            )
        elif action == 1:  # decrease
            self.current_threshold = max(
                self.MIN_THRESHOLD,
                self.current_threshold - self.THRESHOLD_STEP
            )
        # action == 2: maintain (no change)

        return self.current_threshold

    def compute_reward(
        self,
        true_positives: int,
        false_positives: int,
        false_negatives: int,
        total_alerts: int,
    ) -> float:
        """Compute reward based on detection performance.

        Args:
            true_positives: Correctly detected threats
            false_positives: Incorrect alerts
            false_negatives: Missed threats
            total_alerts: Total alerts generated

        Returns:
            Reward value
        """
        reward = 0.0
        reward += true_positives * 1.0   # Reward for TP
        reward -= false_positives * 1.0  # Penalty for FP
        reward -= false_negatives * 0.5  # Penalty for FN

        # Bonus for good balance
        if total_alerts > 0:
            precision = true_positives / total_alerts
            if precision > 0.8:
                reward += 0.5

        return reward

    def update(
        self,
        state: int,
        action: int,
        reward: float,
        next_state: int,
    ) -> None:
        """Update Q-value using Q-learning update rule.

        Args:
            state: Current state
            action: Taken action
            reward: Received reward
            next_state: Resulting state
        """
        best_next = np.max(self.q_table[next_state])
        td_target = reward + self.gamma * best_next
        td_error = td_target - self.q_table[state, action]
        self.q_table[state, action] += self.alpha * td_error

    def train(
        self,
        episodes: int = 10000,
        alert_volume_fn: Optional[callable] = None,
        fp_rate_fn: Optional[callable] = None,
        detection_rate_fn: Optional[callable] = None,
    ) -> dict[str, list[float]]:
        """Train the Q-learning agent.

        Args:
            episodes: Number of training episodes
            alert_volume_fn: Function to simulate alert volume
            fp_rate_fn: Function to simulate FP rate
            detection_rate_fn: Function to simulate detection rate

        Returns:
            Training history
        """
        logger.info(f"Training Q-learning agent for {episodes} episodes")

        for episode in range(episodes):
            # Simulate environment
            time_of_day = np.random.randint(0, 24)
            alert_volume = alert_volume_fn() if alert_volume_fn else np.random.randint(0, 200)
            fp_rate = fp_rate_fn() if fp_rate_fn else np.random.uniform(0, 0.5)
            detection_rate = detection_rate_fn() if detection_rate_fn else np.random.uniform(0.3, 0.95)

            state = self._discretize_state(alert_volume, fp_rate, detection_rate, time_of_day)

            # Take action
            action = self.get_action(state, training=True)
            old_threshold = self.current_threshold
            new_threshold = self.apply_action(action)

            # Simulate outcome
            # Higher threshold -> fewer alerts, higher precision, lower recall
            threshold_change = new_threshold - old_threshold
            adjusted_fp = max(0, fp_rate - threshold_change * 0.5)
            adjusted_detection = max(0, detection_rate - threshold_change * 0.3)

            total_alerts = int(alert_volume * (1 - threshold_change * 0.3))
            tp = int(total_alerts * adjusted_detection * (1 - adjusted_fp))
            fp = int(total_alerts * adjusted_fp)
            fn = int(alert_volume * (1 - adjusted_detection))

            reward = self.compute_reward(tp, fp, fn, max(total_alerts, 1))

            # Get next state
            next_state = self._discretize_state(
                total_alerts, adjusted_fp, adjusted_detection, (time_of_day + 1) % 24
            )

            # Update Q-table
            self.update(state, action, reward, next_state)

            # Record history
            self.reward_history.append(reward)
            self.threshold_history.append(self.current_threshold)
            self.fp_history.append(adjusted_fp)
            self.tp_history.append(adjusted_detection)

            # Decay epsilon
            if self.epsilon > self.epsilon_min:
                self.epsilon *= self.epsilon_decay

            if (episode + 1) % 1000 == 0:
                avg_reward = np.mean(self.reward_history[-1000:])
                logger.info(
                    f"Episode {episode+1}/{episodes} - "
                    f"Avg Reward: {avg_reward:.3f}, "
                    f"Threshold: {self.current_threshold:.3f}, "
                    f"Epsilon: {self.epsilon:.4f}"
                )

        logger.info("Q-learning training complete")
        return {
            "rewards": self.reward_history,
            "thresholds": self.threshold_history,
            "fp_rates": self.fp_history,
            "detection_rates": self.tp_history,
        }

    def get_optimal_threshold(
        self,
        alert_volume: float,
        fp_rate: float,
        detection_rate: float,
        time_of_day: float,
    ) -> float:
        """Get the optimal threshold for current conditions.

        Args:
            alert_volume: Current alert volume
            fp_rate: Current false positive rate
            detection_rate: Current detection rate
            time_of_day: Current hour (0-23)

        Returns:
            Optimal threshold value
        """
        state = self._discretize_state(alert_volume, fp_rate, detection_rate, time_of_day)
        action = self.get_action(state, training=False)
        return self.apply_action(action)

    def get_threshold(self, state: int) -> float:
        """Get threshold for a discrete state.

        Args:
            state: State index

        Returns:
            Threshold value
        """
        action = self.get_action(state, training=False)
        return self.apply_action(action)

    def save(self, path: str | Path) -> None:
        """Save the trained agent."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({
                "q_table": self.q_table,
                "alpha": self.alpha,
                "gamma": self.gamma,
                "epsilon": self.epsilon,
                "current_threshold": self.current_threshold,
                "reward_history": self.reward_history,
            }, f)
        logger.info(f"Agent saved to {path}")

    def load(self, path: str | Path) -> None:
        """Load a trained agent."""
        with open(path, "rb") as f:
            data = pickle.load(f)
        self.q_table = data["q_table"]
        self.alpha = data["alpha"]
        self.gamma = data["gamma"]
        self.epsilon = data["epsilon"]
        self.current_threshold = data["current_threshold"]
        self.reward_history = data.get("reward_history", [])
        logger.info(f"Agent loaded from {path}")

    def get_policy_summary(self) -> dict[str, object]:
        """Get a summary of the learned policy.

        Returns:
            Policy summary dictionary
        """
        optimal_actions = np.argmax(self.q_table, axis=1)
        action_counts = {
            "increase": int(np.sum(optimal_actions == 0)),
            "decrease": int(np.sum(optimal_actions == 1)),
            "maintain": int(np.sum(optimal_actions == 2)),
        }

        return {
            "q_table_shape": list(self.q_table.shape),
            "epsilon": self.epsilon,
            "current_threshold": self.current_threshold,
            "action_distribution": action_counts,
            "avg_reward": float(np.mean(self.reward_history[-100:])) if self.reward_history else 0.0,
        }
