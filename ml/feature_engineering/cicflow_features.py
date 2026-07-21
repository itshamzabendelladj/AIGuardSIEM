"""CICFlowMeter-style flow feature extraction for ML-based intrusion detection.

This module implements 84+ flow features inspired by CICFlowMeter for
real-time network flow analysis and ML-based intrusion detection.

Features:
    - Flow duration and timing statistics
    - Packet size statistics (forward/backward/total)
    - Inter-arrival time statistics
    - TCP flag counts and ratios
    - Flow rate statistics
    - Active/idle time statistics
    - Window size statistics
    - Header length statistics

Author: AIGuard Security Team
License: MIT
"""

from __future__ import annotations

import time
import math
import statistics
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class ProtocolType(Enum):
    """Network protocol types."""
    TCP = 6
    UDP = 17
    ICMP = 1
    OTHER = 0


@dataclass
class PacketInfo:
    """Information about a single packet in a flow."""
    timestamp: float  # Unix timestamp in microseconds
    length: int       # Packet length in bytes
    direction: str    # 'forward' or 'backward'
    tcp_flags: int = 0  # TCP flags byte
    header_length: int = 0  # Transport header length
    window_size: int = 0    # TCP window size


@dataclass
class FlowStatistics:
    """Running statistics for a network flow using Welford's algorithm."""
    count: int = 0
    sum: float = 0.0
    min: float = float('inf')
    max: float = float('-inf')
    mean: float = 0.0
    m2: float = 0.0  # Running variance accumulator

    def update(self, value: float) -> None:
        """Update statistics with a new value using Welford's algorithm."""
        self.count += 1
        self.sum += value
        if value < self.min:
            self.min = value
        if value > self.max:
            self.max = value
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        """Calculate population variance."""
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def std(self) -> float:
        """Calculate standard deviation."""
        return math.sqrt(self.variance)

    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary."""
        return {
            'count': self.count,
            'sum': self.sum,
            'min': self.min if self.count > 0 else 0.0,
            'max': self.max if self.count > 0 else 0.0,
            'mean': self.mean,
            'std': self.std,
            'variance': self.variance,
        }


class CICFlowFeatureExtractor:
    """Extract CICFlowMeter-style features from network flows.

    This class maintains state for an active flow and computes 84+ features
    as packets arrive. Features are compatible with CICIDS2017/2018 datasets.

    Usage:
        >>> extractor = CICFlowFeatureExtractor()
        >>> extractor.add_packet(PacketInfo(timestamp=1000, length=512, direction='forward'))
        >>> extractor.add_packet(PacketInfo(timestamp=2000, length=256, direction='backward'))
        >>> features = extractor.extract_features()
        >>> len(features)  # 84 features
    """

    # Feature names in order (84 features)
    FEATURE_NAMES: list[str] = [
        'flow_duration_ms', 'fwd_pkt_len_min', 'fwd_pkt_len_max', 'fwd_pkt_len_mean',
        'fwd_pkt_len_std', 'bwd_pkt_len_min', 'bwd_pkt_len_max', 'bwd_pkt_len_mean',
        'bwd_pkt_len_std', 'flow_bytes_per_s', 'flow_pkt_per_s', 'flow_iat_min',
        'flow_iat_max', 'flow_iat_mean', 'flow_iat_std', 'fwd_iat_min', 'fwd_iat_max',
        'fwd_iat_mean', 'fwd_iat_std', 'bwd_iat_min', 'bwd_iat_max', 'bwd_iat_mean',
        'bwd_iat_std', 'pkt_len_min', 'pkt_len_max', 'pkt_len_mean', 'pkt_len_std',
        'pkt_len_var', 'fin_flag_count', 'syn_flag_count', 'rst_flag_count',
        'psh_flag_count', 'ack_flag_count', 'urg_flag_count', 'cwr_flag_count',
        'ece_flag_count', 'syn_flag_rate', 'rst_flag_rate', 'psh_flag_rate',
        'ack_flag_rate', 'fwd_pkt_count', 'bwd_pkt_count', 'fwd_byte_count',
        'bwd_byte_count', 'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags',
        'bwd_urg_flags', 'fwd_pkt_per_s', 'bwd_pkt_per_s', 'fwd_bytes_per_s',
        'bwd_bytes_per_s', 'pkt_len_min_max_ratio', 'total_bytes', 'total_packets',
        'down_up_ratio', 'avg_pkt_size', 'fwd_bwd_pkt_size_ratio',
        'fwd_bwd_pkt_ratio', 'fwd_bwd_byte_ratio', 'avg_header_len', 'min_header_len',
        'max_header_len', 'active_min', 'active_max', 'active_mean', 'active_std',
        'idle_min', 'idle_max', 'idle_mean', 'idle_std', 'fwd_pkt_len_min_max_ratio',
        'bwd_pkt_len_min_max_ratio', 'subflow_fwd_pkts', 'subflow_bwd_pkts',
        'fwd_win_min', 'fwd_win_max', 'fwd_win_mean', 'bwd_win_min', 'bwd_win_max',
        'bwd_win_mean', 'total_header_bytes', 'init_win_bytes_fwd', 'protocol',
    ]

    def __init__(self) -> None:
        """Initialize the feature extractor."""
        self._packets: list[PacketInfo] = []
        self._start_time: Optional[float] = None
        self._last_time: Optional[float] = None
        self._last_fwd_time: Optional[float] = None
        self._last_bwd_time: Optional[float] = None

        # Packet size statistics
        self._fwd_pkt_sizes: list[float] = []
        self._bwd_pkt_sizes: list[float] = []
        self._all_pkt_sizes: list[float] = []

        # Inter-arrival times
        self._flow_iats: list[float] = []
        self._fwd_iats: list[float] = []
        self._bwd_iats: list[float] = []

        # TCP flags
        self._fin_count: int = 0
        self._syn_count: int = 0
        self._rst_count: int = 0
        self._psh_count: int = 0
        self._ack_count: int = 0
        self._urg_count: int = 0
        self._cwr_count: int = 0
        self._ece_count: int = 0
        self._fwd_psh: int = 0
        self._bwd_psh: int = 0
        self._fwd_urg: int = 0
        self._bwd_urg: int = 0

        # Byte counts
        self._fwd_bytes: int = 0
        self._bwd_bytes: int = 0

        # Header lengths
        self._header_lengths: list[float] = []

        # Window sizes
        self._fwd_windows: list[int] = []
        self._bwd_windows: list[int] = []

        # Active/idle times
        self._active_times: list[float] = []
        self._idle_times: list[float] = []
        self._current_active_start: Optional[float] = None
        self._last_activity_time: Optional[float] = None

        # Protocol
        self._protocol: int = 0

        # Initial window sizes
        self._init_win_fwd: int = 0
        self._init_win_bwd: int = 0

    def add_packet(self, packet: PacketInfo) -> None:
        """Add a packet to the flow and update statistics."""
        if self._start_time is None:
            self._start_time = packet.timestamp
            self._current_active_start = packet.timestamp

        # Update inter-arrival times
        if self._last_time is not None:
            iat = packet.timestamp - self._last_time
            self._flow_iats.append(iat)

            # Check for idle period (> 1 second)
            if iat > 1000000:  # 1 second in microseconds
                if self._last_activity_time is not None:
                    active_duration = self._last_activity_time - (self._current_active_start or 0)
                    self._active_times.append(active_duration)
                    self._idle_times.append(iat)
                self._current_active_start = packet.timestamp

        self._last_activity_time = packet.timestamp
        self._last_time = packet.timestamp

        # Direction-specific IAT
        if packet.direction == 'forward':
            if self._last_fwd_time is not None:
                self._fwd_iats.append(packet.timestamp - self._last_fwd_time)
            self._last_fwd_time = packet.timestamp
            self._fwd_pkt_sizes.append(float(packet.length))
            self._fwd_bytes += packet.length
            if not self._fwd_windows and packet.window_size > 0:
                self._init_win_fwd = packet.window_size
            if packet.window_size > 0:
                self._fwd_windows.append(packet.window_size)
        else:
            if self._last_bwd_time is not None:
                self._bwd_iats.append(packet.timestamp - self._last_bwd_time)
            self._last_bwd_time = packet.timestamp
            self._bwd_pkt_sizes.append(float(packet.length))
            self._bwd_bytes += packet.length
            if not self._bwd_windows and packet.window_size > 0:
                self._init_win_bwd = packet.window_size
            if packet.window_size > 0:
                self._bwd_windows.append(packet.window_size)

        self._all_pkt_sizes.append(float(packet.length))
        self._header_lengths.append(float(packet.header_length))

        # TCP flags (FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32, ECE=64, CWR=128)
        flags = packet.tcp_flags
        if flags & 0x01:
            self._fin_count += 1
        if flags & 0x02:
            self._syn_count += 1
        if flags & 0x04:
            self._rst_count += 1
        if flags & 0x08:
            self._psh_count += 1
            if packet.direction == 'forward':
                self._fwd_psh += 1
            else:
                self._bwd_psh += 1
        if flags & 0x10:
            self._ack_count += 1
        if flags & 0x20:
            self._urg_count += 1
            if packet.direction == 'forward':
                self._fwd_urg += 1
            else:
                self._bwd_urg += 1
        if flags & 0x40:
            self._ece_count += 1
        if flags & 0x80:
            self._cwr_count += 1

    def _safe_stats(self, values: list[float]) -> tuple[float, float, float, float]:
        """Calculate min, max, mean, std safely."""
        if not values:
            return 0.0, 0.0, 0.0, 0.0
        return (
            min(values),
            max(values),
            statistics.mean(values),
            statistics.stdev(values) if len(values) > 1 else 0.0,
        )

    def extract_features(self) -> list[float]:
        """Extract all 84 flow features.

        Returns:
            List of 84 float values in CICFlowMeter feature order.
        """
        if not self._packets and not self._fwd_pkt_sizes and not self._bwd_pkt_sizes:
            return [0.0] * 84

        duration_ms = ((self._last_time or 0) - (self._start_time or 0)) / 1000.0
        total_packets = len(self._fwd_pkt_sizes) + len(self._bwd_pkt_sizes)
        total_bytes = self._fwd_bytes + self._bwd_bytes

        # Forward packet sizes
        fwd_min, fwd_max, fwd_mean, fwd_std = self._safe_stats(self._fwd_pkt_sizes)
        bwd_min, bwd_max, bwd_mean, bwd_std = self._safe_stats(self._bwd_pkt_sizes)
        all_min, all_max, all_mean, all_std = self._safe_stats(self._all_pkt_sizes)
        all_var = all_std ** 2

        # IAT statistics
        flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std = self._safe_stats(self._flow_iats)
        fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std = self._safe_stats(self._fwd_iats)
        bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std = self._safe_stats(self._bwd_iats)

        # Flow rates
        flow_bps = (total_bytes * 1000.0 / duration_ms) if duration_ms > 0 else 0.0
        flow_pps = (total_packets * 1000.0 / duration_ms) if duration_ms > 0 else 0.0
        fwd_pps = (len(self._fwd_pkt_sizes) * 1000.0 / duration_ms) if duration_ms > 0 else 0.0
        bwd_pps = (len(self._bwd_pkt_sizes) * 1000.0 / duration_ms) if duration_ms > 0 else 0.0
        fwd_bps = (self._fwd_bytes * 1000.0 / duration_ms) if duration_ms > 0 else 0.0
        bwd_bps = (self._bwd_bytes * 1000.0 / duration_ms) if duration_ms > 0 else 0.0

        # Flag ratios
        syn_rate = self._syn_count / total_packets if total_packets > 0 else 0.0
        rst_rate = self._rst_count / total_packets if total_packets > 0 else 0.0
        psh_rate = self._psh_count / total_packets if total_packets > 0 else 0.0
        ack_rate = self._ack_count / total_packets if total_packets > 0 else 0.0

        # Down/up ratio
        down_up = (len(self._bwd_pkt_sizes) / len(self._fwd_pkt_sizes)
                   if self._fwd_pkt_sizes else 0.0)

        # Average packet size
        avg_pkt = (total_bytes / total_packets) if total_packets > 0 else 0.0

        # Ratios
        fwd_bwd_size_ratio = (fwd_mean / bwd_mean) if bwd_mean > 0 else 0.0
        fwd_bwd_pkt_ratio = (len(self._fwd_pkt_sizes) / len(self._bwd_pkt_sizes)
                             if self._bwd_pkt_sizes else 0.0)
        fwd_bwd_byte_ratio = (self._fwd_bytes / self._bwd_bytes
                              if self._bwd_bytes > 0 else 0.0)
        pkt_min_max_ratio = (all_min / all_max) if all_max > 0 else 0.0
        fwd_min_max_ratio = (fwd_min / fwd_max) if fwd_max > 0 else 0.0
        bwd_min_max_ratio = (bwd_min / bwd_max) if bwd_max > 0 else 0.0

        # Header lengths
        hdr_min, hdr_max, hdr_mean, _ = self._safe_stats(self._header_lengths)
        total_hdr = hdr_mean * total_packets

        # Active/idle times
        active_min, active_max, active_mean, active_std = self._safe_stats(self._active_times)
        idle_min, idle_max, idle_mean, idle_std = self._safe_stats(self._idle_times)

        # Window sizes
        fwd_win_min = float(min(self._fwd_windows)) if self._fwd_windows else 0.0
        fwd_win_max = float(max(self._fwd_windows)) if self._fwd_windows else 0.0
        fwd_win_mean = float(statistics.mean(self._fwd_windows)) if self._fwd_windows else 0.0
        bwd_win_min = float(min(self._bwd_windows)) if self._bwd_windows else 0.0
        bwd_win_max = float(max(self._bwd_windows)) if self._bwd_windows else 0.0
        bwd_win_mean = float(statistics.mean(self._bwd_windows)) if self._bwd_windows else 0.0

        return [
            duration_ms, fwd_min, fwd_max, fwd_mean, fwd_std,
            bwd_min, bwd_max, bwd_mean, bwd_std,
            flow_bps, flow_pps, flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std,
            fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std,
            bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std,
            all_min, all_max, all_mean, all_std, all_var,
            float(self._fin_count), float(self._syn_count), float(self._rst_count),
            float(self._psh_count), float(self._ack_count), float(self._urg_count),
            float(self._cwr_count), float(self._ece_count),
            syn_rate, rst_rate, psh_rate, ack_rate,
            float(len(self._fwd_pkt_sizes)), float(len(self._bwd_pkt_sizes)),
            float(self._fwd_bytes), float(self._bwd_bytes),
            float(self._fwd_psh), float(self._bwd_psh), float(self._fwd_urg), float(self._bwd_urg),
            fwd_pps, bwd_pps, fwd_bps, bwd_bps,
            pkt_min_max_ratio, float(total_bytes), float(total_packets),
            down_up, avg_pkt, fwd_bwd_size_ratio, fwd_bwd_pkt_ratio, fwd_bwd_byte_ratio,
            hdr_mean, hdr_min, hdr_max,
            active_min, active_max, active_mean, active_std,
            idle_min, idle_max, idle_mean, idle_std,
            fwd_min_max_ratio, bwd_min_max_ratio,
            float(total_packets), float(total_packets),  # Subflow pkts
            fwd_win_min, fwd_win_max, fwd_win_mean,
            bwd_win_min, bwd_win_max, bwd_win_mean,
            total_hdr, float(self._init_win_fwd),
            float(self._protocol),
        ]

    def reset(self) -> None:
        """Reset the extractor for a new flow."""
        self.__init__()

    @classmethod
    def get_feature_names(cls) -> list[str]:
        """Get the list of feature names."""
        return cls.FEATURE_NAMES.copy()
