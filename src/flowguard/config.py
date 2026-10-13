import math
import tomllib
from dataclasses import asdict, dataclass, fields
from pathlib import Path


@dataclass(frozen=True)
class Config:
    window_seconds: float = 10.0
    min_baseline_windows: int = 6
    spike_factor: float = 3.0
    z_score: float = 4.0
    min_packet_rate: float = 20.0
    min_byte_rate: float = 10_000.0
    persistence_windows: int = 2
    cooldown_seconds: float = 30.0
    scan_ports: int = 20
    syn_min_packets: int = 40
    syn_ratio: float = 0.8
    unexpected_min_packets: int = 3
    allowed_protocols: tuple[str, ...] = ("TCP", "UDP", "ICMP", "ICMPv6", "ARP")
    allowed_ports: tuple[int, ...] = (53, 80, 443)
    max_sources: int = 2048
    max_ports_per_source: int = 1024
    max_cooldown_keys: int = 8192
    max_records: int = 100_000
    host_sweep_hosts: int = 20
    max_hosts_per_source: int = 256
    tcp_flags_min_packets: int = 3
    dns_burst_packets: int = 200
    ignore_service_replies: bool = True
    icmp_echo_packets: int = 100
    rst_min_packets: int = 50
    rst_ratio: float = 0.8

    def __post_init__(self):
        ints = {f.name for f in fields(self) if f.type is int}
        for name, value in asdict(self).items():
            if name == "ignore_service_replies":
                if type(value) is not bool:
                    raise ValueError("ignore_service_replies must be a boolean")
                continue
            if name in ("allowed_protocols", "allowed_ports"):
                continue
            if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
                raise ValueError(f"{name} must be a finite number")
            if name in ints and type(value) is not int:
                raise ValueError(f"{name} must be an integer")
            zero_allowed = {
                "cooldown_seconds",
                "host_sweep_hosts",
                "tcp_flags_min_packets",
                "dns_burst_packets",
                "icmp_echo_packets",
                "rst_min_packets",
            }
            if value < 0 or (name not in zero_allowed and value == 0):
                raise ValueError(f"{name} must be positive (rule thresholds and cooldown may be zero)")
        if self.min_baseline_windows < 2:
            raise ValueError("min_baseline_windows must be at least 2")
        if self.spike_factor <= 1 or self.syn_ratio > 1:
            raise ValueError("spike_factor must exceed 1 and syn_ratio must be in (0, 1]")
        if self.rst_ratio > 1:
            raise ValueError("rst_ratio must be in (0, 1]")
        if not 1 <= self.scan_ports < self.max_ports_per_source <= 65536:
            raise ValueError("Require 1 <= scan_ports < max_ports_per_source <= 65536")
        if self.host_sweep_hosts > self.max_hosts_per_source:
            raise ValueError("host_sweep_hosts must not exceed max_hosts_per_source")
        if not isinstance(self.allowed_protocols, (list, tuple)) or any(
            not isinstance(p, str) or not p.strip() for p in self.allowed_protocols
        ):
            raise ValueError("allowed_protocols must be a list of nonempty protocol names")
        if not isinstance(self.allowed_ports, (list, tuple)) or any(
            type(p) is not int or not 0 <= p <= 65535 for p in self.allowed_ports
        ):
            raise ValueError("allowed_ports must contain integers in 0..65535")

    @classmethod
    def load(cls, path: str | None):
        if path is None:
            return cls()
        with Path(path).open("rb") as file:
            data = tomllib.load(file)
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, data):
        unknown = data.keys() - {f.name for f in fields(cls)}
        if unknown:
            raise ValueError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
        return cls(**data)
