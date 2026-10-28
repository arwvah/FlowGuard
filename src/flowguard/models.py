from dataclasses import dataclass, field


@dataclass(frozen=True)
class PacketMeta:
    timestamp: float
    source: str
    destination: str
    protocol: str
    size: int
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: int = 0
    icmp_type: int | None = None
    # Length only: FlowGuard never retains the queried DNS name.
    dns_query_length: int | None = None


@dataclass
class SourceStats:
    packets: int = 0
    tcp_packets: int = 0
    syn_packets: int = 0
    ports: set[int] = field(default_factory=set)
    ports_truncated: bool = False
    syn_hosts: set[str] = field(default_factory=set)
    hosts_truncated: bool = False
    suspicious_tcp_packets: int = 0
    dns_packets: int = 0
    rst_packets: int = 0
    echo_requests: int = 0
    long_dns_queries: int = 0


@dataclass
class Window:
    start: float
    duration: float
    packets: int = 0
    bytes: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    ports: dict[int, int] = field(default_factory=dict)
    sources: dict[str, SourceStats] = field(default_factory=dict)
    untracked_source_packets: int = 0
    partial: bool = False
    # None preserves callers constructing windows directly from destination counts.
    policy_ports: dict[int, int] | None = None

    @property
    def packet_rate(self):
        return self.packets / self.duration

    @property
    def byte_rate(self):
        return self.bytes / self.duration


@dataclass(frozen=True)
class Alert:
    timestamp: float
    detector: str
    severity: str
    observed: float
    threshold: float
    reason: str
    source: str | None = None
    destination: str | None = None
    baseline: float | None = None
