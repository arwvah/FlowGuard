import math

from flowguard.config import Config
from flowguard.models import PacketMeta, SourceStats, Window


class Aggregator:
    """One active fixed-width event-time window. Empty gaps are represented by timestamps."""

    def __init__(self, config: Config, emit):
        self.config, self.emit = config, emit
        self.current = None
        self.last_timestamp = None
        self.closed_until = None
        self.first_window = True

    def advance(self, timestamp):
        if self.current is not None and timestamp >= self.current.start + self.current.duration:
            self.emit(self.current)
            self.closed_until = self.current.start + self.current.duration
            self.current = None

    def add(self, packet: PacketMeta):
        if self.last_timestamp is not None and packet.timestamp < self.last_timestamp:
            raise ValueError("Out-of-order packet timestamps; sort the capture before analysis (reordercap)")
        if self.closed_until is not None and packet.timestamp < self.closed_until:
            raise ValueError(
                "Packet arrived after its event-time window closed; live capture is falling behind"
            )
        self.last_timestamp = packet.timestamp
        self.advance(packet.timestamp)
        if self.current is None:
            width = self.config.window_seconds
            start = math.floor(packet.timestamp / width) * width
            self.current = Window(
                start,
                width,
                partial=self.first_window and packet.timestamp > start + 1e-6,
                policy_ports={},
            )
            self.first_window = False
        window = self.current
        window.packets += 1
        window.bytes += packet.size
        window.protocols[packet.protocol] = window.protocols.get(packet.protocol, 0) + 1
        if packet.destination_port is not None:
            window.ports[packet.destination_port] = window.ports.get(packet.destination_port, 0) + 1
        # A service-port heuristic, not connection tracking. Keep raw metrics intact.
        service_reply = (
            self.config.ignore_service_replies
            and packet.source_port in self.config.allowed_ports
            and (packet.protocol == "UDP" or (packet.protocol == "TCP" and bool(packet.tcp_flags & 16)))
        )
        if packet.destination_port is not None and not service_reply:
            window.policy_ports[packet.destination_port] = (
                window.policy_ports.get(packet.destination_port, 0) + 1
            )
        if packet.source not in window.sources:
            if len(window.sources) >= self.config.max_sources:
                window.untracked_source_packets += 1
                return
            window.sources[packet.source] = SourceStats()
        source = window.sources[packet.source]
        source.packets += 1
        if packet.destination_port is not None and not service_reply:
            if len(source.ports) < self.config.max_ports_per_source:
                source.ports.add(packet.destination_port)
            elif packet.destination_port not in source.ports:
                source.ports_truncated = True
        if packet.protocol == "TCP":
            source.tcp_packets += 1
            flags = packet.tcp_flags
            source.rst_packets += bool(flags & 4)
            syn = bool(flags & 2 and not flags & 16)
            source.syn_packets += syn
            if syn and self.config.host_sweep_hosts:
                if len(source.syn_hosts) < self.config.max_hosts_per_source:
                    source.syn_hosts.add(packet.destination)
                elif packet.destination not in source.syn_hosts:
                    source.hosts_truncated = True
            # NULL, FIN-only, Xmas (FIN/PSH/URG without ACK), SYN+FIN, SYN+RST.
            control = flags & 0x3F
            source.suspicious_tcp_packets += bool(control in (0, 1, 0x29) or (flags & 2 and flags & 5))
        if packet.protocol == "UDP" and packet.destination_port == 53:
            source.dns_packets += 1
        if (packet.protocol == "ICMP" and packet.icmp_type == 8) or (
            packet.protocol == "ICMPv6" and packet.icmp_type == 128
        ):
            source.echo_requests += 1

    def finish(self):
        if self.current is not None:
            self.current.partial = True
            self.emit(self.current)
            self.current = None
