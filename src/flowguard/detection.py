from collections import OrderedDict

from flowguard.models import Alert, Window


class Detector:
    def __init__(self, config, baseline=None):
        self.config, self.baseline = config, baseline
        if baseline and (
            baseline.window_seconds != config.window_seconds or baseline.samples < config.min_baseline_windows
        ):
            raise ValueError(
                "Baseline window size or sample count is incompatible with configuration; relearn it"
            )
        self.cooldowns = OrderedDict()
        self.streaks = {"packet_rate": 0, "bandwidth": 0}
        self.previous_end = None

    def process(self, window: Window) -> list[Alert]:
        cfg = self.config
        now = window.start + window.duration
        alerts = []
        while self.cooldowns and next(iter(self.cooldowns.values())) + cfg.cooldown_seconds <= now:
            self.cooldowns.popitem(last=False)

        def emit(
            detector, observed, threshold, reason, source=None, baseline=None, severity="medium", key=None
        ):
            identity = (detector, key or source)
            if identity in self.cooldowns:
                return
            alerts.append(Alert(now, detector, severity, observed, threshold, reason, source, None, baseline))
            self.cooldowns[identity] = now
            if len(self.cooldowns) > cfg.max_cooldown_keys:
                self.cooldowns.popitem(last=False)

        if self.previous_end is None or abs(window.start - self.previous_end) > 1e-6:
            self.streaks = dict.fromkeys(self.streaks, 0)
        self.previous_end = now
        if self.baseline:
            base = self.baseline
            for name, value, mean, std, minimum, unit in (
                (
                    "packet_rate",
                    window.packet_rate,
                    base.packet_mean,
                    base.packet_std,
                    cfg.min_packet_rate,
                    "packets/s",
                ),
                ("bandwidth", window.byte_rate, base.byte_mean, base.byte_std, cfg.min_byte_rate, "bytes/s"),
            ):
                threshold = max(minimum, mean * cfg.spike_factor, mean + cfg.z_score * std)
                self.streaks[name] = self.streaks[name] + 1 if value > threshold and not window.partial else 0
                if self.streaks[name] >= cfg.persistence_windows:
                    emit(
                        name,
                        value,
                        threshold,
                        f"{value:.1f} {unit} for {self.streaks[name]} consecutive windows; threshold {threshold:.1f}, baseline {mean:.1f}.",
                        baseline=mean,
                        severity="high",
                    )
        for address, source in window.sources.items():
            if cfg.icmp_echo_packets and source.echo_requests >= cfg.icmp_echo_packets:
                emit(
                    "icmp_echo_flood",
                    source.echo_requests,
                    cfg.icmp_echo_packets,
                    f"{address} sent {source.echo_requests} ICMP echo requests in {window.duration:g} "
                    "seconds; possible ping flood or active diagnostics. Echo replies are excluded.",
                    source=address,
                )
            rst_ratio = source.rst_packets / max(source.tcp_packets, 1)
            if (
                cfg.rst_min_packets
                and source.rst_packets >= cfg.rst_min_packets
                and rst_ratio >= cfg.rst_ratio
            ):
                emit(
                    "tcp_reset_burst",
                    source.rst_packets,
                    cfg.rst_min_packets,
                    f"{address} sent {source.rst_packets} TCP resets in {window.duration:g} seconds "
                    f"({rst_ratio:.0%} of its TCP packets; ratio threshold {cfg.rst_ratio:.0%}). "
                    "Investigate rejected connections, scanning, or service failures; resets do not prove an attack.",
                    source=address,
                )
            if cfg.host_sweep_hosts and len(source.syn_hosts) >= cfg.host_sweep_hosts:
                qualifier = "at least " if source.hosts_truncated else ""
                emit(
                    "host_sweep",
                    len(source.syn_hosts),
                    cfg.host_sweep_hosts,
                    f"{address} sent initial TCP SYNs to {qualifier}{len(source.syn_hosts)} distinct hosts "
                    f"in {window.duration:g} seconds; possible host sweep or legitimate service discovery.",
                    source=address,
                )
            if cfg.tcp_flags_min_packets and source.suspicious_tcp_packets >= cfg.tcp_flags_min_packets:
                emit(
                    "suspicious_tcp_flags",
                    source.suspicious_tcp_packets,
                    cfg.tcp_flags_min_packets,
                    f"{address} sent {source.suspicious_tcp_packets} TCP packets with NULL, FIN-only, "
                    f"Xmas, SYN+FIN or SYN+RST flags in {window.duration:g} seconds; investigate scanning "
                    "or malformed traffic.",
                    source=address,
                )
            if cfg.dns_burst_packets and source.dns_packets >= cfg.dns_burst_packets:
                emit(
                    "dns_burst",
                    source.dns_packets,
                    cfg.dns_burst_packets,
                    f"{address} sent {source.dns_packets} UDP packets to port 53 in "
                    f"{window.duration:g} seconds; investigate excessive DNS activity. "
                    "Resolvers and busy clients can legitimately reach this threshold; payloads are not inspected.",
                    source=address,
                )
            if len(source.ports) > cfg.scan_ports:
                qualifier = "at least " if source.ports_truncated else ""
                emit(
                    "port_scan",
                    len(source.ports),
                    cfg.scan_ports,
                    f"{address} contacted {qualifier}{len(source.ports)} distinct destination ports in {window.duration:g} seconds; threshold is {cfg.scan_ports}.",
                    source=address,
                )
            ratio = source.syn_packets / max(source.tcp_packets, 1)
            if source.syn_packets >= cfg.syn_min_packets and ratio >= cfg.syn_ratio:
                emit(
                    "syn_excess",
                    source.syn_packets,
                    cfg.syn_min_packets,
                    f"{address} sent {source.syn_packets} SYN-without-ACK packets in {window.duration:g} seconds ({ratio:.0%} of its TCP traffic); thresholds {cfg.syn_min_packets} packets and {cfg.syn_ratio:.0%}.",
                    source=address,
                    severity="high",
                )
        for protocol, count in window.protocols.items():
            if (
                cfg.allowed_protocols
                and protocol not in cfg.allowed_protocols
                and count >= cfg.unexpected_min_packets
            ):
                emit(
                    "unexpected_protocol",
                    count,
                    cfg.unexpected_min_packets,
                    f"{count} {protocol} packets; protocol is outside configured allowlist {', '.join(cfg.allowed_protocols)}.",
                    key=protocol,
                )
        policy_ports = window.ports if window.policy_ports is None else window.policy_ports
        for port, count in policy_ports.items():
            if cfg.allowed_ports and port not in cfg.allowed_ports and count >= cfg.unexpected_min_packets:
                emit(
                    "unexpected_port",
                    count,
                    cfg.unexpected_min_packets,
                    f"{count} packets to destination port {port}; port is outside configured allowlist {list(cfg.allowed_ports)}.",
                    key=str(port),
                )
        if window.untracked_source_packets:
            emit(
                "tracking_limit",
                window.untracked_source_packets,
                cfg.max_sources,
                f"Source tracking cap ({cfg.max_sources}) reached; {window.untracked_source_packets} packets counted globally but omitted from per-source detection.",
                severity="low",
            )
        return alerts
