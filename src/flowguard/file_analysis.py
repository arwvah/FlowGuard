"""Independent offline reports: bounded previews, full-capture rule analysis.

No database, baseline training, packet transmission, or payload retention.
"""

from collections import Counter, deque
from dataclasses import asdict, dataclass, field

from flowguard.config import Config
from flowguard.detection import Detector
from flowguard.ingest import read_pcap
from flowguard.metrics import Aggregator

MAX_UPLOAD_BYTES = 100 * 1024 * 1024


@dataclass
class CaptureReport:
    name: str
    config: dict
    packet_count: int = 0
    byte_count: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    window_count: int = 0
    alert_count: int = 0
    untracked_source_packets: int = 0
    omitted_conversation_packets: int = 0
    protocols: dict = field(default_factory=dict)
    detector_counts: dict = field(default_factory=dict)
    packets: list = field(default_factory=list)
    windows: list = field(default_factory=list)
    alerts: list = field(default_factory=list)
    conversations: list = field(default_factory=list)


def analyze_capture(
    capture,
    *,
    name="capture",
    config=None,
    packet_limit=10_000,
    window_limit=1_000,
    alert_limit=5_000,
    conversation_limit=2_048,
    max_packets=1_000_000,
):
    """Analyze every packet up to a hard work limit; never return an incomplete success.

    Preview limits do not affect detection. Exceeding max_packets fails explicitly.
    Conversations are directional source/destination/protocol/port tuples.
    """
    for limit in (packet_limit, window_limit, alert_limit, conversation_limit, max_packets):
        if type(limit) is not int or limit <= 0:
            raise ValueError("Analysis limits must be positive integers")
    cfg = config or Config()
    report = CaptureReport(str(name), asdict(cfg))
    detector = Detector(cfg)
    protocols, detector_counts = Counter(), Counter()
    windows, alerts = deque(maxlen=window_limit), deque(maxlen=alert_limit)
    conversations = {}

    def emit(window):
        found = detector.process(window)
        report.window_count += 1
        report.alert_count += len(found)
        report.untracked_source_packets += window.untracked_source_packets
        detector_counts.update(alert.detector for alert in found)
        alerts.extend(asdict(alert) for alert in found)
        windows.append(
            {
                "timestamp": window.start,
                "packets": window.packets,
                "bytes": window.bytes,
                "packet_rate": window.packet_rate,
                "byte_rate": window.byte_rate,
                "partial": window.partial,
            }
        )

    aggregator = Aggregator(cfg, emit)
    for number, packet in enumerate(read_pcap(capture), 1):
        if number > max_packets:
            raise ValueError(f"Capture exceeds the {max_packets:,}-packet interactive limit; use CLI analyze")
        aggregator.add(packet)
        report.packet_count += 1
        report.byte_count += packet.size
        if report.first_timestamp is None:
            report.first_timestamp = packet.timestamp
        report.last_timestamp = packet.timestamp
        protocols[packet.protocol] += 1
        if len(report.packets) < packet_limit:
            report.packets.append({"number": number, **asdict(packet)})
        key = (
            packet.source,
            packet.destination,
            packet.protocol,
            packet.source_port,
            packet.destination_port,
        )
        if key not in conversations:
            if len(conversations) >= conversation_limit:
                report.omitted_conversation_packets += 1
                continue
            conversations[key] = {
                "source": packet.source,
                "destination": packet.destination,
                "protocol": packet.protocol,
                "source_port": packet.source_port,
                "destination_port": packet.destination_port,
                "packets": 0,
                "bytes": 0,
            }
        conversations[key]["packets"] += 1
        conversations[key]["bytes"] += packet.size
    aggregator.finish()
    if not report.packet_count:
        raise ValueError("No packets found in capture")
    report.protocols = dict(protocols)
    report.detector_counts = dict(detector_counts)
    report.windows, report.alerts = list(windows), list(alerts)
    report.conversations = sorted(conversations.values(), key=lambda row: row["bytes"], reverse=True)
    return report
