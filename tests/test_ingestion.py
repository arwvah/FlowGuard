import struct
from dataclasses import replace

import pytest
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, IPv6, PcapWriter, Raw
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6ExtHdrHopByHop

from flowguard.config import Config
from flowguard.detection import Detector
from flowguard.ingest import capture, extract, read_pcap
from flowguard.metrics import Aggregator
from flowguard.models import PacketMeta


@pytest.mark.parametrize(
    "packet,protocol,port",
    [
        (Ether() / IP() / TCP(dport=443, flags="S"), "TCP", 443),
        (Ether() / IPv6() / UDP(dport=53), "UDP", 53),
        (Ether() / IP() / ICMP(), "ICMP", None),
        (Ether() / IPv6() / ICMPv6EchoRequest(), "ICMPv6", None),
        (Ether() / ARP(), "ARP", None),
        (Ether() / IP(proto=47) / Raw(b"example"), "IP-47", None),
        (Ether() / IPv6() / IPv6ExtHdrHopByHop() / TCP(dport=80), "TCP", 80),
        (Ether() / IP() / ICMP(type=3) / IP() / TCP(dport=22), "ICMP", None),
        (Ether() / IPv6(nh=4) / IP() / TCP(dport=22), "IP-4", None),
        (Ether() / IPv6() / IPv6ExtHdrHopByHop(nh=59) / Raw(b"unknown"), "IP-59", None),
    ],
)
def test_extract_protocols_without_payload(packet, protocol, port):
    packet.time = 123.25
    metadata = extract(packet)
    assert metadata.protocol == protocol
    assert metadata.destination_port == port
    assert metadata.timestamp == 123.25
    assert metadata.size == len(packet)
    assert not hasattr(metadata, "payload")


def test_dns_query_metadata_retains_length_not_name():
    name = f"{'a' * 60}.{'b' * 30}.example.test"
    request = Ether() / IP() / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
    response = Ether() / IP() / UDP(sport=53, dport=53000) / DNS(qr=1, qd=DNSQR(qname=name))
    metadata = extract(request)
    assert metadata.dns_query_length == len(name)
    assert name not in repr(metadata)
    assert extract(response).dns_query_length is None


def meta(timestamp, source="host", port=443, flags=0):
    return PacketMeta(timestamp, source, "destination", "TCP", 100, 40000, port, flags)


def test_event_time_windows_and_bounded_idle_gap():
    emitted = []
    aggregator = Aggregator(Config(), emitted.append)
    for timestamp in (1, 2, 9, 10, 19, 1_000_000_000):
        aggregator.add(meta(timestamp))
    aggregator.finish()
    assert [w.packets for w in emitted] == [3, 2, 1]
    assert [w.start for w in emitted] == [0, 10, 1_000_000_000]
    assert [w.partial for w in emitted] == [True, False, True]
    assert emitted[1].packet_rate == 0.2


def test_live_idle_tick_flushes_and_finish_is_idempotent():
    emitted = []
    aggregator = Aggregator(Config(), emitted.append)
    aggregator.add(meta(0))
    aggregator.advance(10)
    aggregator.finish()
    aggregator.finish()
    assert len(emitted) == 1 and not emitted[0].partial


def test_out_of_order_rejected():
    aggregator = Aggregator(Config(), lambda _: None)
    aggregator.add(meta(10))
    with pytest.raises(ValueError, match="Out-of-order"):
        aggregator.add(meta(9))


def test_late_live_packet_cannot_duplicate_closed_window():
    aggregator = Aggregator(Config(), lambda _: None)
    aggregator.add(meta(0))
    aggregator.advance(10)
    with pytest.raises(ValueError, match="window closed"):
        aggregator.add(meta(9))


def test_capture_propagates_callback_error_and_closes_socket(monkeypatch):
    from types import SimpleNamespace

    closed = []
    monkeypatch.setattr("flowguard.ingest.get_if_list", lambda: ["test0"])
    monkeypatch.setattr(
        "flowguard.ingest.conf.L2listen", lambda **_: SimpleNamespace(close=lambda: closed.append(True))
    )

    def fake_sniff(**kwargs):
        assert kwargs["store"] is False and kwargs["chainCC"] is True
        kwargs["prn"](Ether() / IP() / TCP())
        assert kwargs["stop_filter"](None)

    def failed_consumer(_):
        raise ValueError("storage failure")

    monkeypatch.setattr("flowguard.ingest.sniff", fake_sniff)
    with pytest.raises(ValueError, match="storage failure"):
        capture("test0", failed_consumer, lambda _: None, 1)
    assert closed == [True]


def test_source_port_bounds_syn_flags_and_coverage_alert():
    emitted = []
    cfg = replace(Config(), max_sources=1, max_ports_per_source=22)
    aggregator = Aggregator(cfg, emitted.append)
    for port in range(30):
        aggregator.add(meta(1, port=port, flags=18))
    aggregator.add(meta(2, source="omitted", flags=2))
    aggregator.finish()
    window = emitted[0]
    assert window.packets == 31
    assert len(window.sources) == 1
    assert len(window.sources["host"].ports) == 22
    assert window.sources["host"].ports_truncated
    assert window.sources["host"].syn_packets == 0
    assert window.untracked_source_packets == 1
    assert {a.detector for a in Detector(cfg).process(window)} == {"port_scan", "tracking_limit"}


def test_strict_truncated_pcap(tmp_path):
    path = tmp_path / "valid.pcap"
    with PcapWriter(str(path), linktype=1) as writer:
        writer.write(Ether() / IP() / TCP())
    original = path.read_bytes()
    assert len(list(read_pcap(path))) == 1
    for content in (b"garbage", original[:28], original[:-1]):
        path.write_bytes(content)
        with pytest.raises(ValueError, match="PCAP"):
            list(read_pcap(path))


@pytest.mark.parametrize("endian,nano", [("<", False), (">", False), ("<", True), (">", True)])
def test_pcap_timestamp_precision_and_endianness(tmp_path, endian, nano):
    raw = bytes(Ether() / IP() / UDP())
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    path = tmp_path / "capture.pcap"
    path.write_bytes(
        struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
        + struct.pack(endian + "IIII", 100, 250_000_000 if nano else 250_000, len(raw), len(raw))
        + raw
    )
    records = list(read_pcap(path))
    assert records[0].timestamp == 100.25


def test_capture_invalid_interface_and_permissions(monkeypatch):
    monkeypatch.setattr("flowguard.ingest.get_if_list", lambda: ["test0"])
    with pytest.raises(ValueError, match="Unknown interface"):
        capture("missing", None, None, 1)

    def denied(**kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("flowguard.ingest.conf.L2listen", denied)
    with pytest.raises(ValueError, match="permission denied"):
        capture("test0", None, None, 1)


def test_live_capture_handles_reversed_kernel_timestamps(monkeypatch):
    import itertools
    from types import SimpleNamespace

    timestamps = iter(itertools.count(0, 0.1))
    monkeypatch.setattr("flowguard.ingest.time.monotonic", lambda: next(timestamps))
    monkeypatch.setattr("flowguard.ingest.time.time", lambda: 1000)
    monkeypatch.setattr("flowguard.ingest.get_if_list", lambda: ["test0"])
    monkeypatch.setattr("flowguard.ingest.conf.L2listen", lambda **_: SimpleNamespace(close=lambda: None))
    received, ticks = [], []

    def fake_sniff(**kwargs):
        for timestamp in (2000, 1999):
            packet = Ether() / IP() / TCP()
            packet.time = timestamp
            kwargs["prn"](packet)

    monkeypatch.setattr("flowguard.ingest.sniff", fake_sniff)
    capture("test0", received.append, ticks.append, 0.6)
    assert len(received) == 2
    assert 1000 <= received[0].timestamp < received[1].timestamp < ticks[0] < 1001
