from dataclasses import replace

import pytest

from flowguard.config import Config
from flowguard.detection import Detector
from flowguard.metrics import Aggregator
from flowguard.models import PacketMeta


def aggregate(packets, config=None):
    windows = []
    aggregator = Aggregator(config or Config(), windows.append)
    for packet in packets:
        aggregator.add(packet)
    aggregator.finish()
    return windows[0]


def packet(**changes):
    return replace(PacketMeta(0, "client", "server", "TCP", 80, 50000, 443, 2), **changes)


def names(window, config=None):
    return {alert.detector for alert in Detector(config or Config()).process(window)}


def test_host_sweep_boundary_unique_hosts_and_synack_exclusion():
    assert "host_sweep" not in names(aggregate([packet()] * 30))
    for count in (19, 20):
        window = aggregate([packet(destination=f"2001:db8::{i}") for i in range(count)])
        assert ("host_sweep" in names(window)) == (count == 20)
    replies = [packet(destination=str(i), tcp_flags=18) for i in range(30)]
    assert "host_sweep" not in names(aggregate(replies))


def test_host_tracking_bound_and_lower_bound_evidence():
    cfg = replace(Config(), host_sweep_hosts=2, max_hosts_per_source=2)
    window = aggregate([packet(destination=str(i)) for i in range(10)], cfg)
    assert len(window.sources["client"].syn_hosts) == 2
    assert window.sources["client"].hosts_truncated
    alert = Detector(cfg).process(window)[0]
    assert alert.detector == "host_sweep" and "at least 2" in alert.reason


@pytest.mark.parametrize("flags", [0, 1, 0x29, 3, 6])
def test_suspicious_flags_count_threshold(flags):
    assert "suspicious_tcp_flags" not in names(aggregate([packet(tcp_flags=flags)] * 2))
    assert "suspicious_tcp_flags" in names(aggregate([packet(tcp_flags=flags)] * 3))


@pytest.mark.parametrize("flags", [2, 18, 16, 24, 17, 4, 20, 0xC2])
def test_normal_tcp_flags(flags):
    assert "suspicious_tcp_flags" not in names(aggregate([packet(tcp_flags=flags)] * 3))


def test_dns_burst_threshold_direction_and_protocol():
    request = packet(protocol="UDP", destination_port=53)
    assert "dns_burst" not in names(aggregate([request] * 199))
    assert "dns_burst" in names(aggregate([request] * 200))
    assert "dns_burst" not in names(
        aggregate([replace(request, source_port=53, destination_port=50000)] * 200)
    )
    assert "dns_burst" not in names(aggregate([replace(request, protocol="TCP")] * 200))


@pytest.mark.parametrize("protocol,sport,flags", [("TCP", 443, 24), ("TCP", 443, 18), ("UDP", 53, 0)])
def test_service_replies_preserve_metrics_without_port_alerts(protocol, sport, flags):
    replies = [
        packet(protocol=protocol, source_port=sport, destination_port=50000 + i, tcp_flags=flags)
        for i in range(30)
    ]
    replies += [replies[0]] * 3
    window = aggregate(replies)
    assert window.packets == 33 and len(window.ports) == 30
    assert not names(window) & {"port_scan", "unexpected_port"}
    cfg = replace(Config(), ignore_service_replies=False)
    assert {"port_scan", "unexpected_port"} <= names(aggregate(replies, cfg), cfg)


def test_initial_syn_from_allowed_port_is_not_hidden():
    window = aggregate([packet(source_port=443, destination_port=4444)] * 3)
    assert "unexpected_port" in names(window)


def test_new_rules_disable_and_cooldown_is_per_source():
    packets = [packet(tcp_flags=3, destination=str(i)) for i in range(20)]
    packets += [packet(protocol="UDP", destination_port=53)] * 200
    cfg = replace(Config(), host_sweep_hosts=0, tcp_flags_min_packets=0, dns_burst_packets=0)
    assert not names(aggregate(packets, cfg), cfg)
    window = aggregate([packet(tcp_flags=0)] * 3)
    detector = Detector(Config())
    assert len(detector.process(window)) == 1
    assert detector.process(replace(window, start=10)) == []
    other = replace(window, start=20, sources={"other": window.sources["client"]})
    assert len(detector.process(other)) == 1
    assert len(detector.process(replace(window, start=30))) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"host_sweep_hosts": 257},
        {"max_hosts_per_source": 0},
        {"tcp_flags_min_packets": -1},
        {"dns_burst_packets": True},
        {"ignore_service_replies": 1},
        {"host_sweep_hosts": 1.5},
    ],
)
def test_new_config_validation(kwargs):
    with pytest.raises(ValueError):
        Config(**kwargs)
