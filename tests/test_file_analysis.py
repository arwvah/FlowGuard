import io
import json
import struct
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from scapy.all import ICMP, IP, TCP, Ether, IPv6, PcapNgWriter, PcapWriter
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest

from flowguard.cli import main
from flowguard.config import Config
from flowguard.file_analysis import analyze_capture
from flowguard.ingest import extract, read_pcap
from flowguard.service import run


def block(kind, body, endian="<"):
    assert len(body) % 4 == 0
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def section(endian="<"):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def interface(endian="<", linktype=1, snaplen=65535, options=b""):
    return block(1, struct.pack(endian + "HHI", linktype, 0, snaplen) + options, endian)


def enhanced(raw, timestamp=1_000_000, interface_id=0, endian="<", legacy=False):
    header = (
        struct.pack(endian + "HH", interface_id, 0) if legacy else struct.pack(endian + "I", interface_id)
    )
    header += struct.pack(endian + "4I", timestamp >> 32, timestamp & 0xFFFFFFFF, len(raw), len(raw))
    return block(2 if legacy else 6, header + raw + b"\0" * (-len(raw) % 4), endian)


def tcp(flags="A", destination="198.51.100.1"):
    return Ether() / IP(src="192.0.2.1", dst=destination) / TCP(sport=50000, dport=443, flags=flags)


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("legacy", [False, True])
def test_pcapng_endianness_and_packet_blocks(endian, legacy):
    raw = bytes(tcp())
    stream = io.BytesIO(
        section(endian) + interface(endian) + enhanced(raw, 1_250_000, endian=endian, legacy=legacy)
    )
    packets = list(read_pcap(stream))
    assert len(packets) == 1 and packets[0].timestamp == 1.25
    assert packets[0].destination_port == 443
    assert not stream.closed


@pytest.mark.parametrize("resolution,ticks", [(9, 1_250_000_000), (0x8A, 1280)])
def test_pcapng_resolution_offset_multiple_interfaces_and_sections(resolution, ticks):
    opts = struct.pack("<HHB3x", 9, 1, resolution) + struct.pack("<HHq", 14, 8, 100)
    data = section() + interface() + interface(options=opts)
    data += enhanced(bytes(tcp()), ticks, interface_id=1)
    data += section(">") + interface(">") + enhanced(bytes(tcp()), 102_000_000, endian=">")
    packets = list(read_pcap(io.BytesIO(data)))
    assert [p.timestamp for p in packets] == [101.25, 102]


def test_pcapng_scapy_writer_and_cli_alias(tmp_path, capsys):
    path = tmp_path / "capture.pcapng"
    with PcapNgWriter(str(path)) as writer:
        packet = tcp()
        packet.time = 100.25
        writer.write(packet)
    packets = list(read_pcap(path))
    assert packets[0].timestamp == 100.25
    assert main(["analyze", "--file", str(path), "--db", str(tmp_path / "capture.sqlite")]) == 0
    assert json.loads(capsys.readouterr().out)["packets"] == 1


@pytest.mark.parametrize(
    "data,error",
    [
        (section()[:-1], "Truncated"),
        (section() + b"\x01", "Truncated"),
        (section() + struct.pack("<II", 1, 0xFFFFFFFC), "block length"),
        (section()[:-4] + struct.pack("<I", 12), "Mismatched"),
        (section() + enhanced(bytes(tcp())), "interface ID"),
        (section() + interface(snaplen=1) + enhanced(bytes(tcp())), "packet length"),
        (section() + interface() + block(6, b"\0" * 16), "packet header"),
        (section() + block(1, b"\0" * 4), "interface description"),
        (section() + interface(linktype=65535) + enhanced(bytes(tcp())), "link type"),
        (section() + interface() + block(3, b"\0" * 4), "no timestamps"),
        (section() + interface(options=struct.pack("<HH", 9, 8)), "option value"),
        (section() + interface(options=struct.pack("<HH", 9, 0)), "resolution"),
        (section() + interface(options=struct.pack("<HH", 14, 0)), "offset"),
        (section() + interface() + section() + enhanced(bytes(tcp())), "interface ID"),
    ],
)
def test_malformed_pcapng_is_an_error(data, error):
    with pytest.raises(ValueError, match=error):
        list(read_pcap(io.BytesIO(data)))


def test_pcapng_skips_unknown_blocks_and_rejects_packet_length():
    data = section() + interface() + block(0x1234, b"test") + enhanced(bytes(tcp()))
    assert len(list(read_pcap(io.BytesIO(data)))) == 1
    bad_packet = block(6, struct.pack("<5I", 0, 0, 0, 100, 100))
    with pytest.raises(ValueError, match="packet length"):
        list(read_pcap(io.BytesIO(section() + interface() + bad_packet)))


def write_packets(path, packets):
    with PcapWriter(str(path), linktype=1) as writer:
        for number, packet in enumerate(packets):
            packet.time = number * 0.01
            writer.write(packet)
    return path


def test_report_checks_packets_after_preview_cap_and_exports_no_payload(tmp_path):
    packets = [tcp()] * 5 + [tcp("FPU")] * 3
    path = write_packets(tmp_path / "sample.pcap", packets)
    report = analyze_capture(path, packet_limit=2, conversation_limit=1)
    assert report.packet_count == 8 and len(report.packets) == 2
    assert report.detector_counts == {"suspicious_tcp_flags": 1}
    assert report.conversations[0]["packets"] == 8
    assert report.byte_count == sum(len(p) for p in packets)
    assert "payload" not in json.dumps(asdict(report))
    with pytest.raises(ValueError, match="interactive limit"):
        analyze_capture(path, max_packets=4)


def test_report_caps_windows_alerts_and_conversations_without_losing_totals():
    data = section() + interface()
    for index in range(4):
        data += enhanced(bytes(tcp("FPU", f"198.51.100.{index + 1}")), index * 10_000_000)
    cfg = replace(Config(), tcp_flags_min_packets=1, cooldown_seconds=0)
    report = analyze_capture(
        io.BytesIO(data), config=cfg, window_limit=2, alert_limit=2, conversation_limit=1
    )
    assert report.window_count == report.alert_count == 4
    assert len(report.windows) == len(report.alerts) == 2
    assert report.detector_counts == {"suspicious_tcp_flags": 4}
    assert report.omitted_conversation_packets == 3


def test_empty_out_of_order_and_invalid_config():
    with pytest.raises(ValueError, match="No packets"):
        analyze_capture(io.BytesIO(section()))
    data = section() + interface() + enhanced(bytes(tcp()), 2_000_000) + enhanced(bytes(tcp()), 1_000_000)
    with pytest.raises(ValueError, match="Out-of-order"):
        analyze_capture(io.BytesIO(data))
    with pytest.raises(ValueError, match="Unknown configuration"):
        Config.from_mapping({"bad_rule": True})


@pytest.mark.parametrize(
    "packet,icmp_type",
    [
        (Ether() / IP() / ICMP(type=8), 8),
        (Ether() / IPv6() / ICMPv6EchoRequest(), 128),
        (Ether() / IPv6() / ICMPv6EchoReply(), 129),
        (tcp(), None),
    ],
)
def test_icmp_metadata(packet, icmp_type):
    assert extract(packet).icmp_type == icmp_type


@pytest.mark.parametrize(
    "packet,expected",
    [
        (Ether() / IP() / ICMP(type=8), "icmp_echo_flood"),
        (Ether() / IPv6() / ICMPv6EchoRequest(), "icmp_echo_flood"),
        (tcp("R"), "tcp_reset_burst"),
    ],
)
def test_new_rules_end_to_end_and_disable(tmp_path, packet, expected):
    path = write_packets(tmp_path / "rule.pcap", [packet] * 100)
    assert expected in analyze_capture(path).detector_counts
    cfg = replace(Config(), icmp_echo_packets=0, rst_min_packets=0)
    assert expected not in analyze_capture(path, config=cfg).detector_counts
    result = run(Config(), tmp_path / "rules.sqlite", pcap=path)
    assert result.alerts >= 1


def test_normal_ping_and_reset_ratio_do_not_alert(tmp_path):
    packets = [Ether() / IP() / ICMP(type=0)] * 100
    packets += [tcp("R")] * 50 + [tcp()] * 100
    report = analyze_capture(write_packets(tmp_path / "normal.pcap", packets))
    assert "icmp_echo_flood" not in report.detector_counts
    assert "tcp_reset_burst" not in report.detector_counts


@pytest.mark.parametrize(
    "kwargs", [{"rst_ratio": 0}, {"rst_ratio": 1.1}, {"rst_min_packets": -1}, {"icmp_echo_packets": True}]
)
def test_new_rule_validation(kwargs):
    with pytest.raises(ValueError):
        Config(**kwargs)


def test_packet_filtering(tmp_path):
    from flowguard.file_dashboard import filter_packets, packet_frame

    path = write_packets(tmp_path / "filters.pcap", [tcp("S"), tcp("R"), Ether() / IP() / ICMP()])
    frame = packet_frame(analyze_capture(path))
    assert len(filter_packets(frame, ["TCP"], "192.0.2", 443, "SYN")) == 1
    assert len(filter_packets(frame, ["TCP"], port=50000, flags="RST")) == 1
    assert filter_packets(frame, ["TCP"], address="[.*").empty
    assert filter_packets(frame, ["ICMP"], port=443).empty


def test_file_dashboard_upload_without_database_and_failed_retry(tmp_path, monkeypatch):
    import streamlit as st
    from streamlit.testing.v1 import AppTest

    import flowguard

    data = (
        section()
        + interface()
        + b"".join(enhanced(bytes(tcp("FPU")), timestamp=1_000_000 + index) for index in range(3))
    )
    upload = io.BytesIO(data)
    upload.name, upload.size = "sample.pcapng", len(data)
    monkeypatch.setattr(
        st, "file_uploader", lambda label, **kwargs: upload if label == "Capture file" else None
    )
    db = tmp_path / "missing.sqlite"
    monkeypatch.setattr("sys.argv", ["dashboard.py", "--db", str(db)])
    app = AppTest.from_file(str(Path(flowguard.__file__).with_name("dashboard.py"))).run()
    app.sidebar.radio[0].set_value("Analyze capture file").run()
    assert not app.exception
    app.button[0].click().run(timeout=30)
    assert not app.exception and not app.error
    assert app.session_state["capture_report"].packet_count == 3
    assert app.session_state["capture_report"].alert_count == 1
    assert not db.exists()
    app.checkbox[0].check().run()
    assert not app.exception
    assert len(app.dataframe[2].value) == 3
    app.text_input[0].set_value("192.0.2").run()
    assert not app.exception
    app.text_input[1].set_value("bad").run()
    assert "Port must" in app.error[0].value
    upload.seek(0)
    upload.truncate()
    upload.write(b"not a capture")
    upload.size = upload.tell()
    app.button[0].click().run()
    assert not app.exception
    assert "Cannot analyze" in app.error[0].value
    assert "capture_report" not in app.session_state
