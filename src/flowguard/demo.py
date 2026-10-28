"""Local fixtures only: PcapWriter writes files; this module never sends packets."""

from pathlib import Path

from scapy.all import DNS, DNSQR, GRE, ICMP, IP, TCP, UDP, Ether, IPv6, PcapWriter, Raw

from flowguard.config import Config
from flowguard.service import run
from flowguard.storage import Store

EPOCH = 1_700_000_000
EXPECTED = {"packet_rate", "bandwidth", "port_scan", "syn_excess", "unexpected_protocol", "unexpected_port"}
EXPECTED |= {"host_sweep", "suspicious_tcp_flags", "dns_burst"}
EXPECTED |= {"icmp_echo_flood", "tcp_reset_burst"}
EXPECTED |= {"dns_tunnel_heuristic"}


def packet(index, kind):
    source = f"192.0.2.{1 + index % 4}"
    destination = "198.51.100.20"
    network = IP(src=source, dst=destination)
    transport = TCP(sport=40000 + index % 4, dport=443, flags="PA")
    size = 80
    if kind == "normal" and index % 4 == 0:
        network = IPv6(src="2001:db8::1", dst="2001:db8::20")
        transport = UDP(sport=53000, dport=53)
    elif kind == "spike":
        size = 1000
    elif kind == "scan":
        network = IP(src="192.0.2.10", dst=destination)
        transport = TCP(sport=45000, dport=1000 + index, flags="A")
    elif kind == "syn":
        network = IP(src="192.0.2.11", dst=destination)
        transport = TCP(sport=40000 + index, dport=443, flags="S")
    elif kind == "unexpected":
        transport = GRE()
    elif kind == "port":
        transport = UDP(sport=53000, dport=4444)
    elif kind == "sweep":
        network = IP(src="192.0.2.12", dst=f"198.51.100.{index + 1}")
        transport = TCP(sport=45000, dport=443, flags="S")
    elif kind == "flags":
        network = IP(src="192.0.2.13", dst=destination)
        transport = TCP(sport=45000, dport=443, flags="FPU")
    elif kind == "dns":
        network = IP(src="192.0.2.14", dst=destination)
        transport = UDP(sport=53000, dport=53)
    elif kind == "dns_tunnel":
        network = IP(src="192.0.2.17", dst=destination)
        qname = f"{'a' * 60}.{'b' * 30}.example.test"
        transport = UDP(sport=53000 + index, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
    elif kind == "echo":
        network = IP(src="192.0.2.15", dst=destination)
        transport = ICMP(type=8)
    elif kind == "reset":
        network = IP(src="192.0.2.16", dst=destination)
        transport = TCP(sport=443, dport=45000, flags="RA")
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / network / transport / Raw(b"x" * size)


def write_fixture(path, kinds, counts, start):
    with PcapWriter(str(path), linktype=1, sync=True) as writer:
        for window_index, (kind, count) in enumerate(zip(kinds, counts, strict=True)):
            for index in range(count):
                item = packet(index, kind)
                item.time = start + window_index * 10 + index * 9.0 / count
                writer.write(item)
        # A normal sentinel closes the final full window and becomes a partial window itself.
        item = packet(1, "normal")
        item.time = start + len(kinds) * 10
        writer.write(item)


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    recipes = {
        "normal": (["normal"] * 8, [40] * 8),
        "spike": (["spike"] * 3, [400] * 3),
        "scan": (["scan"], [45]),
        "syn": (["syn"], [80]),
        "unexpected": (["unexpected", "port"], [12, 12]),
        "suspicious": (
            ["sweep", "flags", "dns", "echo", "reset", "dns_tunnel"],
            [20, 3, 200, 100, 50, 5],
        ),
        "mixed": (
            ["normal"] * 2
            + ["spike"] * 3
            + [
                "scan",
                "syn",
                "unexpected",
                "port",
                "normal",
                "sweep",
                "flags",
                "dns",
                "echo",
                "reset",
                "dns_tunnel",
            ],
            [40, 40, 400, 400, 400, 45, 80, 12, 12, 40, 20, 3, 200, 100, 50, 5],
        ),
    }
    for index, (name, (kinds, counts)) in enumerate(recipes.items()):
        write_fixture(directory / f"{name}.pcap", kinds, counts, EPOCH + index * 1000)
    return directory


def run_demo(directory, db):
    directory = generate(directory)
    config = Config()
    learned = run(config, db, pcap=directory / "normal.pcap", learning=True, name="demo-normal", mode="demo")
    normal = run(config, db, pcap=directory / "normal.pcap", baseline_id=learned.baseline_id, mode="demo")
    mixed = run(config, db, pcap=directory / "mixed.pcap", baseline_id=learned.baseline_id, mode="demo")
    store = Store(db)
    try:
        observed = {
            row[0]
            for row in store.connection.execute(
                "SELECT DISTINCT detector FROM alerts WHERE session_id=?", (mixed.session_id,)
            )
        }
    finally:
        store.close()
    if normal.alerts or not EXPECTED <= observed:
        raise ValueError(
            f"Demo verification failed: normal alerts={normal.alerts}, missing={EXPECTED - observed}"
        )
    return {
        "baseline_id": learned.baseline_id,
        "normal_alerts": normal.alerts,
        "session_id": mixed.session_id,
        "alerts": mixed.alerts,
        "detectors": sorted(observed),
        "db": str(db),
    }
