"""Incremental capture and decoding. Payloads never cross the ingestion boundary."""

import math
import struct
import time
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path

from scapy.all import ARP, ICMP, IP, TCP, UDP, IPv6, conf, get_if_list, sniff
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet6 import _ICMPv6

from flowguard.models import PacketMeta


def extract(packet) -> PacketMeta:
    timestamp = float(packet.time)
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError("Packet has an invalid timestamp")
    network = packet
    while network and not isinstance(network, (IP, IPv6, ARP)):
        network = network.payload
    source, destination = "unknown", "unknown"
    protocol = "OTHER"
    sport = dport = None
    flags = 0
    icmp_type = None
    dns_query_length = None
    if isinstance(network, (IP, IPv6)):
        source, destination = network.src, network.dst
        # Inspect only the outer network's transport; never label an ICMP error as its quoted TCP packet.
        transport = network.payload
        number = network.proto if isinstance(network, IP) else network.nh
        while transport.name.startswith("IPv6 Extension Header"):
            number = transport.nh
            transport = transport.payload
        if isinstance(transport, TCP):
            protocol, sport, dport, flags = (
                "TCP",
                int(transport.sport),
                int(transport.dport),
                int(transport.flags),
            )
        elif isinstance(transport, UDP):
            protocol, sport, dport = "UDP", int(transport.sport), int(transport.dport)
        elif isinstance(transport, ICMP):
            protocol = "ICMP"
            icmp_type = int(transport.type)
        elif isinstance(transport, _ICMPv6):
            protocol = "ICMPv6"
            icmp_type = int(transport.type)
        else:
            protocol = f"IP-{number}"
        # Inspect only the first question and retain its length, never its name.
        # Scoping the lookup to the outer transport avoids quoted/nested packets.
        if protocol in ("TCP", "UDP") and dport == 53 and isinstance(transport.payload, DNS):
            dns = transport.payload
            query = dns.getlayer(DNSQR) if int(dns.qr) == 0 else None
            if query is not None:
                dns_query_length = len(bytes(query.qname).rstrip(b"."))
    elif isinstance(network, ARP):
        source, destination, protocol = network.psrc, network.pdst, "ARP"
    return PacketMeta(
        timestamp,
        source,
        destination,
        protocol,
        int(packet.wirelen or len(packet)),
        sport,
        dport,
        flags,
        icmp_type,
        dns_query_length,
    )


def decode_packet(raw, linktype, timestamp, original):
    decoder = conf.l2types.get(linktype)
    if decoder is None:
        raise ValueError(f"Unsupported PCAP link type: {linktype}")
    try:
        packet = decoder(raw)
        packet.time = timestamp
        packet.wirelen = original
        return extract(packet)
    except (IndexError, struct.error) as error:
        raise ValueError(f"Malformed packet: {error}") from error


def read_pcap(path):
    """Stream classic PCAP or PCAPNG from a path or a seekable binary file.

    Caller-owned streams remain open. Format is identified by content, not suffix.
    """
    magics = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e6),
        b"\xa1\xb2\xc3\xd4": (">", 1e6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e9),
        b"\xa1\xb2\x3c\x4d": (">", 1e9),
    }
    with Path(path).open("rb") if isinstance(path, (str, Path)) else nullcontext(path) as file:
        file.seek(0)
        magic = file.read(4)
        file.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            from flowguard.pcapng import read_pcapng

            yield from read_pcapng(file)
            return
        header = file.read(24)
        if len(header) != 24 or header[:4] not in magics:
            raise ValueError("Invalid capture header; expected a PCAP or PCAPNG file")
        endian, precision = magics[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or not 0 < snaplen <= 16 * 1024 * 1024:
            raise ValueError("Unsupported PCAP version or snapshot length (maximum 16 MiB)")
        if conf.l2types.get(linktype) is None:
            raise ValueError(f"Unsupported PCAP link type: {linktype}")
        while raw_header := file.read(16):
            if len(raw_header) != 16:
                raise ValueError("Truncated PCAP record header")
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", raw_header)
            if captured > snaplen or original < captured or fraction >= precision:
                raise ValueError("Invalid PCAP record length or timestamp")
            raw = file.read(captured)
            if len(raw) != captured:
                raise ValueError("Truncated PCAP packet data")
            yield decode_packet(raw, linktype, seconds + fraction / precision, original)


def capture(interface: str, consume, tick, seconds: float | None = None):
    if interface not in get_if_list():
        raise ValueError(f"Unknown interface {interface!r}; run 'flowguard interfaces'")
    try:
        socket = conf.L2listen(iface=interface)
    except PermissionError as error:
        raise ValueError(
            "Capture permission denied. See README Linux permissions; keep the dashboard unprivileged."
        ) from error
    started = time.monotonic()
    clock_origin = time.time()
    failures = []

    def arrival_time():
        # RX/TX kernel timestamps can be delivered out of order. Use a monotonic
        # receipt clock for live windows; offline decoding retains packet timestamps.
        return clock_origin + (time.monotonic() - started)

    def receive(packet):
        # Scapy catches callback exceptions; forward them explicitly to the CLI.
        try:
            consume(replace(extract(packet), timestamp=arrival_time()))
        except Exception as error:  # noqa: BLE001 - re-raised outside Scapy's exception-swallowing callback.
            failures.append(error)

    try:
        while seconds is None or time.monotonic() - started < seconds:
            timeout = 1.0 if seconds is None else min(1.0, max(0.001, seconds - (time.monotonic() - started)))
            sniff(
                opened_socket=socket,
                store=False,
                prn=receive,
                timeout=timeout,
                stop_filter=lambda _: bool(failures),
                chainCC=True,
            )
            if failures:
                raise failures[0]
            tick(arrival_time())
    finally:
        socket.close()
