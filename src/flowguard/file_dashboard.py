"""Capture upload and packet investigation UI, separate from live database views."""

import json
import tomllib
from dataclasses import asdict

import pandas as pd
import streamlit as st
from scapy.error import Scapy_Exception

from flowguard.config import Config
from flowguard.file_analysis import MAX_UPLOAD_BYTES, analyze_capture


def packet_frame(report):
    frame = pd.DataFrame(report.packets)
    frame.insert(1, "time_utc", pd.to_datetime(frame.timestamp, unit="s", utc=True, errors="coerce"))
    for name in ("source_port", "destination_port", "icmp_type"):
        frame[name] = frame[name].astype("Int64")
    frame["tcp_flags_hex"] = frame.tcp_flags.map(lambda value: f"0x{value:02x}")
    return frame


def filter_packets(frame, protocols, address="", port=None, flags="All"):
    selected = frame[frame.protocol.isin(protocols)]
    if address:
        selected = selected[
            selected.source.str.contains(address, regex=False)
            | selected.destination.str.contains(address, regex=False)
        ]
    if port is not None:
        selected = selected[(selected.source_port == port) | (selected.destination_port == port)]
    if flags != "All":
        mask = 2 if flags == "SYN" else 4
        selected = selected[
            (selected.protocol == "TCP") & selected.tcp_flags.map(lambda value: bool(value & mask))
        ]
    return selected


def render():
    st.subheader("Analyze capture file")
    st.write("Open a PCAP or PCAPNG capture to explore packets, conversations, and suspicious traffic.")
    st.caption(
        "Processed on this FlowGuard server, without transmitting packets. Up to 100 MiB / 1,000,000 packets. "
        "Results stay in this browser session; export them before closing it."
    )
    capture = st.file_uploader("Capture file", type=["pcap", "pcapng", "cap"], key="capture_upload")
    with st.expander("Detection rules and settings"):
        st.write(
            "Enabled by default: port scans, host sweeps, SYN excess, suspicious TCP flags, DNS bursts, "
            "ICMP echo floods, TCP reset bursts, and unexpected protocols/ports."
        )
        st.caption(
            "Default thresholds per source / 10 seconds: >20 ports, 20 hosts, 40 SYNs at 80%, "
            "3 suspicious flag packets, 200 DNS packets, 100 echo requests, 50 resets at 80%. "
            "Port policy allows 53, 80, 443; tune it for your network."
        )
        settings = st.file_uploader("Optional rule configuration (TOML)", type=["toml"], key="capture_config")
        st.caption(
            "Use config.example.toml. No baseline is applied; learned rate/bandwidth rules are inactive."
        )
    if st.button("Analyze file", type="primary", disabled=capture is None):
        # A failed upload must never leave a previous successful report on screen.
        st.session_state.pop("capture_report", None)
        try:
            if capture.size > MAX_UPLOAD_BYTES:
                raise ValueError("Capture exceeds 100 MiB; use CLI analyze for larger files")
            if settings is not None and settings.size > 64 * 1024:
                raise ValueError("Rule configuration exceeds 64 KiB")
            cfg = (
                Config.from_mapping(tomllib.loads(settings.getvalue().decode("utf-8")))
                if settings
                else Config()
            )
            with st.spinner("Reading capture and evaluating rules…"):
                report = analyze_capture(capture, name=capture.name, config=cfg)
            st.session_state.capture_report = report
        except (ValueError, OSError, UnicodeError, Scapy_Exception) as error:
            st.error(f"Cannot analyze capture: {error}")
    report = st.session_state.get("capture_report")
    if report is None:
        return
    st.markdown("### Capture results")
    st.write(f"Analyzed file: {report.name}")
    if capture is not None:
        st.caption(
            "Results reflect the last successful analysis. Click Analyze file after changing the file or rules."
        )
    a, b, c, d = st.columns(4)
    a.metric("Packets analyzed", f"{report.packet_count:,}")
    b.metric("Wire bytes", f"{report.byte_count:,}")
    c.metric("Capture duration", f"{report.last_timestamp - report.first_timestamp:,.3f} s")
    d.metric("Alerts", f"{report.alert_count:,}")
    st.info(
        "Rules indicate activity to investigate, not confirmed attacks. Statistical baseline rules are inactive."
    )
    if report.untracked_source_packets:
        st.warning(
            f"Source tracking cap: {report.untracked_source_packets:,} packets lacked per-source detection."
        )
    st.download_button(
        "Export analysis · JSON",
        json.dumps(asdict(report), indent=2),
        file_name="flowguard-analysis.json",
        mime="application/json",
    )
    with st.expander("Configuration used for this analysis"):
        st.json(report.config)
    st.subheader("Traffic overview")
    st.dataframe(pd.DataFrame(report.protocols.items(), columns=["Protocol", "Packets"]), hide_index=True)
    timeline = pd.DataFrame(report.windows)
    timeline["UTC"] = pd.to_datetime(timeline.timestamp, unit="s", utc=True, errors="coerce")
    rate, bandwidth = st.columns(2)
    rate.caption("Packets per second")
    rate.line_chart(timeline.set_index("UTC")[["packet_rate"]])
    bandwidth.caption("Wire bytes per second")
    bandwidth.line_chart(timeline.set_index("UTC")[["byte_rate"]])
    st.caption(
        f"Showing the latest {len(report.windows):,} of {report.window_count:,} active windows. "
        "Rates use the full window duration, including partial windows; idle gaps are omitted."
    )
    st.subheader("Suspicious traffic")
    st.caption(
        f"Showing the latest {len(report.alerts):,} of {report.alert_count:,} alerts after cooldown suppression."
    )
    focus_alert = None
    if report.alerts:
        alerts = pd.DataFrame(report.alerts)
        detectors = st.multiselect(
            "Rule", sorted(alerts.detector.unique()), default=sorted(alerts.detector.unique())
        )
        alerts = alerts[alerts.detector.isin(detectors)]
        st.dataframe(
            alerts[["timestamp", "detector", "severity", "source", "observed", "threshold", "reason"]],
            hide_index=True,
            width="stretch",
        )
        st.download_button(
            "Export filtered alerts · CSV",
            alerts.to_csv(index=False),
            file_name="flowguard-file-alerts.csv",
            mime="text/csv",
        )
        if not alerts.empty:
            selected_alert = st.selectbox(
                "Inspect finding",
                alerts.index.tolist(),
                format_func=lambda index: (
                    f"{index + 1} · {alerts.loc[index, 'detector']} · "
                    f"{alerts.loc[index, 'source'] or 'all sources'}"
                ),
            )
            finding = alerts.loc[selected_alert]
            st.write(finding.reason)
            st.caption(f"Observed: {finding.observed:g} · Threshold: {finding.threshold:g}")
            if st.checkbox("Show this finding's source and time window in the packet explorer"):
                focus_alert = finding
    else:
        st.success("No configured rules triggered. This does not establish that the capture is safe.")
    st.subheader("Packet explorer")
    st.caption(
        f"First {len(report.packets):,} of {report.packet_count:,} packets. Filters and packet CSV apply to this preview. "
        "Rules evaluated the entire capture. Payloads are not retained in results."
    )
    frame = packet_frame(report)
    left, middle, right = st.columns(3)
    protocols = left.multiselect(
        "Packet protocol", sorted(frame.protocol.unique()), default=sorted(frame.protocol.unique())
    )
    address = middle.text_input("Source or destination contains", key="packet_address")
    port_text = right.text_input("Source or destination port", placeholder="443", key="packet_port")
    flags = st.selectbox("TCP flag", ["All", "SYN", "RST"])
    port = None
    if port_text:
        try:
            port = int(port_text)
            if not 0 <= port <= 65535:
                raise ValueError
        except ValueError:
            st.error("Port must be an integer from 0 to 65535.")
            return
    filtered = filter_packets(frame, protocols, address, port, flags)
    if focus_alert is not None:
        filtered = filtered[
            (filtered.timestamp >= focus_alert.timestamp - report.config["window_seconds"])
            & (filtered.timestamp < focus_alert.timestamp)
        ]
        if focus_alert.source is not None:
            filtered = filtered[filtered.source == focus_alert.source]
    if filtered.empty:
        st.info("No packets in the retained preview match these filters.")
    st.dataframe(filtered, hide_index=True, width="stretch")
    st.download_button(
        "Export filtered packets · CSV",
        filtered.to_csv(index=False),
        file_name="flowguard-packets.csv",
        mime="text/csv",
    )
    if not filtered.empty:
        number = st.selectbox("Inspect packet number", filtered.number.tolist())
        st.json(report.packets[number - 1])
    st.subheader("Conversations")
    st.caption(
        "Directional address/port pairs, sorted by wire bytes; no stream reassembly. "
        f"{report.omitted_conversation_packets:,} packets omitted from this table after its 2,048-conversation cap."
    )
    st.dataframe(pd.DataFrame(report.conversations), hide_index=True, width="stretch")
