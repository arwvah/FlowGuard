"""Read-only database dashboard plus independent, in-memory capture-file analysis."""

import argparse
import json
import sqlite3
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="FlowGuard · Traffic intelligence", page_icon="◈", layout="wide")
st.markdown(
    """<style>
.stApp {background: #0a101c; color: #e6eef8;}
.block-container {padding-top: 2.5rem; max-width: 1600px;}
h1 {letter-spacing: -1.8px;} h3 {letter-spacing: -.5px;}
[data-testid="stMetric"] {background: #131e2e; border: 1px solid #26344b; border-radius: 12px; padding: 18px;}
[data-testid="stMetricLabel"] {color: #94a8c4;}
[data-testid="stSidebar"] {background: #101a29;}
.eyebrow {color:#53e0bd; font-size:12px; letter-spacing:3px; font-weight:700;}
</style>""",
    unsafe_allow_html=True,
)

argparser = argparse.ArgumentParser()
argparser.add_argument("--db", default="data/demo.sqlite")
args, _ = argparser.parse_known_args()
db_path = Path(args.db).resolve()


@contextmanager
def connect():
    connection = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        yield connection
    finally:
        connection.close()


def style(figure, height=320):
    figure.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0a101c",
        plot_bgcolor="#0a101c",
        font_color="#a6bad4",
        margin={"l": 15, "r": 15, "t": 25, "b": 15},
        height=height,
        legend={"orientation": "h", "y": 1.15},
        hovermode="x unified",
    )
    figure.update_xaxes(gridcolor="#1c293b")
    figure.update_yaxes(gridcolor="#1c293b")
    return figure


st.markdown('<div class="eyebrow">NETWORK OBSERVABILITY / LOCAL FIRST</div>', unsafe_allow_html=True)
st.title("FlowGuard")
st.caption("Understand your traffic. Investigate what changes.")
page = st.sidebar.radio("Workspace", ["Traffic dashboard", "Analyze capture file"])
if page == "Analyze capture file":
    from flowguard.file_dashboard import render

    render()
    st.stop()
try:
    with connect() as connection:
        sessions = pd.read_sql_query("SELECT * FROM sessions ORDER BY id DESC LIMIT 200", connection)
except (sqlite3.Error, pd.errors.DatabaseError) as error:
    st.error(f"Cannot read FlowGuard database: {error}")
    st.info("Choose Analyze capture file in the sidebar to open a PCAP/PCAPNG without a database.")
    st.code("flowguard demo\nflowguard dashboard --db data/demo.sqlite")
    st.stop()
if sessions.empty:
    st.info("No capture sessions yet. Start the CLI demo or monitor process, then reload this page.")
    st.stop()

with st.sidebar:
    st.markdown("### ◈ Control room")
    session_id = st.selectbox(
        "Capture session",
        sessions["id"].tolist(),
        format_func=lambda value: f"#{value} · {sessions.loc[sessions.id == value, 'mode'].iloc[0].upper()}",
    )
    st.caption("Reload the page to discover new sessions.")
    limit = st.select_slider("Recent windows", options=[30, 100, 300, 1000], value=100)
    st.divider()
    st.caption("DATABASE")
    st.code(db_path.name)
    st.caption("Read-only connection · refreshes every 5 seconds. Capture runs independently.")
    st.info("Alerts are indicators for investigation, not proof of an attack.")


@st.fragment(run_every="5s")
def content():
    try:
        with connect() as connection:
            session = pd.read_sql_query(
                "SELECT * FROM sessions WHERE id=?", connection, params=(session_id,)
            ).iloc[0]
            metrics = pd.read_sql_query(
                "SELECT * FROM metrics WHERE session_id=? ORDER BY timestamp DESC LIMIT ?",
                connection,
                params=(session_id, limit),
            ).sort_values("timestamp")
            alerts = pd.read_sql_query(
                "SELECT * FROM alerts WHERE session_id=? ORDER BY timestamp DESC,id DESC LIMIT 5000",
                connection,
                params=(session_id,),
            )
            baseline = pd.read_sql_query(
                "SELECT * FROM baselines WHERE id=?",
                connection,
                params=(None if pd.isna(session.baseline_id) else int(session.baseline_id),),
            )
    except (sqlite3.Error, pd.errors.DatabaseError) as error:
        st.error(f"Database read failed: {error}")
        return
    mode = str(session["mode"]).upper()
    st.markdown(
        f"**{mode} DATA** · Session #{session_id} · {session['status']} · {'Learning' if session.learning else 'Detection'}"
    )
    st.caption(f"Input: {session['input']} · All chart times are UTC · Rates are per fixed window")
    if metrics.empty:
        st.info("Waiting for the first completed window…")
        return
    metrics["time"] = pd.to_datetime(metrics.timestamp, unit="s", utc=True)
    complete = metrics[metrics.partial == 0]
    latest = complete.iloc[-1] if not complete.empty else metrics.iloc[-1]
    columns = st.columns(4)
    rate_help = "Latest complete window; uses a partial window only when no complete window is available."
    columns[0].metric("LATEST PACKET RATE", f"{latest.packet_rate:,.1f} pps", help=rate_help)
    columns[1].metric("LATEST BANDWIDTH", f"{latest.byte_rate / 1000:,.2f} kB/s", help=rate_help)
    columns[2].metric("PACKETS IN VIEW", f"{metrics.packets.sum():,}")
    columns[3].metric("ALERTS LOADED", f"{len(alerts):,}", help="Most recent 5,000 alerts in this session")
    base = json.loads(baseline.iloc[0]["data"]) if not baseline.empty else None
    if base:
        st.success(
            f"Baseline #{int(session.baseline_id)} ready · {base['samples']} complete active windows · "
            f"{base['packet_mean']:.1f} ± {base['packet_std']:.1f} pps · Explicit learning only"
        )
    else:
        st.warning(
            "No learned baseline attached. Rate/bandwidth detectors are inactive; configured rule detectors still operate outside learning sessions."
        )
    if metrics.untracked.sum():
        st.warning(
            f"Source tracking limit reached: {metrics.untracked.sum():,} packets omitted from per-source analysis in this view."
        )
    st.subheader("Traffic timeline")
    chart = go.Figure()
    chart.add_trace(
        go.Scatter(
            x=metrics.time,
            y=metrics.packet_rate,
            name="Packets/s",
            mode="lines",
            fill="tozeroy",
            line={"color": "#53e0bd", "width": 2},
            fillcolor="rgba(83,224,189,.08)",
        )
    )
    if base:
        cfg = json.loads(session.config)
        threshold = max(
            cfg["min_packet_rate"],
            base["packet_mean"] * cfg["spike_factor"],
            base["packet_mean"] + cfg["z_score"] * base["packet_std"],
        )
        chart.add_hline(y=threshold, line_dash="dot", line_color="#ffbf69", annotation_text="Rate threshold")
    st.plotly_chart(style(chart), width="stretch")
    bandwidth = px.area(
        metrics,
        x="time",
        y="byte_rate",
        color_discrete_sequence=["#819bff"],
        labels={"time": "UTC", "byte_rate": "Bytes/s"},
    )
    st.plotly_chart(style(bandwidth, 210), width="stretch")
    st.caption(
        "First/last partial windows use the full window denominator; rate detection and baseline learning exclude them. Idle gaps have no stored rows."
    )
    protocols, sources, ports = Counter(), Counter(), Counter()
    for _, row in metrics.iterrows():
        protocols.update(json.loads(row.protocols))
        sources.update(json.loads(row.sources))
        ports.update(json.loads(row.ports))
    left, right = st.columns([1, 1.5])
    with left:
        st.subheader("Protocol mix")
        fig = px.pie(
            names=list(protocols),
            values=list(protocols.values()),
            hole=0.7,
            color_discrete_sequence=["#53e0bd", "#819bff", "#ffbf69", "#ff758f", "#56b9e9"],
        )
        fig.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(style(fig), width="stretch")
    with right:
        st.subheader("Most active sources")
        top = pd.DataFrame(sources.most_common(8), columns=["Source", "Packets"]).iloc[::-1]
        st.plotly_chart(
            style(px.bar(top, x="Packets", y="Source", orientation="h", color_discrete_sequence=["#53e0bd"])),
            width="stretch",
        )
    with st.expander("Destination port counts"):
        st.dataframe(
            pd.DataFrame(ports.most_common(30), columns=["Destination port", "Packets"]), hide_index=True
        )
    st.subheader("Investigation queue")
    st.caption(
        "Filters and CSV cover the latest 5,000 retained alerts in this session, independent of the chart window selection."
    )
    if alerts.empty:
        st.info("No alerts recorded in this session.")
        return
    alerts["time"] = pd.to_datetime(alerts.timestamp, unit="s", utc=True)
    a, b, c = st.columns(3)
    severity = a.multiselect("Severity", ["high", "medium", "low"], default=["high", "medium", "low"])
    detectors = b.multiselect(
        "Detector", sorted(alerts.detector.unique()), default=sorted(alerts.detector.unique())
    )
    source = c.text_input("Source contains", placeholder="192.0.2.")
    filtered = alerts[
        alerts.severity.isin(severity)
        & alerts.detector.isin(detectors)
        & alerts.source.fillna("").str.contains(source, regex=False)
    ]
    st.dataframe(
        filtered[["id", "time", "severity", "detector", "source", "observed", "threshold", "reason"]],
        hide_index=True,
        width="stretch",
    )
    st.download_button(
        "↓ Export filtered alerts · CSV",
        filtered.to_csv(index=False).encode(),
        file_name=f"flowguard-session-{session_id}.csv",
        mime="text/csv",
    )
    if not filtered.empty:
        selected = st.selectbox("Inspect alert", filtered.id.tolist())
        row = filtered[filtered.id == selected].iloc[0]
        with st.container(border=True):
            st.markdown(f"**{row.detector.replace('_', ' ').title()} · {row.severity.upper()}**")
            st.write(row.reason)
            st.caption(f"Observed {row.observed:g} · threshold {row.threshold:g} · UTC {row.time}")
            st.write(
                "Review expected workloads, host activity, and capture coverage before drawing conclusions."
            )


content()
