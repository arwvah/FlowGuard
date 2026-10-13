import argparse
import json
import math
import signal
import sqlite3
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from scapy.all import get_if_list
from scapy.error import Scapy_Exception

from flowguard.config import Config
from flowguard.demo import generate, run_demo
from flowguard.service import run


def parser():
    root = argparse.ArgumentParser(description="FlowGuard — explainable network traffic indicators")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("interfaces", help="List capture interfaces")
    desktop = commands.add_parser("desktop", help="Open FlowGuard in its own desktop window")
    desktop.add_argument("--db", help="Existing database; default: persistent desktop demo")
    installer = commands.add_parser("install-desktop", help="Install the Omarchy app-menu entry and icon")
    installer.add_argument("--db", help="Make the menu entry open this existing database")
    for command in ("learn", "analyze", "monitor"):
        item = commands.add_parser(command)
        item.add_argument("--db", default="data/flowguard.sqlite")
        item.add_argument("--config")
        if command == "learn":
            source = item.add_mutually_exclusive_group(required=True)
            source.add_argument("--pcap")
            source.add_argument("--interface")
            item.add_argument("--name", default="normal")
        elif command == "analyze":
            item.add_argument(
                "--pcap", "--file", dest="pcap", required=True, help="PCAP or PCAPNG capture file"
            )
        else:
            item.add_argument("--interface", required=True)
        if command in ("monitor", "learn"):
            item.add_argument("--seconds", type=float, default=120 if command == "learn" else None)
        if command != "learn":
            item.add_argument("--baseline-id", type=int, help="Default: latest baseline in this database")
    for command in ("generate-demo", "demo"):
        item = commands.add_parser(command)
        item.add_argument("--output", default="data/demo")
        if command == "demo":
            item.add_argument("--db", default="data/demo.sqlite")
    dashboard = commands.add_parser("dashboard")
    dashboard.add_argument("--db", default="data/flowguard.sqlite")
    dashboard.add_argument("--port", type=int, default=8501)
    return root


def main(argv=None):
    root = parser()
    args = root.parse_args(argv)
    try:
        if args.command in ("desktop", "install-desktop"):
            from flowguard.desktop import main as desktop_main

            desktop_args = ["--install"] if args.command == "install-desktop" else []
            if args.db:
                desktop_args.extend(["--db", args.db])
            return desktop_main(desktop_args)
        elif args.command == "interfaces":
            print("\n".join(get_if_list()))
        elif args.command == "generate-demo":
            print(generate(args.output).resolve())
        elif args.command == "demo":
            print(json.dumps(run_demo(args.output, args.db), indent=2))
        elif args.command == "dashboard":
            if not 1 <= args.port <= 65535:
                raise ValueError("Dashboard port must be in 1..65535")
            return subprocess.call(
                [
                    sys.executable,
                    "-m",
                    "streamlit",
                    "run",
                    str(Path(__file__).with_name("dashboard.py")),
                    "--server.address=127.0.0.1",
                    "--server.headless=true",
                    f"--server.port={args.port}",
                    "--browser.gatherUsageStats=false",
                    "--theme.base=dark",
                    "--theme.primaryColor=#53e0bd",
                    "--theme.backgroundColor=#0a101c",
                    "--theme.secondaryBackgroundColor=#131e2e",
                    "--",
                    "--db",
                    str(Path(args.db).resolve()),
                ]
            )
        else:
            config = Config.load(args.config)
            seconds = getattr(args, "seconds", None)
            if seconds is not None and (not math.isfinite(seconds) or seconds <= 0):
                raise ValueError("--seconds must be a finite positive number")

            def interrupt(*_):
                raise KeyboardInterrupt

            previous = signal.signal(signal.SIGTERM, interrupt)
            try:
                result = run(
                    config,
                    args.db,
                    pcap=getattr(args, "pcap", None),
                    interface=getattr(args, "interface", None),
                    seconds=seconds,
                    learning=args.command == "learn",
                    name=getattr(args, "name", "normal"),
                    baseline_id=getattr(args, "baseline_id", None),
                )
            finally:
                signal.signal(signal.SIGTERM, previous)
            print(json.dumps(asdict(result), indent=2))
            if args.command != "learn" and result.baseline_id is None:
                print(
                    "No baseline: rate/bandwidth detection disabled; rule detectors remain active.",
                    file=sys.stderr,
                )
        return 0
    except (ValueError, OSError, sqlite3.Error, Scapy_Exception) as error:
        print(f"flowguard: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
