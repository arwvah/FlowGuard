"""Omarchy desktop lifecycle: a private Chromium app window and an owned local server."""

import argparse
import fcntl
import hashlib
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def xdg_directory(variable, fallback):
    value = os.environ.get(variable)
    return Path(value) if value and Path(value).is_absolute() else Path.home() / fallback


def data_directory():
    return xdg_directory("XDG_DATA_HOME", ".local/share") / "flowguard"


def default_database():
    return data_directory() / "flowguard.sqlite"


def notify(message):
    executable = shutil.which("notify-send")
    if executable:
        try:
            subprocess.run(
                [executable, "--app-name=FlowGuard", "--icon=flowguard", "FlowGuard", message],
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            pass  # Notifications are optional; errors still reach stderr and the launch log.


def browser_command(browser, url, profile):
    return [
        browser,
        f"--app={url}",
        f"--user-data-dir={profile}",
        "--class=flowguard",
        "--name=flowguard",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-mode",
        "--window-size=1440,960",
    ]


def server_command(database, port, token):
    return [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(Path(__file__).with_name("dashboard.py")),
        "--server.address=127.0.0.1",
        f"--server.port={port}",
        f"--server.baseUrlPath={token}",
        "--server.headless=true",
        "--server.fileWatcherType=none",
        "--browser.gatherUsageStats=false",
        "--client.toolbarMode=minimal",
        "--theme.base=dark",
        "--theme.primaryColor=#53e0bd",
        "--theme.backgroundColor=#0a101c",
        "--theme.secondaryBackgroundColor=#131e2e",
        "--",
        "--db",
        str(database),
    ]


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_ready(process, url, timeout=30):
    deadline = time.monotonic() + timeout
    # Local readiness must not travel through a user's HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("The local dashboard stopped before it was ready")
        try:
            with opener.open(f"{url}/_stcore/health", timeout=0.5) as response:
                if response.status == 200 and response.read(16).strip() == b"ok":
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise RuntimeError("The local dashboard did not become ready within 30 seconds")


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except ProcessLookupError:
        pass
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def prepare_database(database, automatic, log):
    if database.is_file():
        return
    if not automatic:
        raise ValueError(f"Database does not exist: {database}. Analyze a capture or run the demo first.")
    database.parent.mkdir(parents=True, exist_ok=True)
    notify("Preparing your first offline demo. No capture permissions are needed.")
    # Generate atomically: interrupted initialization must never leave a seemingly ready empty database.
    staging = database.with_name(f".initial-{uuid.uuid4().hex}.sqlite")
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "flowguard.cli",
                "demo",
                "--db",
                str(staging),
                "--output",
                str(database.parent / "demo"),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=120,
        )
        staging.replace(database)
    finally:
        for suffix in ("", "-wal", "-shm"):
            staging.with_name(staging.name + suffix).unlink(missing_ok=True)


def launch(database=None):
    automatic = database is None
    database = Path(database).expanduser().resolve() if database else default_database().resolve()
    browser = shutil.which("chromium")
    if browser is None:
        raise ValueError("Chromium is required. On Omarchy install it with: omarchy pkg add chromium")
    if not (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")):
        raise ValueError("Open FlowGuard from your Omarchy desktop session; no display is available")
    state = xdg_directory("XDG_STATE_HOME", ".local/state") / "flowguard"
    cache = xdg_directory("XDG_CACHE_HOME", ".cache") / "flowguard"
    state.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    identity = hashlib.sha256(os.fsencode(database)).hexdigest()[:16]
    log_path = state / f"desktop-{identity}.log"
    with (cache / f"{identity}.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            notify("FlowGuard is already open for this database. Switch to its existing window.")
            return 0
        # A fresh log per launch; keep one previous log for troubleshooting.
        if log_path.exists():
            log_path.replace(log_path.with_suffix(".previous.log"))
        server = window = None
        with log_path.open("w", buffering=1) as log:
            try:
                prepare_database(database, automatic, log)
                token = f"flowguard-{uuid.uuid4().hex}"
                port = free_port()
                url = f"http://127.0.0.1:{port}/{token}"
                log.write(f"Database: {database}\nDashboard: {url}\n")
                server = subprocess.Popen(
                    server_command(database, port, token),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                wait_ready(server, url)
                window = subprocess.Popen(
                    browser_command(browser, url, cache / f"browser-{identity}"),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                while window.poll() is None:
                    if server.poll() is not None:
                        raise RuntimeError("The local dashboard stopped unexpectedly")
                    time.sleep(0.25)
                if window.returncode:
                    raise RuntimeError(f"Chromium exited with status {window.returncode}")
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                raise RuntimeError(f"{error}. Details: {log_path}") from error
            finally:
                stop_process(window)
                stop_process(server)
    return 0


def desktop_exec_argument(value):
    # Exec quoting occurs before .desktop string escaping (handled by Omarchy's installer).
    escaped = value.replace("%", "%%")
    for character in ("\\", '"', "`", "$"):
        escaped = escaped.replace(character, "\\" + character)
    return f'"{escaped}"'


def install(database=None):
    database = Path(database).expanduser().resolve() if database else None
    if database is not None and not database.is_file():
        raise ValueError(f"Database does not exist: {database}")
    omarchy = shutil.which("omarchy")
    if not omarchy:
        raise ValueError("Desktop installation requires Omarchy's 'omarchy webapp install' command")
    if not shutil.which("chromium"):
        raise ValueError("Install Chromium first: omarchy pkg add chromium")
    launcher = Path.home() / ".local/bin/flowguard-desktop"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    # Use the venv interpreter path, not its resolved symlink to the global Python executable.
    launcher.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + ' -m flowguard.desktop "$@"\n')
    launcher.chmod(0o755)
    icon = Path(__file__).with_name("assets") / "flowguard.svg"
    command = desktop_exec_argument(str(launcher))
    if database is not None:
        command += " --db " + desktop_exec_argument(str(database))
    subprocess.run(
        [
            omarchy,
            "webapp",
            "install",
            "FlowGuard",
            "http://127.0.0.1",
            str(icon),
            command,
        ],
        check=True,
    )
    desktop = Path.home() / ".local/share/applications/FlowGuard.desktop"
    desktop.write_text(
        desktop.read_text().replace(
            "Comment=FlowGuard\n", "Comment=Inspect network traffic and investigate unusual activity\n"
        )
    )
    with desktop.open("a") as file:
        file.write(
            "Categories=Network;Monitor;\nKeywords=network;traffic;security;pcap;\nStartupWMClass=flowguard\n"
        )
    updater = shutil.which("update-desktop-database")
    if updater:
        subprocess.run([updater, str(desktop.parent)], check=False)
    print(f"Installed {desktop}\nOpen the Omarchy launcher (Super+Space) and search for FlowGuard.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="FlowGuard desktop app for Omarchy")
    parser.add_argument("--db", help="Open an existing database; default: the desktop app's persistent demo")
    parser.add_argument("--install", action="store_true", help="Install the app-menu entry and icon")
    args = parser.parse_args(argv)

    def interrupt(*_):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        return install(args.db) if args.install else launch(args.db)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FlowGuard: {error}", file=sys.stderr)
        notify(str(error))
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    sys.exit(main())
