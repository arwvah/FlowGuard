import fcntl
import hashlib
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

from flowguard import desktop


@pytest.fixture
def desktop_environment(tmp_path, monkeypatch):
    for variable, directory in (
        ("XDG_DATA_HOME", "data"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_STATE_HOME", "state"),
    ):
        monkeypatch.setenv(variable, str(tmp_path / directory))
    monkeypatch.setenv("WAYLAND_DISPLAY", "test-display")
    monkeypatch.setattr(desktop, "notify", lambda _: None)
    monkeypatch.setattr(desktop.shutil, "which", lambda name: sys.executable if name == "chromium" else None)
    return tmp_path


def test_owned_server_startup_and_shutdown_without_a_gui(desktop_environment, monkeypatch):
    opened = []

    def test_window(browser, url, profile):
        opened.append(url)
        # Exercise real readiness/startup/cleanup without opening a test GUI or capturing packets.
        return [
            sys.executable,
            "-c",
            (
                "import urllib.request,sys; "
                "opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); "
                "page=opener.open(sys.argv[1]).read(); assert b'<html' in page.lower()"
            ),
            url,
        ]

    monkeypatch.setattr(desktop, "browser_command", test_window)
    assert desktop.launch() == 0
    assert desktop.default_database().is_file()
    timestamp = desktop.default_database().stat().st_mtime_ns
    assert desktop.launch() == 0
    assert desktop.default_database().stat().st_mtime_ns == timestamp
    assert len(opened) == 2
    assert opened[0] != opened[1]
    for url in opened:
        address = urlparse(url)
        with socket.socket() as client:
            client.settimeout(0.5)
            assert client.connect_ex(("127.0.0.1", address.port)) != 0
    assert list((desktop_environment / "state/flowguard").glob("*.previous.log"))


def test_second_launch_does_not_spawn_another_server(desktop_environment, monkeypatch):
    database = desktop.default_database().resolve()
    identity = hashlib.sha256(os.fsencode(database)).hexdigest()[:16]
    cache = desktop_environment / "cache/flowguard"
    cache.mkdir(parents=True)
    notifications = []
    monkeypatch.setattr(desktop, "notify", notifications.append)
    with (cache / f"{identity}.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert desktop.launch() == 0
    assert "already open" in notifications[0]
    assert not database.exists()


def test_explicit_missing_database_never_silently_creates_demo(desktop_environment):
    missing = desktop_environment / "missing.sqlite"
    with pytest.raises(RuntimeError, match="Database does not exist"):
        desktop.launch(missing)
    assert not missing.exists()


def test_no_display_is_useful_error(desktop_environment, monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    with pytest.raises(ValueError, match="desktop session"):
        desktop.launch()


def test_failed_initialization_is_cleaned(desktop_environment, monkeypatch):
    database = desktop.default_database()

    def failed(command, **kwargs):
        Path(command[command.index("--db") + 1]).write_bytes(b"partial database")
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(desktop.subprocess, "run", failed)
    with pytest.raises(subprocess.CalledProcessError):
        desktop.prepare_database(database, True, None)
    assert not database.exists()
    assert list(database.parent.glob(".initial-*")) == []


def test_dead_server_fails_readiness_immediately():
    with pytest.raises(RuntimeError, match="stopped before"):
        desktop.wait_ready(SimpleNamespace(poll=lambda: 1), "http://127.0.0.1:1/token")


def test_browser_profile_is_isolated_without_disabling_sandbox(tmp_path):
    command = desktop.browser_command("chromium", "http://127.0.0.1:1234/test", tmp_path / "profile space")
    assert "--app=http://127.0.0.1:1234/test" in command
    assert f"--user-data-dir={tmp_path / 'profile space'}" in command
    assert "--no-sandbox" not in command


def test_exec_quoting():
    assert desktop.desktop_exec_argument('/path with space/a%"$`\\') == '"/path with space/a%%\\"\\$\\`\\\\"'


@pytest.mark.parametrize("custom_database", [False, True])
def test_installer_uses_current_venv_and_omarchy(tmp_path, monkeypatch, custom_database):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(desktop.shutil, "which", lambda name: f"/usr/bin/{name}")
    commands = []

    def install_command(command, **kwargs):
        commands.append(command)
        if command[1:3] == ["webapp", "install"]:
            entry = tmp_path / ".local/share/applications/FlowGuard.desktop"
            entry.parent.mkdir(parents=True)
            entry.write_text("[Desktop Entry]\nName=FlowGuard\nType=Application\n")

    monkeypatch.setattr(desktop.subprocess, "run", install_command)
    database = tmp_path / "live capture.sqlite"
    database.touch()
    assert desktop.install(database if custom_database else None) == 0
    launcher = tmp_path / ".local/bin/flowguard-desktop"
    assert os.access(launcher, os.X_OK)
    assert sys.executable in launcher.read_text()
    assert '"$@"' in launcher.read_text()
    assert commands[0][1:4] == ["webapp", "install", "FlowGuard"]
    if custom_database:
        assert commands[0][-1].endswith(" --db " + desktop.desktop_exec_argument(str(database)))
    assert (
        "StartupWMClass=flowguard" in (tmp_path / ".local/share/applications/FlowGuard.desktop").read_text()
    )


def test_menu_install_rejects_missing_database(tmp_path):
    with pytest.raises(ValueError, match="Database does not exist"):
        desktop.install(tmp_path / "missing.sqlite")
