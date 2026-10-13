import json
import sqlite3
from pathlib import Path

import pytest

from flowguard.cli import main
from flowguard.config import Config
from flowguard.demo import EXPECTED, generate, run_demo
from flowguard.models import Alert, Window
from flowguard.service import run
from flowguard.storage import Store


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    return generate(tmp_path_factory.mktemp("pcaps"))


def test_fixture_bytes_are_deterministic(fixtures, tmp_path):
    repeated = generate(tmp_path / "repeated")
    for path in fixtures.glob("*.pcap"):
        assert path.read_bytes() == (repeated / path.name).read_bytes()


def test_demo_all_detectors_normal_false_positives_and_no_baseline_contamination(tmp_path):
    db = tmp_path / "demo.sqlite"
    result = run_demo(tmp_path / "pcaps", db)
    assert set(result["detectors"]) == EXPECTED
    assert result["normal_alerts"] == 0
    assert result["alerts"] == 11
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM baselines").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM sessions WHERE status='complete'").fetchone()[0] == 3
        learned = json.loads(connection.execute("SELECT data FROM baselines").fetchone()[0])
        assert learned["samples"] == 8 and learned["packet_mean"] == 4


def test_replay_is_deterministic_and_failed_learning_preserves_baseline(fixtures, tmp_path):
    db = tmp_path / "lab.sqlite"
    cfg = Config()
    first = run(cfg, db, pcap=fixtures / "normal.pcap", learning=True)
    a = run(cfg, db, pcap=fixtures / "mixed.pcap")
    b = run(cfg, db, pcap=fixtures / "mixed.pcap")
    assert a.alerts == b.alerts == 11
    with sqlite3.connect(db) as connection:

        def rows(identifier):
            return connection.execute(
                "SELECT timestamp,detector,observed,reason FROM alerts WHERE session_id=? ORDER BY id",
                (identifier,),
            ).fetchall()

        assert rows(a.session_id) == rows(b.session_id)
    with pytest.raises(ValueError, match="Insufficient"):
        run(cfg, db, pcap=fixtures / "scan.pcap", learning=True)
    store = Store(db)
    assert store.baseline()[0] == first.baseline_id
    assert (
        store.connection.execute("SELECT status FROM sessions ORDER BY id DESC LIMIT 1").fetchone()[0]
        == "failed"
    )
    store.close()


def test_retention_and_immutable_baseline(tmp_path):
    store = Store(tmp_path / "db.sqlite", max_records=2)
    sid = store.session("offline", "test", False, None, Config())
    for i in range(5):
        store.save_window(sid, Window(i * 10, 10), [Alert(i * 10, "test", "low", 1, 1, "test")])
    for table in ("metrics", "alerts"):
        assert store.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 2
        assert store.connection.execute(f"SELECT min(timestamp) FROM {table}").fetchone()[0] == 30
    store.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"window_seconds": 0},
        {"window_seconds": float("nan")},
        {"scan_ports": 1.5},
        {"min_baseline_windows": 1},
        {"syn_ratio": 2},
        {"spike_factor": 1},
        {"allowed_ports": [65536]},
        {"allowed_ports": [True]},
        {"allowed_protocols": "TCP"},
        {"max_sources": True},
        {"scan_ports": 1024},
    ],
)
def test_invalid_config(kwargs):
    with pytest.raises(ValueError):
        Config(**kwargs)


def test_example_config_and_unknown_key(tmp_path):
    assert Config.load(str(Path(__file__).parents[1] / "config.example.toml")).window_seconds == 10
    path = tmp_path / "bad.toml"
    path.write_text("typo = 3")
    with pytest.raises(ValueError, match="Unknown configuration"):
        Config.load(str(path))


def test_cli_errors_and_no_baseline_message(tmp_path, fixtures, capsys):
    db = str(tmp_path / "db.sqlite")
    assert main(["analyze", "--pcap", "missing.pcap", "--db", db]) == 2
    assert "missing.pcap" in capsys.readouterr().err
    assert main(["monitor", "--interface", "none", "--seconds", "nan", "--db", db]) == 2
    assert "finite positive" in capsys.readouterr().err
    assert main(["analyze", "--pcap", str(fixtures / "normal.pcap"), "--db", db]) == 0
    assert "No baseline" in capsys.readouterr().err


def test_graceful_capture_shutdown_flushes_partial(tmp_path, monkeypatch):
    from flowguard.models import PacketMeta

    def interrupted(interface, consume, tick, seconds):
        consume(PacketMeta(0, "host", "dest", "TCP", 100, 12345, 443))
        raise KeyboardInterrupt

    monkeypatch.setattr("flowguard.service.capture", interrupted)
    db = tmp_path / "interrupt.sqlite"
    result = run(Config(), db, interface="mock0")
    assert result.interrupted and result.packets == 1
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT status FROM sessions").fetchone()[0] == "interrupted"
        assert connection.execute("SELECT partial FROM metrics").fetchone()[0] == 1


def test_dashboard_renders_and_filters(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    import flowguard

    db = tmp_path / "dashboard.sqlite"
    run_demo(tmp_path / "pcaps", db)
    monkeypatch.setattr("sys.argv", ["dashboard.py", "--db", str(db)])
    app = AppTest.from_file(str(Path(flowguard.__file__).with_name("dashboard.py"))).run(timeout=30)
    assert not app.exception
    assert [metric.value for metric in app.metric][-1] == "11"
    assert len(app.dataframe[-1].value) == 11
    app.multiselect[0].set_value(["high"]).run()
    assert not app.exception
    assert len(app.dataframe[-1].value) == 3
    app.text_input[0].set_value("192.0.2.11").run()
    assert len(app.dataframe[-1].value) == 1
