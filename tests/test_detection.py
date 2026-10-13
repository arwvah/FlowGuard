from dataclasses import replace

import pytest

from flowguard.baseline import Baseline, Learner
from flowguard.config import Config
from flowguard.detection import Detector
from flowguard.models import SourceStats, Window


def baseline(mean=4, std=0):
    return Baseline(8, 10, mean, std, 600, 0)


def window(start=0, packets=40, size=6000, **kwargs):
    return Window(start, 10, packets, size, **kwargs)


def test_normal_and_zero_variance():
    engine = Detector(Config(), baseline())
    for i in range(10):
        assert engine.process(window(i * 10)) == []
    assert engine.process(window(100, packets=400, size=200_000)) == []
    alerts = engine.process(window(110, packets=400, size=200_000))
    assert {a.detector for a in alerts} == {"packet_rate", "bandwidth"}
    assert alerts[0].threshold == 20
    assert alerts[0].baseline == 4


def test_statistical_threshold_and_strict_boundary():
    engine = Detector(replace(Config(), persistence_windows=1), baseline(mean=10, std=10))
    assert engine.process(window(packets=500)) == []
    alerts = engine.process(window(10, packets=501))
    assert alerts[0].threshold == 50


def test_persistence_resets_on_gap_normal_and_partial():
    for middle in (window(10), window(10, packets=400, partial=True)):
        engine = Detector(Config(), baseline())
        engine.process(window(packets=400))
        assert engine.process(middle) == []
        assert engine.process(window(20, packets=400)) == []
    engine = Detector(Config(), baseline())
    engine.process(window(packets=400))
    assert engine.process(window(30, packets=400)) == []


def scan(start=0, address="192.0.2.10"):
    return window(start, sources={address: SourceStats(45, 45, 0, set(range(45)))})


def test_cooldowns_expire_and_sources_are_independent():
    engine = Detector(Config())
    assert len(engine.process(scan())) == 1
    assert engine.process(scan(10)) == []
    assert len(engine.process(scan(20, "192.0.2.11"))) == 1
    assert len(engine.process(scan(30))) == 1
    assert "45 distinct" in engine.process(scan(60))[0].reason


def test_syn_requires_both_count_and_ratio():
    engine = Detector(Config())
    assert engine.process(window(sources={"host": SourceStats(100, 100, 40)})) == []
    assert engine.process(window(10, sources={"host": SourceStats(39, 39, 39)})) == []
    alerts = engine.process(window(20, sources={"host": SourceStats(50, 50, 40)}))
    assert alerts[0].detector == "syn_excess"


def test_allowlist_minimum_disabled_and_separate_keys():
    engine = Detector(Config())
    assert engine.process(window(protocols={"IP-47": 2}, ports={1234: 2})) == []
    assert len(engine.process(window(10, protocols={"IP-47": 3}, ports={1234: 3}))) == 2
    assert len(engine.process(window(20, protocols={"IP-99": 3}, ports={1235: 3}))) == 2
    assert (
        Detector(replace(Config(), allowed_protocols=(), allowed_ports=())).process(
            window(protocols={"IP-47": 100}, ports={1234: 100})
        )
        == []
    )


def test_bounded_cooldowns():
    engine = Detector(replace(Config(), max_cooldown_keys=2, cooldown_seconds=1000))
    for i in range(20):
        engine.process(scan(i * 10, str(i)))
    assert len(engine.cooldowns) == 2


def test_learning_excludes_partial_insufficient_and_welford():
    learner = Learner(10)
    learner.add(window(packets=100_000, partial=True))
    with pytest.raises(ValueError, match="Insufficient"):
        learner.finish(2)
    learner.add(window(packets=20))
    learner.add(window(10, packets=40))
    learned = learner.finish(2)
    assert learned.packet_mean == 3
    assert learned.packet_std == pytest.approx(2**0.5)
    assert learned.samples == 2


def test_baseline_compatibility():
    with pytest.raises(ValueError, match="incompatible"):
        Detector(replace(Config(), window_seconds=20), baseline())
    with pytest.raises(ValueError, match="incompatible"):
        Detector(Config(), replace(baseline(), samples=2))
