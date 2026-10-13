from dataclasses import dataclass

from flowguard.baseline import Learner
from flowguard.detection import Detector
from flowguard.ingest import capture, read_pcap
from flowguard.metrics import Aggregator
from flowguard.storage import Store


@dataclass
class Result:
    session_id: int
    packets: int = 0
    windows: int = 0
    alerts: int = 0
    baseline_id: int | None = None
    interrupted: bool = False


def run(
    config,
    db,
    *,
    pcap=None,
    interface=None,
    seconds=None,
    learning=False,
    name="normal",
    baseline_id=None,
    mode=None,
):
    store = Store(db, config.max_records)
    session_id = None
    try:
        selected_id, baseline = (None, None) if learning else store.baseline(baseline_id)
        detector = Detector(config, baseline)
        learner = Learner(config.window_seconds)
        session_id = store.session(
            mode or ("offline" if pcap else "live"), pcap or interface, learning, selected_id, config
        )
        result = Result(session_id, baseline_id=selected_id)

        def emit(window):
            alerts = [] if learning else detector.process(window)
            if learning:
                learner.add(window)
            store.save_window(session_id, window, alerts)
            result.windows += 1
            result.alerts += len(alerts)
            result.packets += window.packets

        aggregator = Aggregator(config, emit)
        try:
            if pcap:
                for packet in read_pcap(pcap):
                    aggregator.add(packet)
            else:
                capture(interface, aggregator.add, aggregator.advance, seconds)
        except KeyboardInterrupt:
            result.interrupted = True
        aggregator.finish()
        if not result.packets:
            raise ValueError("No packets captured; check the interface, traffic, or PCAP")
        if learning:
            result.baseline_id = store.save_baseline(learner.finish(config.min_baseline_windows), name)
        store.end_session(session_id, "interrupted" if result.interrupted else "complete", result.baseline_id)
        return result
    except BaseException:
        if session_id is not None:
            store.end_session(session_id, "failed")
        raise
    finally:
        store.close()
