import math
from dataclasses import dataclass

from flowguard.models import Window


@dataclass(frozen=True)
class Baseline:
    samples: int
    window_seconds: float
    packet_mean: float
    packet_std: float
    byte_mean: float
    byte_std: float


class Learner:
    def __init__(self, window_seconds):
        self.window_seconds = window_seconds
        self.n = 0
        self.means = [0.0, 0.0]
        self.m2 = [0.0, 0.0]

    def add(self, window: Window):
        if window.partial:
            return
        self.n += 1
        for index, value in enumerate((window.packet_rate, window.byte_rate)):
            delta = value - self.means[index]
            self.means[index] += delta / self.n
            self.m2[index] += delta * (value - self.means[index])

    def finish(self, minimum):
        if self.n < minimum:
            raise ValueError(
                f"Insufficient baseline: {self.n} complete active windows; need {minimum}. Capture longer normal traffic."
            )
        return Baseline(
            self.n,
            self.window_seconds,
            self.means[0],
            math.sqrt(self.m2[0] / (self.n - 1)),
            self.means[1],
            math.sqrt(self.m2[1] / (self.n - 1)),
        )
