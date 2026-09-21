from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field


@dataclass
class Verdict:
    action: str                  # "pass" | "review" | "block" | "support"
    allowed: bool                # True if the text may continue through your system
    side: str                    # "input" | "output" | "context"
    triggered: list[dict]        # [{"hazard", "probability", "action"}], strongest first
    probabilities: dict[str, float] = field(default_factory=dict)
    severity: float = 0.0
    user_message: str | None = None   # safe, canned text to show instead when not allowed
    reason: str = ""
    error: str | None = None     # set when the guard itself failed (see Guard(on_error=...))
    latency_ms: float = 0.0
    model: str | None = None
    cached: bool = False
    tokens_in: int = 0           # input tokens Jev billed for this verdict (0 for cache hits / no call)
    tokens_out: int = 0          # output tokens reported by Jev (free at the time of writing)

    def to_dict(self) -> dict:
        return asdict(self)

    def __bool__(self) -> bool:  # `if guard.check_input(x):` reads as "if allowed"
        return self.allowed


class GuardrailViolation(Exception):
    def __init__(self, verdict: Verdict):
        super().__init__(verdict.reason or verdict.action)
        self.verdict = verdict


class Usage:
    """Thread-safe running total of Jev usage for one guard. `price_per_million` is USD per million input tokens."""

    def __init__(self, price_per_million: float = 0.042):
        self.price_per_million = price_per_million
        self.calls = self.input_tokens = self.output_tokens = 0
        self._lock = threading.Lock()

    def add(self, tokens_in: int, tokens_out: int) -> None:
        with self._lock:
            self.calls += 1
            self.input_tokens += tokens_in
            self.output_tokens += tokens_out

    def reset(self) -> None:
        with self._lock:
            self.calls = self.input_tokens = self.output_tokens = 0

    @property
    def cost_usd(self) -> float:
        """Estimated cost if input tokens were billed at `price_per_million` (output tokens are free)."""
        return self.input_tokens * self.price_per_million / 1e6

    def to_dict(self) -> dict:
        return {"calls": self.calls, "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "estimated_cost_usd": round(self.cost_usd, 8)}

    def __repr__(self) -> str:
        return f"Usage(calls={self.calls}, input_tokens={self.input_tokens}, output_tokens={self.output_tokens}, cost_usd={self.cost_usd:.6f})"
