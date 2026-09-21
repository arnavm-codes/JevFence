"""Thresholds and the routing rule. Presets are the two policies from TypeSafe's guardrails cookbook."""
from __future__ import annotations

from dataclasses import dataclass, field

PRECEDENCE = ("support", "block", "review", "pass")


@dataclass(frozen=True)
class Policy:
    name: str
    review_threshold: float   # probability >= this -> "review"
    action_threshold: float   # probability >= this -> the hazard's own action (block / support)
    severity_block: float     # severity >= this upgrades every "review" to "block"
    # per-hazard overrides, e.g. {"vulgarity": "review"} or {"vulgarity": "ignore"}
    actions: dict[str, str] = field(default_factory=dict)

    @classmethod
    def strict(cls, **kw) -> "Policy":
        return cls("strict", 0.35, 0.70, 2.0, **kw)

    @classmethod
    def permissive(cls, **kw) -> "Policy":
        return cls("permissive", 0.35, 0.85, 2.0, **kw)


def decide(policy: Policy, probabilities: dict[str, float], severity: float,
           default_actions: dict[str, str]) -> tuple[str, list[dict]]:
    """Return (action, triggered) where triggered lists every hazard that crossed a threshold."""
    triggered = []
    for hazard, p in probabilities.items():
        action = policy.actions.get(hazard, default_actions[hazard])
        if action == "ignore":
            continue
        if p >= policy.action_threshold:
            level = action
        elif p >= policy.review_threshold:
            level = "review"
        else:
            continue
        if level == "review" and severity >= policy.severity_block:
            level = "block"
        triggered.append({"hazard": hazard, "probability": round(p, 4), "action": level})
    levels = {t["action"] for t in triggered}
    return next((a for a in PRECEDENCE if a in levels), "pass"), triggered
