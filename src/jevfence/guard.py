"""Guard (sync) and AsyncGuard: screen text with Jev and return a Verdict. Fails closed by default."""
from __future__ import annotations

import asyncio
import functools
import hashlib
import inspect
import json
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .hazards import BY_ID, SEVERITY, SIDE_DESCRIPTION, SIDES, hazards_for
from .policy import Policy, decide
from .verdict import GuardrailViolation, Usage, Verdict

DEFAULT_MESSAGES = {
    "block": "Sorry, I can't help with that request.",
    "review": "Sorry, I can't process that message right now.",
    "support": ("It sounds like you may be going through something really difficult. You're not alone. "
                "Please consider reaching out to someone you trust or to a local crisis line or emergency services."),
    "output": "Sorry, I can't share that response.",
    "prompt_injection": "That message looks like an attempt to override my instructions, so I can't process it.",
    "classifier_manipulation": "That message looks like an attempt to override my instructions, so I can't process it.",
    "context": "[content removed by safety filter]",
}


class _GuardBase:
    def __init__(self, policy: Policy | str = "strict", *, model: str = "jev-latest", on_error: str = "block",
                 review_mode: str = "block", max_chars: int = 1500, overlap: int = 200, max_chunks: int = 12,
                 timeout: float = 10.0, messages: dict[str, str] | None = None, log_path: str | Path | None = None,
                 log_text: bool = False, cache_size: int = 256, on_verdict: Callable[[Verdict], None] | None = None,
                 price_per_million_input: float = 0.042, client: Any = None):
        if isinstance(policy, str):
            policy = {"strict": Policy.strict, "permissive": Policy.permissive}[policy]()
        assert on_error in ("block", "allow") and review_mode in ("block", "allow")
        self.policy, self.model, self.on_error, self.review_mode = policy, model, on_error, review_mode
        self.max_chars, self.overlap, self.max_chunks, self.timeout = max_chars, overlap, max_chunks, timeout
        self.messages = {**DEFAULT_MESSAGES, **(messages or {})}
        self.log_path = Path(log_path) if log_path else None
        self.log_text, self.on_verdict = log_text, on_verdict
        self._client = client
        self.usage = Usage(price_per_million_input)  # running totals; guard.usage.reset() to zero them
        self._cache: OrderedDict[tuple, Verdict] = OrderedDict()
        self._cache_size = cache_size
        self._lock = threading.Lock()

    def variant(self, policy: str | None = None, review_mode: str | None = None):
        """Sibling guard with a different preset policy and/or review mode. It shares this guard's Jev client, audit log
        and lock, but has its own verdict cache and usage totals (a cached verdict depends on the policy that made it).
        Per-hazard `actions` overrides on the current policy are carried over. Don't close a variant: the client is shared."""
        preset = {"strict": Policy.strict, "permissive": Policy.permissive}[policy or self.policy.name]
        twin = type(self)(preset(actions=self.policy.actions), model=self.model, on_error=self.on_error,
                          review_mode=review_mode or self.review_mode, max_chars=self.max_chars, overlap=self.overlap,
                          max_chunks=self.max_chunks, timeout=self.timeout, messages=self.messages,
                          log_path=self.log_path, log_text=self.log_text, cache_size=self._cache_size,
                          on_verdict=self.on_verdict, price_per_million_input=self.usage.price_per_million,
                          client=self._get_client())
        twin._lock = self._lock
        return twin

    # ---- request building -------------------------------------------------------------------
    def _questions(self, side: str) -> dict:
        qs = {h.id: h.question for h in hazards_for(side)}
        qs["severity"] = SEVERITY
        return qs

    def _state(self, side: str, chunk: str) -> dict:
        return {"context": f"`text_to_screen` is {SIDE_DESCRIPTION[side]}.", "text_to_screen": chunk}

    def _chunks(self, text: str) -> list[str] | None:
        if len(text) <= self.max_chars:
            return [text]
        step = max(1, self.max_chars - self.overlap)
        chunks = [text[i:i + self.max_chars] for i in range(0, len(text), step) if i == 0 or i + self.overlap < len(text)]
        return chunks if len(chunks) <= self.max_chunks else None

    # ---- result building --------------------------------------------------------------------
    def _merge(self, side: str, responses: list) -> tuple[dict, float, str | None, int, int]:
        probs = {h.id: max(r.answers[h.id].noul for r in responses) for h in hazards_for(side)}
        severity = max(r.answers["severity"].score for r in responses)
        tin = sum(getattr(getattr(r, "usage", None), "input_tokens", 0) or 0 for r in responses)
        tout = sum(getattr(getattr(r, "usage", None), "output_tokens", 0) or 0 for r in responses)
        return probs, severity, getattr(responses[0], "model", None), tin, tout

    def _message_for(self, side: str, action: str, triggered: list[dict]) -> str | None:
        if action == "pass":
            return None
        if action == "review" and self.review_mode == "allow":
            return None
        if side == "context":
            return self.messages["context"]
        if action == "support":
            return self.messages["support"]
        if side == "output":
            return self.messages["output"]
        top = triggered[0]["hazard"] if triggered else None
        return self.messages.get(top) or self.messages["review" if action == "review" else "block"]

    def _finish(self, side: str, probs: dict, severity: float, model: str | None, t0: float,
                tokens_in: int = 0, tokens_out: int = 0) -> Verdict:
        default = {h: BY_ID[h].action for h in probs}
        action, triggered = decide(self.policy, probs, severity, default)
        triggered.sort(key=lambda t: t["probability"], reverse=True)
        allowed = action == "pass" or (action == "review" and self.review_mode == "allow")
        reason = ", ".join(f"{t['hazard']}={t['probability']:.2f}" for t in triggered) or "no hazards detected"
        return Verdict(action, allowed, side, triggered, {k: round(v, 4) for k, v in probs.items()}, round(severity, 3),
                       self._message_for(side, action, triggered), reason, None,
                       round((time.perf_counter() - t0) * 1000, 1), model,
                       tokens_in=tokens_in, tokens_out=tokens_out)

    def _error_verdict(self, side: str, err: Exception, t0: float) -> Verdict:
        closed = self.on_error == "block"
        msg = f"{type(err).__name__}: {err}"
        return Verdict("block" if closed else "pass", not closed, side, [], {}, 0.0,
                       (self.messages["output"] if side == "output" else self.messages["block"]) if closed else None,
                       f"guard error, failing {'closed' if closed else 'open'}", msg,
                       round((time.perf_counter() - t0) * 1000, 1))

    def _prepare(self, text: str, side: str, t0: float, use_cache: bool = True):
        """Return (early_verdict, chunks). early_verdict is set when no Jev call is needed."""
        if side not in SIDES:
            raise ValueError(f"side must be one of {SIDES}, got {side!r}")
        if not isinstance(text, str):
            raise TypeError(f"expected str, got {type(text).__name__}")
        if not text.strip():
            return Verdict("pass", True, side, [], reason="empty text"), None
        with self._lock:
            hit = self._cache.get((side, text)) if use_cache else None
            if hit is not None:
                self._cache.move_to_end((side, text))
                return replace(hit, cached=True, tokens_in=0, tokens_out=0,
                               latency_ms=round((time.perf_counter() - t0) * 1000, 3)), None
        chunks = self._chunks(text)
        if chunks is None:  # too long to screen reliably: an attacker could bury a payload, so fail closed
            v = Verdict("block", False, side, [], reason=f"text longer than {self.max_chars * self.max_chunks} chars",
                        user_message=self.messages["context" if side == "context" else "block"],
                        latency_ms=round((time.perf_counter() - t0) * 1000, 1))
            return self._emit(text, v), None
        return None, chunks

    def _emit(self, text: str, v: Verdict) -> Verdict:
        self._log(text, v)
        if self.on_verdict:
            self.on_verdict(v)
        return v

    def _store(self, side: str, text: str, v: Verdict) -> Verdict:
        if v.error is None:
            self.usage.add(v.tokens_in, v.tokens_out)
        if v.error is None and self._cache_size:
            with self._lock:
                self._cache[(side, text)] = v
                while len(self._cache) > self._cache_size:
                    self._cache.popitem(last=False)
        return self._emit(text, v)

    def _log(self, text: str, v: Verdict) -> None:
        if not self.log_path:
            return
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "side": v.side, "action": v.action, "allowed": v.allowed,
               "triggered": v.triggered, "severity": v.severity, "latency_ms": v.latency_ms, "error": v.error,
               "text_sha256": hashlib.sha256(text.encode()).hexdigest(), "text_len": len(text)}
        if self.log_text:
            rec["text"] = text
        with self._lock, self.log_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def _blocked_result(self, v: Verdict, on_block: str):
        if on_block == "raise":
            raise GuardrailViolation(v)
        return v.user_message

    @staticmethod
    def _extract(fn: Callable, args: tuple, kwargs: dict, input_arg: int | str) -> str:
        if isinstance(input_arg, int):
            return args[input_arg]
        bound = inspect.signature(fn).bind(*args, **kwargs)
        return bound.arguments[input_arg]


class Guard(_GuardBase):
    """Synchronous guard. `Guard().check_input(text)` returns a Verdict (truthy when allowed)."""

    def _get_client(self):
        if self._client is None:
            from typesafe_sdk import TypeSafeClient
            self._client = TypeSafeClient()
        return self._client

    def _call(self, side: str, chunk: str):
        return self._get_client().system_one(state=self._state(side, chunk), questions=self._questions(side),
                                             model=self.model, timeout=self.timeout)

    def check(self, text: str, side: str = "input", *, use_cache: bool = True) -> Verdict:
        t0 = time.perf_counter()
        early, chunks = self._prepare(text, side, t0, use_cache)
        if early is not None:
            return early
        try:
            if len(chunks) == 1:
                responses = [self._call(side, chunks[0])]
            else:
                with ThreadPoolExecutor(max_workers=min(8, len(chunks))) as pool:
                    responses = list(pool.map(lambda c: self._call(side, c), chunks))
            probs, severity, model, tin, tout = self._merge(side, responses)
            verdict = self._finish(side, probs, severity, model, t0, tin, tout)
        except Exception as e:  # noqa: BLE001 - any failure of the guard must be handled per on_error
            verdict = self._error_verdict(side, e, t0)
        return self._store(side, text, verdict)

    def check_input(self, text: str) -> Verdict:
        return self.check(text, "input")

    def check_output(self, text: str) -> Verdict:
        return self.check(text, "output")

    def check_context(self, text: str) -> Verdict:
        return self.check(text, "context")

    def filter_context(self, chunks: Iterable[str]) -> tuple[list[str], list[Verdict]]:
        """Screen retrieved docs / tool results / agent messages; return (safe_chunks, all_verdicts)."""
        chunks = list(chunks)
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(chunks)))) as pool:
            verdicts = list(pool.map(self.check_context, chunks))
        return [c for c, v in zip(chunks, verdicts) if v.allowed], verdicts

    def protect(self, fn: Callable | None = None, *, input_arg: int | str = 0, on_block: str = "return"):
        """Decorator: screen the input argument before `fn` runs and its str result afterwards.

        on_block="return" gives back the verdict's safe message; on_block="raise" raises GuardrailViolation.
        """
        def deco(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                v_in = self.check_input(self._extract(f, args, kwargs, input_arg))
                if not v_in.allowed:
                    return self._blocked_result(v_in, on_block)
                result = f(*args, **kwargs)
                if isinstance(result, str):
                    v_out = self.check_output(result)
                    if not v_out.allowed:
                        return self._blocked_result(v_out, on_block)
                return result
            return wrapper
        return deco(fn) if fn else deco

    def close(self) -> None:
        if self._client is not None and hasattr(self._client, "close"):
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class AsyncGuard(_GuardBase):
    """Async twin of Guard, for asyncio apps (FastAPI, async agent frameworks)."""

    def _get_client(self):
        if self._client is None:
            from typesafe_sdk import AsyncTypeSafeClient
            self._client = AsyncTypeSafeClient()
        return self._client

    async def _call(self, side: str, chunk: str):
        return await self._get_client().system_one(state=self._state(side, chunk), questions=self._questions(side),
                                                   model=self.model, timeout=self.timeout)

    async def check(self, text: str, side: str = "input", *, use_cache: bool = True) -> Verdict:
        t0 = time.perf_counter()
        early, chunks = self._prepare(text, side, t0, use_cache)
        if early is not None:
            return early
        try:
            responses = await asyncio.gather(*(self._call(side, c) for c in chunks))
            probs, severity, model, tin, tout = self._merge(side, list(responses))
            verdict = self._finish(side, probs, severity, model, t0, tin, tout)
        except Exception as e:  # noqa: BLE001
            verdict = self._error_verdict(side, e, t0)
        return self._store(side, text, verdict)

    async def check_input(self, text: str) -> Verdict:
        return await self.check(text, "input")

    async def check_output(self, text: str) -> Verdict:
        return await self.check(text, "output")

    async def check_context(self, text: str) -> Verdict:
        return await self.check(text, "context")

    async def filter_context(self, chunks: Iterable[str]) -> tuple[list[str], list[Verdict]]:
        chunks = list(chunks)
        verdicts = await asyncio.gather(*(self.check_context(c) for c in chunks))
        return [c for c, v in zip(chunks, verdicts) if v.allowed], list(verdicts)

    def protect(self, fn: Callable | None = None, *, input_arg: int | str = 0, on_block: str = "return"):
        """Decorator for `async def` functions; same behaviour as Guard.protect."""
        def deco(f):
            @functools.wraps(f)
            async def wrapper(*args, **kwargs):
                v_in = await self.check_input(self._extract(f, args, kwargs, input_arg))
                if not v_in.allowed:
                    return self._blocked_result(v_in, on_block)
                result = await f(*args, **kwargs)
                if isinstance(result, str):
                    v_out = await self.check_output(result)
                    if not v_out.allowed:
                        return self._blocked_result(v_out, on_block)
                return result
            return wrapper
        return deco(fn) if fn else deco

    async def aclose(self) -> None:
        if self._client is not None and hasattr(self._client, "aclose"):
            await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()
