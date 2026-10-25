"""Concurrency caps and per-report budgets (FR-1.4).

A flood of reports must not turn into a flood of builds. Each source gets
a cap on how many reports it may have in flight, and each report gets a
wall-clock budget.

The limits live here rather than in the adapters, so every adapter gets
the same behaviour without having to remember it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from ..schemas.common import BudgetExceeded

__all__ = ["BudgetExceeded", "ConcurrencyLimiter", "ReportBudget", "SourceLimiter"]


@dataclass
class SourceLimiter:
    """How many reports one source may have in flight at once."""

    limit: int = 2
    _semaphore: threading.BoundedSemaphore = field(init=False)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)
    _active: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("the concurrency limit must be at least 1")
        self._semaphore = threading.BoundedSemaphore(self.limit)

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    @contextmanager
    def slot(self) -> Iterator[None]:
        """Take a slot, or wait for one."""
        self._semaphore.acquire()
        with self._lock:
            self._active += 1
        try:
            yield
        finally:
            with self._lock:
                self._active -= 1
            self._semaphore.release()


@dataclass
class ConcurrencyLimiter:
    """One cap per source."""

    default_limit: int = 2
    limits: dict[str, int] = field(default_factory=dict)
    _sources: dict[str, SourceLimiter] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def for_source(self, source: str) -> SourceLimiter:
        with self._lock:
            limiter = self._sources.get(source)
            if limiter is None:
                limit = self.limits.get(source, self.default_limit)
                limiter = SourceLimiter(limit=limit)
                self._sources[source] = limiter
            return limiter

    def set_limit(self, source: str, limit: int) -> None:
        with self._lock:
            self.limits[source] = limit
            self._sources.pop(source, None)

    @contextmanager
    def slot(self, source: str) -> Iterator[None]:
        with self.for_source(source).slot():
            yield


@dataclass
class ReportBudget:
    """A wall-clock and token budget for one report (FR-1.4)."""

    seconds: float = 900.0
    tokens: int = 20_000
    started_at: float = field(default_factory=time.monotonic)
    tokens_used: int = 0

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.seconds - (time.monotonic() - self.started_at))

    @property
    def remaining_tokens(self) -> int:
        return max(0, self.tokens - self.tokens_used)

    def check(self) -> None:
        """Raise when the budget is spent."""
        if self.remaining_seconds <= 0:
            raise BudgetExceeded(
                f"the report used up its {self.seconds:.0f}s budget"
            )

    def spend_tokens(self, count: int) -> None:
        """Record tokens used and refuse to go over."""
        self.tokens_used += count
        if self.tokens_used > self.tokens:
            raise BudgetExceeded(
                f"the report used up its {self.tokens} token budget"
            )
