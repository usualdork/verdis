"""Tests for the limits, the job store and the advisory lookups.

These cover the parts of FR-1.4 (concurrency caps and budgets) and FR-4.2
(published advisories) that the pipeline relies on.
"""

from __future__ import annotations

import threading
import time

import httpx
import pytest

from verdis.dedupe.index import DedupeEngine
from verdis.dedupe.osv import OSVAdvisorySource
from verdis.intake.limits import (
    BudgetExceeded,
    ConcurrencyLimiter,
    ReportBudget,
    SourceLimiter,
)
from verdis.storage.db import Store


class TestSourceLimiter:
    def test_it_caps_the_concurrency(self) -> None:
        limiter = SourceLimiter(limit=2)
        started = threading.Event()
        release = threading.Event()
        active = 0
        peak = 0
        lock = threading.Lock()

        def worker() -> None:
            nonlocal active, peak
            with limiter.slot():
                with lock:
                    active += 1
                    peak = max(peak, active)
                started.set()
                release.wait(2)
                with lock:
                    active -= 1

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        started.wait(2)
        time.sleep(0.05)
        with lock:
            assert active <= 2
        release.set()
        for thread in threads:
            thread.join(2)
        assert limiter.active == 0

    def test_a_limit_below_one_is_refused(self) -> None:
        with pytest.raises(ValueError):
            SourceLimiter(limit=0)

    def test_the_slot_is_released_after_an_error(self) -> None:
        limiter = SourceLimiter(limit=1)
        with pytest.raises(RuntimeError), limiter.slot():
            raise RuntimeError("boom")
        assert limiter.active == 0


class TestConcurrencyLimiter:
    def test_each_source_gets_its_own_cap(self) -> None:
        limiter = ConcurrencyLimiter(default_limit=1)
        limiter.set_limit("imap", 3)
        assert limiter.for_source("imap").limit == 3
        assert limiter.for_source("github").limit == 1
        assert limiter.for_source("imap") is limiter.for_source("imap")

    def test_a_slot_can_be_taken(self) -> None:
        limiter = ConcurrencyLimiter()
        with limiter.slot("github"):
            assert limiter.for_source("github").active == 1


class TestReportBudget:
    def test_the_time_budget_is_enforced(self) -> None:
        budget = ReportBudget(seconds=0.0)
        with pytest.raises(BudgetExceeded):
            budget.check()

    def test_the_token_budget_is_enforced(self) -> None:
        budget = ReportBudget(tokens=10)
        budget.spend_tokens(5)
        assert budget.remaining_tokens == 5
        budget.spend_tokens(5)
        with pytest.raises(BudgetExceeded):
            budget.spend_tokens(1)

    def test_a_fresh_budget_is_usable(self) -> None:
        budget = ReportBudget()
        budget.check()
        assert budget.remaining_seconds > 0


class TestJobStore:
    def test_a_job_is_recorded_and_updated(self, store: Store) -> None:
        store.save_job("VDS-0001", "claim")
        job = store.get_job("VDS-0001")
        assert job is not None
        assert job.stage == "claim"
        assert job.status == "running"

        store.save_job("VDS-0001", "build", status="running")
        job = store.get_job("VDS-0001")
        assert job is not None
        assert job.stage == "build"

    def test_finished_jobs_are_listed(self, store: Store) -> None:
        store.save_job("VDS-0001", "done", status="finished")
        store.save_job("VDS-0002", "claim")
        jobs = store.list_jobs()
        assert {job.report_id for job in jobs} == {"VDS-0001", "VDS-0002"}

    def test_deleting_a_report_deletes_its_job(self, store: Store) -> None:
        from verdis.schemas.common import ReportSource
        from verdis.schemas.report import Report

        store.save_report(Report(id="VDS-0001", source=ReportSource.FILE, body="x"))
        store.save_job("VDS-0001", "claim")
        store.delete_report("VDS-0001")
        assert store.get_job("VDS-0001") is None


class TestOSVAdvisorySource:
    def _client(self, handler) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=5)

    def test_it_queries_the_api(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["payload"] = request.read().decode("utf-8")
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Heap overflow in parse_header",
                            "details": "A heap buffer overflow.",
                            "affected": [
                                {
                                    "package": {"name": "libfoo"},
                                    "database_specific": {"cwe_ids": ["CWE-122"]},
                                }
                            ],
                        }
                    ]
                },
            )

        source = OSVAdvisorySource(
            package="libfoo", ecosystem="Debian", client=self._client(handler)
        )
        candidates = source.lookup()
        assert candidates[0].identifier == "GHSA-xxxx-yyyy-zzzz"
        assert candidates[0].vuln_class == "CWE-122"
        assert "libfoo" in str(captured["payload"])

    def test_it_does_nothing_without_a_package(self) -> None:
        source = OSVAdvisorySource(package="")
        assert source.lookup(repo="") == []

    def test_an_error_response_is_not_fatal(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        source = OSVAdvisorySource(
            package="libfoo", ecosystem="Debian", client=self._client(handler)
        )
        assert source.lookup() == []

    def test_it_is_off_by_default(self, monkeypatch) -> None:
        monkeypatch.delenv("VERDIS_OSV", raising=False)
        assert OSVAdvisorySource.from_env() is None

    def test_it_can_be_enabled_by_the_environment(self, monkeypatch) -> None:
        monkeypatch.setenv("VERDIS_OSV", "1")
        monkeypatch.setenv("VERDIS_OSV_PACKAGE", "libfoo")
        source = OSVAdvisorySource.from_env()
        assert source is not None
        assert source.package == "libfoo"

    def test_a_lookup_without_an_ecosystem_is_not_made(self) -> None:
        # The advisory database rejects a package without an ecosystem, so
        # the lookup is not made at all.
        source = OSVAdvisorySource(package="libfoo")
        assert source.lookup() == []

    def test_a_lookup_that_cannot_reach_the_database_returns_nothing(self) -> None:
        # The source opens and closes its own client.
        source = OSVAdvisorySource(
            package="libfoo",
            ecosystem="Debian",
            api_url="http://127.0.0.1:1/none",
            timeout=1.0,
        )
        assert source.lookup() == []

    def test_an_advisory_becomes_a_duplicate_candidate(self, store: Store) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Heap overflow in parse_header",
                            "details": "A heap buffer overflow in parse_header of libfoo.",
                            "affected": [
                                {
                                    "package": {"name": "libfoo"},
                                    "database_specific": {"cwe_ids": ["CWE-122"]},
                                }
                            ],
                        }
                    ]
                },
            )

        source = OSVAdvisorySource(
            package="libfoo", ecosystem="Debian", client=self._client(handler)
        )
        engine = DedupeEngine(store=store, advisory_source=source)
        from verdis.dedupe.fingerprint import DedupeFingerprint

        fingerprint = DedupeFingerprint.build(
            report_id="VDS-0002",
            body="heap buffer overflow in parse_header of libfoo",
            vuln_class="CWE-122",
            component="parse_header",
        )
        matches = engine.search(
            fingerprint, "heap buffer overflow in parse_header of libfoo"
        )
        assert any(match.source == "advisory" for match in matches)
