"""Tests for the orchestrator's branches.

The pipeline is the part a maintainer depends on most, so each of its
decision points gets a test: which backend it picks, what it does with a
rejected plan, how it records its progress, and what it does when the
sandbox is missing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from verdis.config import Config
from verdis.pipeline.orchestrator import (
    Orchestrator,
    build_backend,
    build_provider,
)
from verdis.sandbox.local import LocalBackend
from verdis.schemas.common import ReportSource, Verdict
from verdis.schemas.report import Report, Target
from verdis.storage.db import Store
from verdis.storage.evidence import EvidenceStore


class TestBuildBackend:
    def test_a_named_backend_is_built(self) -> None:
        from verdis.sandbox.docker import DockerBackend
        from verdis.sandbox.podman import PodmanBackend

        assert isinstance(build_backend("podman"), PodmanBackend)
        assert isinstance(build_backend("docker"), DockerBackend)
        assert isinstance(build_backend("local"), LocalBackend)

    def test_an_unknown_backend_is_an_error(self) -> None:
        with pytest.raises(ValueError, match="unknown sandbox backend"):
            build_backend("chroot")

    def test_the_default_picks_a_container_when_there_is_one(self, monkeypatch) -> None:
        from verdis.sandbox import podman as podman_module

        class _Available:
            name = "podman"

            def available(self) -> bool:
                return True

        monkeypatch.setattr(podman_module, "PodmanBackend", _Available)
        backend = build_backend("default")
        assert backend.name == "podman"

    def test_the_default_falls_back_to_docker(self, monkeypatch) -> None:
        from verdis.sandbox import docker as docker_module
        from verdis.sandbox import podman as podman_module

        class _Unavailable:
            def available(self) -> bool:
                return False

        class _Available:
            name = "docker"

            def available(self) -> bool:
                return True

        monkeypatch.setattr(podman_module, "PodmanBackend", _Unavailable)
        monkeypatch.setattr(docker_module, "DockerBackend", _Available)
        assert build_backend("default").name == "docker"

    def test_the_default_refuses_without_a_container_runtime(self, monkeypatch) -> None:
        from verdis.pipeline.orchestrator import SandboxUnavailable
        from verdis.sandbox import docker as docker_module
        from verdis.sandbox import podman as podman_module

        class _Unavailable:
            def available(self) -> bool:
                return False

        monkeypatch.setattr(podman_module, "PodmanBackend", _Unavailable)
        monkeypatch.setattr(docker_module, "DockerBackend", _Unavailable)
        # Falling back to the host would run an untrusted proof of concept
        # with no isolation, so the tool refuses instead.
        with pytest.raises(SandboxUnavailable, match="no container runtime"):
            build_backend("default")

    def test_local_has_to_be_asked_for(self) -> None:
        assert isinstance(build_backend("local"), LocalBackend)


class TestBuildProvider:
    def test_the_no_llm_mode_builds_the_null_provider(self) -> None:
        from verdis.extract.providers import NullProvider

        assert isinstance(build_provider(Config()), NullProvider)

    def test_a_named_provider_is_built(self) -> None:
        from verdis.extract.providers import OllamaProvider

        config = Config()
        config.llm.provider = "ollama"
        assert isinstance(build_provider(config), OllamaProvider)


REPORT = """\
# Heap buffer overflow in parse_header

**Version**: 2.3.1
**Class**: CWE-122

```
./build/parse_demo poc.bin
```

AddressSanitizer reports a heap-buffer-overflow in parse_header.
"""


def _report() -> Report:
    return Report(
        id="VDS-0001",
        source=ReportSource.FILE,
        body=REPORT,
        subject="Heap overflow",
        target=Target(repo=".", ref="v1"),
    )


class TestOrchestratorBranches:
    def _orchestrator(self, tmp_path: Path, **kwargs: Any) -> Orchestrator:
        config = Config(mode="shadow", sandbox="local", repeats=1, **kwargs)
        return Orchestrator(
            config=config,
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )

    def test_a_spent_budget_is_inconclusive(self, tmp_path: Path) -> None:
        # A report that uses up its budget stops with an honest verdict
        # rather than an exception.
        orchestrator = self._orchestrator(tmp_path, report_budget_seconds=0.0)
        outcome = orchestrator.triage(_report(), repo_path=tmp_path)
        assert outcome.verdict.verdict is Verdict.INCONCLUSIVE
        assert "budget" in outcome.verdict.why

    def test_the_stages_are_recorded(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path)
        orchestrator.triage(_report(), repo_path=tmp_path)
        job = orchestrator.store.get_job("VDS-0001")
        assert job is not None
        assert job.stage == "done"
        assert job.status == "finished"

    def test_a_rejected_plan_is_inconclusive(self, tmp_path: Path) -> None:
        report = Report(
            id="VDS-0002",
            source=ReportSource.FILE,
            body=(
                "# Report\n\n**Version**: 2.3.1\n\n"
                "```\n./demo http://attacker.example/x\n```\n"
            ),
            target=Target(repo=".", ref="v1"),
        )
        orchestrator = self._orchestrator(tmp_path)
        result = orchestrator.triage(report, repo_path=tmp_path)
        assert result.verdict.verdict is Verdict.INCONCLUSIVE
        assert "allowlist" in result.verdict.why

    def test_a_plan_that_needs_confirmation_fails_closed(
        self, tmp_path: Path
    ) -> None:
        # A project that builds, so the plan is what stops the run.
        project = tmp_path / "project"
        project.mkdir()
        (project / "Makefile").write_text("all:\n\t@echo built\n", encoding="utf-8")
        report = Report(
            id="VDS-0003",
            source=ReportSource.FILE,
            body=(
                "# Report\n\n**Version**: 2.3.1\n\n"
                "```\nbin/rm -rf keep\n```\n"
            ),
            target=Target(repo=".", ref="v1"),
        )
        orchestrator = self._orchestrator(tmp_path)
        result = orchestrator.triage(report, repo_path=tmp_path)
        assert result.verdict.verdict is Verdict.INCONCLUSIVE
        assert "maintainer's approval" in result.verdict.why

    def test_the_confirmation_can_be_given(self, tmp_path: Path) -> None:
        report = Report(
            id="VDS-0004",
            source=ReportSource.FILE,
            body=(
                "# Report\n\n**Version**: 2.3.1\n\n"
                "```\n./demo pip install requests\n```\n"
            ),
            target=Target(repo=".", ref="v1"),
        )
        orchestrator = self._orchestrator(tmp_path)
        result = orchestrator.triage(report, repo_path=tmp_path, confirm=True)
        assert "maintainer's approval" not in result.verdict.why

    def test_a_duplicate_can_stop_the_run(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path, stop_on_duplicate=True)
        orchestrator.triage(_report(), repo_path=tmp_path)
        second = Report(
            id="VDS-0002",
            source=ReportSource.FILE,
            body=REPORT,
            target=Target(repo=".", ref="v1"),
        )
        result = orchestrator.triage(second, repo_path=tmp_path)
        assert result.verdict.verdict is Verdict.DUPLICATE

    def test_the_advisory_source_is_optional(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path, advisory_lookups=True)
        assert orchestrator.dedupe is not None
        assert orchestrator.dedupe.advisory_source is not None

    def test_an_orchestrator_without_a_store_records_nothing(self, tmp_path: Path) -> None:
        orchestrator = Orchestrator(config=Config(sandbox="local"), backend=LocalBackend())
        orchestrator._stage(_report(), "claim")  # must not raise

    def test_a_broken_rrs_block_is_a_warning(self, tmp_path: Path) -> None:
        report = Report(
            id="VDS-0005",
            source=ReportSource.FILE,
            body="```yaml\nrrs: 0.1\ntarget: [unclosed\n```\n",
            target=Target(repo=".", ref="v1"),
        )
        orchestrator = self._orchestrator(tmp_path)
        result = orchestrator.triage(report, repo_path=tmp_path)
        assert any("RRS" in warning for warning in result.warnings)

    def test_the_comparison_ref_defaults_to_the_branch(
        self, tmp_path: Path, git_repo: Path
    ) -> None:
        orchestrator = self._orchestrator(tmp_path)
        assert orchestrator._default_comparison(git_repo, "v1.0") == "main"
        assert orchestrator._default_comparison(git_repo, "") == ""
        assert orchestrator._default_comparison(tmp_path, "v1") == ""

    def test_a_local_comparison_ref_is_accepted(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path)
        source, cleanup = orchestrator._prepare_source(tmp_path, str(tmp_path))
        try:
            assert (source / "x").exists() or source.is_dir()
        finally:
            cleanup()

    def test_the_work_root_defaults_to_the_temporary_directory(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # The work root can be pointed elsewhere by the environment;
        # the default is only the default when nothing says otherwise.
        monkeypatch.delenv("VERDIS_WORK_DIR", raising=False)
        orchestrator = self._orchestrator(tmp_path)
        assert orchestrator._work_root() == Path(__import__("tempfile").gettempdir())

    def test_the_work_root_can_be_set(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path, work_dir=str(tmp_path / "work"))
        assert orchestrator._work_root() == tmp_path / "work"
        assert orchestrator._work_root().is_dir()
