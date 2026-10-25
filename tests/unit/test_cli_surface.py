"""The rest of the command line surface (PRD 9.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from verdis.cli import (
    _default_evidence,
    _default_store,
    _echo_json,
    _exit_code,
    _load_config,
    _missing_images,
    _write_preflight_bundle,
    app,
)
from verdis.schemas.common import Verdict

runner = CliRunner()


@pytest.fixture()
def isolated(tmp_path: Path) -> list[str]:
    store = tmp_path / "store"
    evidence = tmp_path / "evidence"
    store.mkdir()
    evidence.mkdir()
    return ["--store", str(store), "--evidence", str(evidence)]


class TestHelpers:
    def test_the_default_store_is_under_the_home(self) -> None:
        assert _default_store().name == "verdis"

    def test_the_default_evidence_sits_beside_the_store(self) -> None:
        assert _default_evidence().parent == _default_store()

    def test_a_config_file_is_loaded(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yml"
        path.write_text("mode: label\nsandbox: hardened\n", encoding="utf-8")
        config = _load_config(str(path))
        assert config.mode == "label"
        assert config.sandbox == "hardened"

    def test_an_empty_config_file_is_the_default(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yml"
        path.write_text("", encoding="utf-8")
        assert _load_config(str(path)).mode == "shadow"

    def test_a_backend_without_image_support_reports_nothing(self) -> None:
        class _Plain:
            pass

        assert _missing_images(_Plain()) == []

    def test_a_missing_image_is_reported(self) -> None:
        class _Backend:
            @staticmethod
            def missing_images(images: tuple[str, ...]) -> list[str]:
                return list(images)

        assert _missing_images(_Backend()) == ["ghcr.io/usualdork/verdis/base:latest"]

    def test_json_is_echoed(self, capsys: pytest.CaptureFixture[str]) -> None:
        _echo_json({"b": 1, "a": 2})
        assert json.loads(capsys.readouterr().out) == {"a": 2, "b": 1}

    @pytest.mark.parametrize(
        ("verdict", "expected"),
        [
            (Verdict.REPRODUCED, 0),
            (Verdict.NOT_REPRODUCED, 0),
            (Verdict.OUT_OF_SCOPE, 0),
            (Verdict.DUPLICATE, 0),
            (Verdict.INCONCLUSIVE, 1),
            (Verdict.NEEDS_INFO, 1),
            (Verdict.UNSAFE_ATTACHMENT, 1),
        ],
    )
    def test_the_exit_code_follows_the_verdict(
        self, verdict: Verdict, expected: int
    ) -> None:
        assert _exit_code(verdict) == expected


class TestPreflightBundle:
    def test_the_bundle_is_written(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.mkdir()
        (poc / "poc.bin").write_bytes(b"A" * 8)
        bundle = tmp_path / "bundle"
        _write_preflight_bundle(poc, "rrs: 0.1\n", [], str(bundle))
        assert (bundle / "rrs.yaml").is_file()
        assert (bundle / "preflight.md").is_file()
        payload = json.loads((bundle / "inputs.json").read_text(encoding="utf-8"))
        assert payload["inputs"][0]["path"] == "poc.bin"

    def test_the_findings_are_written(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.mkdir()
        (poc / "poc.bin").write_bytes(b"A")
        bundle = tmp_path / "bundle"
        _write_preflight_bundle(poc, "rrs: 0.1\n", ["found something"], str(bundle))
        assert "found something" in (bundle / "preflight.md").read_text(encoding="utf-8")

    def test_no_findings_still_produces_a_readable_file(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.mkdir()
        bundle = tmp_path / "bundle"
        _write_preflight_bundle(poc, "rrs: 0.1\n", [], str(bundle))
        assert "nothing observed" in (bundle / "preflight.md").read_text(encoding="utf-8")

    def test_a_subdirectory_is_skipped(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.mkdir()
        (poc / "sub").mkdir()
        (poc / "poc.bin").write_bytes(b"A")
        bundle = tmp_path / "bundle"
        _write_preflight_bundle(poc, "rrs: 0.1\n", [], str(bundle))
        payload = json.loads((bundle / "inputs.json").read_text(encoding="utf-8"))
        assert len(payload["inputs"]) == 1


class TestPreflightCommand:
    def test_a_bundle_is_written(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.mkdir()
        (poc / "poc.bin").write_bytes(b"A" * 8)
        bundle = tmp_path / "bundle"
        result = runner.invoke(
            app, ["preflight", str(poc), "--bundle-out", str(bundle)]
        )
        assert result.exit_code == 0
        assert (bundle / "rrs.yaml").is_file()
        assert (bundle / "inputs.json").is_file()

    def test_a_subdirectory_is_ignored(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.mkdir()
        (poc / "sub").mkdir()
        (poc / "poc.bin").write_bytes(b"A")
        result = runner.invoke(app, ["preflight", str(poc)])
        assert result.exit_code == 0
        assert "poc.bin" in result.stdout


class TestTriageCommand:
    def _report(self, tmp_path: Path) -> Path:
        report = tmp_path / "report.md"
        report.write_text(
            "# Something is wrong\n\nThe parser misbehaves with long inputs.\n",
            encoding="utf-8",
        )
        return report

    def test_the_json_output(self, tmp_path: Path, isolated: list[str]) -> None:
        result = runner.invoke(
            app,
            [
                "triage",
                str(self._report(tmp_path)),
                "--repo",
                str(tmp_path),
                "--sandbox",
                "local",
                "--output",
                "json",
                *isolated,
            ],
        )
        assert json.loads(result.stdout)["verdict"] == "NEEDS_INFO"

    def test_the_sarif_output(self, tmp_path: Path, isolated: list[str]) -> None:
        result = runner.invoke(
            app,
            [
                "triage",
                str(self._report(tmp_path)),
                "--repo",
                str(tmp_path),
                "--sandbox",
                "local",
                "--output",
                "sarif",
                *isolated,
            ],
        )
        payload = json.loads(result.stdout)
        assert payload["version"] == "2.1.0"

    def test_the_bundle_is_copied_out(
        self, tmp_path: Path, isolated: list[str]
    ) -> None:
        bundle = tmp_path / "copied"
        result = runner.invoke(
            app,
            [
                "triage",
                str(self._report(tmp_path)),
                "--repo",
                str(tmp_path),
                "--sandbox",
                "local",
                "--bundle-out",
                str(bundle),
                *isolated,
            ],
        )
        assert result.exit_code == 1
        assert (bundle / "verdict.json").is_file()

    def test_a_config_file_is_used(self, tmp_path: Path, isolated: list[str]) -> None:
        config = tmp_path / "config.yml"
        config.write_text("mode: shadow\nsandbox: local\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "triage",
                str(self._report(tmp_path)),
                "--repo",
                str(tmp_path),
                "--config",
                str(config),
                *isolated,
            ],
        )
        assert result.exit_code == 1

    def test_a_broken_config_file_is_reported(
        self, tmp_path: Path, isolated: list[str]
    ) -> None:
        config = tmp_path / "config.yml"
        config.write_text("mode: [\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "triage",
                str(self._report(tmp_path)),
                "--repo",
                str(tmp_path),
                "--config",
                str(config),
                *isolated,
            ],
        )
        assert result.exit_code == 2
        assert "configuration error" in result.stderr

    def test_a_sandbox_error_is_reported(
        self, tmp_path: Path, isolated: list[str], monkeypatch
    ) -> None:
        from verdis import cli
        from verdis.sandbox.base import SandboxError

        # The report has to reach the run stage, so the project has to
        # build.
        project = tmp_path / "project"
        project.mkdir()
        (project / "Makefile").write_text("all:\n\t@echo built\n", encoding="utf-8")
        report = tmp_path / "runnable.md"
        report.write_text(
            "# Heap overflow in parse_header\n\n**Version**: 2.3.1\n\n"
            "```\n./demo poc.bin\n```\n",
            encoding="utf-8",
        )

        class _Broken:
            name = "broken"

            def available(self) -> bool:
                return True

            def doctor(self) -> list[str]:
                return []

            def run(self, request: object) -> object:
                raise SandboxError("no runtime here")

        monkeypatch.setattr(cli, "build_backend", lambda name: _Broken())
        result = runner.invoke(
            app,
            [
                "triage",
                str(report),
                "--repo",
                str(project),
                "--sandbox",
                "local",
                *isolated,
            ],
        )
        assert result.exit_code == 3
        assert "sandbox error" in result.stderr

    def test_the_sandbox_and_model_overrides(
        self, tmp_path: Path, isolated: list[str]
    ) -> None:
        result = runner.invoke(
            app,
            [
                "triage",
                str(self._report(tmp_path)),
                "--repo",
                str(tmp_path),
                "--sandbox",
                "local",
                "--model-provider",
                "none",
                *isolated,
            ],
        )
        assert result.exit_code == 1

    def test_the_policy_override_is_used(
        self, tmp_path: Path, isolated: list[str]
    ) -> None:
        policy = tmp_path / "policy.yml"
        policy.write_text(
            "supported_versions: ['9.x']\n"
            "evidence_requirements:\n  poc_required: true\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "triage",
                str(self._report(tmp_path)),
                "--repo",
                str(tmp_path),
                "--sandbox",
                "local",
                "--policy",
                str(policy),
                *isolated,
            ],
        )
        assert result.exit_code == 1
        # The report asks for no version, so the policy's own requirement
        # drives the verdict.
        assert "NEEDS_INFO" in result.stdout

    def test_a_warning_is_printed(self, tmp_path: Path, isolated: list[str]) -> None:
        (tmp_path / "SECURITY.md").write_text(
            "# Security\n\n## Supported versions\n\n- 2.x\n", encoding="utf-8"
        )
        result = runner.invoke(
            app,
            [
                "triage",
                str(self._report(tmp_path)),
                "--repo",
                str(tmp_path),
                "--sandbox",
                "local",
                *isolated,
            ],
        )
        assert "unverified" in result.stderr


class TestInboxCommand:
    def _seed(self, tmp_path: Path, isolated: list[str]) -> str:
        report = tmp_path / "report.md"
        report.write_text("# Something is wrong\n\nThe parser misbehaves.\n", encoding="utf-8")
        runner.invoke(
            app,
            [
                "triage",
                str(report),
                "--repo",
                str(tmp_path),
                "--sandbox",
                "local",
                *isolated,
            ],
        )
        rows = runner.invoke(app, ["inbox", "list", *isolated])
        assert rows.exit_code == 0
        for line in rows.stdout.splitlines():
            if line.startswith("VDS-"):
                return line.split()[0]
        raise AssertionError("no report in the inbox")

    def test_the_inbox_lists_the_reports(
        self, tmp_path: Path, isolated: list[str]
    ) -> None:
        report_id = self._seed(tmp_path, isolated)
        rows = runner.invoke(app, ["inbox", "list", *isolated])
        assert report_id in rows.stdout
        assert "NEEDS_INFO" in rows.stdout

    def test_a_report_can_be_shown(self, tmp_path: Path, isolated: list[str]) -> None:
        report_id = self._seed(tmp_path, isolated)
        result = runner.invoke(app, ["inbox", "show", report_id, *isolated])
        assert result.exit_code == 0
        assert "Verdis verdict" in result.stdout

    def test_a_report_can_be_shown_as_json(
        self, tmp_path: Path, isolated: list[str]
    ) -> None:
        report_id = self._seed(tmp_path, isolated)
        result = runner.invoke(
            app, ["inbox", "show", report_id, "--output", "json", *isolated]
        )
        assert json.loads(result.stdout)["verdict"] == "NEEDS_INFO"

    def test_a_report_can_be_re_run(self, tmp_path: Path, isolated: list[str]) -> None:
        report_id = self._seed(tmp_path, isolated)
        result = runner.invoke(
            app, ["inbox", "rerun", report_id, "--ref", "v1", "--sandbox", "local", *isolated]
        )
        assert result.exit_code == 0
        assert "Verdis verdict" in result.stdout

    def test_re_running_an_unknown_report(self, tmp_path: Path, isolated: list[str]) -> None:
        result = runner.invoke(
            app, ["inbox", "rerun", "VDS-nope", "--sandbox", "local", *isolated]
        )
        assert result.exit_code == 1


class TestDoctorCommand:
    def test_the_missing_images_are_reported(
        self, isolated: list[str], monkeypatch
    ) -> None:
        from verdis import cli

        class _Backend:
            name = "fake"

            def available(self) -> bool:
                return True

            def doctor(self) -> list[str]:
                return ["all good"]

            def missing_images(self, images: tuple[str, ...]) -> list[str]:
                return ["ghcr.io/usualdork/verdis/base:latest"]

        monkeypatch.setattr(cli, "build_backend", lambda name: _Backend())
        result = runner.invoke(app, ["doctor", *isolated])
        assert result.exit_code == 0
        assert "is not on this machine" in result.stdout

    def test_a_backend_without_image_support(self, isolated: list[str], monkeypatch) -> None:
        from verdis import cli

        class _Backend:
            name = "fake"

            def available(self) -> bool:
                return True

            def doctor(self) -> list[str]:
                return ["all good"]

        monkeypatch.setattr(cli, "build_backend", lambda name: _Backend())
        result = runner.invoke(app, ["doctor", *isolated])
        assert result.exit_code == 0
        assert "all good" in result.stdout
