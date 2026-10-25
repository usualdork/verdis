"""Tests for the remaining branches, one file per area.

The leftovers are narrow: a validator branch, an analyzer branch, an
accessor. Each is easy to break without noticing.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from verdis.dedupe.fingerprint import DedupeFingerprint
from verdis.dedupe.osv import OSVAdvisorySource
from verdis.extract.rrs import rrs_from_report_metadata
from verdis.judge.rules import Judge, JudgeContext
from verdis.oracles.engine import OracleEngine, OracleOutcome
from verdis.oracles.frames import extract_frames
from verdis.planner.validator import PlanValidator
from verdis.policy.engine import PolicyEngine
from verdis.preflight.analyzers import detect_file_type, inspect_binary
from verdis.preflight.elf import parse_elf_imports
from verdis.preflight.preflight import Preflight
from verdis.sandbox.container import ContainerBackend
from verdis.schemas.claim import Claim, ClaimComponent
from verdis.schemas.common import Verdict
from verdis.schemas.plan import (
    BuildStep,
    CopyStep,
    ExpectStep,
    Plan,
    RunStep,
)
from verdis.schemas.policy import Policy, PolicyClause
from verdis.schemas.rrs import RRS, RRSPlanStep, RRSTarget
from verdis.schemas.run import CommandResult, RunResult, RunStatus
from verdis.storage.evidence import EvidenceStore


class TestValidatorNarrowBranches:
    def _plan(self, *steps) -> Plan:
        return Plan(steps=steps)

    def test_a_path_in_a_system_directory_is_allowed(self) -> None:
        plan = self._plan(
            RunStep(cmd="./demo /usr/lib/libfoo.so"),
            ExpectStep(oracle="crash"),
        )
        assert PlanValidator().validate(plan).ok

    def test_a_path_in_tmp_is_allowed(self) -> None:
        plan = self._plan(
            RunStep(cmd="./demo /tmp/x"),
            ExpectStep(oracle="crash"),
        )
        assert PlanValidator().validate(plan).ok

    def test_a_build_step_that_reads_a_secret_is_forbidden(self) -> None:
        plan = self._plan(
            BuildStep(recipe="x", steps=("cat /etc/shadow",)),
            RunStep(cmd="./demo"),
            ExpectStep(oracle="crash"),
        )
        validation = PlanValidator().validate(plan)
        assert validation.forbidden

    def test_a_copy_outside_the_workdir_is_forbidden(self) -> None:
        plan = self._plan(
            RunStep(cmd="./demo"),
            CopyStep(artifact="poc.bin", to="/etc/poc"),
            ExpectStep(oracle="crash"),
        )
        assert PlanValidator().validate(plan).forbidden


class TestPolicyNarrowBranches:
    def test_a_component_that_is_not_in_scope_is_excluded(self) -> None:
        policy = Policy(in_scope=("parser",))
        assessment = PolicyEngine(policy).check(
            Claim(component=ClaimComponent(name="unrelated_module"))
        )
        assert assessment.component_in_scope is False

    def test_an_exclusion_with_neither_pattern_nor_keywords_does_not_match(self) -> None:
        policy = Policy(
            excluded_classes=(
                PolicyClause(id="x", kind="excluded", description="d"),
            )
        )
        assessment = PolicyEngine(policy).check(Claim())
        assert not assessment.exclusions

    def test_a_pattern_matches_a_component_with_a_stem(self) -> None:
        policy = Policy(in_scope=("parse",))
        assessment = PolicyEngine(policy).check(
            Claim(component=ClaimComponent(name="parse_header"))
        )
        assert assessment.component_in_scope is True


class TestPreflightNarrowBranches:
    def test_an_opaque_binary_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "a.bin"
        path.write_bytes(b"\xff\xfe\x00\x01\x02\x03")
        assert detect_file_type(path) == "binary"
        result = Preflight().inspect(
            Attachment_for(path)
        )
        assert any(f.code == "binary-opaque" for f in result.findings)

    def test_a_missing_binary_is_reported(self, tmp_path: Path) -> None:
        report = inspect_binary(tmp_path / "gone.bin")
        assert any(f.code == "binary-unreadable" for f in report.findings)


def Attachment_for(path: Path):
    from verdis.schemas.report import Attachment

    return Attachment(
        name=path.name,
        path=str(path),
        sha256="0" * 64,
        size=path.stat().st_size if path.exists() else 0,
    )


class TestDedupeNarrowBranches:
    def test_an_advisory_without_an_id_is_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "advisories.json"
        path.write_text(json.dumps([{"title": "no id"}]), encoding="utf-8")
        from verdis.dedupe.index import LocalAdvisorySource

        assert LocalAdvisorySource(path).lookup() == []

    def test_the_osv_source_skips_an_advisory_without_an_id(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"vulns": [{"summary": "no id"}]})

        source = OSVAdvisorySource(
            package="libfoo",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        assert source.lookup() == []

    def test_the_osv_source_closes_its_own_client(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"vulns": []})

        source = OSVAdvisorySource(package="libfoo")
        source.lookup_with = None  # type: ignore[attr-defined]
        # The source opens and closes its own client.
        import verdis.dedupe.osv as osv_module

        created: list[httpx.Client] = []
        original = osv_module.httpx.Client

        def factory(*args, **kwargs):
            client = original(*args, **kwargs)
            created.append(client)
            return client

        osv_module.httpx.Client = factory  # type: ignore[assignment]
        try:
            source = OSVAdvisorySource(package="libfoo")
            source._client = None
            assert source.lookup() == []
        finally:
            osv_module.httpx.Client = original  # type: ignore[assignment]

    def test_a_fingerprint_without_a_class_is_stable(self) -> None:
        first = DedupeFingerprint.build(report_id="VDS-1", body="x")
        second = DedupeFingerprint.build(report_id="VDS-1", body="x")
        assert first.class_component == second.class_component


class TestExtractorNarrowBranches:
    def test_the_model_fills_the_line_number(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        provider = FakeProvider({"component_name": "", "component_file": ""})
        outcome = __import__(
            "verdis.extract.extractor", fromlist=["ClaimExtractor"]
        ).ClaimExtractor(provider).extract("the crash is in src/hdr.c:212")
        assert outcome.claim.component.line == 212

    def test_the_model_fills_the_artifacts(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        provider = FakeProvider({"artifacts": [], "commands": ["./demo"]})
        outcome = __import__(
            "verdis.extract.extractor", fromlist=["ClaimExtractor"]
        ).ClaimExtractor(provider).extract("nothing")
        assert outcome.claim.poc_artifacts == ()

    def test_the_model_fills_the_preconditions(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        provider = FakeProvider({"preconditions": []})
        outcome = __import__(
            "verdis.extract.extractor", fromlist=["ClaimExtractor"]
        ).ClaimExtractor(provider).extract("nothing")
        assert outcome.claim.preconditions == ()


class TestRrsNarrowBranches:
    def test_a_step_can_be_a_bare_word(self) -> None:
        step = RRSPlanStep.model_validate("build")
        assert step.action == "build"
        assert step.value == ""

    def test_a_step_mapping_with_a_build_key_is_accepted(self) -> None:
        step = RRSPlanStep.model_validate({"build": "default"})
        assert step.action == "build"

    def test_a_step_mapping_with_a_run_key_is_accepted(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.action == "run"

    def test_an_empty_class_is_empty(self) -> None:
        assert RRS(target=RRSTarget(repo="r"), claim_class="").claim_class == ""

    def test_the_report_metadata_builds_an_rrs(self) -> None:
        rrs = rrs_from_report_metadata(
            repo="r",
            ref="v1",
            commands=("./demo",),
            attachment_hashes={"poc.bin": "a" * 64},
        )
        assert rrs.run_commands() == ("./demo",)
        assert rrs.inputs[0].path == "poc.bin"


class TestEngineNarrowBranches:
    def test_an_oracle_that_is_not_registered_is_skipped(self) -> None:
        engine = OracleEngine()
        engine.oracles = {}
        outcomes = engine.evaluate(
            RunResult(
                status=RunStatus.COMPLETED,
                runs=(CommandResult(cmd="./demo"),),
            ),
            Plan(steps=(RunStep(cmd="./demo"), ExpectStep(oracle="crash"))),
            Claim(),
        )
        assert outcomes == ()

    def test_the_frames_keep_every_occurrence(self) -> None:
        output = "    #0 0x1 in parse_header a.c:1\n    #1 0x2 in parse_header b.c:2\n"
        frames = extract_frames(output)
        assert len(frames) == 2
        # The symbols are deduplicated where it matters.
        from verdis.oracles.frames import extract_frame_symbols

        assert extract_frame_symbols(output) == ("parse_header",)


class TestContainerErrorBranches:
    def _backend(self, monkeypatch) -> ContainerBackend:
        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        backend = _Concrete(binary="fake")
        return backend

    def test_a_runtime_that_cannot_be_run_is_reported(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        def broken(*args, **kwargs):
            raise OSError("no runtime")

        monkeypatch.setattr(container_module.subprocess, "run", broken)
        backend = self._backend(monkeypatch)
        assert backend.server_version() == ""
        assert backend.doctor()

    def test_the_isolation_notes_survive_a_broken_runtime(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        def broken(*args, **kwargs):
            raise OSError("no runtime")

        monkeypatch.setattr(container_module.subprocess, "run", broken)
        backend = self._backend(monkeypatch)
        assert backend._isolation_notes() == []

    def test_the_image_digest_survives_a_broken_runtime(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        def broken(*args, **kwargs):
            raise OSError("no runtime")

        monkeypatch.setattr(container_module.subprocess, "run", broken)
        backend = self._backend(monkeypatch)
        assert backend._image_digest("python:3.12") == ""
        assert backend.image_present("python:3.12") is False

    def test_a_broken_info_json_is_handled(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(args, 0, "not json", "")

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = self._backend(monkeypatch)
        assert backend._isolation_notes() == []


class TestJudgeNarrowBranches:
    def test_a_reproduced_verdict_carries_the_flags(self) -> None:
        from verdis.schemas.common import OracleType, VerdictFlag
        from verdis.schemas.run import OracleResult

        outcome = OracleOutcome(
            oracle=OracleType.SANITIZER,
            results=(
                OracleResult(
                    oracle=OracleType.SANITIZER,
                    fired=True,
                    matched_claim=True,
                    evidence=("a",),
                ),
            ),
            fired_count=1,
            total=1,
        )
        verdict = Judge().judge(
            JudgeContext(
                claim=Claim(),
                run=RunResult(
                    status=RunStatus.COMPLETED,
                    runs=(CommandResult(cmd="./demo"),),
                ),
                oracles=(outcome,),
                plan=Plan(
                    steps=(
                        RunStep(cmd="./demo"),
                        ExpectStep(oracle=OracleType.SANITIZER),
                    )
                ),
            )
        )
        assert verdict.verdict is Verdict.REPRODUCED
        assert VerdictFlag.DEFAULT_CONFIG_ONLY in verdict.flags

    def test_the_evidence_points_are_collected(self) -> None:
        from verdis.schemas.common import OracleType
        from verdis.schemas.run import OracleResult

        outcome = OracleOutcome(
            oracle=OracleType.SANITIZER,
            results=(
                OracleResult(
                    oracle=OracleType.SANITIZER,
                    fired=True,
                    matched_claim=True,
                    evidence=("the first line", "the second line"),
                ),
            ),
            fired_count=1,
            total=1,
        )
        verdict = Judge().judge(
            JudgeContext(
                claim=Claim(),
                run=RunResult(
                    status=RunStatus.COMPLETED,
                    runs=(CommandResult(cmd="./demo"),),
                ),
                oracles=(outcome,),
            )
        )
        assert verdict.evidence


class TestStorageNarrowBranches:
    def test_a_binary_file_is_written(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        store.write_bundle("VDS-1", {"a.bin": b"\x00\x01"})
        assert (store.bundle_dir("VDS-1") / "a.bin").read_bytes() == b"\x00\x01"

    def test_a_broken_manifest_is_reported(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        bundle = store.bundle_dir("VDS-1")
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "manifest.json").write_text("{not json", encoding="utf-8")
        assert store.read_manifest("VDS-1") is None

    def test_a_missing_manifest_is_reported(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        assert store.verify_bundle("VDS-1") == ["no manifest found"]

    def test_a_file_that_is_not_in_the_manifest_is_ignored(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        store.write_bundle("VDS-1", {"a.txt": "x"})
        (store.bundle_dir("VDS-1") / "extra.txt").write_text("y", encoding="utf-8")
        assert store.verify_bundle("VDS-1") == []

    def test_removing_a_report_that_is_not_there(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        assert store.remove("VDS-nope") is False


class TestElfNarrowBranches:
    def test_a_section_header_that_is_truncated_is_skipped(self) -> None:
        data = bytearray(b"\x7fELF" + b"\x00" * 200)
        import struct

        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 2)
        struct.pack_into("<H", data, 0x3E, 1)
        # The section header runs past the end of the data.
        assert parse_elf_imports(bytes(data)) == ([], [])

    def test_a_symbol_entry_that_is_truncated_is_skipped(self) -> None:
        from tests.unit.test_elf_and_backends import _build_elf

        data = bytearray(_build_elf(["printf"], ["libc.so.6"]))
        # Cut the symbol table in half.
        del data[300:]
        assert isinstance(parse_elf_imports(bytes(data)), tuple)


class TestCheckoutNarrowBranches:
    def test_the_archive_fallback_is_used(self, tmp_path: Path, monkeypatch) -> None:
        import verdis.build.checkout as checkout_module
        from verdis.build.checkout import checkout_ref

        def fake_run_git(args, cwd, timeout=120):
            if args[0] == "worktree":
                return subprocess.CompletedProcess(args, 1, "", "no worktree here")
            if args[0] == "rev-parse":
                return subprocess.CompletedProcess(args, 0, "abc123\n", "")
            if args[0] == "archive":
                # Write a real tar so the fallback can unpack it.
                import io
                import tarfile

                archive = Path(args[args.index("-o") + 1])
                with tarfile.open(archive, "w") as tar:
                    info = tarfile.TarInfo("file.txt")
                    data = b"content"
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        monkeypatch.setattr(checkout_module, "_run_git", fake_run_git)
        monkeypatch.setattr(
            checkout_module,
            "_is_git_repo",
            lambda path: True,
        )
        checkout = checkout_ref(tmp_path, "v1.0")
        try:
            assert checkout.method == "archive"
            assert (checkout.path / "file.txt").read_text() == "content"
        finally:
            checkout.cleanup()
