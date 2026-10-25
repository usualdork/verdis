"""Property tests: the invariants that must hold for any input (PRD 13.2)."""

from __future__ import annotations

import re

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from verdis.dedupe.fingerprint import (
    DedupeFingerprint,
    cosine_similarity,
    extract_stack_signature,
    hashed_embedding,
    normalize_poc_bytes,
)
from verdis.extract.rrs import emit_rrs, parse_rrs
from verdis.planner.validator import PlanValidator, Severity
from verdis.policy.loader import matches_version
from verdis.schemas.plan import ExpectStep, Plan, RunStep

SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

#: Programs the validator treats as unusual. They are excluded from the
#: "ordinary command" strategy, because an ordinary command is one the
#: validator has no reason to ask about.
UNUSUAL_PROGRAMS = frozenset(
    {
        "dd", "rm", "mv", "mkdir", "touch", "chmod", "chown", "useradd",
        "crontab", "pip", "pip3", "npm", "apt", "apt-get", "go", "cargo",
        "git", "gh", "curl", "wget", "nc", "ssh", "sudo", "mount", "docker",
        "systemctl", "kill", "printenv", "shred", "tee", "su", "passwd",
    }
)

SAFE_PROGRAM = st.from_regex(r"\A[a-z][a-z0-9_]{0,15}\Z").filter(
    lambda name: name not in UNUSUAL_PROGRAMS
)

SAFE_COMMANDS = st.builds(
    lambda name, arg: f"./{name} {arg}",
    SAFE_PROGRAM,
    st.from_regex(r"\A[a-z0-9_.-]{0,20}\Z"),
)

DANGEROUS_FRAGMENTS = [
    "curl",
    "wget",
    "nc ",
    "ssh ",
    "sudo",
    "cat /etc/shadow",
    "~/.ssh",
    "printenv",
    "mount ",
    "docker ",
    "systemctl",
    "pip install",
    "npm install",
    "chmod ",
    "rm -rf",
    "crontab",
    "http://",
    "https://",
    "$(",
    "`",
    ";",
    "|",
    "&&",
    ">",
    "/etc/passwd",
    "$AWS_SECRET_ACCESS_KEY",
]


class TestPlanValidatorProperties:
    @given(cmd=st.text(min_size=1, max_size=80))
    @SETTINGS
    def test_the_validator_never_raises(self, cmd: str) -> None:
        plan = Plan(steps=(RunStep(cmd=cmd), ExpectStep(oracle="crash")))
        validation = PlanValidator().validate(plan)
        assert validation.issues or validation.ok

    @given(cmd=SAFE_COMMANDS)
    @SETTINGS
    def test_ordinary_commands_are_allowed(self, cmd: str) -> None:
        plan = Plan(steps=(RunStep(cmd=cmd), ExpectStep(oracle="crash")))
        validation = PlanValidator().validate(plan)
        assert validation.ok, [i.message for i in validation.issues]

    @given(
        cmd=st.builds(
            lambda fragment: f"{fragment} payload",
            st.sampled_from(DANGEROUS_FRAGMENTS),
        )
    )
    @SETTINGS
    def test_dangerous_commands_are_never_runnable_unattended(self, cmd: str) -> None:
        plan = Plan(steps=(RunStep(cmd=cmd), ExpectStep(oracle="crash")))
        validation = PlanValidator().validate(plan)
        assert not validation.ok

    @given(
        fragment=st.sampled_from(["nc", "curl", "wget", "sudo", "mount", "ssh"]),
    )
    @SETTINGS
    def test_a_tool_name_as_an_argument_is_not_a_command(self, fragment: str) -> None:
        # The validator looks at the program of a command, not at its
        # arguments: an argument that happens to be called "nc" is not a
        # network call.
        plan = Plan(steps=(RunStep(cmd=f"./demo {fragment}"), ExpectStep(oracle="crash")))
        validation = PlanValidator().validate(plan)
        assert not any(
            issue.code in {"network-access", "host-access"}
            for issue in validation.issues
        )

    @given(cmd=st.text(min_size=1, max_size=60))
    @SETTINGS
    def test_a_forbidden_plan_is_never_ok(self, cmd: str) -> None:
        plan = Plan(steps=(RunStep(cmd=cmd), ExpectStep(oracle="crash")))
        validation = PlanValidator().validate(plan)
        if any(issue.severity is Severity.FORBIDDEN for issue in validation.issues):
            assert not validation.ok
            assert not validation.runnable

    @given(
        destination=st.text(min_size=1, max_size=40).filter(
            lambda d: not d.startswith("/work")
        )
    )
    @SETTINGS
    def test_a_copy_outside_the_workdir_is_forbidden(self, destination: str) -> None:
        from verdis.schemas.plan import CopyStep

        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                CopyStep(artifact="poc.bin", to=destination),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert validation.forbidden

    @given(ref=st.from_regex(r"\A-[a-z]{1,10}\Z"))
    @SETTINGS
    def test_an_option_like_ref_is_forbidden(self, ref: str) -> None:
        from verdis.schemas.plan import CheckoutStep

        plan = Plan(
            steps=(
                CheckoutStep(ref=ref),
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert validation.forbidden


class TestRRSProperties:
    @given(
        repo=st.text(min_size=1, max_size=40).filter(lambda s: "\n" not in s),
        ref=st.text(min_size=0, max_size=20).filter(lambda s: "\n" not in s),
        command=st.text(min_size=1, max_size=40).filter(
            lambda s: s == s.strip() and s.strip() and "\n" not in s and ":" not in s
        ),
    )
    @SETTINGS
    def test_a_generated_block_round_trips(self, repo: str, ref: str, command: str) -> None:
        block = emit_rrs(repo=repo, ref=ref, commands=(command,), oracle="crash")
        parsed = parse_rrs(block)
        assert parsed is not None
        assert parsed.target.repo == repo
        assert parsed.target.ref == ref
        assert parsed.run_commands() == (command,)

    @given(
        repo=st.text(min_size=1, max_size=40).filter(lambda s: s.strip() and "\n" not in s),
        ref=st.text(min_size=0, max_size=20).filter(lambda s: "\n" not in s),
    )
    @SETTINGS
    def test_an_empty_command_is_rejected_by_the_model(self, repo: str, ref: str) -> None:
        from pydantic import ValidationError

        from verdis.schemas.plan import RunStep

        with pytest.raises(ValidationError):
            RunStep(cmd="")

    @given(text=st.text(max_size=200))
    @SETTINGS
    def test_parsing_never_raises_on_arbitrary_text(self, text: str) -> None:
        from verdis.extract.rrs import RRSParseError

        try:
            parse_rrs(text)
        except RRSParseError:
            pass  # a broken block is reported, not crashed on


class TestFingerprintProperties:
    @given(body=st.text(max_size=200))
    @SETTINGS
    def test_the_fingerprint_is_deterministic(self, body: str) -> None:
        first = DedupeFingerprint.build(report_id="VDS-1", body=body)
        second = DedupeFingerprint.build(report_id="VDS-1", body=body)
        assert first == second

    @given(body=st.text(max_size=200))
    @SETTINGS
    def test_the_embedding_is_deterministic_and_normalised(self, body: str) -> None:
        vector = hashed_embedding(body)
        assert vector == hashed_embedding(body)
        norm = sum(value * value for value in vector) ** 0.5
        assert norm <= 1.0 + 1e-9

    @given(
        left=st.text(max_size=100),
        right=st.text(max_size=100),
    )
    @SETTINGS
    def test_cosine_similarity_is_in_range(self, left: str, right: str) -> None:
        score = cosine_similarity(hashed_embedding(left), hashed_embedding(right))
        assert 0.0 <= score <= 1.0

    @given(data=st.binary(max_size=200))
    @SETTINGS
    def test_normalising_poc_bytes_never_raises(self, data: bytes) -> None:
        assert isinstance(normalize_poc_bytes(data), bytes)

    @given(output=st.text(max_size=300))
    @SETTINGS
    def test_the_stack_signature_is_stable(self, output: str) -> None:
        assert extract_stack_signature(output) == extract_stack_signature(output)

    @given(
        address=st.integers(min_value=0x1000, max_value=0xFFFFFFFF),
        symbol=st.from_regex(r"\A[a-z_][a-z0-9_]{2,20}\Z"),
    )
    @SETTINGS
    def test_addresses_do_not_change_the_signature(self, address: int, symbol: str) -> None:
        first = extract_stack_signature(f"    #0 0x{address:x} in {symbol} src/x.c:1")
        second = extract_stack_signature(f"    #0 0x{address + 16:x} in {symbol} src/x.c:99")
        assert first == second
        assert symbol in first


class TestVersionProperties:
    @given(
        major=st.integers(min_value=0, max_value=9),
        minor=st.integers(min_value=0, max_value=99),
        patch=st.integers(min_value=0, max_value=99),
    )
    @SETTINGS
    def test_an_exact_version_matches_itself(self, major: int, minor: int, patch: int) -> None:
        version = f"{major}.{minor}.{patch}"
        assert matches_version(version, version)

    @given(
        major=st.integers(min_value=1, max_value=9),
        minor=st.integers(min_value=0, max_value=99),
        patch=st.integers(min_value=0, max_value=99),
    )
    @SETTINGS
    def test_a_wildcard_matches_its_own_major(self, major: int, minor: int, patch: int) -> None:
        assert matches_version(f"{major}.x", f"{major}.{minor}.{patch}")
        assert not matches_version(f"{major}.x", f"{major + 1}.0.0")

    @given(
        low=st.integers(min_value=0, max_value=50),
        high=st.integers(min_value=0, max_value=50),
        version=st.integers(min_value=0, max_value=50),
    )
    @SETTINGS
    def test_a_range_matches_only_inside_the_range(self, low: int, high: int, version: int) -> None:
        low, high = min(low, high), max(low, high)
        pattern = f"{low}.0-{high}.0"
        result = matches_version(pattern, f"{version}.0.0")
        assert result == (low <= version <= high)


class TestExtractionProperties:
    @given(text=st.text(max_size=300))
    @SETTINGS
    def test_extraction_never_raises_and_never_invents(self, text: str) -> None:
        from verdis.extract.heuristics import extract_claim

        claim = extract_claim(text)
        assert isinstance(claim.vuln_class, str)
        if claim.vuln_class:
            assert re.fullmatch(r"CWE-\d+", claim.vuln_class)
        for name, span in claim.spans.items():
            assert 0 <= span.start <= span.end <= len(text) + 1, name
