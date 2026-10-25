"""Fuzzing of the parsers (PRD 13.2).

The parsers read text that a stranger wrote: a report, a machine
readable report block, a plan, a policy file. They must never crash,
never hang, and never return something the schema does not allow. A
parser that raises an unexpected exception on hostile input is a
denial of service in the tool that is supposed to be triaging the
report.

Hypothesis does the work: it generates the awkward inputs that a
person would not think of.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from verdis.extract.guard import summarize
from verdis.extract.rrs import RRSParseError, parse_rrs, parse_rrs_document
from verdis.planner.validator import PlanValidator
from verdis.policy.loader import PolicyLoadError, policy_from_dict
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.report import Report

SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

#: The text a parser is most likely to choke on.
TEXT = st.text(
    alphabet=st.characters(
        min_codepoint=32, max_codepoint=126, blacklist_characters="\\x00"
    )
    | st.characters(min_codepoint=1, max_codepoint=31),
    max_size=400,
)

#: A plausible report block.
BLOCKS = st.lists(
    st.tuples(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12),
        st.one_of(
            st.text(max_size=40),
            st.integers(),
            st.booleans(),
            st.none(),
        ),
    ),
    max_size=12,
)


class TestTheReportParser:
    @SETTINGS
    @given(TEXT)
    def test_any_text_becomes_a_report(self, text: str) -> None:
        report = Report(
            id="VDS-0001",
            source="file",
            body=text,
        )
        assert isinstance(report.body, str)

    @SETTINGS
    @given(TEXT)
    def test_the_injection_guard_never_raises(self, text: str) -> None:
        summary = summarize(text)
        assert summary["count"] >= 0


class TestTheRrsParser:
    @SETTINGS
    @given(TEXT)
    def test_any_text_is_either_a_block_or_an_error(self, text: str) -> None:
        try:
            block = parse_rrs(text)
        except RRSParseError:
            return
        if block is not None:
            assert block.version

    @SETTINGS
    @given(BLOCKS)
    def test_any_mapping_is_either_a_block_or_an_error(self, pairs: list) -> None:
        document = dict(pairs)
        try:
            parse_rrs_document(document)
        except RRSParseError:
            return


class TestThePlanValidator:
    @SETTINGS
    @given(st.text(min_size=1, max_size=200))
    def test_any_command_is_rejected_or_accepted(self, command: str) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd=command),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert isinstance(validation.ok, bool)


class TestThePolicyLoader:
    @SETTINGS
    @given(
        st.dictionaries(
            st.text(alphabet="abcdefghij", min_size=1, max_size=8),
            st.one_of(st.text(max_size=30), st.integers(), st.booleans(), st.none()),
            max_size=6,
        )
    )
    def test_any_policy_is_either_loaded_or_rejected(self, document: dict) -> None:
        try:
            policy = policy_from_dict(document)
        except PolicyLoadError:
            return
        assert policy is not None


class TestTheSchema:
    @SETTINGS
    @given(st.text(min_size=1, max_size=100))
    def test_any_ref_is_either_valid_or_rejected(self, ref: str) -> None:
        from pydantic import ValidationError

        from verdis.schemas.plan import CompareStep

        try:
            CompareStep(ref=ref)
        except ValidationError:
            return
