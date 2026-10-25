"""Tests for RRS parsing and emission (FR-2.4, section 9.4)."""

from __future__ import annotations

import pytest

from verdis.extract.rrs import (
    RRSParseError,
    emit_rrs,
    find_rrs_blocks,
    parse_rrs,
    parse_rrs_document,
)

VALID_RRS = """\
# My report

```yaml
rrs: 0.1
target:
  repo: https://github.com/example/libfoo
  ref: v2.3.1
claim:
  class: CWE-122
  component: src/hdr.c:parse_header
  impact: memory corruption leading to crash
steps:
  - build: default
  - run: ./build/parse_demo poc.bin
inputs:
  - path: poc.bin
    sha256: 0000000000000000000000000000000000000000000000000000000000000000
expect:
  oracle: sanitizer
  signature: heap-buffer-overflow in parse_header
config:
  default: true
```
"""


class TestParseRRS:
    def test_parses_a_valid_block(self) -> None:
        rrs = parse_rrs(VALID_RRS)
        assert rrs is not None
        assert rrs.target.repo == "https://github.com/example/libfoo"
        assert rrs.target.ref == "v2.3.1"
        assert rrs.claim_class == "CWE-122"
        assert rrs.component == "src/hdr.c:parse_header"
        assert rrs.run_commands() == ("./build/parse_demo poc.bin",)
        assert rrs.inputs[0].path == "poc.bin"
        assert rrs.oracle is not None
        assert rrs.oracle.value == "sanitizer"
        assert rrs.signature == "heap-buffer-overflow in parse_header"
        assert rrs.default_config is True

    def test_returns_none_without_a_block(self) -> None:
        assert parse_rrs("just a normal report") is None

    def test_returns_none_for_an_unrelated_yaml_block(self) -> None:
        text = "```yaml\nfoo: bar\n```\n"
        assert parse_rrs(text) is None

    def test_ignores_a_shell_block(self) -> None:
        text = "```sh\nls -la\n```\n"
        assert parse_rrs(text) is None

    def test_rrs_info_string_is_accepted(self) -> None:
        text = "```rrs\nrrs: 0.1\ntarget:\n  repo: r\n  ref: v1\n```\n"
        rrs = parse_rrs(text)
        assert rrs is not None
        assert rrs.target.repo == "r"

    def test_malformed_yaml_in_an_rrs_block_raises(self) -> None:
        text = "```rrs\nrrs: 0.1\ntarget: [unclosed\n```\n"
        with pytest.raises(RRSParseError):
            parse_rrs(text)

    def test_missing_version_raises(self) -> None:
        text = "```yaml\nrrs: ''\ntarget:\n  repo: r\n  ref: v1\n```\n"
        with pytest.raises(RRSParseError):
            parse_rrs(text)

    def test_missing_target_raises(self) -> None:
        with pytest.raises(RRSParseError):
            parse_rrs_document({"rrs": "0.1", "claim": {}})

    def test_unknown_oracle_is_none(self) -> None:
        rrs = parse_rrs_document(
            {"rrs": "0.1", "target": {"repo": "r"}, "expect": {"oracle": "telepathy"}}
        )
        assert rrs.oracle is None

    def test_unknown_version_is_rejected(self) -> None:
        with pytest.raises(RRSParseError, match="unsupported RRS version"):
            parse_rrs_document({"rrs": "9.9", "target": {"repo": "r"}})

    def test_default_config_defaults_to_true(self) -> None:
        rrs = parse_rrs_document({"rrs": "0.1", "target": {"repo": "r"}})
        assert rrs.default_config is True

    def test_non_default_config_is_read(self) -> None:
        rrs = parse_rrs_document(
            {"rrs": "0.1", "target": {"repo": "r"}, "config": {"default": False}}
        )
        assert rrs.default_config is False

    def test_version_key_is_accepted(self) -> None:
        rrs = parse_rrs_document({"version": "0.1", "target": {"repo": "r"}})
        assert rrs.version == "0.1"


class TestAStatedExpectation:
    """An RRS block may state a pattern or an exit code (FR-2.4)."""

    BLOCK = """\
```yaml
rrs: 0.1
target:
  repo: https://github.com/example/libfoo
  ref: v2.3.1
steps:
  - run: ./build/demo poc.bin
expect:
  oracle: output
  regex: "TOKEN-[0-9a-f]+"
  exit_code: 3
```
"""

    def test_reads_the_regex_and_the_exit_code(self) -> None:
        rrs = parse_rrs(self.BLOCK)
        assert rrs is not None
        assert rrs.regex == "TOKEN-[0-9a-f]+"
        assert rrs.exit_code == 3

    def test_a_block_without_them_is_empty(self) -> None:
        rrs = parse_rrs(VALID_RRS)
        assert rrs is not None
        assert rrs.regex == ""
        assert rrs.exit_code is None

    def test_an_exit_code_that_is_not_a_number_is_ignored(self) -> None:
        block = self.BLOCK.replace("exit_code: 3", "exit_code: soon")
        rrs = parse_rrs(block)
        assert rrs is not None
        assert rrs.exit_code is None


class TestFindBlocks:
    def test_finds_every_fenced_block(self) -> None:
        text = "```yaml\na: 1\n```\n\n```sh\nls\n```\n"
        assert len(find_rrs_blocks(text)) == 2

    def test_handles_no_blocks(self) -> None:
        assert find_rrs_blocks("plain text") == []

    def test_handles_an_unterminated_block(self) -> None:
        assert find_rrs_blocks("```yaml\nnot closed") == []


class TestEmit:
    def test_round_trips(self) -> None:
        text = emit_rrs(
            repo="https://github.com/example/libfoo",
            ref="v2.3.1",
            vuln_class="CWE-122",
            component="src/hdr.c:parse_header",
            impact="memory corruption",
            commands=("./build/parse_demo poc.bin",),
            inputs=(("poc.bin", "a" * 64),),
            oracle="sanitizer",
            signature="heap-buffer-overflow",
        )
        rrs = parse_rrs(text)
        assert rrs is not None
        assert rrs.target.ref == "v2.3.1"
        assert rrs.claim_class == "CWE-122"
        assert rrs.run_commands() == ("./build/parse_demo poc.bin",)
        assert rrs.inputs[0].sha256 == "a" * 64

    def test_emits_a_config_block(self) -> None:
        text = emit_rrs(repo="r", ref="v1", default_config=False)
        assert "default: false" in text
