"""Tests for heuristic claim extraction (FR-2)."""

from __future__ import annotations

from verdis.extract.heuristics import HeuristicExtractor, extract_claim


class TestExtraction:
    def test_extracts_class_version_and_component(self) -> None:
        text = (
            "Version 2.3.1 of libfoo has a heap buffer overflow in parse_header() "
            "at src/hdr.c:212."
        )
        claim = extract_claim(text)
        assert claim.vuln_class == "CWE-122"
        assert claim.affected_version == "2.3.1"
        assert claim.component.name == "parse_header"
        assert claim.component.file == "src/hdr.c"
        assert claim.component.line == 212

    def test_extracts_a_cwe_stated_explicitly(self) -> None:
        claim = extract_claim("This is CWE-787 an out-of-bounds write.")
        assert claim.vuln_class == "CWE-787"

    def test_explicit_cwe_beats_a_keyword(self) -> None:
        claim = extract_claim("A use after free (CWE-416) in the parser.")
        assert claim.vuln_class == "CWE-416"

    def test_extracts_a_command_from_a_shell_block(self) -> None:
        text = "Steps:\n\n```sh\n./build/parse_demo poc.bin\n```\n"
        claim = extract_claim(text)
        assert [c.command for c in claim.poc_commands] == ["./build/parse_demo poc.bin"]

    def test_extracts_a_prompt_style_command(self) -> None:
        text = "Run this:\n\n$ python3 exploit.py --target localhost\n"
        claim = extract_claim(text)
        assert any("exploit.py" in c.command for c in claim.poc_commands)

    def test_detects_a_sanitizer_observable(self) -> None:
        text = "AddressSanitizer: heap-buffer-overflow on address 0x60200000"
        claim = extract_claim(text)
        assert claim.expected.kind == "sanitizer"
        assert "heap-buffer-overflow" in claim.expected.signature

    def test_detects_a_crash_observable(self) -> None:
        claim = extract_claim("The program dies with a segmentation fault.")
        assert claim.expected.kind == "crash"

    def test_detects_an_exception_observable(self) -> None:
        claim = extract_claim("It raises an unhandled exception every time.")
        assert claim.expected.kind == "exception"

    def test_records_the_impact(self) -> None:
        claim = extract_claim("This gives remote code execution to the attacker.")
        assert "remote code execution" in claim.impact.summary

    def test_marks_missing_fields(self) -> None:
        claim = extract_claim("Something is wrong.")
        assert "affected_version" in claim.missing_fields
        assert "poc" in claim.missing_fields
        assert "expected_observable" in claim.missing_fields

    def test_does_not_invent_a_version(self) -> None:
        claim = extract_claim("No version is mentioned here at all.")
        assert claim.affected_version == ""
        assert "affected_version" in claim.missing_fields

    def test_records_source_spans(self) -> None:
        text = "Version 2.3.1 of libfoo has a heap buffer overflow in parse_header()."
        claim = extract_claim(text)
        span = claim.span_for("affected_version")
        assert span is not None
        assert text[span.start : span.end] == "2.3.1"

    def test_spans_point_at_real_text(self) -> None:
        text = "Version 2.3.1 of libfoo has a heap buffer overflow in parse_header()."
        claim = extract_claim(text)
        for name, span in claim.spans.items():
            assert 0 <= span.start <= span.end <= len(text), name

    def test_records_preconditions(self) -> None:
        claim = extract_claim(
            "This requires the server to run with the debug configuration enabled."
        )
        assert claim.preconditions

    def test_detects_a_non_default_configuration(self) -> None:
        claim = extract_claim("It only happens with a custom config file.")
        assert claim.non_default_config is True

    def test_attachment_names_become_artifacts(self) -> None:
        claim = extract_claim("See attached.", attachment_names=("poc.bin",))
        assert [a.name for a in claim.poc_artifacts] == ["poc.bin"]
        assert claim.poc_artifacts[0].role == "input"

    def test_script_attachment_role(self) -> None:
        claim = extract_claim("See attached.", attachment_names=("run.sh",))
        assert claim.poc_artifacts[0].role == "script"

    def test_empty_text_is_safe(self) -> None:
        claim = extract_claim("")
        assert claim.vuln_class == ""
        assert claim.missing_fields

    def test_whitespace_only_text_is_safe(self) -> None:
        claim = extract_claim("   \n\t  \n")
        assert claim.missing_fields

    def test_source_is_heuristic(self) -> None:
        assert extract_claim("x").source == "heuristic"

    def test_extractor_is_reusable(self) -> None:
        extractor = HeuristicExtractor()
        first = extractor.extract("CWE-79 in index()")
        second = extractor.extract("CWE-79 in index()")
        assert first == second


class TestAStatedOutput:
    """A report that says what it expects to see (FR-2, FR-8.2)."""

    def test_extracts_an_expected_output_from_a_block(self) -> None:
        text = (
            "Run it and the program prints the secret.\n\n"
            "## Expected output\n\n```\nVERDIS-SECRET-9f3a\n```\n"
        )
        claim = extract_claim(text)
        assert claim.expected.kind == "output"
        assert claim.expected.signature == "VERDIS-SECRET-9f3a"
        assert claim.expected.regex

    def test_extracts_an_expected_output_from_a_line(self) -> None:
        claim = extract_claim("Expected output: SUCCESS\n")
        assert claim.expected.kind == "output"
        assert claim.expected.signature == "SUCCESS"

    def test_extracts_an_expected_exit_code(self) -> None:
        claim = extract_claim("The command exits with code 3 when it is exploited.\n")
        assert claim.expected.kind == "output"
        assert claim.expected.exit_code == 3

    def test_prose_that_mentions_printing_is_not_an_expectation(self) -> None:
        text = "The program prints the contents of the file it was asked for.\n"
        claim = extract_claim(text)
        assert claim.expected.kind == "unknown"
        assert claim.expected.signature == ""

    def test_a_sanitizer_observable_still_wins(self) -> None:
        text = (
            "AddressSanitizer: heap-buffer-overflow\n\n"
            "Expected output:\n\n```\nTOKEN\n```\n"
        )
        claim = extract_claim(text)
        assert claim.expected.kind == "sanitizer"


class TestEdgeCases:
    def test_a_very_long_report_does_not_blow_up(self) -> None:
        text = "word " * 50_000 + "CWE-79"
        claim = extract_claim(text)
        assert claim.vuln_class == "CWE-79"

    def test_a_report_with_many_commands_keeps_them_all(self) -> None:
        body = "\n".join(f"$ ./run_{i} --flag" for i in range(20))
        claim = extract_claim(body)
        assert len(claim.poc_commands) == 20

    def test_duplicate_commands_are_deduplicated(self) -> None:
        body = "$ ./run\n$ ./run\n"
        claim = extract_claim(body)
        assert len(claim.poc_commands) == 1

    def test_a_version_like_word_is_not_a_version(self) -> None:
        claim = extract_claim("The C library is fine.")
        assert claim.affected_version == ""

    def test_a_bare_version_is_accepted(self) -> None:
        claim = extract_claim("Affected: 3.10.1")
        assert claim.affected_version == "3.10.1"

    def test_a_file_without_a_function_is_still_found(self) -> None:
        claim = extract_claim("The bug is in src/parser/reader.py")
        assert claim.component.file == "src/parser/reader.py"
