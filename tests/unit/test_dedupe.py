"""Tests for duplicate detection (FR-4)."""

from __future__ import annotations

import json
from pathlib import Path

from verdis.dedupe.fingerprint import (
    DedupeFingerprint,
    cosine_similarity,
    extract_stack_signature,
    hashed_embedding,
    jaccard,
    normalize_poc_bytes,
    token_set,
)
from verdis.dedupe.index import DedupeEngine, LocalAdvisorySource
from verdis.storage.db import Store


class TestFingerprint:
    def test_is_deterministic(self) -> None:
        first = DedupeFingerprint.build(report_id="VDS-1", vuln_class="CWE-122", component="f", body="b")
        second = DedupeFingerprint.build(report_id="VDS-1", vuln_class="CWE-122", component="f", body="b")
        assert first == second

    def test_different_classes_differ(self) -> None:
        first = DedupeFingerprint.build(report_id="VDS-1", vuln_class="CWE-122", component="f", body="b")
        second = DedupeFingerprint.build(report_id="VDS-1", vuln_class="CWE-79", component="f", body="b")
        assert first.class_component != second.class_component

    def test_poc_hash_ignores_trailing_padding(self) -> None:
        first = DedupeFingerprint.build(report_id="VDS-1", body="b", poc_bytes=b"data")
        second = DedupeFingerprint.build(report_id="VDS-1", body="b", poc_bytes=b"data\x00\x00")
        assert first.poc_hash == second.poc_hash

    def test_different_poc_bytes_differ(self) -> None:
        first = DedupeFingerprint.build(report_id="VDS-1", body="b", poc_bytes=b"a")
        second = DedupeFingerprint.build(report_id="VDS-1", body="b", poc_bytes=b"b")
        assert first.poc_hash != second.poc_hash

    def test_the_stack_signature_drops_addresses(self) -> None:
        output = "    #0 0x4f2a in parse_header src/hdr.c:212\n    #1 0x4f80 in main src/hdr.c:260"
        signature = extract_stack_signature(output)
        assert "parse_header" in signature
        assert "0x4f2a" not in signature

    def test_an_empty_output_has_no_signature(self) -> None:
        assert extract_stack_signature("") == ""

    def test_normalize_poc_bytes_strips_padding(self) -> None:
        assert normalize_poc_bytes(b"abc\x00") == b"abc"


class TestSimilarity:
    def test_the_embedding_is_deterministic(self) -> None:
        assert hashed_embedding("hello world") == hashed_embedding("hello world")

    def test_similar_text_scores_highly(self) -> None:
        a = hashed_embedding("heap buffer overflow in parse_header of libfoo")
        b = hashed_embedding("heap buffer overflow in parse_header of libfoo version 2")
        assert cosine_similarity(a, b) > 0.7

    def test_unrelated_text_scores_lowly(self) -> None:
        a = hashed_embedding("heap buffer overflow in parse_header")
        b = hashed_embedding("the weather in london is mild today")
        assert cosine_similarity(a, b) < 0.4

    def test_cosine_of_different_lengths_is_zero(self) -> None:
        assert cosine_similarity((1.0, 0.0), (1.0, 0.0, 0.0)) == 0.0

    def test_cosine_of_empty_vectors_is_zero(self) -> None:
        assert cosine_similarity((), ()) == 0.0

    def test_jaccard(self) -> None:
        assert jaccard(frozenset({"a", "b"}), frozenset({"a", "b"})) == 1.0
        assert jaccard(frozenset({"a"}), frozenset({"b"})) == 0.0
        assert jaccard(frozenset(), frozenset()) == 1.0

    def test_stopwords_are_dropped(self) -> None:
        assert "the" not in token_set("the quick brown fox")
        assert "quick" in token_set("the quick brown fox")


class TestDedupeEngine:
    def _index(self, engine: DedupeEngine, report_id: str, body: str, **kwargs) -> None:
        fingerprint = DedupeFingerprint.build(report_id=report_id, body=body, **kwargs)
        engine.index(report_id=report_id, fingerprint=fingerprint, body=body)

    def test_an_identical_report_is_a_duplicate(self, store: Store) -> None:
        engine = DedupeEngine(store=store, threshold=0.82)
        body = "heap buffer overflow in parse_header of libfoo version 2.3.1"
        self._index(engine, "VDS-0001", body, vuln_class="CWE-122", component="parse_header")
        fingerprint = DedupeFingerprint.build(
            report_id="VDS-0002", body=body, vuln_class="CWE-122", component="parse_header"
        )
        matches = engine.search(fingerprint, body, exclude_report_id="VDS-0002")
        assert matches
        assert matches[0].candidate_id == "VDS-0001"
        assert matches[0].similarity >= 0.82
        assert any(match.similarity >= 0.82 for match in matches)

    def test_the_same_poc_bytes_are_a_duplicate(self, store: Store) -> None:
        engine = DedupeEngine(store=store, threshold=0.82)
        body = "one report"
        self._index(engine, "VDS-0001", body, poc_bytes=b"same bytes")
        fingerprint = DedupeFingerprint.build(
            report_id="VDS-0002", body="a completely different report text", poc_bytes=b"same bytes"
        )
        matches = engine.search(fingerprint, "a completely different report text")
        assert matches
        assert any("PoC bytes" in reason for reason in matches[0].reasons)

    def test_the_same_stack_signature_is_a_duplicate(self, store: Store) -> None:
        engine = DedupeEngine(store=store, threshold=0.82)
        stack = "    #0 0x1 in parse_header src/hdr.c:212"
        self._index(engine, "VDS-0001", "first", stack_output=stack)
        fingerprint = DedupeFingerprint.build(
            report_id="VDS-0002", body="second", stack_output=stack
        )
        matches = engine.search(fingerprint, "second")
        assert matches
        assert any("stack signature" in reason for reason in matches[0].reasons)

    def test_an_unrelated_report_is_not_a_duplicate(self, store: Store) -> None:
        engine = DedupeEngine(store=store, threshold=0.82)
        self._index(engine, "VDS-0001", "heap overflow in the parser of libfoo")
        fingerprint = DedupeFingerprint.build(
            report_id="VDS-0002", body="the login page has a missing csrf token"
        )
        matches = engine.search(fingerprint, "the login page has a missing csrf token")
        assert not any(match.similarity >= 0.82 for match in matches)

    def test_text_alone_does_not_reach_the_threshold(self, store: Store) -> None:
        engine = DedupeEngine(store=store, threshold=0.82)
        body = "a heap buffer overflow in parse_header"
        self._index(engine, "VDS-0001", body)
        fingerprint = DedupeFingerprint.build(report_id="VDS-0002", body=body)
        matches = engine.search(fingerprint, body)
        assert matches[0].similarity < 0.82

    def test_a_report_does_not_match_itself(self, store: Store) -> None:
        engine = DedupeEngine(store=store)
        body = "same body"
        self._index(engine, "VDS-0001", body)
        fingerprint = DedupeFingerprint.build(report_id="VDS-0001", body=body)
        matches = engine.search(fingerprint, body, exclude_report_id="VDS-0001")
        assert not matches

    def test_matches_carry_reasons(self, store: Store) -> None:
        engine = DedupeEngine(store=store)
        body = "the same body text"
        self._index(engine, "VDS-0001", body)
        fingerprint = DedupeFingerprint.build(report_id="VDS-0002", body=body)
        matches = engine.search(fingerprint, body)
        assert matches[0].reasons

    def test_an_empty_store_gives_no_matches(self, store: Store) -> None:
        engine = DedupeEngine(store=store)
        fingerprint = DedupeFingerprint.build(report_id="VDS-0002", body="anything")
        assert engine.search(fingerprint, "anything") == []

    def test_the_pre_pass_is_cheaper(self, store: Store) -> None:
        engine = DedupeEngine(store=store)
        body = "heap buffer overflow"
        self._index(engine, "VDS-0001", body, stack_output="#0 0x1 in parse_header")
        fingerprint = DedupeFingerprint.build(
            report_id="VDS-0002", body=body, stack_output="#0 0x1 in parse_header"
        )
        pre = engine.search(fingerprint, body, mode="pre")
        post = engine.search(fingerprint, body, mode="post")
        assert post[0].similarity >= pre[0].similarity


class TestAdvisories:
    def test_local_advisories_are_loaded(self, tmp_path: Path) -> None:
        path = tmp_path / "advisories.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "id": "GHSA-xxxx-yyyy-zzzz",
                        "title": "Heap overflow in parse_header",
                        "description": "A heap buffer overflow in parse_header of libfoo",
                        "class": "CWE-122",
                        "component": "parse_header",
                    }
                ]
            ),
            encoding="utf-8",
        )
        source = LocalAdvisorySource(path)
        candidates = source.lookup()
        assert candidates[0].identifier == "GHSA-xxxx-yyyy-zzzz"

    def test_a_missing_advisory_file_is_not_an_error(self, tmp_path: Path) -> None:
        assert LocalAdvisorySource(tmp_path / "nope.json").lookup() == []

    def test_advisories_can_produce_matches(self, store: Store, tmp_path: Path) -> None:
        path = tmp_path / "advisories.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "id": "GHSA-xxxx-yyyy-zzzz",
                        "title": "Heap overflow in parse_header",
                        "description": "A heap buffer overflow in parse_header of libfoo",
                        "class": "CWE-122",
                        "component": "parse_header",
                    }
                ]
            ),
            encoding="utf-8",
        )
        engine = DedupeEngine(store=store, advisory_source=LocalAdvisorySource(path))
        fingerprint = DedupeFingerprint.build(
            report_id="VDS-0002",
            body="heap buffer overflow in parse_header of libfoo",
            vuln_class="CWE-122",
            component="parse_header",
        )
        matches = engine.search(fingerprint, "heap buffer overflow in parse_header of libfoo")
        assert any(match.source == "advisory" for match in matches)
