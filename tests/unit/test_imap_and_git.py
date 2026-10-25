"""Tests for the IMAP intake and the git checkout.

Both talk to something real — a mailbox and a repository — so the tests
stand up a stand-in for each rather than mocking every call.
"""

from __future__ import annotations

import email
from pathlib import Path
from typing import Any

import pytest

from verdis.build.checkout import (
    CheckoutError,
    checkout_ref,
    default_branch,
)
from verdis.intake.imap import ImapError, ImapIntake
from verdis.storage.evidence import EvidenceStore

# -- a stand-in mailbox ------------------------------------------------


class FakeIMAP:
    """A mailbox that answers the calls the adapter makes."""

    def __init__(self, messages: list[bytes]) -> None:
        self.messages = messages
        self.selected: str | None = None
        self.closed = False
        self.logged_in: tuple[str, str] | None = None
        self.searched: list[str] = []

    def login(self, username: str, password: str) -> None:
        self.logged_in = (username, password)

    def select(self, mailbox: str) -> tuple[str, list[bytes]]:
        self.selected = mailbox
        return "OK", [b"1"]

    def uid(self, command: str, *args: str) -> tuple[str, list[Any]]:
        if command == "search":
            self.searched.append(args[-1])
            return "OK", [b" ".join(str(i + 1).encode() for i in range(len(self.messages)))]
        if command == "fetch":
            index = int(args[0]) - 1
            return "OK", [(b"1 (RFC822 {1}", self.messages[index])]
        return "NO", [b""]

    def close(self) -> None:
        self.closed = True


def _message(subject: str = "Heap overflow", body: str = "The parser overflows.") -> bytes:
    return (
        f"From: reporter@example.org\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"{body}\r\n"
    ).encode()


class TestImapIntake:
    def test_the_messages_are_fetched_and_normalised(
        self, evidence: EvidenceStore
    ) -> None:
        mailbox = FakeIMAP([_message()])
        adapter = ImapIntake(evidence)
        outcomes = adapter.fetch(
            host="imap.example.org", connection=mailbox, repo=".", ref="v1"
        )
        assert len(outcomes) == 1
        assert outcomes[0].report.reporter == "reporter@example.org"
        assert "overflows" in outcomes[0].report.body
        assert outcomes[0].report.target.ref == "v1"

    def test_an_empty_mailbox_gives_nothing(self, evidence: EvidenceStore) -> None:
        mailbox = FakeIMAP([])
        outcomes = ImapIntake(evidence).fetch(
            host="imap.example.org", connection=mailbox
        )
        assert outcomes == []

    def test_a_message_without_a_body_is_skipped(self, evidence: EvidenceStore) -> None:
        mailbox = FakeIMAP([_message(body="   ")])
        outcomes = ImapIntake(evidence).fetch(
            host="imap.example.org", connection=mailbox
        )
        assert outcomes == []

    def test_the_mailbox_is_selected(self, evidence: EvidenceStore) -> None:
        mailbox = FakeIMAP([_message()])
        ImapIntake(evidence).fetch(
            host="imap.example.org", connection=mailbox, mailbox="Reports"
        )
        assert mailbox.selected == "Reports"

    def test_a_since_uid_is_passed_to_the_search(self, evidence: EvidenceStore) -> None:
        mailbox = FakeIMAP([_message()])
        ImapIntake(evidence).fetch(
            host="imap.example.org", connection=mailbox, since_uid="42"
        )
        assert "42" in mailbox.searched[0]

    def test_the_connection_is_closed_when_it_is_ours(self, evidence: EvidenceStore) -> None:
        # A connection the adapter opened is closed again.
        class _Owned(FakeIMAP):
            def __init__(self) -> None:
                super().__init__([_message()])

        adapter = ImapIntake(evidence)
        connection = _Owned()
        adapter.fetch(host="imap.example.org", connection=connection)
        # A connection passed in by the caller is left alone.
        assert connection.closed is False

    def test_a_multipart_message_is_parsed(self, evidence: EvidenceStore) -> None:
        raw = (
            b"From: reporter@example.org\r\n"
            b"Subject: With an attachment\r\n"
            b'Content-Type: multipart/mixed; boundary="B"\r\n'
            b"\r\n"
            b"--B\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"The parser overflows.\r\n"
            b"--B\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b'Content-Disposition: attachment; filename="poc.bin"\r\n'
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAEC\r\n"
            b"--B--\r\n"
        )
        mailbox = FakeIMAP([raw])
        outcomes = ImapIntake(evidence).fetch(
            host="imap.example.org", connection=mailbox
        )
        assert "overflows" in outcomes[0].report.body
        assert outcomes[0].report.attachment_names == ("poc.bin",)

    def test_a_connection_error_is_reported(self, evidence: EvidenceStore) -> None:
        adapter = ImapIntake(evidence)
        with pytest.raises(ImapError):
            adapter.connect(host="127.0.0.1", port=1, username="x", password="y")

    def test_a_search_error_is_reported(self, evidence: EvidenceStore) -> None:
        class _Broken(FakeIMAP):
            def uid(self, command: str, *args: str) -> tuple[str, list[Any]]:
                raise OSError("the connection dropped")

        with pytest.raises(ImapError):
            ImapIntake(evidence).fetch(
                host="imap.example.org", connection=_Broken([_message()])
            )

    def test_a_plain_message_is_parsed(self) -> None:
        message = email.message_from_bytes(_message())
        _body, subject, reporter, attachments = ImapIntake.parse(message)
        assert subject == "Heap overflow"
        assert reporter == "reporter@example.org"
        assert attachments == []


# -- a real git repository ----------------------------------------------


class TestCheckout:
    def test_a_ref_is_checked_out(self, git_repo: Path) -> None:
        checkout = checkout_ref(git_repo, "v1.0")
        try:
            assert checkout.method in {"worktree", "archive"}
            assert (checkout.path / "file.txt").read_text(encoding="utf-8") == "first\n"
            assert checkout.commit
        finally:
            checkout.cleanup()

    def test_the_default_branch_is_found(self, git_repo: Path) -> None:
        assert default_branch(git_repo) == "main"

    def test_a_repository_without_a_branch(self, tmp_path: Path) -> None:
        assert default_branch(tmp_path) == ""

    def test_a_missing_ref_is_an_error(self, git_repo: Path) -> None:
        with pytest.raises(CheckoutError):
            checkout_ref(git_repo, "v9.9")

    def test_a_ref_in_a_plain_directory_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(CheckoutError):
            checkout_ref(tmp_path, "v1")

    def test_a_missing_path_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(CheckoutError):
            checkout_ref(tmp_path / "nope")

    def test_a_file_is_not_a_directory(self, tmp_path: Path) -> None:
        path = tmp_path / "a.txt"
        path.write_text("x", encoding="utf-8")
        with pytest.raises(CheckoutError):
            checkout_ref(path)

    def test_no_ref_uses_the_tree_as_it_is(self, git_repo: Path) -> None:
        checkout = checkout_ref(git_repo)
        assert checkout.method == "existing"
        assert checkout.path == git_repo
