"""IMAP mailbox intake (FR-1.1).

Large-list owners receive reports by mail. The adapter polls a mailbox,
keeps track of what it has already seen (so re-polling is idempotent,
FR-1.5) and normalises each message the same way as every other source.
"""

from __future__ import annotations

import email
import hashlib
import imaplib
import os
from email.message import Message
from typing import Any

from ..schemas.common import ReportSource
from ..schemas.report import Target
from ..storage.evidence import EvidenceStore, build_report
from .base import IntakeOutcome
from .limits import ConcurrencyLimiter

__all__ = ["ImapError", "ImapIntake"]


class ImapError(RuntimeError):
    """Raised when the mailbox cannot be read."""


class ImapIntake:
    """Polls an IMAP mailbox for new reports."""

    name = "imap"
    source = ReportSource.IMAP

    def __init__(
        self, store: EvidenceStore, *, limiter: ConcurrencyLimiter | None = None
    ) -> None:
        self.store = store
        self.limiter = limiter or ConcurrencyLimiter()

    def connect(
        self,
        *,
        host: str,
        username: str = "",
        password: str = "",
        port: int = 993,
        use_ssl: bool = True,
    ) -> imaplib.IMAP4:
        password = password or os.environ.get("VERDIS_IMAP_PASSWORD", "")
        try:
            if use_ssl:
                connection: imaplib.IMAP4 = imaplib.IMAP4_SSL(host, port)
            else:
                connection = imaplib.IMAP4(host, port)
            if username:
                connection.login(username, password)
        except (OSError, imaplib.IMAP4.error) as exc:
            raise ImapError(f"cannot reach the IMAP mailbox: {exc}") from exc
        return connection

    def fetch_messages(
        self,
        connection: imaplib.IMAP4,
        *,
        mailbox: str = "INBOX",
        since_uid: str = "",
    ) -> list[tuple[str, Message]]:
        """Fetch messages newer than ``since_uid``."""
        try:
            connection.select(mailbox)
            criteria = f"(UID {since_uid}:*)" if since_uid else "ALL"
            status, data = connection.uid("search", "ALL", criteria)
        except (OSError, imaplib.IMAP4.error) as exc:
            raise ImapError(f"cannot search the mailbox: {exc}") from exc
        if status != "OK" or not data or not data[0]:
            return []
        uids = data[0].split()
        messages: list[tuple[str, Message]] = []
        for uid in uids:
            status, payload = connection.uid("fetch", uid, "(RFC822)")
            if status != "OK" or not payload or not isinstance(payload[0], tuple):
                continue
            raw = payload[0][1]
            if not isinstance(raw, bytes):
                continue
            messages.append((uid.decode("ascii", "replace"), email.message_from_bytes(raw)))
        return messages

    @staticmethod
    def parse(message: Message) -> tuple[str, str, str, list[tuple[str, bytes]]]:
        """Return ``(body, subject, reporter, attachments)``."""
        subject = str(message.get("Subject", ""))
        reporter = str(message.get("From", ""))
        attachments: list[tuple[str, bytes]] = []
        if message.is_multipart():
            body_parts: list[str] = []
            for part in message.walk():
                disposition = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()
                if filename and "attachment" in disposition:
                    raw = part.get_payload(decode=True)
                    attachments.append((str(filename), raw if isinstance(raw, bytes) else b""))
                elif part.get_content_type() == "text/plain":
                    raw = part.get_payload(decode=True)
                    payload = raw if isinstance(raw, bytes) else b""
                    body_parts.append(payload.decode("utf-8", "replace"))
            body = "\n".join(body_parts)
        else:
            raw = message.get_payload(decode=True)
            payload = raw if isinstance(raw, bytes) else b""
            body = payload.decode("utf-8", "replace")
        return body, subject, reporter, attachments

    def normalize(
        self,
        body: str,
        subject: str,
        reporter: str,
        attachments: list[tuple[str, bytes]],
        *,
        repo: str = ".",
        ref: str = "",
    ) -> IntakeOutcome:
        target = Target(repo=repo, ref=ref)
        report = build_report(
            body=body,
            source=self.source,
            reporter=reporter,
            subject=subject,
            target=target,
            metadata={"message_id": hashlib.sha256(body.encode("utf-8")).hexdigest()},
        )
        self.store.ensure_report(report.id)
        body_path, stored = self.store.store_original(
            report.id, body, attachments=tuple(attachments), subject=subject
        )
        report = report.model_copy(update={"attachments": stored})
        return IntakeOutcome(report=report, attachments=stored, body_path=body_path)

    def fetch(
        self,
        *,
        host: str,
        username: str = "",
        password: str = "",
        repo: str = ".",
        ref: str = "",
        mailbox: str = "INBOX",
        since_uid: str = "",
        connection: imaplib.IMAP4 | None = None,
    ) -> list[IntakeOutcome]:
        owned = connection is None
        connection = connection or self.connect(host=host, username=username, password=password)
        try:
            messages = self.fetch_messages(connection, mailbox=mailbox, since_uid=since_uid)
        finally:
            if owned:
                try:
                    connection.close()
                except (OSError, imaplib.IMAP4.error):  # pragma: no cover
                    pass
        outcomes: list[IntakeOutcome] = []
        with self.limiter.slot(self.source.value):
            for _uid, message in messages:
                body, subject, reporter, attachments = self.parse(message)
                if not body.strip():
                    continue
                outcomes.append(
                    self.normalize(body, subject, reporter, attachments, repo=repo, ref=ref)
                )
        return outcomes


_ = Any
