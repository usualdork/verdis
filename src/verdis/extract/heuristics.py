"""Heuristic claim extraction (FR-2.5).

The heuristic extractor never invents facts. Anything it cannot locate is
left unknown and recorded in ``Claim.missing_fields`` so the pipeline can
produce NEEDS_INFO instead of a confident wrong claim.

Every extracted field carries the span of report text it came from (FR-2.2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..schemas.claim import (
    Claim,
    ClaimComponent,
    ClaimImpact,
    ExpectedObservable,
    PoCArtifact,
    PoCCommand,
)
from ..schemas.common import SourceSpan, normalize_cwe, normalize_text

__all__ = ["HeuristicExtractor", "extract_claim"]

# Keyword -> CWE. Only used to *suggest* a class; the span shows the words
# that triggered it so a human can check the mapping.
KEYWORD_CWE: tuple[tuple[str, str], ...] = (
    ("heap buffer overflow", "CWE-122"),
    ("stack buffer overflow", "CWE-121"),
    ("buffer overflow", "CWE-120"),
    ("out of bounds", "CWE-125"),
    ("use after free", "CWE-416"),
    ("double free", "CWE-415"),
    ("command injection", "CWE-78"),
    ("shell injection", "CWE-78"),
    ("sql injection", "CWE-89"),
    ("path traversal", "CWE-22"),
    ("directory traversal", "CWE-22"),
    ("cross-site scripting", "CWE-79"),
    ("xss", "CWE-79"),
    ("server-side request forgery", "CWE-918"),
    ("ssrf", "CWE-918"),
    ("insecure deserialization", "CWE-502"),
    ("deserialization", "CWE-502"),
    ("race condition", "CWE-362"),
    ("data race", "CWE-362"),
    ("integer overflow", "CWE-190"),
    ("null pointer dereference", "CWE-476"),
    ("null dereference", "CWE-476"),
    ("format string", "CWE-134"),
    ("open redirect", "CWE-601"),
    ("hardcoded credential", "CWE-798"),
    ("hardcoded password", "CWE-798"),
    ("certificate validation", "CWE-295"),
    ("csrf", "CWE-352"),
    ("cross-site request forgery", "CWE-352"),
    ("xml external entity", "CWE-611"),
    ("xxe", "CWE-611"),
    ("denial of service", "CWE-400"),
    ("infinite loop", "CWE-835"),
    ("memory leak", "CWE-401"),
    ("prototype pollution", "CWE-1321"),
    ("zip slip", "CWE-22"),
    ("symlink", "CWE-59"),
    ("improper access control", "CWE-284"),
    ("privilege escalation", "CWE-269"),
    ("stack overflow", "CWE-674"),
    ("uncontrolled recursion", "CWE-674"),
    ("file disclosure", "CWE-200"),
    ("information disclosure", "CWE-200"),
)

_IMPACT_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("remote code execution", "remote code execution"),
    ("arbitrary code execution", "arbitrary code execution"),
    ("rce", "remote code execution"),
    ("code execution", "code execution"),
    ("command injection", "code execution"),
    ("buffer overflow", "memory corruption"),
    ("memory corruption", "memory corruption"),
    ("arbitrary file read", "arbitrary file read"),
    ("file read", "file read"),
    ("information disclosure", "information disclosure"),
    ("disclosed", "information disclosure"),
    ("disclosure", "information disclosure"),
    ("privilege escalation", "privilege escalation"),
    ("denial of service", "denial of service"),
    ("crash", "crash"),
    ("authentication bypass", "authentication bypass"),
    ("sql injection", "sql injection"),
)

_OBSERVABLE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"AddressSanitizer[:\s]+(heap-buffer-overflow|stack-buffer-overflow|heap-use-after-free|"
     r"use-after-free|global-buffer-overflow|stack-overflow|SEGV|attempting free)",
     "sanitizer"),
    (r"UndefinedBehaviorSanitizer", "sanitizer"),
    (r"MemorySanitizer", "sanitizer"),
    (r"ThreadSanitizer", "sanitizer"),
    (r"\b(?:heap|stack|global|heap-use-after)-buffer-overflow\b", "sanitizer"),
    (r"\bheap-use-after-free\b", "sanitizer"),
    (r"\buse-after-free\b", "sanitizer"),
    (r"\bdynamic-stack-buffer-overflow\b", "sanitizer"),
    (r"\bASan\b", "sanitizer"),
    (r"runtime error:", "sanitizer"),
    (r"\bdata race\b", "sanitizer"),
    (r"segmentation fault", "crash"),
    (r"\bSIGSEGV\b", "crash"),
    (r"\bSIGABRT\b", "crash"),
    (r"core dumped", "crash"),
    (r"\bcrashes?\b", "crash"),
    (r"assertion failed", "exception"),
    (r"unhandled exception", "exception"),
    (r"traceback \(most recent call last\)", "exception"),
    (r"panic:", "exception"),
    (r"\bAssertionError\b", "exception"),
    (r"\bUncaught exception\b", "exception"),
)

#: "Expected output:" followed by a fenced block, or on the same line.
_EXPECTED_OUTPUT_BLOCK_RE = re.compile(
    r"expected (?:output|result)\s*:?\s*\n+```[^\n]*\n(?P<value>[^\n]+)",
    re.IGNORECASE,
)
_EXPECTED_OUTPUT_INLINE_RE = re.compile(
    "expected (?:output|result)\\s*[:=]\\s*[`\"']?(?P<value>[^`\"'\\n]+)",
    re.IGNORECASE,
)
#: "exits with code 3".
_EXIT_CODE_RE = re.compile(
    r"exits? with (?:code|status|an exit code of)\s*[:=]?\s*(?P<code>\d+)",
    re.IGNORECASE,
)

_VERSION_RE = re.compile(
    r"\b(?:version|versions|release|releases|v)\s*"
    r"(?P<version>\d+\.\d+(?:\.\d+)?(?:[-._][0-9A-Za-z]+)*)\b",
    re.IGNORECASE,
)
_BARE_VERSION_RE = re.compile(r"\bv?(\d+\.\d+(?:\.\d+)?)\b")
_CWE_RE = re.compile(r"\bCWE[-_ ]?(\d{1,5})\b", re.IGNORECASE)
_FILE_RE = re.compile(r"(?P<file>[\w./+-]+\.[A-Za-z]{1,6})\s*[:(]\s*(?P<line>\d{1,6})")
_FILE_ONLY_RE = re.compile(r"\b(?P<file>(?:[\w.-]+/)+[\w.-]+\.[A-Za-z]{1,6})\b")
#: A report that states its component in a field, the way a structured
#: report does: "**Component**: src/hdr.c:parse_header".
_COMPONENT_FIELD_RE = re.compile(
    r"(?im)^[ \t]*\*\*(?:component|function)\*\*[ \t]*:[ \t]*(?P<value>[^\n]+)"
)
_BACKTICK_FUNC_RE = re.compile(r"`(?P<func>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)`")
_FUNC_CALL_RE = re.compile(r"\bin\s+(?:the\s+)?(?:function\s+)?`?(?P<func>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FUNC_PAREN_RE = re.compile(r"`(?P<func>[A-Za-z_][A-Za-z0-9_.]*)\s*\(")
_SHELL_FENCE_RE = re.compile(
    r"^[ \t]*```[ \t]*(?:sh|bash|shell|zsh|console|cmd)?[ \t]*\n(?P<body>.*?)^[ \t]*```",
    re.MULTILINE | re.DOTALL,
)
#: Only a ``$`` prompt counts: ``#`` is a Markdown heading and ``>`` is a
#: Markdown quote, and mistaking either for a shell prompt turns prose into
#: a "proof of concept".
_PROMPT_LINE_RE = re.compile(r"^[ \t]*\$\s+(?P<cmd>\S.*)$", re.MULTILINE)
_COMMAND_HINT_RE = re.compile(
    r"^\s*(?:\./[\w./+-]+|python3?\s+[\w./+-]+\.py|node\s+[\w./+-]+\.js|"
    r"go run\s+[\w./+-]+|cargo run|make\s+\S+|npm\s+(?:run|test)\s+\S+|"
    r"pytest\s+\S+|go test\s+\S+)\b",
    re.MULTILINE,
)

#: Binaries a proof of concept plausibly starts with.
_KNOWN_BINARIES = frozenset(
    {
        "python", "python3", "node", "go", "cargo", "rustc", "make", "cmake",
        "gcc", "g++", "clang", "clang++", "cc", "pytest", "npm", "npx", "yarn",
        "ruby", "perl", "php", "java", "javac", "mvn", "gradle", "dotnet",
        "bash", "sh", "zsh", "env", "timeout",
    }
)
_PRECONDITION_RE = re.compile(
    r"\b(?P<text>(?:requires?|only when|when|if)\b[^.\n]{3,160})",
    re.IGNORECASE,
)
_CONFIG_HINT_RE = re.compile(
    r"\b(non-default|custom config|configuration file|config(?:uration)?\s+\w+\s*=)",
    re.IGNORECASE,
)

_SHELL_METACHARS = ("&&", "||", ";", "|", "`", "$(", ">", ">>", "<")


@dataclass(frozen=True)
class _Hit:
    """A located fact with its span."""

    value: str
    span: SourceSpan
    full: str = ""


class HeuristicExtractor:
    """Extract a claim from report prose without any model."""

    def extract(
        self,
        text: str,
        *,
        attachment_names: tuple[str, ...] = (),
    ) -> Claim:
        spans: dict[str, SourceSpan] = {}
        component = self._component(text, spans)
        vuln_class = self._vuln_class(text, spans)
        version = self._version(text, spans)
        commands = self._commands(text, spans)
        artifacts = self._artifacts(text, attachment_names)
        impact = self._impact(text, spans)
        expected = self._expected(text, spans)
        preconditions = self._preconditions(text, spans)
        config = self._config(text, spans)

        missing: list[str] = []
        if not version:
            missing.append("affected_version")
        if not component.name and not component.file:
            missing.append("component")
        if not commands:
            missing.append("poc")
        if expected.kind == "unknown":
            missing.append("expected_observable")

        return Claim(
            component=component,
            vuln_class=vuln_class,
            affected_version=version,
            preconditions=preconditions,
            poc_commands=commands,
            poc_artifacts=artifacts,
            impact=impact,
            expected=expected,
            config_assumptions=config,
            non_default_config=self._non_default(text),
            source="heuristic",
            missing_fields=tuple(missing),
            spans=spans,
        )

    # -- components -----------------------------------------------------

    def _component(self, text: str, spans: dict[str, SourceSpan]) -> ClaimComponent:
        # A report that states its component in a field means it. The
        # guesses below are for the reports that do not.
        field = self._locate(_COMPONENT_FIELD_RE, text)
        if field is not None:
            component, file_span, name_span = self._component_from_field(
                field.value, field.span
            )
            if component.name or component.file:
                if file_span is not None:
                    spans["component.file"] = file_span
                if name_span is not None:
                    spans["component.name"] = name_span
                return component
        file_hit = self._locate(_FILE_RE, text)
        line: int | None = None
        file_name = ""
        if file_hit is not None:
            file_name = file_hit.full.split(":")[0].split("(")[0].strip()
            line_match = re.search(r"[:(]\s*(\d{1,6})", file_hit.full)
            if line_match:
                line = int(line_match.group(1))
            spans["component.file"] = file_hit.span
        else:
            file_only = self._locate(_FILE_ONLY_RE, text)
            if file_only is not None:
                file_name = file_only.value
                spans["component.file"] = file_only.span

        func_hit = self._locate(_BACKTICK_FUNC_RE, text)
        if func_hit is None:
            func_hit = self._locate(_FUNC_CALL_RE, text)
        if func_hit is None:
            func_hit = self._locate(_FUNC_PAREN_RE, text)
        if func_hit is not None:
            spans["component.name"] = func_hit.span

        name = func_hit.value if func_hit else ""
        if not name and file_name:
            name = file_name.rsplit("/", 1)[-1]
        return ClaimComponent(name=name, file=file_name, line=line)

    @staticmethod
    def _component_from_field(
        value: str, span: SourceSpan
    ) -> tuple[ClaimComponent, SourceSpan | None, SourceSpan | None]:
        """Read "file.c:function", "file.c:12" or "function" out of a field.

        The field is what the reporter wrote, so it is read as written:
        a file with a function, a file with a line, or a bare name. The
        spans point at the parts themselves, not at the whole line.
        """
        raw = value.strip()
        # The value may be quoted, and the span has to point at the value
        # inside the report, not at the text after the quotes.
        stripped = raw.strip("`").strip()
        offset = raw.find(stripped) if stripped else 0
        if offset < 0:  # pragma: no cover - the value is always a substring
            offset = 0
        text = stripped
        if not text:
            return ClaimComponent(), None, None

        def _span(start: int, length: int) -> SourceSpan:
            begin = span.start + offset + start
            return SourceSpan(
                start=begin, end=begin + length, quote=text[start : start + length]
            )

        left, separator, right = text.rpartition(":")
        if not separator:
            # A bare name, or a bare path.
            if "/" in text or "." in text:
                return ClaimComponent(name="", file=text), _span(0, len(text)), None
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
                # Prose. An ambiguous field is marked unknown, never
                # invented (FR-2.3).
                return ClaimComponent(), None, None
            return ClaimComponent(name=text), None, _span(0, len(text))
        if right.isdigit():
            if "/" in left or "." in left:
                return (
                    ClaimComponent(name="", file=left, line=int(right)),
                    _span(0, len(left)),
                    None,
                )
            # "name:line" is a function and a line, not a file.
            return (
                ClaimComponent(name=left, line=int(right)),
                None,
                _span(0, len(left)),
            )
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", right):
            name_offset = len(text) - len(right)
            if "/" in left or "." in left:
                return (
                    ClaimComponent(name=right, file=left),
                    _span(0, len(left)),
                    _span(name_offset, len(right)),
                )
            # Two bare words: the first is the file, the second the name.
            return (
                ClaimComponent(name=right, file=left),
                _span(0, len(left)),
                _span(name_offset, len(right)),
            )
        return ClaimComponent(name="", file=text), _span(0, len(text)), None

    # -- class ----------------------------------------------------------

    def _vuln_class(self, text: str, spans: dict[str, SourceSpan]) -> str:
        cwe = self._locate(_CWE_RE, text)
        if cwe is not None:
            spans["vuln_class"] = cwe.span
            return normalize_cwe(cwe.value)
        lowered = text.lower()
        for keyword, cwe_id in KEYWORD_CWE:
            index = lowered.find(keyword)
            if index >= 0:
                spans["vuln_class"] = SourceSpan(
                    start=index, end=index + len(keyword), quote=text[index : index + len(keyword)]
                )
                return cwe_id
        return ""

    # -- version --------------------------------------------------------

    def _version(self, text: str, spans: dict[str, SourceSpan]) -> str:
        hit = self._locate(_VERSION_RE, text)
        if hit is not None:
            spans["affected_version"] = hit.span
            return hit.value
        hit = self._locate(_BARE_VERSION_RE, text)
        if hit is not None:
            spans["affected_version"] = hit.span
            return hit.value
        return ""

    # -- poc ------------------------------------------------------------

    def _commands(self, text: str, spans: dict[str, SourceSpan]) -> tuple[PoCCommand, ...]:
        commands: list[PoCCommand] = []
        seen: set[str] = set()

        def add(command: str, span: SourceSpan | None) -> None:
            command = command.strip()
            if not command or command in seen:
                return
            if not self._looks_like_command(command):
                return  # pragma: no cover - prose is not a command
            seen.add(command)
            commands.append(PoCCommand(command=command, shell=True, span=span))

        for match in _SHELL_FENCE_RE.finditer(text):
            body = match.group("body")
            for line_match in _PROMPT_LINE_RE.finditer(body):
                add(
                    line_match.group("cmd"),
                    self._line_span(text, body, line_match),
                )
            if not commands:
                # A fenced block is a command block: every line in it is a
                # candidate, and add() decides whether it looks like a
                # command or like prose.
                for raw_line in body.splitlines():
                    candidate = raw_line.strip()
                    if not candidate or candidate.startswith("#"):
                        continue
                    add(candidate, self._line_span(text, body, None))

        if not commands:
            for match in _PROMPT_LINE_RE.finditer(text):
                add(
                    match.group("cmd"),
                    SourceSpan(
                        start=match.start("cmd"), end=match.end("cmd"), quote=match.group("cmd")
                    ),
                )

        if not commands:
            for match in _COMMAND_HINT_RE.finditer(text):
                add(
                    match.group(0).strip(),
                    SourceSpan(start=match.start(), end=match.end(), quote=match.group(0).strip()),
                )

        if commands:
            spans["poc_command"] = commands[0].span or SourceSpan(start=0, end=0, quote="")
        return tuple(commands)

    @staticmethod
    def _looks_like_command(text: str) -> bool:
        """Is this text plausibly a command rather than prose?

        Prose that starts with a capital letter and contains spaces is not
        a command, and treating it as one produces a nonsense plan.
        """
        candidate = (text or "").strip()
        if not candidate:
            return False
        first = candidate.split()[0]
        if first.startswith(("./", "../", "/")):
            return True
        if "/" in first:
            return True
        if first.lower() in _KNOWN_BINARIES:
            return True
        return bool(first.endswith((".py", ".sh", ".js", ".rb", ".pl", ".exe", ".bin")))

    def _line_span(
        self, text: str, body: str, match: re.Match[str] | None
    ) -> SourceSpan:
        if match is not None:
            return SourceSpan(start=match.start("cmd"), end=match.end("cmd"), quote=match.group("cmd"))
        offset = text.find(body)
        if offset < 0:  # pragma: no cover - defensive
            return SourceSpan(start=0, end=0, quote="")
        return SourceSpan(start=offset, end=offset + len(body), quote=body.strip())

    def _artifacts(self, text: str, attachment_names: tuple[str, ...]) -> tuple[PoCArtifact, ...]:
        artifacts: list[PoCArtifact] = []
        for name in attachment_names:
            artifacts.append(PoCArtifact(name=name, role=self._artifact_role(name)))
        for match in _FILE_RE.finditer(text):
            candidate = match.group("file")
            if candidate not in attachment_names and not any(a.name == candidate for a in artifacts):
                artifacts.append(PoCArtifact(name=candidate, role=self._artifact_role(candidate)))
        return tuple(artifacts)

    @staticmethod
    def _artifact_role(name: str) -> str:
        lowered = name.lower()
        if lowered.endswith((".sh", ".bash", ".py", ".js", ".rb", ".pl")):
            return "script"
        if lowered.endswith((".patch", ".diff")):
            return "patch"
        return "input"

    # -- impact & observable -------------------------------------------

    def _impact(self, text: str, spans: dict[str, SourceSpan]) -> ClaimImpact:
        lowered = text.lower()
        for keyword, summary in _IMPACT_KEYWORDS:
            index = lowered.find(keyword)
            if index >= 0:
                spans["impact"] = SourceSpan(
                    start=index, end=index + len(keyword), quote=text[index : index + len(keyword)]
                )
                return ClaimImpact(summary=summary)
        return ClaimImpact()

    def _expected(self, text: str, spans: dict[str, SourceSpan]) -> ExpectedObservable:
        for pattern, kind in _OBSERVABLE_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match is None:
                continue
            spans["expected"] = SourceSpan(
                start=match.start(), end=match.end(), quote=match.group(0)
            )
            signature = match.group(0)
            function = self._expected_function(text, match.start())
            return ExpectedObservable(kind=kind, signature=signature, function=function)
        return self._expected_output(text, spans)

    def _expected_output(
        self, text: str, spans: dict[str, SourceSpan]
    ) -> ExpectedObservable:
        """What the report says the program should print, or exit with.

        A report that says "the command prints ``SUCCESS``" states an
        output-level observable, and the output oracle can check it. The
        wording is deliberately narrow: a prose sentence that happens to
        contain the word "prints" is not a stated expectation.
        """
        match = _EXPECTED_OUTPUT_BLOCK_RE.search(text) or (
            _EXPECTED_OUTPUT_INLINE_RE.search(text)
        )
        if match is not None:
            value = match.group("value").strip().strip("`\"'").strip()
            if value:
                spans["expected"] = SourceSpan(
                    start=match.start(), end=match.end(), quote=match.group(0)
                )
                return ExpectedObservable(
                    kind="output",
                    signature=value,
                    regex=re.escape(value),
                    function=self._expected_function(text, match.start()),
                )
        code = _EXIT_CODE_RE.search(text)
        if code is not None:
            spans["expected"] = SourceSpan(
                start=code.start(), end=code.end(), quote=code.group(0)
            )
            return ExpectedObservable(
                kind="output",
                signature="",
                exit_code=int(code.group("code")),
                function=self._expected_function(text, code.start()),
            )
        return ExpectedObservable()

    @staticmethod
    def _expected_function(text: str, around: int) -> str:
        window = text[max(0, around - 400) : around + 400]
        func = _FUNC_PAREN_RE.search(window)
        return func.group("func") if func else ""

    # -- preconditions & config ----------------------------------------

    def _preconditions(self, text: str, spans: dict[str, SourceSpan]) -> tuple[str, ...]:
        found: list[str] = []
        for match in _PRECONDITION_RE.finditer(text):
            value = normalize_text(match.group("text"))
            if value and value not in found:
                found.append(value)
        if found:
            spans["preconditions"] = SourceSpan(
                start=0, end=0, quote=found[0]
            )
        return tuple(found)

    def _config(self, text: str, spans: dict[str, SourceSpan]) -> tuple[str, ...]:
        found: list[str] = []
        for match in _CONFIG_HINT_RE.finditer(text):
            value = normalize_text(match.group(0))
            if value and value not in found:
                found.append(value)
        return tuple(found)

    @staticmethod
    def _non_default(text: str) -> bool:
        return bool(_CONFIG_HINT_RE.search(text))

    # -- helpers --------------------------------------------------------

    @staticmethod
    def _locate(pattern: re.Pattern[str], text: str) -> _Hit | None:
        match = pattern.search(text)
        if match is None:
            return None
        groups = match.groupdict()
        value = ""
        span: SourceSpan | None = None
        for name in ("version", "func", "file", "value"):
            if groups.get(name):
                value = groups[name]
                span = SourceSpan(
                    start=match.start(name), end=match.end(name), quote=match.group(name)
                )
                break
        if not value:
            value = match.group(0)
        if span is None:
            span = SourceSpan(start=match.start(), end=match.end(), quote=match.group(0))
        return _Hit(value=value, span=span, full=match.group(0))


def extract_claim(text: str, *, attachment_names: tuple[str, ...] = ()) -> Claim:
    """Convenience wrapper around :class:`HeuristicExtractor`."""
    return HeuristicExtractor().extract(text, attachment_names=attachment_names)
