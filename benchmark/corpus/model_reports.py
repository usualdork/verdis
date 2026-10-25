"""Negatives that are written like a model writes them.

Section 13.1 asks for negatives "written by hand and by models". A
report that a person wrote and a report that a model wrote fail in
different ways: a person misremembers a version, a model invents a
function that sounds right and states it confidently. Both have to be
represented, or the false-positive rate is measured against the wrong
kind of mistake.

The generator asks the tool's own model provider when one is
configured, and falls back to a deterministic generator when it is not.
Every case records which of the two wrote it, in ``written_by``.
"""

from __future__ import annotations

from typing import Any

#: The prompt a model is given. It asks for a report that is plausible
#: and false, which is the hard case: a report that is obviously wrong
#: teaches the tool nothing.
MODEL_PROMPT = """\
You are writing a security report for a project that is NOT vulnerable \
in the way the report claims.

The report must be:
  * plausible: a maintainer would not immediately dismiss it;
  * confident: it states a version, a function and a consequence;
  * false: the function it names does not exist, or the version it \
names is not affected, or the outcome it describes is not what \
happens.

Write the report in Markdown, in the style of a real security report. \
Do not add any commentary about it being fictional. \
The report must be under 400 words.
"""

#: The deterministic generator. Each style is a way of being wrong
#: that a model writes in, and each one is a report a maintainer would
#: have to spend time on.
TEMPLATE_STYLES: tuple[tuple[str, str], ...] = (
    (
        "invented-function",
        """\
# Heap buffer overflow in decode_segment

**Version**: 2.3.1
**Component**: src/segment.c:decode_segment
**Class**: CWE-122

Decoding a segment with a length field that is not validated copies past
the end of the destination buffer. A crafted segment triggers it.

## Steps to reproduce

```
./build/target poc.bin
```

AddressSanitizer reports a heap-buffer-overflow in decode_segment.

## Impact

An attacker who can supply a segment can corrupt the heap.
""",
    ),
    (
        "wrong-version",
        """\
# Stack buffer overflow in parse_header

**Version**: 1.4.7
**Component**: src/target.c:parse_header
**Class**: CWE-121

The header parser copies the length from the file into a fixed size
buffer. In 1.4.7 this overflows the stack.

## Steps to reproduce

```
./build/target poc.bin
```

AddressSanitizer reports a stack-buffer-overflow in parse_header.

## Impact

Code execution in the context of the parsing process.
""",
    ),
    (
        "wrong-consequence",
        """\
# Out-of-bounds read in the checksum routine

**Version**: 2.3.1
**Component**: src/target.c:checksum
**Class**: CWE-125

The checksum is computed over the wrong range, so a record whose last
byte differs is still accepted. This leaks the bytes that follow the
record in memory.

## Steps to reproduce

```
./build/target poc.bin
```

The program prints a checksum that does not cover the whole record.

## Impact

Information disclosure of a small number of heap bytes.
""",
    ),
    (
        "wrong-observable",
        """\
# {title}

**Version**: 2.3.1
**Component**: src/target.c:{function}
**Class**: {cwe}

The {function} function does not check the length it was given, so a
crafted input makes it read or write outside the buffer.

## Steps to reproduce

```
./build/target poc.bin
```

The program aborts with an AddressSanitizer diagnostic: {signature}.

## Impact

Memory corruption in a parser that handles untrusted input.
""",
    ),
    (
        "neighbouring-function",
        """\
# Use after free in session_open

**Version**: 2.3.1
**Component**: src/target.c:session_open
**Class**: CWE-416

A session is released and then used again, so the freed memory is
read.

## Steps to reproduce

```
./build/target poc.bin
```

AddressSanitizer reports a heap-use-after-free in session_open.

## Impact

A use after free that an attacker controls the contents of.
""",
    ),
)


def _provider(config: Any) -> Any:
    """The model provider, when one is configured."""
    try:
        from verdis.extract.providers import build_provider
    except Exception:  # pragma: no cover - the provider is optional
        return None
    try:
        provider = build_provider(config)
    except Exception:  # pragma: no cover - a broken configuration
        return None
    if provider is None or type(provider).__name__ == "NullProvider":
        return None
    return provider


#: The signatures a program might produce, and the ones it does not. A
#: report that names a signature the program does not produce is false
#: in a way the tool can see.
OTHER_SIGNATURES: tuple[str, ...] = (
    "stack-buffer-overflow",
    "heap-buffer-overflow",
    "global-buffer-overflow",
    "heap-use-after-free",
    "double-free",
    "SEGV on unknown address",
    "negative-size-param",
    "stack-overflow",
)


def write_reports(
    program_key: str,
    title: str,
    component: str,
    cwe: str,
    *,
    function: str = "",
    real_signature: str = "",
    config: Any = None,
    count: int = 6,
) -> list[tuple[str, str, str]]:
    """The false reports for one program.

    Returns ``(name, report, written_by)`` for each one. ``written_by``
    is ``model`` when a provider wrote it and ``template`` when the
    deterministic generator did, so the corpus always says where a
    report came from.
    """
    provider = _provider(config)
    written: list[tuple[str, str, str]] = []

    if provider is not None:
        prompt = (
            f"{MODEL_PROMPT}\n\n"
            f"The project is {program_key}. The report should claim a "
            f"vulnerability in {component} ({cwe}) affecting version 2.3.1.\n"
        )
        for index in range(count):
            try:
                payload, _metadata = provider.complete_json(
                    system=MODEL_PROMPT,
                    user=prompt,
                    schema={
                        "type": "object",
                        "properties": {"report": {"type": "string"}},
                        "required": ["report"],
                    },
                    purpose="benchmark-negative",
                )
            except Exception:  # pragma: no cover - the provider failed
                break
            report = str(payload.get("report", "")).strip()
            if report:
                written.append((f"model-{index:02d}", report, "model"))
        if written:
            return written

    # A signature the program does not produce, so the report is false
    # in the observable the tool can actually check.
    other = next(
        (
            signature
            for signature in OTHER_SIGNATURES
            if signature != real_signature
        ),
        "stack-buffer-overflow",
    )
    for index, (_style, report) in enumerate(TEMPLATE_STYLES[:count]):
        report = report.format(
            title=title,
            function=function,
            cwe=cwe,
            signature=other,
        )
        written.append((f"template-{index:02d}", report, "template"))
    return written
