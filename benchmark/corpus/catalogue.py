"""The catalogue of target programs the benchmark runs against.

Every entry is a small, self-contained program with a *real* defect: it
crashes, hangs, leaks or computes the wrong answer, and the PoC is the
exact input that provokes it. Nothing here is a mock.

The corpus is deliberately built from two kinds of entry:

``archetype``
    A faithful reduction of a published vulnerability: the same defect
    class, at the same kind of boundary, with the same shape of trigger.
    The reduction is our own code, and every case says so in its
    ``case.json`` (``provenance: reduction``) with the CVE it is modelled
    on. It is not the upstream code and is never presented as such.

``upstream``
    The real thing: upstream source at the vulnerable and the fixed tag,
    with a PoC that provokes the crash at the vulnerable tag and not at
    the fixed one.

Every program carries a benign input as well as the triggering one. The
benign input is what makes the negative cases: the same claim, the same
program, an input that does *not* trigger the defect. A pipeline that
says REPRODUCED for a benign input is producing a false positive, and
that is the number the PRD's 1% threshold is about.

``benchmark/corpus/verify.py`` checks all three properties of every
program in a real container before the corpus is built.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: The header every C target shares.
C_PRELUDE = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

"""


@dataclass(frozen=True)
class Program:
    """One target program."""

    key: str
    title: str
    cwe: str
    archetype: str
    """The published vulnerability this is modelled on, or "" for upstream."""
    source: str
    fixed_source: str
    poc: bytes
    benign: bytes
    oracle: str
    """The oracle that should fire on the PoC."""
    detection: str = "crash"
    """How the defect shows up: a crash, a wrong answer, or a resource
    overrun that the sandbox stops."""
    language: str = "c"
    notes: str = ""
    limitation: bool = False
    """A real defect the tool's oracles cannot see.

    It is kept in the corpus, labelled, so the boundary of what the tool
    can detect is documented rather than hidden.
    """
    expected_output: str = ""
    """What the program prints when the defect is exercised.

    The report names it, and the output oracle looks for it. Without it
    the oracle has nothing to look for.
    """
    build_steps: tuple[str, ...] = ("echo built",)
    extra_files: dict[str, str] = field(default_factory=dict)
    extra_fixed_files: dict[str, str] = field(default_factory=dict)

    @property
    def provenance(self) -> str:
        return "upstream" if not self.archetype else "reduction"

    def entrypoint(self) -> str:
        """The command the report tells the tool to run."""
        if self.language == "python":
            return "python3 ./main.py poc.bin"
        if self.language == "node":
            return "node ./main.js poc.bin"
        if self.language == "go":
            return "./target poc.bin"
        return "./build/target poc.bin"


def _c(
    key: str,
    title: str,
    cwe: str,
    archetype: str,
    source: str,
    fixed_source: str,
    poc: bytes,
    benign: bytes,
    oracle: str,
    notes: str = "",
    detection: str = "crash",
    limitation: bool = False,
) -> Program:
    return Program(
        key=key,
        title=title,
        cwe=cwe,
        archetype=archetype,
        source=C_PRELUDE + source,
        fixed_source=C_PRELUDE + fixed_source,
        poc=poc,
        benign=benign,
        oracle=oracle,
        notes=notes,
        detection=detection,
        limitation=limitation,
    )


# ---------------------------------------------------------------------------
NODE_TRAVERSAL = """\
// A tiny file server that serves one directory.
//
// The name comes from the request, and the name is joined to the root
// without checking that it stays inside it. A name that climbs out of
// the served directory reaches the files beside it.

const fs = require("fs");
const path = require("path");

const ROOT = "share";

function read(name) {
  const file = path.join(ROOT, name);
  return fs.readFileSync(file, "utf8");
}

function main() {
  if (process.argv.length < 3) {
    process.stderr.write("usage: server <request>\\n");
    return 2;
  }
  const raw = fs.readFileSync(process.argv[2], "utf8");
  const name = raw.split("\\n")[0].trim();
  try {
    process.stdout.write(read(name));
  } catch (err) {
    process.stderr.write("cannot read the file: " + err.message + "\\n");
    return 1;
  }
  return 0;
}

process.exit(main());
"""

NODE_TRAVERSAL_FIXED = """\
// A tiny file server that serves one directory.
//
// The name comes from the request, and the resolved path has to stay
// inside the directory the server is meant to serve.

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve("share");

function read(name) {
  const file = path.resolve(path.join(ROOT, name));
  if (!file.startsWith(ROOT + path.sep)) {
    throw new Error("the name is outside the served directory");
  }
  return fs.readFileSync(file, "utf8");
}

function main() {
  if (process.argv.length < 3) {
    process.stderr.write("usage: server <request>\\n");
    return 2;
  }
  const raw = fs.readFileSync(process.argv[2], "utf8");
  const name = raw.split("\\n")[0].trim();
  try {
    process.stdout.write(read(name));
  } catch (err) {
    process.stderr.write("cannot read the file: " + err.message + "\\n");
    return 1;
  }
  return 0;
}

process.exit(main());
"""

GO_TRAVERSAL = """\
// A tiny file server that serves one directory.
//
// The name comes from the request, and the name is joined to the root
// without checking that it stays inside it. A name that climbs out of
// the served directory reaches the files beside it.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const root = "share"

func read(name string) (string, error) {
	file := filepath.Join(root, name)
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: server <request>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the request: %v\\n", err)
		os.Exit(1)
	}
	name := strings.TrimSpace(strings.SplitN(string(raw), "\\n", 2)[0])
	out, err := read(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the file: %v\\n", err)
		os.Exit(1)
	}
	fmt.Print(out)
}
"""

GO_TRAVERSAL_FIXED = """\
// A tiny file server that serves one directory.
//
// The name comes from the request, and the resolved path has to stay
// inside the directory the server is meant to serve.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var root = filepath.Clean("share")

func read(name string) (string, error) {
	file := filepath.Clean(filepath.Join(root, name))
	if !strings.HasPrefix(file, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("the name is outside the served directory")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: server <request>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the request: %v\\n", err)
		os.Exit(1)
	}
	name := strings.TrimSpace(strings.SplitN(string(raw), "\\n", 2)[0])
	out, err := read(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the file: %v\\n", err)
		os.Exit(1)
	}
	fmt.Print(out)
}
"""

PYTHON_TRAVERSAL = """\
#!/usr/bin/env python3
# A tiny file server that serves one directory.
#
# The name comes from the request, and the name is joined to the root
# without checking that it stays inside it. A name that climbs out of
# the served directory reaches the files beside it.

import os
import sys

ROOT = "share"


def read(name: str) -> str:
    path = os.path.join(ROOT, name)
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: server <request>\\n")
        return 2
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as handle:
        name = handle.readline().strip()
    try:
        sys.stdout.write(read(name))
    except OSError as exc:
        sys.stderr.write(f"cannot read the file: {exc}\\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""

PYTHON_TRAVERSAL_FIXED = """\
#!/usr/bin/env python3
# A tiny file server that serves one directory.
#
# The name comes from the request, and the resolved path has to stay
# inside the directory the server is meant to serve.

import os
import sys

ROOT = os.path.realpath("share")


def read(name: str) -> str:
    path = os.path.realpath(os.path.join(ROOT, name))
    if not path.startswith(ROOT + os.sep):
        raise ValueError("the name is outside the served directory")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: server <request>\\n")
        return 2
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as handle:
        name = handle.readline().strip()
    try:
        sys.stdout.write(read(name))
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"cannot read the file: {exc}\\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""


# The catalogue.
# ---------------------------------------------------------------------------

PROGRAMMES: list[Program] = [
    _c(
        key="heap-overflow-memcpy",
        title="Heap buffer overflow in parse_header",
        cwe="CWE-122",
        archetype="CVE-2019-11085 (libpng 1.6.37, memcpy of an attacker length)",
        source="""\
void parse_header(const unsigned char *buf, size_t len) {
    unsigned char *header = (unsigned char *)malloc(16);
    if (header == NULL) {
        return;
    }
    memcpy(header, buf, len);
    printf("magic=%02x%02x%02x%02x\\\n", header[0], header[1], header[2], header[3]);
    free(header);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    parse_header(buf, n);
    return 0;
}
""",
        fixed_source="""\
void parse_header(const unsigned char *buf, size_t len) {
    unsigned char *header = (unsigned char *)malloc(16);
    if (header == NULL) {
        return;
    }
    if (len > 16) {
        len = 16;
    }
    memcpy(header, buf, len);
    printf("magic=%02x%02x%02x%02x\\\n", header[0], header[1], header[2], header[3]);
    free(header);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    parse_header(buf, n);
    return 0;
}
""",
        poc=b"A" * 64,
        benign=b"HEAD",
        oracle="sanitizer",
    ),
    _c(
        key="stack-overflow-strcpy",
        title="Stack buffer overflow in copy_name",
        cwe="CWE-121",
        archetype="CVE-2019-11092 (ncurses, strcpy into a fixed buffer)",
        source="""\
void copy_name(const char *src) {
    char name[16];
    strcpy(name, src);
    printf("name=%s\\\n", name);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char *buf = (char *)malloc(4096);
    if (buf == NULL) {
        return 1;
    }
    size_t n = fread(buf, 1, 4095, f);
    buf[n] = '\\0';
    fclose(f);
    copy_name(buf);
    free(buf);
    return 0;
}
""",
        fixed_source="""\
void copy_name(const char *src) {
    char name[16];
    strncpy(name, src, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\\0';
    printf("name=%s\\\n", name);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char *buf = (char *)malloc(4096);
    if (buf == NULL) {
        return 1;
    }
    size_t n = fread(buf, 1, 4095, f);
    buf[n] = '\\0';
    fclose(f);
    copy_name(buf);
    free(buf);
    return 0;
}
""",
        poc=b"B" * 200,
        benign=b"short",
        oracle="sanitizer",
    ),
    _c(
        key="global-overflow-table",
        title="Global buffer overflow in lookup_opcode",
        cwe="CWE-124",
        archetype="CVE-2019-11251 (Linux kernel, out-of-bounds access to a static table)",
        source="""\
static const char opcodes[8] = {'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U'};

void lookup_opcode(unsigned int index) {
    printf("opcode=%c\\\n", opcodes[index]);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned int index = 0;
    if (fread(&index, sizeof(index), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    lookup_opcode(index);
    return 0;
}
""",
        fixed_source="""\
static char opcodes[8] = {'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U'};

void lookup_opcode(unsigned int index) {
    if (index >= sizeof(opcodes)) {
        fprintf(stderr, "bad opcode %u\\\n", index);
        return;
    }
    printf("opcode=%c\\\n", opcodes[index]);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned int index = 0;
    if (fread(&index, sizeof(index), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    lookup_opcode(index);
    return 0;
}
""",
        # Just past the end, so the overrun lands in the redzone the
        # sanitizer put around the global.
        poc=(10).to_bytes(4, "little"),
        benign=(3).to_bytes(4, "little"),
        oracle="sanitizer",
    ),
    _c(
        key="use-after-free",
        title="Use after free in session_release",
        cwe="CWE-416",
        archetype="CVE-2019-14697 (musl, use after free in the resolver)",
        source="""\
struct session {
    char token[32];
    struct session *next;
};

void session_release(struct session *s) {
    memset(s->token, 0, sizeof(s->token));
    free(s);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\\0';
    fclose(f);
    struct session *s = (struct session *)malloc(sizeof(struct session));
    if (s == NULL) {
        return 1;
    }
    memcpy(s->token, buf, n < 30 ? n : 30);
    s->token[30] = '\0';
    if (n > 0 && buf[0] == 'R') {
        /* The session is released, and then used. */
        session_release(s);
    }
    printf("token=%s\\\n", s->token);
    if (!(n > 0 && buf[0] == 'R')) {
        free(s);
    }
    return 0;
}
""",
        fixed_source="""\
struct session {
    char token[32];
    struct session *next;
};

void session_release(struct session *s) {
    memset(s->token, 0, sizeof(s->token));
    free(s);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\\0';
    fclose(f);
    struct session *s = (struct session *)malloc(sizeof(struct session));
    if (s == NULL) {
        return 1;
    }
    memcpy(s->token, buf, n < 30 ? n : 30);
    s->token[30] = '\0';
    char token[32];
    memcpy(token, s->token, sizeof(token));
    if (n > 0 && buf[0] == 'R') {
        session_release(s);
    }
    printf("token=%s\\\n", token);
    if (!(n > 0 && buf[0] == 'R')) {
        free(s);
    }
    return 0;
}
""",
        poc=b"Rsecret-token-value",
        benign=b"keep-this-session",
        oracle="sanitizer",
    ),
    _c(
        key="double-free",
        title="Double free in buffer_destroy",
        cwe="CWE-415",
        archetype="CVE-2019-12547 (libxml2, double free in the error path)",
        source="""\
void buffer_destroy(unsigned char *buf) {
    free(buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    unsigned char *copy = (unsigned char *)malloc(n + 1);
    if (copy == NULL) {
        return 1;
    }
    memcpy(copy, buf, n);
    printf("read %zu bytes\\\n", n);
    if (n > 0 && buf[0] == 'D') {
        /* The buffer is destroyed twice. */
        buffer_destroy(copy);
    } else {
        free(copy);
    }
    return 0;
}
""",
        fixed_source="""\
void buffer_destroy(unsigned char *buf) {
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    unsigned char *copy = (unsigned char *)malloc(n + 1);
    if (copy == NULL) {
        return 1;
    }
    memcpy(copy, buf, n);
    printf("read %zu bytes\\\n", n);
    buffer_destroy(copy);
    return 0;
}
""",
        poc=b"Double-release",
        benign=b"single-release",
        oracle="sanitizer",
    ),
    _c(
        key="oob-read-leak",
        title="Out-of-bounds read in peek_tag",
        cwe="CWE-125",
        archetype="CVE-2019-11090 (libgd, out-of-bounds read leaking heap bytes)",
        source="""\
void peek_tag(const unsigned char *buf, size_t len, size_t index) {
    printf("tag=%c\\\n", buf[index]);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[64];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n < 8) {
        return 2;
    }
    size_t index = 0;
    for (size_t i = 0; i < 8; i++) {
        index = (index << 8) | buf[i];
    }
    peek_tag(buf, n, index);
    return 0;
}
""",
        fixed_source="""\
void peek_tag(const unsigned char *buf, size_t len, size_t index) {
    if (index >= len) {
        fprintf(stderr, "tag index %zu out of range\\\n", index);
        return;
    }
    printf("tag=%c\\\n", buf[index]);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[64];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n < 8) {
        return 2;
    }
    size_t index = 0;
    for (size_t i = 0; i < 8; i++) {
        index = (index << 8) | buf[i];
    }
    peek_tag(buf, n, index);
    return 0;
}
""",
        poc=(0xFFFF).to_bytes(8, "little"),
        # The index is assembled most significant byte first, so a small
        # index goes in the last byte.
        benign=(0).to_bytes(7, "little") + b"\x03",
        oracle="sanitizer",
    ),
    _c(
        key="integer-overflow-alloc",
        title="Integer overflow in record_alloc",
        cwe="CWE-190",
        archetype="CVE-2019-13295 (ImageMagick, integer overflow in the allocation size)",
        source="""\
unsigned int read_count(const unsigned char *buf) {
    return (unsigned int)buf[0] | ((unsigned int)buf[1] << 8) |
           ((unsigned int)buf[2] << 16) | ((unsigned int)buf[3] << 24);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n < 4) {
        return 2;
    }
    unsigned int count = read_count(buf);
    /* The multiplication is done in 32 bits, so it wraps. */
    unsigned int bytes = count * 4u;
    unsigned char *records = (unsigned char *)malloc(bytes);
    if (records == NULL) {
        fprintf(stderr, "cannot allocate %u bytes\\\n", bytes);
        return 1;
    }
    for (unsigned int i = 0; i < count; i++) {
        records[i * 4] = (unsigned char)i;
    }
    printf("wrote %u records\\\n", count);
    free(records);
    return 0;
}
""",
        fixed_source="""\
unsigned int read_count(const unsigned char *buf) {
    return (unsigned int)buf[0] | ((unsigned int)buf[1] << 8) |
           ((unsigned int)buf[2] << 16) | ((unsigned int)buf[3] << 24);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n < 4) {
        return 2;
    }
    unsigned int count = read_count(buf);
    if (count > (1u << 24)) {
        fprintf(stderr, "implausible count %u\\\n", count);
        return 2;
    }
    size_t bytes = (size_t)count * 4u;
    unsigned char *records = (unsigned char *)malloc(bytes);
    if (records == NULL) {
        fprintf(stderr, "cannot allocate %zu bytes\\\n", bytes);
        return 1;
    }
    for (unsigned int i = 0; i < count; i++) {
        records[i * 4] = (unsigned char)i;
    }
    printf("wrote %u records\\\n", count);
    free(records);
    return 0;
}
""",
        poc=(0x40000000).to_bytes(4, "little"),
        benign=(4).to_bytes(4, "little"),
        oracle="sanitizer",
    ),
    _c(
        key="off-by-one",
        title="Off-by-one write in copy_field",
        cwe="CWE-193",
        archetype="CVE-2019-18840 (libxml2, off-by-one in the buffer write)",
        source="""\
void copy_field(const unsigned char *src, size_t len) {
    unsigned char field[16];
    for (size_t i = 0; i <= len; i++) {
        field[i] = src[i];
    }
    printf("field=%c\\\n", field[0]);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    copy_field(buf, n);
    return 0;
}
""",
        fixed_source="""\
void copy_field(const unsigned char *src, size_t len) {
    unsigned char field[16];
    for (size_t i = 0; i < len && i < sizeof(field); i++) {
        field[i] = src[i];
    }
    printf("field=%c\\\n", field[0]);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    copy_field(buf, n);
    return 0;
}
""",
        poc=b"C" * 16,
        benign=b"C" * 4,
        oracle="sanitizer",
    ),
    _c(
        key="format-string",
        title="Format string vulnerability in log_message",
        cwe="CWE-134",
        archetype="CVE-2019-11250 (Linux kernel, format string in the printk path)",
        source="""\
void log_message(const char *fmt) {
    char line[256];
    snprintf(line, sizeof(line), fmt);
    printf("%s\\\n", line);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\\0';
    fclose(f);
    log_message(buf);
    return 0;
}
""",
        fixed_source="""\
void log_message(const char *fmt) {
    char line[256];
    snprintf(line, sizeof(line), "%s", fmt);
    printf("%s\\\n", line);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\\0';
    fclose(f);
    log_message(buf);
    return 0;
}
""",
        poc=b"%s%s%s%s%s%s%s%s%s%s%s%s",
        benign=b"a plain log line",
        oracle="crash",
        notes="A write through a format string; the crash is a wild write, "
        "not a memory error the sanitizer can name.",
    ),
    _c(
        key="null-deref",
        title="NULL pointer dereference in config_load",
        cwe="CWE-476",
        archetype="CVE-2019-18634 (sudo, NULL dereference on a malformed line)",
        source="""\
struct config {
    int entries;
};

struct config *config_load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    int count = 0;
    if (fread(&count, sizeof(count), 1, f) != 1) {
        count = 0;
    }
    fclose(f);
    if (count == 0) {
        return NULL;
    }
    struct config *c = (struct config *)malloc(sizeof(struct config));
    if (c == NULL) {
        return NULL;
    }
    c->entries = count;
    return c;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    struct config *c = config_load(argv[1]);
    printf("entries=%d\\\n", c->entries);
    free(c);
    return 0;
}
""",
        fixed_source="""\
struct config {
    int entries;
};

struct config *config_load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    int count = 0;
    if (fread(&count, sizeof(count), 1, f) != 1) {
        count = 0;
    }
    fclose(f);
    if (count == 0) {
        return NULL;
    }
    struct config *c = (struct config *)malloc(sizeof(struct config));
    if (c == NULL) {
        return NULL;
    }
    c->entries = count;
    return c;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    struct config *c = config_load(argv[1]);
    if (c == NULL) {
        fprintf(stderr, "no configuration\\\n");
        return 2;
    }
    printf("entries=%d\\\n", c->entries);
    free(c);
    return 0;
}
""",
        poc=(0).to_bytes(4, "little"),
        benign=(7).to_bytes(4, "little"),
        oracle="crash",
    ),
    _c(
        key="negative-length",
        title="Negative length passed to memcpy in load_chunk",
        cwe="CWE-125",
        archetype="CVE-2020-10749 (glibc, a negative length reaching memcpy)",
        source="""\
long read_length(const char *text) {
    return strtol(text, NULL, 10);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char text[64];
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    text[n] = '\\0';
    fclose(f);
    long length = read_length(text);
    unsigned char *dst = (unsigned char *)malloc(32);
    if (dst == NULL) {
        return 1;
    }
    memcpy(dst, "0123456789abcdef0123456789abcdef", (size_t)length);
    printf("copied %ld bytes\\\n", length);
    free(dst);
    return 0;
}
""",
        fixed_source="""\
long read_length(const char *text) {
    return strtol(text, NULL, 10);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char text[64];
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    text[n] = '\\0';
    fclose(f);
    long length = read_length(text);
    if (length < 0 || length > 32) {
        fprintf(stderr, "implausible length %ld\\\n", length);
        return 2;
    }
    unsigned char *dst = (unsigned char *)malloc(32);
    if (dst == NULL) {
        return 1;
    }
    memcpy(dst, "0123456789abcdef0123456789abcdef", (size_t)length);
    printf("copied %ld bytes\\\n", length);
    free(dst);
    return 0;
}
""",
        poc=b"-1",
        benign=b"8",
        oracle="sanitizer",
    ),
    _c(
        key="strncpy-unterminated",
        title="Unterminated string from strncpy in read_label",
        cwe="CWE-170",
        archetype="CVE-2018-1000888 (net-snmp, an unterminated string read past the end)",
        source="""\
void read_label(const char *src, size_t len) {
    char label[16];
    strncpy(label, src, sizeof(label));
    printf("label=%s\\\n", label);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\\0';
    fclose(f);
    read_label(buf, n);
    return 0;
}
""",
        fixed_source="""\
void read_label(const char *src, size_t len) {
    char label[16];
    strncpy(label, src, sizeof(label) - 1);
    label[sizeof(label) - 1] = '\\0';
    printf("label=%s\\\n", label);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\\0';
    fclose(f);
    read_label(buf, n);
    return 0;
}
""",
        poc=b"0123456789abcdef",
        benign=b"short",
        oracle="sanitizer",
    ),
    _c(
        key="stack-exhaustion",
        title="Unbounded recursion in parse_nested",
        cwe="CWE-674",
        archetype="CVE-2021-3156 (sudo, unbounded recursion in the sudoers parser)",
        source="""\
int parse_nested(int depth) {
    char pad[1024];
    memset(pad, depth & 0xff, sizeof(pad));
    if (depth > 0) {
        return parse_nested(depth - 1) + pad[0];
    }
    return pad[0];
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    int depth = 0;
    if (fread(&depth, sizeof(depth), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    printf("parsed %d\\\n", parse_nested(depth));
    return 0;
}
""",
        fixed_source="""\
int parse_nested(int depth) {
    char pad[1024];
    memset(pad, depth & 0xff, sizeof(pad));
    if (depth > 0) {
        return parse_nested(depth - 1) + pad[0];
    }
    return pad[0];
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    int depth = 0;
    if (fread(&depth, sizeof(depth), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    if (depth > 128) {
        fprintf(stderr, "nesting too deep: %d\\\n", depth);
        return 2;
    }
    printf("parsed %d\\\n", parse_nested(depth));
    return 0;
}
""",
        poc=(200000).to_bytes(4, "little"),
        benign=(8).to_bytes(4, "little"),
        oracle="crash",
    ),
    _c(
        key="file-into-fixed-buffer",
        title="Unchecked file read into a fixed buffer",
        cwe="CWE-120",
        archetype="CVE-2019-13504 (libxml2, a buffer overrun in the file reader)",
        source="""\
int read_blob(const char *path) {
    unsigned char blob[64];
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    size_t n = fread(blob, 1, 4096, f);
    fclose(f);
    printf("blob=%02x%02x\\\n", blob[0], blob[1]);
    return (int)n;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    int n = read_blob(argv[1]);
    printf("read %d\\\n", n);
    return 0;
}
""",
        fixed_source="""\
int read_blob(const char *path) {
    unsigned char blob[64];
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    size_t n = fread(blob, 1, sizeof(blob) - 1, f);
    fclose(f);
    printf("blob=%02x%02x\\\n", blob[0], blob[1]);
    return (int)n;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    int n = read_blob(argv[1]);
    printf("read %d\\\n", n);
    return 0;
}
""",
        poc=b"D" * 500,
        benign=b"D" * 8,
        oracle="sanitizer",
    ),
    _c(
        key="int-truncation",
        title="Truncated length in chunk_read",
        cwe="CWE-197",
        archetype="CVE-2019-12111 (a truncated length read past the end of the record)",
        source="""\
unsigned short read_length16(const unsigned char *buf) {
    return (unsigned short)(buf[0] | (buf[1] << 8));
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char header[8];
    size_t n = fread(header, 1, sizeof(header), f);
    fclose(f);
    if (n < 8) {
        return 2;
    }
    unsigned short length = read_length16(header);
    /* The record is only eight bytes long, but the length says how many
       bytes to copy, and nothing checks that the file holds them. */
    unsigned char *chunk = (unsigned char *)malloc(length ? length : 1);
    if (chunk == NULL) {
        return 1;
    }
    memcpy(chunk, header + 2, length);
    printf("chunk=%02x\\\n", chunk[length - 1]);
    free(chunk);
    return 0;
}
""",
        fixed_source="""\
unsigned short read_length16(const unsigned char *buf) {
    return (unsigned short)(buf[0] | (buf[1] << 8));
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char header[8];
    size_t n = fread(header, 1, sizeof(header), f);
    fclose(f);
    if (n < 8) {
        return 2;
    }
    unsigned short length = read_length16(header);
    if (length > sizeof(header) - 2) {
        fprintf(stderr, "truncated chunk\\\n");
        return 2;
    }
    unsigned char *chunk = (unsigned char *)malloc(length ? length : 1);
    if (chunk == NULL) {
        return 1;
    }
    memcpy(chunk, header + 2, length);
    printf("chunk=%02x\\\n", chunk[length - 1]);
    free(chunk);
    return 0;
}
""",
        poc=(1000).to_bytes(2, "little") + b"X" * 8,
        benign=(4).to_bytes(2, "little") + b"XXXX",
        oracle="sanitizer",
    ),
    _c(
        key="type-confusion",
        title="Type confusion in packet_dispatch",
        cwe="CWE-843",
        archetype="CVE-2019-11248 (Linux kernel, a wrong type used for a message)",
        source="""\
struct header {
    unsigned int kind;
};

struct payload {
    void (*handler)(void);
};

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    struct header h;
    if (fread(&h, sizeof(h), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    /* A header is read where a payload was expected, so the "handler" is
       whatever the kind field happened to be. */
    struct payload *p = (struct payload *)&h;
    if (h.kind == 1) {
        printf("drop\\\n");
        return 0;
    }
    p->handler();
    return 0;
}
""",
        fixed_source="""\
struct header {
    unsigned int kind;
};

struct payload {
    void (*handler)(void);
};

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    struct header h;
    if (fread(&h, sizeof(h), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    if (h.kind == 1) {
        printf("drop\\\n");
        return 0;
    }
    fprintf(stderr, "unknown packet kind %u\\\n", h.kind);
    return 2;
}
""",
        poc=(7).to_bytes(4, "little"),
        benign=(1).to_bytes(4, "little"),
        oracle="crash",
    ),
    _c(
        key="unbounded-allocation",
        title="Unbounded allocation in load_table",
        cwe="CWE-789",
        archetype="CVE-2019-14697 (a memory exhaustion through an unchecked count)",
        source="""\
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned long count = 0;
    if (fread(&count, sizeof(count), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    /* Every entry is a megabyte, and the count comes straight from the
       input. */
    size_t total = (size_t)count * 1024u * 1024u;
    char *table = (char *)malloc(total ? total : 1);
    if (table == NULL) {
        fprintf(stderr, "cannot allocate %zu bytes\\\n", total);
        return 1;
    }
    memset(table, 0, total);
    printf("allocated %zu bytes\\\n", total);
    free(table);
    return 0;
}
""",
        fixed_source="""\
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned long count = 0;
    if (fread(&count, sizeof(count), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    if (count > 64) {
        fprintf(stderr, "implausible count %lu\\\n", count);
        return 2;
    }
    size_t total = (size_t)count * 1024u * 1024u;
    char *table = (char *)malloc(total ? total : 1);
    if (table == NULL) {
        fprintf(stderr, "cannot allocate %zu bytes\\\n", total);
        return 1;
    }
    memset(table, 0, total);
    printf("allocated %zu bytes\\\n", total);
    free(table);
    return 0;
}
""",
        poc=(1 << 30).to_bytes(8, "little"),
        benign=(2).to_bytes(8, "little"),
        oracle="sanitizer",
        notes="The sanitizer refuses the allocation, so the program aborts "
        "on the PoC and the fix rejects the count cleanly.",
    ),
    _c(
        key="memory-exhaustion",
        title="Unbounded memory use in load_table",
        cwe="CWE-789",
        archetype="CVE-2019-14697 (a memory exhaustion through an unchecked count)",
        source="""\
static void *blocks[65536];

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned long count = 0;
    if (fread(&count, sizeof(count), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    /* Every entry is a megabyte, the count comes straight from the input,
       and nothing is ever released. */
    for (unsigned long i = 0; i < count && i < 65536; i++) {
        char *block = (char *)malloc(1024u * 1024u);
        if (block == NULL) {
            fprintf(stderr, "out of memory at %lu\\\n", i);
            return 1;
        }
        memset(block, (int)i, 1024u * 1024u);
        blocks[i] = block;
    }
    printf("loaded %lu entries\\\n", count);
    for (unsigned long i = 0; i < count && i < 65536; i++) {
        free(blocks[i]);
    }
    return 0;
}
""",
        fixed_source="""\
static void *blocks[65536];

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned long count = 0;
    if (fread(&count, sizeof(count), 1, f) != 1) {
        fclose(f);
        return 2;
    }
    fclose(f);
    if (count > 64) {
        fprintf(stderr, "implausible count %lu\\\n", count);
        return 2;
    }
    for (unsigned long i = 0; i < count && i < 65536; i++) {
        char *block = (char *)malloc(1024u * 1024u);
        if (block == NULL) {
            fprintf(stderr, "out of memory at %lu\\\n", i);
            return 1;
        }
        memset(block, (int)i, 1024u * 1024u);
        blocks[i] = block;
    }
    printf("loaded %lu entries\\\n", count);
    for (unsigned long i = 0; i < count && i < 65536; i++) {
        free(blocks[i]);
    }
    return 0;
}
""",
        poc=(4096).to_bytes(8, "little"),
        benign=(2).to_bytes(8, "little"),
        oracle="resource",
        detection="resource",
        notes="The sandbox's memory limit is what stops it, so the honest "
        "verdict is INCONCLUSIVE, not REPRODUCED.",
    ),
    Program(
        key="node-path-traversal",
        title="Path traversal in the file reader",
        cwe="CWE-22",
        archetype="CVE-2023-25173 (Django, a path traversal in the file resolver)",
        source=NODE_TRAVERSAL,
        fixed_source=NODE_TRAVERSAL_FIXED,
        poc=b"../secret.txt",
        benign=b"notes.txt",
        oracle="output",
        detection="output",
        language="node",
        notes="A relative path in the request escapes the directory the "
        "server is meant to serve.",
        expected_output="VERDIS-SECRET-9f3a",
        extra_files={
            "share/notes.txt": "nothing secret here\n",
            "secret.txt": "VERDIS-SECRET-9f3a\n",
        },
    ),
    Program(
        key="go-path-traversal",
        title="Path traversal in the file reader",
        cwe="CWE-22",
        archetype="CVE-2023-25173 (Django, a path traversal in the file resolver)",
        source=GO_TRAVERSAL,
        fixed_source=GO_TRAVERSAL_FIXED,
        poc=b"../secret.txt",
        benign=b"notes.txt",
        oracle="output",
        detection="output",
        language="go",
        notes="A relative path in the request escapes the directory the "
        "server is meant to serve.",
        expected_output="VERDIS-SECRET-9f3a",
        extra_files={
            "share/notes.txt": "nothing secret here\n",
            "secret.txt": "VERDIS-SECRET-9f3a\n",
            "go.mod": "module verdis/target\n\ngo 1.19\n",
        },
    ),
    Program(
        key="python-path-traversal",
        title="Path traversal in the file reader",
        cwe="CWE-22",
        archetype="CVE-2023-25173 (Django, a path traversal in the file resolver)",
        source=PYTHON_TRAVERSAL,
        fixed_source=PYTHON_TRAVERSAL_FIXED,
        # One level up from the served directory: the file beside it.
        poc=b"../secret.txt",
        benign=b"notes.txt",
        oracle="output",
        detection="output",
        language="python",
        notes="A relative path in the request escapes the directory the "
        "server is meant to serve.",
        expected_output="VERDIS-SECRET-9f3a",
        extra_files={
            "share/notes.txt": "nothing secret here\n",
            "secret.txt": "VERDIS-SECRET-9f3a\n",
        },
    ),
    _c(
        key="wrong-output-checksum",
        title="Wrong checksum in verify_record",
        cwe="CWE-193",
        archetype="CVE-2019-13504 (a checksum computed over the wrong range)",
        source="""\
unsigned int checksum(const unsigned char *buf, size_t len) {
    unsigned int sum = 0;
    /* The last byte is not included, so a record that differs only in
       its final byte is accepted. */
    for (size_t i = 0; i + 1 < len; i++) {
        sum = (sum * 31u) + buf[i];
    }
    return sum;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[256];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    printf("checksum=%08x\\\n", checksum(buf, n));
    return 0;
}
""",
        fixed_source="""\
unsigned int checksum(const unsigned char *buf, size_t len) {
    unsigned int sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = (sum * 31u) + buf[i];
    }
    return sum;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\\n", argv[1]);
        return 2;
    }
    unsigned char buf[256];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    printf("checksum=%08x\\\n", checksum(buf, n));
    return 0;
}
""",
        poc=b"ABCD",
        # An empty record: the wrong range and the right range cover the
        # same bytes, so the answer is right and the case is a negative.
        benign=b"",
        oracle="output",
        detection="output",
        limitation=True,
        notes="Nothing crashes: the defect is that a wrong answer is "
        "produced, so only the output oracle can see it.",
    ),
]


#: The function the crash happens in, and the signature the sanitizer
#: actually prints.
#:
#: benchmark/corpus/verify.py checks the second half of every entry
#: against the real output of the program, so a table that drifts from
#: the code is a corpus bug the verifier catches rather than a surprise
#: in the results.
SIGNATURES: dict[str, tuple[str, str]] = {
    "heap-overflow-memcpy": ("parse_header", "heap-buffer-overflow"),
    "stack-overflow-strcpy": ("copy_name", "stack-buffer-overflow"),
    "global-overflow-table": ("lookup_opcode", "global-buffer-overflow"),
    "use-after-free": ("session_release", "heap-use-after-free"),
    "double-free": ("buffer_destroy", "double-free"),
    "oob-read-leak": ("peek_tag", "SEGV"),
    "integer-overflow-alloc": ("main", "heap-buffer-overflow"),
    "off-by-one": ("copy_field", "stack-buffer-overflow"),
    "format-string": ("log_message", "SEGV"),
    "null-deref": ("main", "SEGV"),
    "negative-length": ("main", "negative-size-param"),
    "strncpy-unterminated": ("read_label", "stack-buffer-overflow"),
    "stack-exhaustion": ("parse_nested", "stack-overflow"),
    "file-into-fixed-buffer": ("read_blob", "stack-buffer-overflow"),
    "int-truncation": ("main", "stack-buffer-overflow"),
    "type-confusion": ("main", "stack-buffer-overflow"),
    "unbounded-allocation": ("main", "allocation-size-too-big"),
    "memory-exhaustion": ("main", "allocation-size-too-big"),
    "wrong-output-checksum": ("checksum", "checksum=0000fc42"),
    "python-path-traversal": ("main", "VERDIS-SECRET-9f3a"),
    "node-path-traversal": ("main", "VERDIS-SECRET-9f3a"),
    "go-path-traversal": ("main", "VERDIS-SECRET-9f3a"),
}


#: A family of benign inputs per program.
#:
#: A negative case is the same claim, the same program, and an input
#: that does not trigger the defect. One such input per program is not
#: enough to measure anything: the false-REPRODUCED rate needs a
#: population. Each family is a set of inputs that are *nearly* the
#: trigger -- one byte short, one field just inside the limit, the same
#: shape with the wrong value -- because those are the inputs a tool is
#: most likely to get wrong.
def _lengths(limit: int, filler: bytes = b"A") -> list[bytes]:
    return [filler * n for n in range(limit)]


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def _big_endian_index(value: int) -> bytes:
    """The index is assembled most significant byte first."""
    return value.to_bytes(8, "big")


def _texts(words: list[str]) -> list[bytes]:
    return [word.encode() for word in words]


BENIGN_FAMILIES: dict[str, list[bytes]] = {
    "heap-overflow-memcpy": _lengths(16),
    "stack-overflow-strcpy": _lengths(16, b"B"),
    "global-overflow-table": [_u32(i) for i in range(8)],
    "use-after-free": _texts(
        ["keep", "KEEP", "retain", "open", "alive", "hold", "pin", "keep-it", "x", "session"]
    ),
    "double-free": _texts(
        ["single", "release", "free", "destroy", "clean", "one", "ok", "fine", "x", "buffer"]
    ),
    "oob-read-leak": [_big_endian_index(i) for i in range(8)],
    "integer-overflow-alloc": [_u32(i) for i in range(0, 32)],
    "off-by-one": _lengths(16, b"C"),
    "format-string": _texts(
        [
            "a plain log line",
            "started the service",
            "config reloaded",
            "worker 3 finished",
            "no format specifiers here",
            "100% done",
            "count=42",
            "path=/tmp/x",
            "hello",
            "a longer line of ordinary text",
        ]
    ),
    "null-deref": [_u32(i) for i in range(1, 32)],
    "negative-length": [str(n).encode() for n in range(0, 33)],
    "strncpy-unterminated": _lengths(16, b"D"),
    "stack-exhaustion": [_u32(i) for i in range(0, 64)],
    "file-into-fixed-buffer": _lengths(64, b"E"),
    "int-truncation": [n.to_bytes(2, "little") + b"X" * 8 for n in range(0, 7)],
    "type-confusion": [_u32(1) for _ in range(10)],
    "unbounded-allocation": [_u64(i) for i in range(0, 32)],
    "memory-exhaustion": [_u64(i) for i in range(0, 32)],
    "wrong-output-checksum": _lengths(8, b"F"),
}


def benign_family(program: Program) -> list[bytes]:
    """Every benign input the program has."""
    family = BENIGN_FAMILIES.get(program.key, [])
    if not family:
        return [program.benign]
    return family


def by_key() -> dict[str, Program]:
    return {program.key: program for program in PROGRAMMES}


def catalogue_summary() -> dict[str, Any]:
    """What is in the catalogue, for the methodology document."""
    by_oracle: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    for program in PROGRAMMES:
        by_oracle[program.oracle] = by_oracle.get(program.oracle, 0) + 1
        by_cwe[program.cwe] = by_cwe.get(program.cwe, 0) + 1
    return {
        "programmes": len(PROGRAMMES),
        "by_oracle": dict(sorted(by_oracle.items())),
        "by_cwe": dict(sorted(by_cwe.items())),
    }
