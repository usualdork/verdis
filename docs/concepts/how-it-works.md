# How it works

The pipeline is fixed and deterministic. Every stage is idempotent, every
partial result is saved, and a crash resumes rather than restarts.

```
report -> intake -> claim -> policy -> dedupe (pre) -> preflight
preflight -> UNSAFE_ATTACHMENT                  (stop, quarantine)
preflight -> plan -> build -> run (sandbox) -> oracles -> judge
judge -> dedupe (post) -> evidence bundle -> verdict card + draft reply
```

## Intake

Every source — a file, a GitHub private vulnerability report, a GitHub
issue with a security label, an IMAP mailbox — is normalised into the same
`Report` object: an id, a source, a received time, the reporter handle
exactly as given, the body, the attachments (each hashed with SHA-256) and
the claimed target.

The report id is content-addressed: a hash of the normalised report and
the target ref. That makes ingestion idempotent — re-ingesting a report
yields the same id and no duplicate run.

Originals are written once and marked read-only.

## Claim extraction

The report becomes a schema-validated claim: component, file and function;
vulnerability class; affected version or commit range; preconditions; PoC
artifacts and commands; claimed impact; expected observable.

Three rules govern the extraction:

- every field carries the source span it came from, so a human can check
  it;
- a missing or ambiguous field is marked unknown and **never invented**;
- if the report carries an [RRS block](rrs.md), it is parsed
  deterministically, without a model.

In no-LLM mode, heuristics extract what they can and the gaps become
`NEEDS_INFO`.

## Policy check

`.verdis/policy.yml` is the authoritative source. When it is absent,
hints are derived from `SECURITY.md` and `THREAT_MODEL.md` and are
labelled *derived, unverified* until a maintainer confirms them.

A claim is mapped onto the project's own clauses, with citations: file,
heading and line range. A claim that hits an exclusion is **still
reproduced first**, so the maintainer sees whether it works, and only then
is it marked `OUT_OF_SCOPE`.

## Deduplication

Two passes. A cheap text-based pass before the run, and a strong
stack-signature pass after it. Fingerprints combine the normalised
vulnerability class and component, the crash or sanitizer stack signature,
the normalised PoC hash and a text embedding.

Matches are suggestions with reasons. Nothing is ever merged
automatically, because dedupe poisoning is a real attack.

## Attachment preflight

Every attachment is inspected statically before anything runs: file type,
archive structure (size limits, path traversal, compression bombs),
script behaviour (network calls, credential paths, obfuscation,
persistence, destructive commands) and binary characteristics (imports,
strings, packing).

Above the risk threshold the attachment is marked `UNSAFE_ATTACHMENT` and
quarantined. It runs only if a maintainer overrides with a logged
decision.

Findings state observed behaviour only. Nothing labels a reporter
malicious.

## Planning

A plan is written in a restricted step language: `checkout`, `build`,
`copy`, `run`, `expect`, `compare`. Network, host and secret access
**cannot be expressed in it**, and a validator enforces that before the
plan can be stored or run.

Unusual commands — a run-time package install, a privilege change, a write
outside the workdir — need a maintainer's confirmation, and fail closed
when unattended.

## Build

The target is built inside a build sandbox, from a recipe. Recipe sources,
in priority order:

1. the maintainer's `.verdis/recipe.yml`;
2. Dockerfile mode;
3. auto-detection from the repository;
4. a model-suggested recipe, stored for maintainer review.

First-class ecosystems in v1.0: Python, JavaScript and TypeScript (Node),
Go, and C/C++ (CMake, Make, autotools). Instrumented builds are used where
they matter: ASan and UBSan for C/C++, the race detector for Go.

Dependency fetching happens in a separate phase, through an allowlisted
mirror or a vendored cache. The run phase has no network at all.

## Run and oracles

The plan runs in a fresh, ephemeral sandbox. Oracles observe the run:

| Oracle | Fires when |
| --- | --- |
| crash | the process died from a signal, or printed a crash message |
| sanitizer | ASan, UBSan, MSan or TSan printed a diagnostic |
| exception | a managed runtime reported an uncaught exception |
| canary | a planted secret was read, or an outbound attempt was recorded |
| differential | the behaviour appears at the claimed ref but not at the comparison ref |
| property | a maintainer's assertion script failed |
| output | the output matched a stated regex or exit code |

Oracle results are matched to the claim. A crash in an unrelated function
does not confirm a claim about another, and the matching reasoning is
always shown.

The run is repeated three times by default, so flakiness is visible. A
flaky outcome is `INCONCLUSIVE`, never `REPRODUCED`.

## Judgment

The rules are deterministic, ordered and written down in
`src/verdis/judge/rules.py`:

1. `UNSAFE_ATTACHMENT` — preflight blocked execution.
2. `NEEDS_INFO` — required evidence is missing.
3. `DUPLICATE` — a prior report or advisory matched above the threshold.
4. `MISSING_SYMBOL` — the report names a function or file the target does
   not have, so the claim cannot be checked at all. A crash in a
   *different* function is not a reproduction of this claim.
5. `INCONCLUSIVE` — build failure, timeout, flakiness, unsupported
   environment.
6. `REPRODUCED` — an oracle fired at the claimed ref and matched the claim.
   A reproduced claim that policy excludes becomes `OUT_OF_SCOPE` instead.
7. `NOT_REPRODUCED` — the PoC ran and the claimed behaviour did not occur.

A duplicate is a statement about the *report*, not about the run, so it
comes before the run-dependent rules: a report that is already known does
not need to be reproduced again. The reproduction evidence, when there is
any, is still on the card.

`MISSING_SYMBOL` comes next for the same reason: if the report says the
defect is in a function the target does not have, the tool cannot check
the claim, and a crash somewhere else is not a reproduction of it.

The duplicate check also runs *before* the run, as a cheap text pass. A
pre-run match above the threshold short-circuits the run when
`dedupe.stop_on_duplicate` is on.

A duplicate is a statement about the *report*, not about the run: the
prior report's fingerprint does not depend on whether this run finished.
So a report that matches a prior one and whose run then times out is
still `DUPLICATE` — the maintainer's inbox needs the same answer either
way, and the pre-run match is the one that fires. The run's own
outcome is recorded on the card and in the bundle.

Any ambiguity falls back to `INCONCLUSIVE`, never to `REPRODUCED`.
