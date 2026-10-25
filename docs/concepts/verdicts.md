# Verdicts

There are seven verdicts. Each one says something different, and each one
says what it does *not* establish.

## REPRODUCED

An oracle fired at the claimed ref **and** matched the claim.

- **Tier 1** — the claimed impact was demonstrated.
- **Tier 2** — the behaviour was demonstrated, the claimed impact was not
  proven.

A report that claims remote code execution, where the run shows a heap
overflow, is Tier 2. The overflow is real; the code execution is not
shown. Both are honest statements, and a maintainer needs both.

## NOT_REPRODUCED

The build and the PoC ran, and the claimed behaviour did not occur.

This is the hardest verdict to get right, and the most dangerous one to
get wrong. It never means "the code is safe". It means: *this proof of
concept, in this environment, did not show the claimed behaviour.*

The verdict card always says so, and the draft reply always invites the
reporter to say if their steps differed.

When the PoC did not even start — a missing binary, a wrong path — the
verdict is `INCONCLUSIVE`, not `NOT_REPRODUCED`. The absence of a crash
in a run that never happened proves nothing.

## INCONCLUSIVE

The build failed, the run timed out, the result was flaky, or the
environment is not supported.

This is the honest answer when the tool cannot tell. It is deliberately
the default under doubt: a false dismissal costs a maintainer a real
vulnerability, and the mitigation for that is to fall back to
`INCONCLUSIVE` rather than to guess.

## OUT_OF_SCOPE

The claim reproduced, but the project's own policy excludes it. The
clause is cited, with the file, the heading and the line range.

The order matters: the tool reproduces first, so the maintainer can see
that it works, and only then is it marked out of scope.

## DUPLICATE

The report matches a prior report or a published advisory above the
threshold.

Duplicates are **suggestions**. The card names the candidate, the
similarity and the reasons (same function, same frames, same PoC bytes).
Nothing is merged, nothing is closed, and a human decides.

## NEEDS_INFO

Required evidence is missing: the affected version, the proof of concept
or the steps. The card quotes the project's own clause, and the draft
reply carries a short checklist.

This is a first-class outcome, not a failure. Most reports that a human
would bounce are `NEEDS_INFO`, and a good `NEEDS_INFO` reply saves a
maintainer an hour.

## UNSAFE_ATTACHMENT

Preflight blocked execution of an attachment. The attachment is
quarantined and the reasons are stated as observed behaviour.

It is a speed bump, not a wall: a maintainer can override the block with
a logged decision.

## Secondary flags

| Flag | Meaning |
| --- | --- |
| `FIXED_AT_HEAD` | the behaviour appears at the claimed ref but not at the comparison ref |
| `DEFAULT_CONFIG_ONLY` | the run used the default configuration |
| `NON_DEFAULT_CONFIG` | the claim only affects a non-default configuration |
| `FLAKY` | the oracle fired in some repetitions but not others |
| `NEEDS_HUMAN_RECIPE` | no build recipe could be found or trusted |
