# Threat model

Verdis runs attacker-controlled input by design, so its own security is
a first-class requirement, not a section at the end.

## Trust boundaries

| Boundary | What crosses it |
| --- | --- |
| **Trusted** | the orchestrator, the maintainer's credentials and configuration. |
| **Untrusted** | report text, attachments, PoCs and anything derived from them ("tainted"). |
| **Semi-trusted** | the target source at the claimed ref. It is the maintainers' own code, but its dependencies may be hostile. |
| **Untrusted for secrets** | external model providers. |
| **Confidential** | the evidence store. |

## The default sandbox profile

- Rootless Podman or Docker, a non-root user inside, user namespaces on.
- **No network in the run stage** (`--network none`). Loopback only, with
  the canary listener inside the sandbox.
- Read-only root filesystem, a writable tmpfs workdir, the source mounted
  read-only, an evidence directory that is write-only from inside.
- All capabilities dropped, `no-new-privileges`, the default seccomp
  profile or stricter, no devices, no other host mounts, and the container
  runtime socket never exposed.
- Limits on CPU, memory, process count, disk, open files and wall-clock
  time. The process group is killed on a timeout and the output size is
  capped.
- No secrets: a scrubbed environment, and the orchestrator's tokens never
  enter any sandbox.
- Ephemeral: a fresh container per run, with images pinned by digest.
- Observable: blocked network attempts, file changes and exit signals are
  recorded.

## The hardened profile

The hardened profile asks for gVisor (`runsc`), a per-report ephemeral
runner, a stricter seccomp profile and a separate network policy for the
build stage, which gets no network of its own.

**When the runtime cannot provide gVisor, the evidence bundle says so.**
The bundle records the isolation the run *actually* had, not the one that
was requested: the OCI runtime the host used, read from the runtime
itself. A profile that claims more than it delivers would be worse than
one that admits the limit.

The request is also expressed in each runtime's own vocabulary. Docker
takes a runtime per container, so the hardened profile asks for
`--runtime runsc`. Podman does not: its runtime is the machine's
default and there is no flag to change it for one container, so the
request is not made there — asking for something the runtime cannot
select would make the run fail rather than harden it. The bundle then
records whichever runtime the machine used.

**Recommended for any project that runs the tool unattended.**

## Threats and mitigations

### 1. Prompt injection through report text

*Mitigation:* structured outputs only, no tool use, taint tracking, plan
validation against an allowlist, flagging of instruction-like text, and an
adversarial test suite. The adversarial suite is a release gate: zero
successful plan injections.

### 2. Malicious PoC or sandbox escape

*Mitigation:* layered isolation, no secrets, ephemeral runners, the
hardened profile, a conformance suite in CI, prompt patching of base
images, and plain documentation that no sandbox is perfect.

### 3. Archive attacks (zip bombs, path traversal)

*Mitigation:* size and entry limits, a compression-ratio check, and safe
extraction. The preflight analyzer refuses to extract an archive with a
traversing entry.

### 4. Resource exhaustion and floods

*Mitigation:* per-report budgets, per-source concurrency caps,
backpressure, and hard limits on time, memory, processes and output.

### 5. Supply-chain risk in builds

*Mitigation:* allowlisted mirrors, a vendored mode, pinned images, and the
build separated from the run. A build step that downloads and executes
code in one line is rejected by the validator.

### 6. Leakage of confidential reports

*Mitigation:* local-first operation, a no-LLM mode, redaction before
external calls, and retention limits. Nothing leaves the host unless a
provider is configured.

### 7. Evidence tampering

*Mitigation:* hashes in the manifest, read-only bundles, and
`verdis bundle verify`. Signing arrives in 1.x.

### 8. Dedupe poisoning

*Mitigation:* suggestions only, never automatic merges, and provenance on
every match. A match is a hint with reasons, and a human decides.

### 9. False reassurance

*Mitigation:* every verdict card states what it does not establish, and
ambiguity defaults to `INCONCLUSIVE`.

### 10. Forged observations

The oracles read what the sandboxed process prints and how it exits. A
proof of concept can therefore print text that looks like a sanitizer
report, a crash or the expected output without triggering the defect, and
an oracle that reads that text will fire.

*Mitigation today:* the card quotes the exact output that matched and
points at `run.log`, so a reviewer can read it. `--compare <fixed-ref>`
runs the same plan at the fix: a real defect disappears there, and a
forged print does not. Output-level matches are reported as Tier 2, which
says the behaviour was shown and the impact was not.

*Not mitigated yet:* observation from outside the process (sanitizer logs
written to a file the proof of concept cannot reach, tracing), and a
forged-output case in the benchmark. Treat `REPRODUCED` as strong
evidence to be read, not as proof, until a maintainer has looked at the
matched output.

### 11. Other local users (Linux)

The sandbox runs as an unprivileged user that is not the user who started
Verdis. On Linux a bind mount keeps the host's owner and mode, so Verdis
opens the copies it makes for a run (the source copy, the staged
attachments and the build directory) to that user. Each copy sits inside a
parent directory with mode 0700, so other local users can reach it only
through the parent, and the parent is removed when the run ends.

Files the sandbox itself creates belong to the sandbox user. If cleanup
cannot remove them, they stay in the work directory until it is cleared.

*Mitigation:* run Verdis on a machine or runner you control, and set
`VERDIS_WORK_DIR` to a directory only you can enter.

## Operator guidance

- Run the tool on a dedicated ephemeral runner that holds no other
  secrets.
- Keep the container runtime patched.
- Never expose its socket.
- Review recipes before first use.
- Start in shadow mode.

## The tool's own disclosure policy

Verdis ships its own `SECURITY.md` and an RRS-ready reporting
template, and runs the tool on its own inbox once it is stable.
