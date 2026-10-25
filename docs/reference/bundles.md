# Evidence bundles

An evidence bundle is the currency of the tool. It is what lets a
maintainer check a verdict, re-run it, or hand it to somebody else.

## What is in it

```
bundle/
├── manifest.json          versions, hashes, the environment
├── original/
│   └── report.md          the report as it arrived, unmodified
├── claim.json             what the tool understood, with source spans
├── plan.json              the plan, in full
├── plan.txt               the plan, in the human-readable form
├── policy_matches.json    the clauses that matched, with citations
├── build.json             the build outcome
├── build.log              the build output
├── run.json               every run, with exit codes and timings
├── run.log                the combined output of the runs
├── oracles.json           what each oracle saw, and whether it matched
├── fs_changes.json        files the run created or changed
├── blocked_network.json   outbound attempts the sandbox refused
├── environment.json       image digests, kernel, tool versions
├── verdict.json           the verdict, machine-readable
├── verdict.md             the verdict card
├── draft_reply.md         a reply you can approve, edit or discard
└── rerun.sh               reproduces the run elsewhere
```

## The manifest

Every file in the bundle is listed in `manifest.json` with its SHA-256 and
its size. The manifest also records the tool version, the schema version,
the environment, and which model produced which part of the work.

## Verifying a bundle

```bash
verdis bundle verify bundles/VDS-0042/
```

Every file is re-hashed and compared with the manifest. A mismatch is
reported, and the exit code is 1.

This is the defence against evidence tampering: a bundle that verifies is
one whose contents have not changed since the tool wrote it.

## Re-running a bundle

```bash
cd bundles/VDS-0042/
./rerun.sh
```

The script re-runs the same plan against the same target and writes a
fresh bundle next to the original. It needs the same prerequisites the
original run needed: a container runtime, and the target repository at
the recorded ref.

`VERDIS_REPO` and `VERDIS_SANDBOX` override the defaults.

## What a bundle does not contain

- **No secrets.** The orchestrator's tokens never enter a sandbox, so
  they cannot end up in a log.
- **No exploit material.** The bundle holds the reporter's own proof of
  concept, which the reporter already has. The tool does not generate,
  improve or weaponise anything.
