# Quickstart

Ten minutes, one project, a real verdict.

The ten minutes are the time to *install* the tool and see it reach a
verdict on a report you already have. Reading the evidence afterwards
takes as long as you like.

## 1. Install

```bash
pipx install "verdis @ git+https://github.com/usualdork/verdis"
verdis doctor
```

`doctor` checks the sandbox backend, the images and the permissions.

Verdis runs proofs of concept inside a sandbox, so it needs Podman or
Docker. If neither is available it **refuses to run** rather than falling
back to the host: a proof of concept is attacker-controlled code, and the
development backend (`--sandbox local`) is not a security boundary. Ask
for it by name, and only on a machine you are willing to risk.

If your container runtime is a VM or a remote daemon, set a work
directory it can see:

```bash
export VERDIS_WORK_DIR=~/.cache/verdis
```

## 2. Triage one report

```bash
verdis triage report.md --repo ./libfoo --ref v2.3.1
```

You get a verdict card:

```
Verdis verdict: REPRODUCED (Tier 1)   report VDS-0042   target libfoo@v2.3.1
...
```

The exit code is 0 for a definitive verdict and 1 otherwise, so the
command drops into a CI job cleanly.

## 3. Read the evidence

Every verdict ships with a bundle:

```
~/.local/share/verdis/reports/VDS-0042/bundle/
├── manifest.json      versions, hashes, the environment
├── original/          the report as it arrived
├── claim.json         what the tool understood
├── plan.json          what it intended to run
├── policy_matches.json
├── build.log
├── run.log
├── oracles.json
├── verdict.json
├── verdict.md
├── draft_reply.md
└── rerun.sh
```

`rerun.sh` reproduces the run on another machine.

## 3a. If your runtime is a VM or a remote daemon

Set a work directory it can see:

```bash
export VERDIS_WORK_DIR=~/.cache/verdis
```

The tool copies the target source and stages the proof of concept in a
scratch directory before it runs anything, and the container runtime has to
be able to see those paths. On Linux the system temporary directory
always works. On macOS with a Docker VM, the shared path is the one under
your home directory.

## 4. Tell the tool about your project

Two optional files make the tool much more useful.

`.verdis/policy.yml` — your own scope and evidence rules:

```yaml
supported_versions: ['2.x']
in_scope: [parser, network-client]
excluded_classes:
  - id: local-dos-cli
    description: Denial of service from unbounded local CLI input
evidence_requirements:
  poc_required: true
  default_config_only: true
```

`.verdis/recipe.yml` — how to build your project:

```yaml
language: c
build:
  system: cmake
  flags: [asan, ubsan]
  steps:
    - cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
    - cmake --build build -j
```

Both have starter templates:

```bash
verdis policy init
verdis recipe init
verdis policy check
verdis recipe validate
```

## 5. Start in shadow mode

Before you trust a verdict, run the tool for a month and look at what it
says without acting on it:

```yaml
# .verdis/config.yml
mode: shadow
```

Shadow mode writes verdicts and evidence bundles and posts nothing.

## 6. The GitHub Action

```yaml
- uses: usualdork/verdis@v1
  with:
    mode: shadow
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## 7. If you are a reporter

```bash
verdis preflight ./poc --repo https://github.com/example/libfoo --ref v2.3.1
```

This checks your PoC in a clean environment and gives you an RRS block you
can paste into your report, so the maintainer can reproduce it without
guessing.
