# CLI reference

```
verdis triage <report> --repo <path|url> [--ref <rev>] [--policy <file>]
verdis preflight <poc-dir> --repo <path|url> --ref <rev>    # reporter mode
verdis inbox | show <id> | rerun <id> --ref <rev>
verdis recipe init | validate
verdis policy init | check
verdis bundle verify <path>
verdis doctor
```

## `verdis triage`

Triage one report and print a verdict card.

| Option | Meaning |
| --- | --- |
| `--repo` | the path or URL of the target repository. |
| `--ref` | the ref to build and run against. |
| `--policy` | a policy file to use instead of the repository's. |
| `--compare` | a comparison ref, such as the fixed branch. |
| `--store` | where the report store lives. |
| `--evidence` | where the evidence store lives. |
| `--sandbox` | `default`, `hardened`, `podman`, `docker` or `local`. |
| `--model-provider` | `none`, `openai`, `anthropic` or `ollama`. |
| `--confirm` | approve commands that need confirmation. |
| `--output` | `card`, `json` or `sarif`. |
| `--bundle-out` | copy the evidence bundle to this path. |

**Exit codes.** `0` for a definitive verdict (`REPRODUCED`,
`NOT_REPRODUCED`, `OUT_OF_SCOPE`, `DUPLICATE`), `1` otherwise, `2` for a
usage or configuration error, `3` for a sandbox error.

## `verdis preflight`

Check a proof of concept in a clean environment and produce an RRS block.
This is the reporter's mode.

| Option | Meaning |
| --- | --- |
| `--repo` | the target repository. |
| `--ref` | the ref to test against. |
| `--out` | write the RRS block to this file. |

Preflight prints what it observed. It never executes the attachment.

## `verdis inbox`

| Command | What it does |
| --- | --- |
| `inbox list` | list the reports in the local store. |
| `inbox show <id>` | show a stored report and its verdict. |
| `inbox rerun <id> --ref <rev>` | re-run a stored report against another ref. |

## `verdis recipe` and `verdis policy`

| Command | What it does |
| --- | --- |
| `recipe init` | write a starter `.verdis/recipe.yml`. |
| `recipe validate` | check that the recipe parses. |
| `policy init` | write a starter `.verdis/policy.yml`. |
| `policy check` | load the policy and show where it came from. |

## `verdis bundle verify <path>`

Re-hash every file in an evidence bundle and report the mismatches. A
bundle that verifies is one a maintainer can trust.

## `verdis doctor`

Check the sandbox backend, the images and the permissions. It tells you
which backend it found, whether it is rootless, and — if you selected the
development backend — that it is not a security boundary.
