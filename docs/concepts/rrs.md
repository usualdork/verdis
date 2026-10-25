# The Reproducible Report Spec

RRS is a small YAML block a reporter can include in their report. When it
is present, the report is triaged **without a model** and deduplicated
reliably.

It is deliberately small. The long-term aim is to propose it to the
OpenSSF Vulnerability Disclosures Working Group.

## The block

```yaml
rrs: 0.1
target:
  repo: https://github.com/example/libfoo
  ref: v2.3.1
claim:
  class: CWE-122
  component: src/hdr.c:parse_header
  impact: memory corruption leading to crash
steps:
  - build: default
  - run: ./build/parse_demo poc.bin
inputs:
  - path: poc.bin
    sha256: 8f14e45fceea167a5a36dedd4bea2543...
expect:
  oracle: sanitizer
  signature: heap-buffer-overflow in parse_header
config:
  default: true
```

## The fields

| Field | Meaning |
| --- | --- |
| `rrs` | the spec version. Only `0.1` exists today. |
| `target.repo` | the repository the report is about. |
| `target.ref` | the version, tag or commit the report claims to affect. |
| `claim.class` | the vulnerability class, CWE-aligned. |
| `claim.component` | the component, as `file:function` or a free-form string. |
| `claim.impact` | the impact the reporter claims. |
| `steps` | ordered instructions, such as `build: default` and `run: …`. |
| `inputs` | the files the PoC needs, with their SHA-256 hashes. |
| `expect.oracle` | `crash`, `sanitizer`, `exception`, `canary`, `differential`, `property` or `output`. |
| `expect.signature` | the text or stack fragment to match. |
| `config.default` | whether the default configuration is affected. |

## Producing one

Reporters can run the tool against their own PoC:

```bash
verdis preflight ./poc --repo https://github.com/example/libfoo --ref v2.3.1
```

which prints an RRS block and, optionally, writes it to a file with
`--out`.

## What an RRS block does *not* do

It does not make a report safe. The steps in an RRS block are still
validated against the allowlist, and an RRS block that asks for the
network is rejected like any other plan.

The block is a *machine-readable claim*, not a permission slip.
