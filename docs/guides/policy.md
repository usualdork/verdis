# Writing a policy

A policy is the project's own statement of what it will act on. Verdis
reads it, cites it, and quotes it back to reporters.

## The file

`.verdis/policy.yml` in the root of the repository.

```yaml
supported_versions: ['2.x']
in_scope: [parser, network-client]
out_of_scope: [documentation-only]

excluded_classes:
  - id: needs-malicious-config
    description: Requires attacker-controlled configuration files
  - id: local-dos-cli
    description: Denial of service from unbounded local CLI input

evidence_requirements:
  poc_required: true
  default_config_only: true
  min_tested_version: '2.0'
  requires_steps: true

sla:
  first_response_days: 7

severity_rubric: docs/severity.md
```

## The fields

| Field | Meaning |
| --- | --- |
| `supported_versions` | the versions you still act on. Patterns: `2.x`, `2.3.1`, `>=2.0`, `<3.0`, `2.0-2.5`, `2.x \|\| 3.x`. |
| `in_scope` | the components you act on. |
| `out_of_scope` | components you do not act on. Shorthand for an exclusion. |
| `excluded_classes` | classes of report you do not act on, each with an `id` and a `description`. |
| `evidence_requirements` | what a report must contain. |
| `sla` | your response times. Shown to you, not to reporters. |
| `severity_rubric` | where your severity rubric lives. |

## How the tool matches a claim

- **Component.** A claim's component (function name, file, or both) is
  matched against `in_scope` and `out_of_scope`. Matching is generous:
  `parser` matches `parse_header`, and `network-client` matches
  `network_client`.
- **Version.** The claimed version is matched against
  `supported_versions`.
- **Exclusions.** An excluded class matches when the claim's impact,
  component or preconditions overlap with the exclusion's description, or
  when the exclusion names the component explicitly.

## What happens when a claim is out of scope

The tool **still reproduces it first**. A maintainer should see whether it
works, and then see that the project does not act on this class of
report. Only then is the verdict `OUT_OF_SCOPE`, with the clause cited.

## What happens when evidence is missing

`NEEDS_INFO`, with the policy clause quoted, and a short checklist in the
draft reply. The reply never accuses the reporter of anything.

## Deriving a policy from your documentation

If there is no `.verdis/policy.yml`, the tool reads `SECURITY.md` and
`THREAT_MODEL.md` and derives hints from the headings it recognises:
supported versions, in scope, out of scope, and requirements for reports.

Those hints are labelled **derived, unverified** until a maintainer
confirms them, and the tool says so in the warnings. Derivation is a
starting point, not a policy.

## A worked example

```yaml
supported_versions: ['2.x', '3.x']
in_scope:
  - parser
  - network-client
  - tls
excluded_classes:
  - id: needs-malicious-config
    description: Requires attacker-controlled configuration files
    components: [config-loader]
  - id: local-dos-cli
    description: Denial of service from unbounded local CLI input
evidence_requirements:
  poc_required: true
  default_config_only: true
  min_tested_version: '2.0'
sla:
  first_response_days: 7
  triage_days: 3
```

Check it before you rely on it:

```bash
verdis policy check
```
