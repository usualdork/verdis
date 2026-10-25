# JSON schemas

Verdis publishes a JSON schema for every object in its data model, so
that other tools can consume a verdict without scraping text.

| Schema | The object |
| --- | --- |
| `report.schema.json` | a normalized report |
| `claim.schema.json` | an extracted claim |
| `plan.schema.json` | a reproduction plan |
| `policy.schema.json` | a project's policy |
| `build.schema.json` | a build result |
| `run.schema.json` | a run result |
| `oracle-result.schema.json` | one oracle's result |
| `verdict.schema.json` | the verdict |
| `bundle-manifest.schema.json` | the bundle manifest |
| `rrs.schema.json` | a Reproducible Report Spec block |

## Using them

```python
import json
from pathlib import Path

from verdis.schemas.verdict import VerdictResult

payload = json.loads(Path("bundle/verdict.json").read_text())
verdict = VerdictResult.model_validate(payload)
```

The schemas are also on disk, in `schemas/`, and are regenerated from the
models:

```bash
python -m verdis.schemas.generate schemas/
```

A test checks that the committed schemas match the models, so a change to
a model without a schema change fails the build.

## Stability

The schemas are frozen at 1.0. Before 1.0 they may change; after it,
anything that would break a consumer is a major version bump.

## A note on the verdict

The verdict schema is the one most likely to be consumed by other tools.
The important fields:

| Field | Meaning |
| --- | --- |
| `verdict` | one of the seven verdicts. |
| `tier` | `tier1` or `tier2`, only for `REPRODUCED`. |
| `flags` | the secondary flags. |
| `why` | one paragraph on why. |
| `evidence` | the points behind the verdict. |
| `policy_matches` | the clauses that matched, with citations. |
| `dedupe_matches` | the duplicate candidates, with reasons. |
| `not_established` | what the verdict does **not** establish. |
| `next_action` | what a human should do next. |
