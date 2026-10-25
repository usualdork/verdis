# What this example shows

A report that reproduces, but that the project's own policy excludes.

`.verdis/policy.yml`:

```yaml
excluded_classes:
  - id: local-dos-cli
    description: Denial of service from unbounded local CLI input
```

The verdict is `OUT_OF_SCOPE`, and the card cites the clause:

```
Verdis verdict: OUT_OF_SCOPE   report VDS-...   target libfoo@v2.3.1

Why:
     the claim reproduced but the project policy excludes it: Denial of
     service from unbounded local CLI input
Policy:
- policy.yml: Denial of service from unbounded local CLI input
```

The order matters: the tool still reproduces the behaviour first, so the
maintainer can see that it works. Only then is it marked out of scope. A
tool that refused to run out-of-scope reports would hide real findings,
and a tool that ran them without saying so would waste the maintainer's
time.
