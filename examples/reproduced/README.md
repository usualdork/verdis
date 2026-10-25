# What this example shows

A report whose proof of concept really does trigger the bug it claims.

Running it against the fixture project in `tests/conftest.py`:

```bash
verdis triage examples/reproduced/report.md --repo <libfoo> --ref v2.3.1
```

produces:

```
Verdis verdict: REPRODUCED (Tier 1)   report VDS-...   target libfoo@v2.3.1

Why:
     the sanitizer oracle fired and matched the claim; the claimed impact
     (memory corruption) was demonstrated
Evidence:
  1. run 1: AddressSanitizer reported a diagnostic
  2. run 1: sanitizer class heap-buffer-overflow
  3. run 1: frame #1 parse_header (src/hdr.c:212)
Policy: ...
Duplicates: none above threshold.
Suggested next action: confirm the severity and decide on a fix
Bundle: .../bundle/  (run ./rerun.sh to reproduce)
Not established: exploitability beyond what the evidence shows; behaviour on
configurations other than the one tested.
```

Two things are worth noticing:

* the verdict is **Tier 1** because the claimed impact (memory corruption)
  is exactly what the oracle demonstrated. Had the report claimed remote
  code execution, the same run would have been **Tier 2**: the behaviour
  was demonstrated, the claimed impact was not.
* the card says what the verdict does **not** establish. A reproduction is
  not a severity assessment.
