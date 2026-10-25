# What this example shows

A small, real project and a report about it. It is the project the
README's recording is made from, so the recording is a run and not a
picture of a run.

The program is a file reader that serves one directory. The name in the
request is joined to that directory without checking that the result
stays inside it, so a name that climbs out reaches the files beside it
(CWE-22).

```bash
verdis triage examples/demo/report.md --repo examples/demo/target
```

produces:

```
Verdis verdict: REPRODUCED (Tier 2)   report VDS-...

Why:
     the output oracle fired and matched the claim; the behaviour was
     demonstrated (output-level behaviour) but the claimed impact (file
     read) was not proven

Evidence:
  1. run 1: output matched 'VERDIS_SECRET_9f3a' [run.log]
  2. run 1: VERDIS_SECRET_9f3a [run.log]
```

The tier is 2, not 1, and the reason is worth reading. The report's
expected output appeared, which is the behaviour it describes. The
*impact* it claims — that a file is disclosed — was not separately
proven, so the tool does not say it was. A report that stated the
observable more precisely would earn the higher tier.

To make the recording again:

```bash
python tools/recording.py --out docs/assets/verdis-demo.svg
```
