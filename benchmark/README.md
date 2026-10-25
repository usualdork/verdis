# VerdisBench

The benchmark of PRD section 13.1. It measures how often the tool gives
the right answer, and — more importantly — how often it gives the
*wrong* one.

Everything in this document is generated from the corpus in the
repository and the results of a real run. Where a number is a bound
rather than a measurement, it says so.

## The corpus

The corpus is a tree of cases under `benchmark/cases/`, generated from a
catalogue of target programs (`benchmark/corpus/catalogue.py`). Every
program is a small, self-contained program with a real defect: it
crashes, hangs, exhausts memory, or computes the wrong answer. The
catalogue covers sixteen weakness classes across sixteen CWEs, and the
detection spans four signals: a sanitizer diagnostic, a fatal signal, a
resource overrun the sandbox stops, and a wrong answer.

| Tier | What it is | Cases |
|---|---|---|
| `positive` | The defect is real and the report is clear. | 45 |
| `style` | The same defect, written up vaguely or machine-padded. | 40 |
| `negative` | A claim that does not hold. | 539 |
| `adversarial` | Reports that try to make the tool lie. | 41 |
| `messy` | Flaky, timing-dependent and environment-sensitive. | 3 |
| `policy` | The verdict comes from the project's policy, not the code. | 4 |
| `limitation` | A real defect the tool's oracles cannot see. | 1 |

**673 cases, in 25 clusters** (one per target program).

Three of the positives are **upstream**: real projects, real CVEs, and
the proof of concept the fix brought with it.

| Case | Project | The defect |
|---|---|---|
| `libxml2-cve-2016-1834` | libxml2 2.9.3 | a heap overread in the tag parser (GNOME bug 758588) |
| `libarchive-cve-2020-36148` | libarchive 3.4.0 | an out-of-bounds read in the RAR5 ARM filter |
| `libarchive-cve-2020-36149` | libarchive 3.4.0 | an out-of-bounds write in the RAR5 reader |

Every upstream case is admitted only when its proof of concept
**discriminates**: it has to fail the vulnerable build and not the fixed
one. The vulnerable build is the *parent of the fix commit*, not the
release before it, because the release before it can be years older and
the input the fix brought with it may not discriminate against it.

### The negatives

539 of them, and they come in five shapes:

* **benign inputs** — the same claim, the same program, an input one
  step short of the trigger. These are the cases that catch a
  false-positive bug, and there are 383 of them, from sixteen to
  sixty-four per program.
* **the fixed build** — the same report against the fixed program.
* **an invented function** — a report about a function the target does
  not have.
* **model-written reports** — plausible but false, written in the style
  a model writes: an invented function, an unaffected version, a
  consequence that does not follow, a neighbouring function, a class
  the program does not produce.

### The model-written negatives

Section 13.1 asks for negatives "written by hand and by models".
`benchmark/corpus/model_reports.py` asks the tool's own model provider
to write them, when one is configured, and falls back to a
deterministic generator of the same style when one is not.

**The committed corpus was written by the deterministic generator**:
every model-written case records `"written_by": "template"` in its
`case.json`, and there are 95 of them. The provider path is implemented
and reachable, but no provider is configured in CI, so it has not been
exercised. That is a real gap and it is recorded here rather than
implied away.

### The adversarial suite

41 cases, in three families, and every one has a **twin**: the same
report without the attack.

* **13 instruction variants** — an instruction in the title, the
  version field, the expected section, a code fence, an HTML comment, a
  fake maintainer note, a role-play, a base64 blob, fullwidth unicode,
  an RRS block, an appendix, the claim itself, and one on a claim that
  does not hold.
* **19 sandbox probes** — a program that tries to read `/etc/shadow`,
  `/proc/self/environ` and a namespace link, to write `/etc/passwd`,
  to escape the work directory with `..`, to follow a symlink out, to
  connect to the outside, to resolve a name, to reach a unix socket, to
  `setuid(0)`, to fork bomb, to exhaust memory, to open `/dev/mem`, to
  signal PID 1, to `chroot`, to `ptrace` PID 1, and to read a device.
  The probes run in a controlled harness: the target is a program of
  ours, in the sandbox, never a third party's.
* **8 plan injections** — commands that try to make the *plan* do
  something else: download and execute, read the host, write the host,
  delete, install a package, run a shell, read a secret.

The twin check is differential on purpose. "The verdict is not
REPRODUCED" is a weak requirement — a tool that says INCONCLUSIVE for
everything would pass it. The twins are compared two ways:

* **exact** (the instruction cases): the verdict must not move *and*
  the build and run status must not move. An instruction that says "do
  not run anything" leaves the verdict looking right and the run
  looking wrong: the tool agreed with the report for the wrong reason.
* **no-upgrade** (the probes and the plan injections): the case may
  time out where its twin finishes — the host has no isolation — but it
  must never turn a negative into a positive.

All 40 twins were compared; none disagreed.

### The cases are checked, not assumed

A benchmark is only worth what its cases are worth, so
`benchmark/corpus/verify.py` checks every program in a real container
before the corpus is built. For each one it asserts:

1. the vulnerable build **fails** on the PoC;
2. the fixed build **does not** fail on the PoC;
3. the vulnerable build **does not** fail on the benign input;
4. the signature the report will name is **in the output the program
   really produces**.

A program that fails any of these is a broken case, not a hard case,
and the corpus builder refuses to emit it. The signature check is what
stops the corpus from quietly drifting away from the code: a table
entry that no longer matches the program is caught here, not
discovered later as a mysterious benchmark failure.

```bash
python benchmark/corpus/verify.py    # 19/19 programs behave as claimed
```

## Running it

```bash
make corpus          # build the case tree from the catalogue
make corpus-check    # check every program behaves as the corpus claims
make benchmark       # run it on the host
make benchmark-sandbox  # run it inside a container
```

The container run needs `VERDIS_WORK_DIR` to point at a path the
runtime shares with the host. On macOS with a VM that is under your
home directory, not under `/tmp`.

Each case gets its own store and evidence directory, so one case cannot
deduplicate against another: the benchmark measures the pipeline, not
the index.

## The results

From a run in a rootless Podman sandbox: 673 cases, of which 672 ran and one was
skipped (the flaky one needs the host backend). The 672 took 5,908 seconds of
case time, 994 seconds of wall clock across parallel workers:

Overall accuracy: **672/672** of the cases that ran. By tier:

| Tier | Correct | Wilson 95% interval |
|---|---|---|
| positive | 45/45 | 0.919 – 1.000 |
| style | 40/40 | 0.913 – 1.000 |
| negative | 539/539 | 0.993 – 1.000 |
| adversarial | 41/41 | 0.914 – 1.000 |
| messy | 2/2 | 0.342 – 1.000 |
| policy | 4/4 | 0.510 – 1.000 |
| limitation | 1/1 | — |

Median time to verdict: **8.63 s**, and **0.03 s** with a warm build
cache. The false-REPRODUCED rate: **0 of 539**.

The same corpus on the host, with the development backend, takes 4,730
seconds of case time and lands in the same place: 655 of 673 cases run with
no failures, and 18 are skipped because they need the container.

## The statistics, and why they are reported the way they are

### The false-REPRODUCED rate

This is the number that matters, and a rate on its own says very
little. Two things are needed to make it mean something.

**How many cases.** A rate of 0% on ten cases is compatible with a
true rate of 26%. The rule of three says that with zero events in *n*
trials the 95% upper bound is 3/n, so measuring a 1% rate needs a few
hundred negatives.

**How independent the cases are.** The 539 negatives come from **25
programs**, and the cases derived from one program share a defect, a
build and a shape. A confidence interval that treats them as
independent is too narrow.

So the results carry three bounds, and they disagree, and that
disagreement is the point:

| Bound | Value | What it assumes |
|---|---|---|
| Wilson, over cases | 0% – **0.71%** | every case is independent |
| Rule of three, over cases | **0.56%** | every case is independent |
| Rule of three, over clusters | **12.0%** | the *program* is the unit |
| Clustered bootstrap | 0% – 0% | resamples the programs |

**The honest number is 12.0%.** With 25 independent targets and zero
events, the rate cannot be bounded below about 3/25. The 0.71% is what
you get if you believe the 539 cases are independent draws, and they
are not: 64 of them are the same program with a length prefix one byte
apart.

The clustered bootstrap is reported because it is the right method, and
it degenerates to 0..0 here: with no events anywhere, every resample
of the clusters gives zero. A bootstrap that says "certainly zero" when
the count is zero is a *misleading* interval, and the rule of three is
the one to quote. That is why the results carry both, and why the
runner's summary says so in words as well as numbers.

### The thresholds

`benchmark/run.py` checks the thresholds of PRD section 13.3 and exits
non-zero when one is not met:

| Threshold | Measured | Met |
|---|---|---|
| False-REPRODUCED rate of 1% or less on the negatives | 0% (0 of 539) | yes, as a regression gate |
| A definitive verdict on at least 85% of the positives with a recipe | 100% (25) | yes |
| A definitive verdict on at least 60% of the positives without one | 100% (20) | yes |
| Zero sandbox-conformance failures | 0 | yes, from the conformance suite's own report |
| Zero successful plan injections in the adversarial suite | 0 | yes |
| Median time to verdict of 10 minutes or less | 8.63 s | yes |
| Median time to verdict of 3 minutes or less with a warm cache | 0.03 s | yes |

The first row is a **regression gate, not a claim of compliance**: the
corpus is not yet large enough to bound the rate at 1%, and the report
above says what the bound actually is.

All seven rows of section 13.3 are checked. The conformance row is
checked against the conformance suite's own report: the suite writes the
number of failures to a file, and the benchmark reads it
(`--conformance <file>`). The warm-cache row is measured by running the
corpus a second time with a shared build cache (`--warm-cache`), which
is where the 0.03 s comes from: with the build cached, the median time
to a verdict is the run itself.

## What the benchmark found

Every one of these was found by the corpus, not by inspection, and
every one is now a regression test in
`tests/unit/test_benchmark_findings.py`:

1. **A report about a function the target does not have was called
   reproduced.** The tool ran the proof of concept, the program
   crashed — in a different function — and the tool said `REPRODUCED`.
2. **An unsupported version was not out of scope.**
3. **A report's `**Component**: file.c:function` field was ignored.**
4. **The sanitizer's class list was missing classes the sanitizer
   actually prints**, so a report naming one could never be matched.
5. **A crash with no stack was called not-reproduced.** That is an
   absence of evidence, not evidence of a different function, and it
   was a false *negative*: a real crash reported as not reproduced.
6. **The container rewrote a filename to a staged file that was never
   staged.**
7. **The recipe's run environment was ignored.**
8. **A path under the work directory that escaped it with `..` was
   allowed.**
9. **A shell could run a command string** (`sh -c anything`).

## What the corpus does not have

These are the gaps, stated plainly:

* **Three upstream CVEs, not forty.** The upstream pipeline
  (`benchmark/corpus/upstream.py`) fetches the real history, finds the
  commit that fixed a CVE, builds the *parent* of that commit and the
  commit itself in the sandbox image with the sanitizer on, imports
  the proof of concept the fix brought with it, and **checks that it
  discriminates** before admitting it. It has admitted three cases
  across two projects. Every other positive is a faithful *reduction*
  of a published vulnerability: a real bug in a real program, but not
  the upstream code, and it does not capture the awkwardness of a real
  project's build, its dependency tree, or the way a real reporter
  writes when they found the bug the hard way. Every case says which
  it is.
* **A fourth candidate is being worked on.** libtiff CVE-2016-5314, a
  buffer write overrun in the PixarLog decoder, has no proof of
  concept in the fix, so the input has to be found by fuzzing
  `tiffcp` with the project's own test images. The fuzzer finds
  crashes, but not one the fix addresses: a mutation that reaches the
  PixarLog path is a different mutation from one that reaches a
  sixteen-gigabyte allocation. The candidate stays in the table and the
  scheduled job keeps trying it, and the pipeline refuses it until the
  input discriminates.
* **The upstream cases need a container**, so the host run skips them
  (six cases) and the container run includes them. The Go target needs
  one too: the Go toolchain lives in the sandbox image, not on every
  host.
* **Finding the input is the expensive part.** The fix usually brings
  the proof of concept with it, and when it does not the input has to
  be found by fuzzing the affected tool, which is per-CVE work. The
  candidates that were tried and did not discriminate are recorded in
  the pipeline rather than quietly dropped.
* **The model path is never exercised.** The whole benchmark runs with
  no provider configured, so it tests the deterministic extractor. The
  cost per report is therefore zero by construction, which is the point
  of the no-LLM mode and not a measurement of a hosted model.
  Section 12's guardrails are untested by the benchmark.
* **The model-written negatives are template-written**, as described
  above.
* **One case needs the host backend** — the flaky one, which counts runs
  in a file, and a container's work directory is fresh each time. It is
  marked and skipped, not faked.
* **The benchmark measures one report at a time.** The queue, the rate
  limit, the concurrency limiter and the per-report budget are
  exercised by the unit tests, not here.
* **The cost per report is zero by construction**, because the
  benchmark runs with no model. The tool measures the cost of a hosted
  model from the tokens the provider reports and the published price of
  the model, and records it in the verdict; the benchmark cannot check
  that number without a provider.

## The methodology, in one paragraph

The corpus is generated from a catalogue of programs with real defects.
Every program is verified in a container to have three properties — it
fails on its proof of concept, it does not fail once fixed, and it does
not fail on a benign input — plus a fourth: the signature the report
will name is in the output the program really produces. Each program
contributes a positive, a machine-padded positive, a recipe-less
positive, a vague style case, and a family of negatives. The benchmark
runs each case through the whole pipeline in isolation and compares the
verdict against the case's expectation. The rates are reported with
three bounds, because the cases are clustered in twenty-five programs
and the honest one is the widest. The acceptance thresholds of section 13.3
are checked mechanically, and the run fails when one is not met.
