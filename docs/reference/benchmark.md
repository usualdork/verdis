# The benchmark

VerdisBench measures how often the tool gives the right answer, and how
often it gives the *wrong* one. It is the benchmark PRD section 13.1
asks for.

The full methodology, the corpus layout and the results are in
`benchmark/README.md` in the repository. This page is the short version:
what the numbers are, and what they do and do not mean.

## Running it

```bash
make corpus          # build the case tree from the catalogue
make corpus-check    # check every program behaves as the corpus claims
make benchmark       # run it on the host
make benchmark-sandbox  # run it inside a container
```

## The corpus

673 cases in 25 clusters. Every case is a report, a target program, and
a statement of what the case expects.

| Tier | Cases | What it is |
|---|---|---|
| positive | 45 | the defect is real and the report is clear |
| style | 40 | the same defect, vague or machine-padded |
| negative | 539 | a claim that does not hold |
| adversarial | 41 | reports that try to make the tool lie |
| messy | 3 | flaky, timing-dependent, environment-sensitive |
| policy | 4 | the verdict comes from the policy, not the code |
| limitation | 1 | a real defect the oracles cannot see |

The target programs are written in four languages: C, Python, Node and Go.
Each one is built and run in the same sandbox, with the same recipes and
the same oracles.

Three of the positives are **upstream**: real projects at a real
vulnerable commit, with the proof of concept the fix brought with it.

| Case | Project | The defect |
|---|---|---|
| `libxml2-cve-2016-1834` | libxml2 2.9.3 | a heap overread in the tag parser |
| `libarchive-cve-2020-36148` | libarchive 3.4.0 | an out-of-bounds read in the RAR5 ARM filter |
| `libarchive-cve-2020-36149` | libarchive 3.4.0 | an out-of-bounds write in the RAR5 reader |

A case is admitted only when its proof of concept **discriminates**:
it has to fail the vulnerable build and not the fixed one. The
vulnerable build is the parent of the fix commit, not the release
before it.

Every target program is checked in a real container before any case is
written from it: the vulnerable build must fail on the proof of
concept, the fixed build must not, the benign input must not, and the
signature the report names must be in the output the program really
produces. A program that fails any of those is a broken case, and the
corpus builder refuses to emit it.

## The numbers

From a run in a rootless Podman sandbox: 672 of the 673 cases ran (the flaky
case needs the host backend) and every tier landed at 100%, with a
false-REPRODUCED rate of 0 of 539, a median time to verdict of 8.63 s, and
0.03 s with a warm build cache.

## The confidence intervals

A rate on its own says very little, so every rate comes with three
bounds, and they disagree.

| Bound | Value | What it assumes |
|---|---|---|
| Wilson, over cases | 0% – 0.71% | every case is independent |
| Rule of three, over cases | 0.56% | every case is independent |
| **Rule of three, over clusters** | **12.0%** | the *program* is the unit |
| Clustered bootstrap | 0% – 0% | resamples the programs |

The 539 negatives come from **25 targets**, and the cases from one
program share a defect, a build and a shape. Sixty-four of them are
the same program with a length prefix one byte apart. **The honest
bound is 12.0%**, not 0.71%.

The clustered bootstrap is reported because it is the right method, and
it degenerates to 0..0 when there are no events: every resample of the
clusters gives zero. A bootstrap that says "certainly zero" when the
count is zero is a misleading interval, and the rule of three is the
one to quote. The results carry both, and the runner says so in words
as well as numbers.

## The acceptance thresholds

The thresholds of PRD section 13.3 are checked mechanically: the run
fails when one is not met.

| Threshold | Measured |
|---|---|
| False-REPRODUCED rate of 1% or less on the negatives | 0% (0 of 539) |
| A definitive verdict on at least 85% of the positives with a recipe | 100% (25) |
| A definitive verdict on at least 60% of the positives without one | 100% (20) |
| Zero sandbox-conformance failures | 0 |
| Zero successful plan injections in the adversarial suite | 0 |
| Median time to verdict of 10 minutes or less | 8.63 s |
| Median time to verdict of 3 minutes or less with a warm cache | 0.03 s |

The first row is a **regression gate, not a claim of compliance**: the
corpus is not yet large enough to bound the rate at 1%, and the
interval above says what the bound actually is.

All seven rows are measured. The conformance row is checked against the
conformance suite's own report: the suite writes down its failures and
the benchmark reads that file. The warm-cache row is measured by
running the corpus a second time with a shared build cache, which is
where the 0.03 s comes from: with the build cached, the median time to
a verdict is the run itself.

## The adversarial suite

Forty-one cases, and every one has a **twin**: the same report without
the attack. The twins are compared two ways — the instruction cases
must not move the verdict *or* the run, and the sandbox probes and plan
injections must never turn a negative into a positive.

The point is that "the verdict is not REPRODUCED" is a weak
requirement: a tool that says INCONCLUSIVE for everything would pass
it. "The verdict is the same as the clean report's" is the check that
catches an attack.

## What it found

The corpus was built to measure the tool, and it found nine real
defects. Each is now a regression test:

1. A report about a function the target does not have was called
   reproduced.
2. An unsupported version was not out of scope.
3. A report's `**Component**:` field was ignored.
4. The sanitizer's class list was missing classes the sanitizer prints.
5. A crash with no stack was called not-reproduced — a false
   *negative*, which for a security tool is worse than a false
   positive.
6. The container rewrote a filename to a staged file that was never
   staged.
7. The recipe's run environment was ignored.
8. A path under the work directory that escaped it with `..` was
   allowed.
9. A shell could run a command string.

## What it does not have

* **Three upstream CVEs, not forty.** The upstream pipeline exists and
  works — it finds the fix commit, builds both sides in the sandbox, and
  checks that a proof of concept discriminates — and it has admitted
  three cases across two projects. The rest are reductions.
* **The model path is never exercised**, and the model-written
  negatives are template-written.
* **Not enough independent clusters to claim the 1% threshold.**
* The queue, the rate limit and the budget are exercised by the unit
  tests, not here.
