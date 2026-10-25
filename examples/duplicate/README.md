# What this example shows

The same report, triaged twice.

The second time, the dedupe index finds the first report: the same
vulnerability class and component, nearly the same text, and the same
sanitizer stack signature.

```
Verdis verdict: DUPLICATE   report VDS-...   target libfoo@v2.3.1

Why:
     this report matches VDS-... with similarity 0.97 (same crash or sanitizer
     stack signature; same vulnerability class and component)
Duplicates: closest: VDS-..., similarity 0.97 (same crash or sanitizer stack
signature). Matches are suggestions, not decisions.
Suggested next action: check the linked report before spending more time on
this one; the match is a suggestion, not a decision
Not established: that the two reports describe the same issue; a human
decides.
```

Two properties are load-bearing here:

* **the tool never merges anything.** A duplicate is a suggestion with
  reasons, and a human decides. Dedupe poisoning is a real attack, and
  this is the defence.
* **the evidence is still there.** The bundle of the second run contains
  the full reproduction, so the maintainer can check for themselves.
