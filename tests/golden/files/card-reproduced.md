Verdis verdict: REPRODUCED (Tier 1)   report VDS-0042   target libfoo@v2.3.1

Why:
     The submitted PoC triggers a heap-buffer-overflow in parse_header().

Evidence:
  1. ASan reports heap-buffer-overflow, frame #1 parse_header
  2. The same PoC is clean on v2.3.2 (FIXED_AT_HEAD)
  3. No network attempts; no writes outside /work

Policy: no policy was matched (no policy file or documentation was found).

Duplicates: none above threshold.

Flags: FIXED_AT_HEAD

Suggested next action: confirm severity; consider a coordinated release

Bundle: bundles/VDS-0042/  (run ./rerun.sh to reproduce)

Not established: exploitability beyond a crash.
