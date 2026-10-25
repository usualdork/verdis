# What this example shows

A report that looks exactly like the reproduced one, but which is run
against a build where the bug is fixed.

The verdict is `NOT_REPRODUCED`, and the card says so honestly:

```
Verdis verdict: NOT_REPRODUCED   report VDS-...   target libfoo@v2.3.1

Why:
     the PoC ran and no oracle fired
Evidence:
  1. the command ran 3 time(s) and exited with (0, 0, 0) without triggering
     any oracle
Suggested next action: reply with what was tried and invite the reporter to
confirm the steps; a human may still want to look at this
Not established: that the code is not vulnerable; only that this PoC, in
this environment, did not show the claimed behaviour.
```

The last line is the important one. `NOT_REPRODUCED` never means "not
vulnerable"; it means "this proof of concept, in this environment, did not
show the claimed behaviour". The draft reply says the same thing and
invites the reporter to say if their steps differed.
