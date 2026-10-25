# Security Policy

## Reporting a vulnerability in Verdis

**Do not open a public issue.** Use GitHub's private vulnerability
reporting: open the repository's Security tab and choose *Report a
vulnerability*.

Please include:

- what the vulnerability lets an attacker do;
- the steps to reproduce it, ideally as an RRS block or a script;
- the version or commit you tested.

We aim to acknowledge a report within three working days and to ship a
fix or a mitigation within fourteen days for a confirmed issue that
affects the sandbox boundary. Issues in the *judge* (a wrong verdict) are
serious but not sandbox escapes, and are triaged in the same queue.

## What counts as a serious vulnerability here

Verdis runs attacker-controlled input by design, so the interesting
failures are the ones that break that boundary:

- a proof of concept that escapes the sandbox;
- a proof of concept that reaches the network during the run stage;
- a proof of concept that reads a secret, an environment variable or a
  file outside the workdir;
- a report that makes the tool run a command it should have refused;
- a report that makes the tool mark a verdict the evidence does not
  support, in a way that hides a real vulnerability.

## The tool's own policy

Verdis is a triage helper, and its own reports follow the same rules
it enforces elsewhere:

- a working proof of concept is required;
- the default configuration must be affected;
- reports against the *sandbox boundary* are in scope;
- reports about verdict accuracy are in scope;
- issues in the documentation, the wording of replies and the ergonomics
  of the CLI are out of scope until v1.0.

## What we will not do

We will not ask you to demonstrate exploitation beyond what is needed to
show the boundary is broken, and we will not ask you to run an exploit
against a third party.

## The tool on its own inbox

Once the tool is stable, Verdis runs on its own reports, in shadow
mode. A verdict is never a decision, and a human still decides.
