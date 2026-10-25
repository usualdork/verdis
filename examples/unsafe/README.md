# What this example shows

A report with an attachment that preflight refuses to run.

The attachment is inspected statically — never executed — and the
observations are stated as behaviour, not as a judgement about the
reporter:

```
Verdis verdict: UNSAFE_ATTACHMENT   report VDS-...   target libfoo@v2.3.1

Why:
     attachment preflight blocked execution: run.sh: script-credential-access:
     script reads credential paths or secret-looking environment variables;
     run.sh: script-network-call: script makes network calls
```

The draft reply is careful:

> We could not run the attached file, so we have not been able to try the
> report yet. Our static checks observed the following in the attachment: …
> This is a safety check on our side, not a judgement about you.

Nothing here says the reporter is an attacker. The tool states what it
observed and asks for the same information in a form it can run.

A maintainer can still override the block with a logged decision; the
quarantine is a speed bump, not a wall.
