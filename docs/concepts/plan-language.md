# The plan language

A plan is a small, typed sequence of steps. The vocabulary is deliberately
tiny, and the point of the tiny vocabulary is what it *cannot* express.

```yaml
checkout ref=v2.3.1
build recipe=cmake flags=asan,ubsan
copy artifact=poc.bin to=/work/poc.bin
run cmd='./build/parse_demo /work/poc.bin' timeout=30s repeat=3
expect oracle=sanitizer class=heap-buffer-overflow function=parse_header
compare ref=v2.3.2
```

## The steps

| Step | What it does |
| --- | --- |
| `checkout` | check out a ref of the target repository |
| `build` | build the target from a recipe |
| `copy` | copy a PoC artifact into the sandbox workdir |
| `run` | run the PoC command inside the sandbox |
| `expect` | declare what should be observed if the claim is true |
| `compare` | run the same plan against a comparison ref |

## What the language cannot express

There is no step for the network. There is no step for the host. There is
no step for a secret. A plan that wants one of those has to smuggle it
into a command, and the validator is there to stop that.

## The allowlist

Every plan is validated before it is stored or run. The validator has
three verdicts:

- **ALLOWED** — safe to run unattended.
- **NEEDS CONFIRMATION** — unusual but not forbidden: a run-time package
  install, a privilege change, a write outside the workdir. A human must
  approve; unattended runs fail closed.
- **FORBIDDEN** — never runnable.

### Forbidden in a run step

| Category | Examples |
| --- | --- |
| network | `curl`, `wget`, `nc`, `ssh`, `git clone`, any `http://` or `https://` |
| host | `mount`, `nsenter`, `chroot`, `docker`, `systemctl`, `sudo`, `kill` |
| secrets | `/etc/shadow`, `~/.ssh`, `~/.aws`, `/proc/self/environ`, `printenv`, `$AWS_SECRET_ACCESS_KEY` |
| shell | `;`, `&&`, `|`, backticks, `$(...)`, redirection |
| escape | `..` in a program path or a copy destination |

### Needing confirmation in a run step

`pip install`, `npm install`, `chmod`, `chown`, `rm`, `useradd`,
`crontab`, a write to a path outside the workdir.

## Why the language is so small

Every step the language does not have is a step the validator does not
have to understand. The sandbox does the enforcing; the language keeps
the number of things that can go wrong small enough to reason about.

The plan is stored in the evidence bundle, so a maintainer can read
exactly what was run.
