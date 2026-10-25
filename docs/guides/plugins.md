# Writing a plugin

Verdis has a small core and plugins at the edges. Everything that
varies between projects, platforms or runtimes is a plugin.

## The extension points

| Entry point group | The interface | What you write |
| --- | --- | --- |
| `verdis.intake` | `IntakeAdapter` | a new source of reports |
| `verdis.llm` | `LLMProvider` | a new model provider |
| `verdis.sandbox` | `SandboxBackend` | a new isolation backend |
| `verdis.oracle` | `Oracle` | a new way to observe a run |
| `verdis.emitter` | a callable | a new output format |
| `verdis.preflight` | a callable | a new attachment analysis |

## An example

```python
from verdis.schemas.preflight import PreflightFinding, RiskLevel


class MyAnalyzer:
    name = "my-analyzer"

    def inspect(self, path):
        if b"MY_MAGIC" not in path.read_bytes():
            return []
        return [
            PreflightFinding(
                code="my-magic",
                severity=RiskLevel.MEDIUM,
                message="the file carries MY_MAGIC",
                weight=20,
            )
        ]
```

And register it:

```toml
[project.entry-points."verdis.preflight"]
mine = "mypackage:MyAnalyzer"
```

## The REA plugin

The first-party plugin is [REA](https://github.com/hermes-agent/rea), which
inspects a native binary, an Android package or an Electron app and
reports what it found. It lives in `plugins/rea_preflight/`.

REA is **not** a sandbox: it runs the code it inspects. The plugin
therefore refuses to run unless it is told it is inside the sandbox
(`VERDIS_SANDBOXED=1`), and the preflight only hands it a file that
has already been quarantined. Point the tool at it by path:

```yaml
preflight:
  threshold: 45
  rea_plugin: plugins/rea_preflight/reapreflight.py
```

The path is relative to the repository being triaged, so a project can
ship the setting in its own `.verdis/config.yml`. A file passed with
`--config` works too. The plugin is optional: when it is not configured,
or when it cannot run, the built-in analysis stands on its own and the
triage carries on.

The plugin's findings join the built-in analysis for ELF, PE and Mach-O
files. A finding it reports can push the attachment over the quarantine
threshold, which is the point: a binary that a reverse engineer can see
inside is a binary the tool will not run on the host.

## The rules a plugin must follow

1. **A plugin never decides a verdict.** It reports what it observed.
   The judge turns observations into verdicts.
2. **A plugin never executes untrusted code on the host.** If it needs to
   run anything, it runs inside the sandbox.
3. **A plugin is deterministic.** The same input gives the same output.
   A model may *propose*; it may not decide.
4. **A plugin ships with a conformance test kit**, so a third party can
   extend Verdis without patching it.

## The sandbox backend contract

A backend must:

- run the command in an isolated environment;
- apply the profile's limits (time, memory, processes, disk, output size);
- kill the whole process group on a timeout;
- return the exit code, the output, whether it timed out, and what the
  sandbox observed (blocked network attempts, canary hits, filesystem
  changes);
- never pass the orchestrator's environment into the sandbox.

The conformance suite in `tests/conformance/` checks exactly these, and
runs against every registered backend.
