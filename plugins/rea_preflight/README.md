# The REA preflight plugin

An optional addition to Verdis's built-in attachment analysis. It uses
[REA](https://github.com/hermes-agent/rea) over MCP to look at native
binaries, Android packages and Electron apps.

## Safety

**REA is not a sandbox.** It runs the code it inspects in a controlled
environment, which means a hostile binary can misbehave while being
described.

The plugin therefore:

* runs **inside** the same sandbox as every other part of the tool, never
  on the host;
* only ever inspects a file that preflight has already scored — a file
  that is already quarantined;
* never executes the target as part of the reproduction run;
* is optional: the built-in static analysis (magic bytes, ELF imports,
  printable strings, packing markers) always runs, with or without it.

## Usage

```bash
python plugins/rea_preflight/reapreflight.py ./suspicious-binary
```

The output is a JSON list of findings in the same shape as the built-in
analyzers, so the two can be merged.

## Installing

```bash
pip install -e plugins/rea_preflight
```

and then register the plugin through the `verdis.preflight` entry point
group.
