"""The Verdis command line (PRD 9.1).

    verdis triage <report> --repo <path|url> [--ref <rev>] [--policy <file>]
    verdis preflight <poc-dir> --repo <path|url> --ref <rev>   # reporter mode
    verdis inbox | show <id> | rerun <id> --ref <rev>
    verdis recipe init | validate
    verdis policy init | check
    verdis bundle verify <path>
    verdis doctor
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from . import __version__
from .config import Config, ConfigError, load_config
from .emit.card import render_card
from .emit.json_verdict import render_json
from .emit.sarif import render_sarif
from .pipeline.orchestrator import Orchestrator, build_backend, build_provider
from .policy.loader import PolicyLoadError, load_policy
from .preflight.preflight import Preflight
from .sandbox.base import SandboxError
from .schemas.common import Verdict
from .storage.db import Store
from .storage.evidence import EvidenceStore

__all__ = ["app", "main"]

app = typer.Typer(
    name="verdis",
    help="Reproduce-first triage for security reports.",
    no_args_is_help=True,
    add_completion=False,
)
inbox_app = typer.Typer(help="Inspect the local report store.", no_args_is_help=True)
recipe_app = typer.Typer(help="Create and check build recipes.", no_args_is_help=True)
policy_app = typer.Typer(help="Create and check triage policies.", no_args_is_help=True)
bundle_app = typer.Typer(help="Inspect evidence bundles.", no_args_is_help=True)
app.add_typer(inbox_app, name="inbox")
app.add_typer(recipe_app, name="recipe")
app.add_typer(policy_app, name="policy")
app.add_typer(bundle_app, name="bundle")

# -- shared options -----------------------------------------------------


def _state(
    store_dir: str = "",
    evidence_dir: str = "",
    config_path: str = "",
    repo_path: str = "",
) -> tuple[Config, Store, EvidenceStore]:
    """Load the configuration and the two stores.

    The project's own ``.verdis/config.yml`` is honoured unless an
    explicit configuration file was given.
    """
    config = _load_config(config_path) if config_path else load_config(repo_path or None)
    store_path = store_dir or config.store_dir or ""
    evidence_path = evidence_dir or config.evidence_dir or ""
    store = Store(store_path) if store_path else Store(_default_store())
    evidence = (
        EvidenceStore(Path(evidence_path))
        if evidence_path
        else EvidenceStore(_default_evidence())
    )
    return config, store, evidence


def _default_store() -> Path:
    from .storage.db import default_store_path

    return default_store_path()


def _default_evidence() -> Path:
    from .storage.db import default_store_path

    return default_store_path() / "evidence"


def _load_config(path: str) -> Config:
    """Load a configuration file, reporting a broken one cleanly."""
    import yaml

    from .config import ConfigError, config_from_dict

    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    return config_from_dict(data)


def _missing_images(backend: Any) -> list[str]:
    """The images the tool needs that are not present."""
    missing = getattr(backend, "missing_images", None)
    if missing is None:
        return []
    from .build.builder import DEFAULT_IMAGE

    return list(missing((DEFAULT_IMAGE,)))


def _echo_json(payload: Any) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _write_preflight_bundle(
    directory: Path, block: str, findings: list[str], target: str
) -> None:
    """Write the reporter's evidence bundle.

    A reporter attaches this to their report so the maintainer can check
    the proof of concept without guessing.
    """
    from .schemas.common import now_utc, sha256_file

    bundle = Path(target)
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "rrs.yaml").write_text(block, encoding="utf-8")
    (bundle / "preflight.md").write_text(
        "# Preflight findings\n\n"
        + ("\n".join(f"- {finding}" for finding in findings) or "- nothing observed")
        + "\n",
        encoding="utf-8",
    )
    files = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        files.append({"path": path.name, "sha256": sha256_file(str(path))})
    (bundle / "inputs.json").write_text(
        json.dumps({"created": now_utc().isoformat(), "inputs": files}, indent=2),
        encoding="utf-8",
    )


# -- triage -------------------------------------------------------------


@app.command()
def triage(
    report: Annotated[
        str, typer.Argument(help="Path to the report file (Markdown or text).")
    ],
    repo: Annotated[
        str, typer.Option("--repo", help="Path or URL of the target repository.")
    ] = ".",
    ref: Annotated[str, typer.Option("--ref", help="The claimed ref to build.")] = "",
    policy: Annotated[
        str, typer.Option("--policy", help="Path to a policy file to use.")
    ] = "",
    comparison_ref: Annotated[
        str, typer.Option("--compare", help="A comparison ref, such as the fixed branch.")
    ] = "",
    config_path: Annotated[
        str, typer.Option("--config", help="A configuration file to use.")
    ] = "",
    store_dir: Annotated[str, typer.Option("--store", help="Where the report store lives.")] = "",
    evidence_dir: Annotated[
        str, typer.Option("--evidence", help="Where the evidence store lives.")
    ] = "",
    sandbox: Annotated[
        str, typer.Option("--sandbox", help="default | hardened | podman | docker | local")
    ] = "",
    model: Annotated[
        str, typer.Option("--model-provider", help="none | openai | anthropic | ollama")
    ] = "",
    confirm: Annotated[
        bool, typer.Option("--confirm", help="Approve commands that need confirmation.")
    ] = False,
    override_preflight: Annotated[
        str,
        typer.Option(
            "--override-preflight",
            help=(
                "Run an attachment the preflight quarantined. Give the reason: it "
                "is recorded in the evidence bundle."
            ),
        ),
    ] = "",
    output: Annotated[
        str, typer.Option("--output", help="card | json | sarif")
    ] = "card",
    bundle_out: Annotated[
        str, typer.Option("--bundle-out", help="Write the evidence bundle to this path.")
    ] = "",
) -> None:
    """Triage one report and print a verdict card."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    try:
        config, store, evidence = _state(store_dir, evidence_dir, config_path, repo)
    except (ConfigError, OSError) as exc:
        typer.secho(f"configuration error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    if sandbox:
        config.sandbox = sandbox
    if model:
        config.llm.provider = model

    from .intake.file import FileIntake

    adapter = FileIntake(evidence)
    try:
        outcome = adapter.fetch(report, repo=repo, ref=ref)
    except FileNotFoundError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    backend = build_backend(config.sandbox)
    provider = build_provider(config)
    orchestrator = Orchestrator(
        config=config,
        store=store,
        evidence=evidence,
        backend=backend,
        provider=provider,
    )
    try:
        result = orchestrator.triage(
            outcome.report,
            target_ref=ref,
            comparison_ref=comparison_ref,
            repo_path=repo,
            confirm=confirm,
            policy_path=policy or None,
            preflight_override=override_preflight,
        )
    except SandboxError as exc:
        typer.secho(f"sandbox error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=3) from exc

    if output == "json":
        typer.echo(render_json(result.verdict).rstrip())
    elif output == "sarif":
        typer.echo(render_sarif(result.verdict).rstrip())
    else:
        typer.echo(result.card.rstrip())

    for warning in result.warnings:
        typer.secho(f"warning: {warning}", fg=typer.colors.YELLOW, err=True)

    if bundle_out:
        target = Path(bundle_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        import shutil

        shutil.copytree(result.bundle_path, target, dirs_exist_ok=True)

    raise typer.Exit(code=_exit_code(result.verdict.verdict))


def _exit_code(verdict: Verdict) -> int:
    """Map a verdict to a process exit code (0 for a definitive verdict)."""
    if verdict in {Verdict.REPRODUCED, Verdict.NOT_REPRODUCED, Verdict.OUT_OF_SCOPE}:
        return 0
    if verdict is Verdict.DUPLICATE:
        return 0
    return 1


# -- preflight (reporter mode) -----------------------------------------


@app.command()
def preflight(
    poc_dir: Annotated[str, typer.Argument(help="Directory holding the PoC.")],
    repo: Annotated[str, typer.Option("--repo", help="Path or URL of the target.")] = ".",
    ref: Annotated[str, typer.Option("--ref", help="The ref to test against.")] = "",
    out: Annotated[
        str, typer.Option("--out", help="Where to write the RRS block.")
    ] = "",
    bundle_out: Annotated[
        str, typer.Option("--bundle-out", help="Where to write the evidence bundle.")
    ] = "",
    sandbox: Annotated[str, typer.Option("--sandbox", help="Sandbox backend.")] = "local",
) -> None:
    """Check a PoC in a clean environment and produce an RRS block (U7)."""
    from .extract.rrs import emit_rrs

    directory = Path(poc_dir)
    if not directory.is_dir():
        typer.secho(f"not a directory: {directory}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    attachments: list[tuple[str, str]] = []
    for path in sorted(directory.iterdir()):
        if path.is_file():
            from .schemas.common import sha256_file

            attachments.append((path.name, sha256_file(str(path))))

    preflight_engine = Preflight()
    findings: list[str] = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        from .schemas.common import sha256_file
        from .schemas.report import Attachment

        attachment = Attachment(
            name=path.name,
            path=str(path),
            sha256=sha256_file(str(path)),
            size=path.stat().st_size,
        )
        result = preflight_engine.inspect(attachment)
        if result.blocked:
            findings.extend(f"{result.name}: {reason}" for reason in result.reasons)

    block = emit_rrs(
        repo=repo,
        ref=ref,
        inputs=tuple(attachments),
        oracle="crash",
    )
    typer.echo(block.rstrip())
    if findings:
        typer.secho(
            "preflight findings (stated as observed behaviour):", fg=typer.colors.YELLOW, err=True
        )
        for finding in findings:
            typer.secho(f"- {finding}", fg=typer.colors.YELLOW, err=True)

    if out:
        target = Path(out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(block, encoding="utf-8")

    if bundle_out:
        _write_preflight_bundle(directory, block, findings, bundle_out)


# -- inbox --------------------------------------------------------------


@inbox_app.command("list")
def inbox_list(
    store_dir: Annotated[str, typer.Option("--store", help="Where the store lives.")] = "",
    evidence_dir: Annotated[
        str, typer.Option("--evidence", help="Where the evidence store lives.")
    ] = "",
    limit: Annotated[int, typer.Option("--limit", help="How many to show.")] = 20,
) -> None:
    """List the reports in the local store."""
    _config, store, _evidence = _state(store_dir, evidence_dir)
    rows = store.list_reports(limit=limit)
    if not rows:
        typer.echo("the inbox is empty")
        return
    for row in rows:
        verdict = store.get_verdict(row.id)
        label = str(verdict.verdict) if verdict else "not triaged"
        typer.echo(f"{row.id}  {label:<18}  {row.subject or row.target_repo}")


@inbox_app.command("show")
def inbox_show(
    report_id: Annotated[str, typer.Argument(help="The report id.")],
    store_dir: Annotated[str, typer.Option("--store", help="Where the store lives.")] = "",
    evidence_dir: Annotated[
        str, typer.Option("--evidence", help="Where the evidence store lives.")
    ] = "",
    output: Annotated[str, typer.Option("--output", help="card | json")] = "card",
) -> None:
    """Show a stored report and its verdict."""
    _config, store, _evidence = _state(store_dir, evidence_dir)
    verdict = store.get_verdict(report_id)
    if verdict is None:
        typer.secho(f"no verdict stored for {report_id}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if output == "json":
        typer.echo(render_json(verdict).rstrip())
    else:
        typer.echo(render_card(verdict).rstrip())


@inbox_app.command("rerun")
def inbox_rerun(
    report_id: Annotated[str, typer.Argument(help="The report id.")],
    ref: Annotated[str, typer.Option("--ref", help="The ref to re-run against.")] = "",
    store_dir: Annotated[str, typer.Option("--store", help="Where the store lives.")] = "",
    evidence_dir: Annotated[
        str, typer.Option("--evidence", help="Where the evidence store lives.")
    ] = "",
    sandbox: Annotated[str, typer.Option("--sandbox", help="Sandbox backend.")] = "",
) -> None:
    """Re-run a stored report against another ref (U5)."""
    _config, store, evidence = _state(store_dir, evidence_dir)
    report = store.get_report(report_id)
    if report is None:
        typer.secho(f"no report stored for {report_id}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    config = load_config(None)
    if sandbox:
        config.sandbox = sandbox
    orchestrator = Orchestrator(
        config=config, store=store, evidence=evidence, backend=build_backend(config.sandbox)
    )
    outcome = orchestrator.triage(
        report, target_ref=ref, repo_path=report.target.repo
    )
    typer.echo(outcome.card.rstrip())


# -- recipe -------------------------------------------------------------

_RECIPE_TEMPLATE = """\
language: c
build:
  system: cmake
  flags: [asan, ubsan]
  steps:
    - cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
    - cmake --build build -j
run:
  workdir: /work
  default_timeout: 30s
"""


@recipe_app.command("init")
def recipe_init(
    path: Annotated[str, typer.Argument(help="The repository to initialise.")] = ".",
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing recipe.")] = False,
) -> None:
    """Create a starter .verdis/recipe.yml."""
    target = Path(path) / ".verdis" / "recipe.yml"
    if target.exists() and not force:
        typer.secho(f"{target} already exists", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_RECIPE_TEMPLATE, encoding="utf-8")
    typer.echo(f"wrote {target}")


@recipe_app.command("validate")
def recipe_validate(
    path: Annotated[str, typer.Argument(help="The repository to check.")] = ".",
) -> None:
    """Check that the recipe parses and looks sane."""
    from .build.recipe import RecipeError, load_recipe_file

    target = Path(path) / ".verdis" / "recipe.yml"
    if not target.is_file():
        typer.secho(f"no recipe at {target}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    try:
        recipe = load_recipe_file(target)
    except RecipeError as exc:
        typer.secho(f"invalid recipe: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"recipe is valid (language: {recipe.language}, steps: {len(recipe.build.steps)})")


# -- policy -------------------------------------------------------------

_POLICY_TEMPLATE = """\
supported_versions: ['2.x']
in_scope: [parser, network-client]
excluded_classes:
  - id: needs-malicious-config
    description: Requires attacker-controlled configuration files
  - id: local-dos-cli
    description: Denial of service from unbounded local CLI input
evidence_requirements:
  poc_required: true
  default_config_only: true
  min_tested_version: '2.0'
sla:
  first_response_days: 7
"""


@policy_app.command("init")
def policy_init(
    path: Annotated[str, typer.Argument(help="The repository to initialise.")] = ".",
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing policy.")] = False,
) -> None:
    """Create a starter .verdis/policy.yml."""
    target = Path(path) / ".verdis" / "policy.yml"
    if target.exists() and not force:
        typer.secho(f"{target} already exists", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_POLICY_TEMPLATE, encoding="utf-8")
    typer.echo(f"wrote {target}")


@policy_app.command("check")
def policy_check(
    path: Annotated[str, typer.Argument(help="The repository to check.")] = ".",
) -> None:
    """Load the policy and show where it came from."""
    try:
        policy, origin = load_policy(path)
    except PolicyLoadError as exc:
        typer.secho(f"invalid policy: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"policy origin: {origin}")
    typer.echo(f"supported versions: {', '.join(policy.supported_versions) or '(none)'}")
    typer.echo(f"in scope: {', '.join(policy.in_scope) or '(none)'}")
    typer.echo(f"excluded classes: {len(policy.excluded_classes)}")
    typer.echo(f"poc required: {policy.evidence.poc_required}")
    if origin == "derived":
        typer.secho(
            "this policy was derived from project documentation and is unverified",
            fg=typer.colors.YELLOW,
            err=True,
        )
    if origin == "default":
        typer.secho(
            "no policy was found; the permissive defaults are in use",
            fg=typer.colors.YELLOW,
            err=True,
        )
        raise typer.Exit(code=1)


# -- bundle -------------------------------------------------------------


@bundle_app.command("verify")
def bundle_verify(
    path: Annotated[str, typer.Argument(help="The bundle directory to verify.")],
) -> None:
    """Re-hash every file in a bundle and report mismatches."""
    directory = Path(path)
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        typer.secho(f"no manifest at {manifest_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        typer.secho(f"cannot read the manifest: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    from .schemas.common import sha256_file

    problems: list[str] = []
    files = data.get("files", [])
    for entry in files:
        target = directory / str(entry.get("path", ""))
        if not target.is_file():
            problems.append(f"missing: {entry.get('path')}")
            continue
        if sha256_file(str(target)) != entry.get("sha256"):
            problems.append(f"hash mismatch: {entry.get('path')}")
    if problems:
        for problem in problems:
            typer.secho(problem, fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(f"bundle is intact ({len(files)} files)")


# -- doctor -------------------------------------------------------------


@app.command()
def doctor(
    store_dir: Annotated[str, typer.Option("--store", help="Where the store lives.")] = "",
    evidence_dir: Annotated[
        str, typer.Option("--evidence", help="Where the evidence store lives.")
    ] = "",
    sandbox: Annotated[str, typer.Option("--sandbox", help="Sandbox backend to check.")] = "",
) -> None:
    """Check the sandbox backend, images and permissions."""
    _config, store, _evidence = _state(store_dir, evidence_dir)
    typer.echo(f"verdis {__version__}")
    typer.echo(f"python {sys.version.split()[0]}")
    typer.echo(f"store: {store.root}")
    backend = build_backend(sandbox) if sandbox else build_backend("default")
    typer.echo(f"sandbox backend: {backend.name} (available: {backend.available()})")
    for note in backend.doctor():
        typer.echo(f"  - {note}")
    missing = _missing_images(backend)
    for image in missing:
        typer.secho(
            f"  - the image {image} is not on this machine; pull it before running "
            "(the tool never pulls an image itself)",
            fg=typer.colors.YELLOW,
        )
    typer.echo(f"store stats: {store.stats()}")


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


def main() -> None:
    """Entry point."""
    app()  # pragma: no cover - the console entry point


if __name__ == "__main__":  # pragma: no cover
    main()
