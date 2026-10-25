"""The orchestrator: the pipeline of PRD 10.2.

    report -> intake -> claim -> policy -> dedupe (pre) -> preflight
    preflight -> UNSAFE_ATTACHMENT                  (stop, quarantine)
    preflight -> plan -> build -> run (sandbox) -> oracles -> judge
    judge -> dedupe (post) -> evidence bundle -> verdict card + draft reply

One resumable job per report. Every stage is idempotent and every partial
result is saved, so a crash resumes rather than restarts.
"""

from __future__ import annotations

import logging
import re
import secrets
import shlex
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..build.builder import BuildCache, Builder
from ..build.checkout import CheckoutError, checkout_ref
from ..config import Config, default_config
from ..dedupe.fingerprint import DedupeFingerprint
from ..dedupe.index import DedupeEngine
from ..extract.extractor import ClaimExtractor
from ..extract.providers import LLMProvider
from ..intake.limits import ReportBudget
from ..judge.rules import Judge, JudgeContext
from ..oracles.engine import OracleEngine, OracleOutcome
from ..planner.planner import Planner
from ..planner.validator import PlanValidator
from ..policy.engine import PolicyEngine
from ..policy.loader import load_policy
from ..preflight.preflight import Preflight
from ..sandbox.base import (
    CONTAINER_BACKENDS,
    Mount,
    SandboxBackend,
    SandboxLimits,
    SandboxRequest,
    SandboxResult,
    default_profile,
    hardened_profile,
    share_with_sandbox,
)
from ..schemas.bundle import ModelInfo
from ..schemas.common import BudgetExceeded
from ..schemas.plan import Plan
from ..schemas.policy import PolicyMatch
from ..schemas.preflight import PreflightResult
from ..schemas.report import Report
from ..schemas.run import (
    BuildResult,
    CommandResult,
    ResourceUsage,
    RunResult,
    RunStatus,
)
from ..schemas.verdict import DedupeMatch, VerdictResult
from ..storage.db import Store
from ..storage.evidence import EvidenceStore

log = logging.getLogger(__name__)

__all__ = [
    "Orchestrator",
    "SandboxUnavailable",
    "TriageOutcome",
    "build_backend",
    "build_provider",
]


#: How many source files the symbol check reads before it gives up.
_MAX_FILES_SEARCHED = 4000


class SandboxUnavailable(RuntimeError):
    """Raised when no sandbox can be created.

    The tool runs attacker-controlled code. When no isolation is
    available the honest answer is to refuse, not to run the proof of
    concept on the host.
    """


def build_backend(name: str = "default") -> SandboxBackend:
    """Choose a sandbox backend by name."""
    if name in {"default", "hardened"}:
        from ..sandbox.docker import DockerBackend
        from ..sandbox.podman import PodmanBackend

        podman = PodmanBackend()
        if podman.available():
            return podman
        docker = DockerBackend()
        if docker.available():
            return docker
        # Falling back to the host here would run an untrusted proof of
        # concept outside any sandbox. The operator has to ask for it.
        raise SandboxUnavailable(
            "no container runtime is available. Verdis runs proofs of concept "
            "inside a sandbox, so it needs Podman or Docker. Install one, or pass "
            "--sandbox local to run without isolation (development only)."
        )
    if name == "podman":
        from ..sandbox.podman import PodmanBackend

        return PodmanBackend()
    if name == "docker":
        from ..sandbox.docker import DockerBackend

        return DockerBackend()
    if name == "local":
        from ..sandbox.local import LocalBackend

        return LocalBackend()
    raise ValueError(f"unknown sandbox backend: {name!r}")


def build_provider(config: Config) -> LLMProvider:
    """Build the model provider described by the configuration."""
    from ..extract.providers import build_provider as _build

    return _build(config.llm)


@dataclass
class TriageOutcome:
    """Everything one triage produced."""

    verdict: VerdictResult
    claim: Any = None
    plan: Plan | None = None
    policy_matches: tuple[PolicyMatch, ...] = ()
    preflight: tuple[PreflightResult, ...] = ()
    bundle_path: str = ""
    card: str = ""
    reply: str = ""
    model_info: ModelInfo = field(default_factory=ModelInfo)
    warnings: list[str] = field(default_factory=list)


class Orchestrator:
    """Runs the pipeline for one report."""

    def __init__(
        self,
        *,
        config: Config | None = None,
        store: Store | None = None,
        evidence: EvidenceStore | None = None,
        backend: SandboxBackend | None = None,
        provider: LLMProvider | None = None,
    ) -> None:
        self.config = config or default_config()
        self.store = store
        self.evidence = evidence
        self.backend = backend or build_backend(self.config.sandbox)
        self.provider = provider if provider is not None else build_provider(self.config)
        self.extractor = ClaimExtractor(self.provider)
        self.planner = Planner(self.provider)
        self.policy_engine: PolicyEngine | None = None
        self.preflight = Preflight(
            threshold=self.config.preflight_threshold,
            plugin=self.config.rea_plugin,
        )
        self.oracles = OracleEngine()
        self.judge = Judge(dedupe_threshold=self.config.dedupe_threshold)
        self.dedupe: DedupeEngine | None = None
        if self.store is not None:
            advisory_source = None
            if self.config.advisory_lookups:
                from ..dedupe.osv import OSVAdvisorySource

                advisory_source = OSVAdvisorySource(
                    ecosystem=self.config.advisory_ecosystem
                )
            self.dedupe = DedupeEngine(
                store=self.store,
                threshold=self.config.dedupe_threshold,
                advisory_source=advisory_source,
            )

    # -- the pipeline ---------------------------------------------------

    def _stage(self, report: Report, stage: str, *, status: str = "running") -> None:
        """Record how far the pipeline got, so a crash is resumable."""
        if self.store is None:
            return
        self.store.save_job(report.id, stage, status=status)

    def triage(
        self,
        report: Report,
        *,
        target_ref: str = "",
        comparison_ref: str = "",
        repo_path: str | Path | None = None,
        confirm: bool = False,
        policy_path: str | Path | None = None,
        preflight_override: str = "",
    ) -> TriageOutcome:
        """Run the full pipeline for one report.

        A report that uses up its budget stops with an INCONCLUSIVE
        verdict: the tool ran out of time or tokens, which says nothing
        about the claim.
        """
        try:
            return self._triage(
                report,
                target_ref=target_ref,
                comparison_ref=comparison_ref,
                repo_path=repo_path,
                confirm=confirm,
                policy_path=policy_path,
                preflight_override=preflight_override,
            )
        except BudgetExceeded as exc:
            ref = target_ref or report.target.ref
            context = self._judge_context(report, None, ref=ref)
            verdict = self.judge.inconclusive(
                context,
                reason=str(exc),
                next_action="raise the budget for this report, or narrow it",
            )
            return self._finish(
                report, verdict, None, None, (), (), ModelInfo(), [str(exc)]
            )

    def _triage(
        self,
        report: Report,
        *,
        target_ref: str = "",
        comparison_ref: str = "",
        repo_path: str | Path | None = None,
        confirm: bool = False,
        policy_path: str | Path | None = None,
        preflight_override: str = "",
    ) -> TriageOutcome:
        """The pipeline itself."""
        started = time.monotonic()
        warnings: list[str] = []
        repo_raw = str(repo_path or report.target.repo or ".")
        repo = Path(repo_raw)
        ref = target_ref or report.target.ref

        # A report that has already been triaged at the same ref does not
        # need to be triaged again (FR-1.5). The stored verdict is
        # returned, and the evidence bundle is left alone.
        existing = self._existing_verdict(report, ref)
        if existing is not None:
            return self._finish(
                report,
                existing,
                None,
                None,
                (),
                (),
                ModelInfo(),
                ["the report had already been triaged at this ref; the stored verdict "
                 "was returned without running it again"],
            )

        budget = ReportBudget(seconds=self.config.report_budget_seconds)
        budget.check()

        self._stage(report, "claim")

        # -- claim
        outcome = self.extractor.extract(
            report.body, attachment_names=report.attachment_names
        )
        claim = outcome.claim
        warnings.extend(outcome.warnings)
        model_info = ModelInfo(
            provider=outcome.model_metadata.get("provider", ""),
            name=outcome.model_metadata.get("model", ""),
            used_for=("claim-extraction",) if outcome.method == "model" else (),
            prompt_hash=outcome.model_metadata.get("prompt_hash", ""),
            response_hash=outcome.model_metadata.get("response_hash", ""),
            tokens_used=int(outcome.model_metadata.get("tokens_used", 0) or 0),
            cost_usd=float(outcome.model_metadata.get("cost_usd", 0.0) or 0.0),
        )

        budget.spend_tokens(model_info.tokens_used)

        self._stage(report, "policy")

        # -- policy
        if policy_path:
            from ..policy.loader import load_policy_file

            policy = load_policy_file(policy_path)
            policy_origin = "policy file"
        else:
            policy, policy_origin = load_policy(repo)
        self.policy_engine = PolicyEngine(policy)
        assessment = self.policy_engine.check(claim)
        policy_matches = tuple(assessment.all_matches)
        policy_missing = tuple(assessment.missing_evidence)
        exclusion = assessment.first_out_of_scope()
        if policy_origin == "derived":
            warnings.append(
                "policy was derived from project documentation and is unverified"
            )

        # -- dedupe (pre)
        pre_matches: tuple[DedupeMatch, ...] = ()
        if self.dedupe is not None:
            fingerprint = self._fingerprint(report, claim)
            pre_matches = tuple(
                self.dedupe.search(
                    fingerprint,
                    report.body,
                    exclude_report_id=report.id,
                    mode="pre",
                    repo=report.target.repo,
                    version=claim.affected_version,
                )
            )
        self._stage(report, "preflight")

        # -- preflight
        preflight_results = tuple(
            self.preflight.inspect(attachment) for attachment in report.attachments
        )
        if any(result.blocked for result in preflight_results) and not preflight_override:
            verdict = self.judge.judge(
                self._judge_context(
                    report,
                    claim,
                    ref=ref,
                    policy_matches=policy_matches,
                    preflight=preflight_results,
                    dedupe_matches=pre_matches,
                    model_name=model_info.name,
                )
            )
            return self._finish(
                report, verdict, claim, None, policy_matches, preflight_results,
                model_info, warnings,
            )

        if preflight_override and any(result.blocked for result in preflight_results):
            # A human looked at the attachment and said it is safe. The
            # decision is recorded, because the evidence bundle has to
            # show who overrode what, and the findings no longer stop the
            # run.
            warnings.append(
                "the preflight quarantine was overridden by a human: "
                f"{preflight_override}"
            )
            for result in preflight_results:
                if result.blocked:
                    warnings.append(
                        f"{result.name} was quarantined and then overridden: "
                        + "; ".join(result.reasons)
                    )
            preflight_results = tuple(
                result for result in preflight_results if not result.blocked
            )

        self._stage(report, "plan")

        if self.config.stop_on_duplicate and pre_matches:
            best = pre_matches[0]
            if best.similarity >= self.config.dedupe_threshold:
                verdict = self.judge.judge(
                    self._judge_context(
                        report,
                        claim,
                        ref=ref,
                        policy_matches=policy_matches,
                        preflight=preflight_results,
                        dedupe_matches=pre_matches,
                        model_name=model_info.name,
                    )
                )
                return self._finish(
                    report, verdict, claim, None, policy_matches, preflight_results,
                    model_info, warnings,
                )

        # -- plan
        rrs = None
        try:
            from ..extract.rrs import parse_rrs

            rrs = parse_rrs(report.body)
        except Exception as exc:
            warnings.append(f"RRS block ignored: {exc}")
        plan = self.planner.plan(
            claim,
            ref=ref,
            rrs=rrs,
            comparison_ref=comparison_ref or self.config.comparison_ref,
        )
        validation = PlanValidator().validate(plan)
        if validation.forbidden:
            warnings.append(
                "the plan was rejected: " + "; ".join(i.message for i in validation.forbidden)
            )
            verdict = self.judge.inconclusive(
                self._judge_context(
                    report,
                    claim,
                    ref=ref,
                    policy_matches=policy_matches,
                    preflight=preflight_results,
                    dedupe_matches=pre_matches,
                    plan=plan,
                    model_name=model_info.name,
                    notes=list(warnings),
                ),
                reason=(
                    "the reproduction plan was rejected by the allowlist, so nothing "
                    "was executed: "
                    + "; ".join(i.message for i in validation.forbidden)
                ),
                next_action=(
                    "review the plan; it tried to use a capability the sandbox does "
                    "not allow"
                ),
            )
            return self._finish(
                report, verdict, claim, plan, policy_matches, preflight_results,
                model_info, warnings,
            )
        if validation.needs_confirmation and not confirm:
            verdict = self.judge.inconclusive(
                self._judge_context(
                    report,
                    claim,
                    ref=ref,
                    policy_matches=policy_matches,
                    preflight=preflight_results,
                    dedupe_matches=pre_matches,
                    plan=plan,
                    model_name=model_info.name,
                ),
                reason=(
                    "the plan contains commands that need a maintainer's approval, and "
                    "this run was unattended: "
                    + "; ".join(i.message for i in validation.needs_confirmation)
                ),
                next_action=(
                    "review the plan and re-run with confirmation to approve those "
                    "commands"
                ),
            )
            return self._finish(
                report, verdict, claim, plan, policy_matches, preflight_results,
                model_info, warnings,
            )

        budget.check()

        self._stage(report, "build")

        # -- build and run, on a private copy of the source
        (
            build_result,
            run_result,
            comparison_result,
            canary_secret,
            property_result,
            missing_symbol,
        ) = self._build_and_run(
            repo_raw,
            ref,
            plan,
            report,
            comparison_ref or self.config.comparison_ref or self._default_comparison(repo, ref),
            claim=claim,
        )

        budget.check()

        self._stage(report, "run")

        # -- oracles
        outcomes: tuple[OracleOutcome, ...] = ()
        if run_result is not None:
            outcomes = self.oracles.evaluate(
                run_result,
                plan,
                claim,
                comparison_run=comparison_result,
                canary_secret=canary_secret,
                property_result=property_result,
            )
            run_result = run_result.model_copy(
                update={"oracles": tuple(o.to_result() for o in outcomes)}
            )

        self._stage(report, "dedupe")

        # -- dedupe (post)
        post_matches = pre_matches
        if self.dedupe is not None:
            fingerprint = self._fingerprint(report, claim, stack_output=run_result.combined_output if run_result else "")
            post_matches = tuple(
                self.dedupe.search(
                    fingerprint,
                    report.body,
                    exclude_report_id=report.id,
                    mode="post",
                    repo=report.target.repo,
                    version=claim.affected_version,
                )
            )
            self.dedupe.index(
                report_id=report.id,
                fingerprint=fingerprint,
                body=report.body,
                subject=report.subject,
            )

        # -- judge
        context = self._judge_context(
            report,
            claim,
            ref=ref,
            policy_matches=policy_matches,
            policy_missing=policy_missing,
            policy_exclusion=exclusion,
            preflight=preflight_results,
            build=build_result,
            run=run_result,
            comparison_run=comparison_result,
            oracles=outcomes,
            dedupe_matches=post_matches,
            plan=plan,
            model_name=model_info.name,
            duration_ms=int((time.monotonic() - started) * 1000),
            notes=list(warnings),
            missing_symbol=missing_symbol,
        )
        verdict = self.judge.judge(context)
        verdict = verdict.model_copy(update={"model_cost_usd": model_info.cost_usd})
        self._stage(report, "done", status="finished")
        return self._finish(
            report, verdict, claim, plan, policy_matches, preflight_results,
            model_info, warnings, run_result=run_result, build_result=build_result,
            comparison_run=comparison_result,
        )

    # -- stages ---------------------------------------------------------

    def _judge_context(
        self,
        report: Report,
        claim: Any,
        *,
        ref: str,
        policy_matches: tuple[PolicyMatch, ...] = (),
        policy_missing: tuple[str, ...] = (),
        policy_exclusion: PolicyMatch | None = None,
        preflight: tuple[PreflightResult, ...] = (),
        build: BuildResult | None = None,
        run: RunResult | None = None,
        comparison_run: RunResult | None = None,
        oracles: tuple[OracleOutcome, ...] = (),
        dedupe_matches: tuple[DedupeMatch, ...] = (),
        plan: Plan | None = None,
        model_name: str = "",
        duration_ms: int = 0,
        notes: list[str] | None = None,
        missing_symbol: str = "",
    ) -> JudgeContext:
        """Everything the judge is allowed to look at, in one place."""
        return JudgeContext(
            report_id=report.id,
            target_ref=ref,
            claim=claim,
            policy_matches=policy_matches,
            policy_missing=policy_missing,
            policy_exclusion=policy_exclusion,
            preflight=preflight,
            build=build,
            run=run,
            comparison_run=comparison_run,
            oracles=oracles,
            dedupe_matches=dedupe_matches,
            plan=plan,
            model_name=model_name,
            duration_ms=duration_ms,
            notes=notes or [],
            missing_symbol=missing_symbol,
        )

    def _fingerprint(
        self, report: Report, claim: Any, *, stack_output: str = ""
    ) -> DedupeFingerprint:
        poc_bytes = b""
        for attachment in report.attachments:
            path = Path(attachment.path)
            if path.is_file():
                poc_bytes = path.read_bytes()
                break
        return DedupeFingerprint.build(
            report_id=report.id,
            vuln_class=claim.vuln_class,
            component=claim.component.key or claim.component.name,
            body=report.body,
            poc_bytes=poc_bytes or None,
            stack_output=stack_output,
        )

    def _build_and_run(
        self,
        repo: str,
        ref: str,
        plan: Plan,
        report: Report,
        comparison_ref: str,
        claim: Any = None,
    ) -> tuple[
        BuildResult, RunResult | None, RunResult | None, str, RunResult | None, str
    ]:
        """Build the target and run the PoC against it.

        The build and the run share one private copy of the source, so the
        artefacts the build produced are exactly where the PoC expects
        them, and the maintainer's own tree is never written to.
        """
        source, cleanup = self._prepare_source(repo, ref)
        try:
            recipe = self._recipe_for(source)
            missing_symbol = self._missing_symbol(claim, source) if claim else ""
            build_result = self._build(source, ref, plan, recipe=recipe)
            run_result = None
            comparison_result = None
            canary_secret = ""
            property_result = None
            if build_result.ok:
                run_result, canary_secret, property_result = self._run_at(
                    source, plan, report, recipe=recipe
                )
                if comparison_ref and comparison_ref != ref:
                    comparison_source, comparison_cleanup = self._prepare_source(
                        repo, comparison_ref
                    )
                    try:
                        comparison_recipe = self._recipe_for(comparison_source)
                        comparison_build = self._build(
                            comparison_source, comparison_ref, plan, recipe=comparison_recipe
                        )
                        if comparison_build.ok:
                            comparison_result, _secret, _property = self._run_at(
                                comparison_source, plan, report, recipe=comparison_recipe
                            )
                    finally:
                        comparison_cleanup()
            return (
                build_result,
                run_result,
                comparison_result,
                canary_secret,
                property_result,
                missing_symbol,
            )
        finally:
            cleanup()

    def _prepare_source(self, repo: str | Path, ref: str) -> tuple[Path, Any]:
        """Make a private copy of the target source at ``ref``."""
        raw = str(repo)
        if raw.startswith(("http://", "https://", "git@", "ssh://")):
            from ..build.checkout import clone

            root = self._temp_dir("verdis-clone-")
            source = clone(raw, root / "source")
            return source, lambda: shutil.rmtree(root, ignore_errors=True)
        if raw.startswith("file://"):
            # A local path written as a URL.
            return self._copy_source(Path(raw[len("file://") :]))
        if ref:
            candidate = Path(ref)
            if candidate.is_dir():
                # A comparison ref may be a local tree (a fixed checkout, a
                # worktree) rather than a git ref.
                return self._copy_source(candidate)
            try:
                checkout = checkout_ref(repo, ref)
            except CheckoutError:
                checkout = None
            if checkout is not None and checkout.method != "existing":
                return checkout.path, checkout.cleanup

        return self._copy_source(Path(repo))

    def _work_root(self) -> Path:
        """Where the scratch directories go.

        A container runtime that is not on this machine (a VM, a remote
        daemon) can only see the paths it shares with the host, so the
        work directory has to be configurable. The default is the system
        temporary directory, which is always right on Linux.
        """
        if self.config.work_dir:
            root = Path(self.config.work_dir).expanduser()
            root.mkdir(parents=True, exist_ok=True)
            return root
        return Path(tempfile.gettempdir())

    def _temp_dir(self, prefix: str) -> Path:
        """A private scratch directory under the work root."""
        return Path(tempfile.mkdtemp(prefix=prefix, dir=str(self._work_root())))

    def _copy_source(self, repo: Path) -> tuple[Path, Any]:
        """Copy a source tree into a private directory."""
        root = self._temp_dir("verdis-src-")
        target = root / "source"
        shutil.copytree(
            repo,
            target,
            symlinks=False,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "node_modules"),
        )
        # The build runs in this copy and the run stage mounts it, so it is
        # opened for writing.
        share_with_sandbox(target, writable=True)
        return target, lambda: shutil.rmtree(root, ignore_errors=True)

    @staticmethod
    def _default_comparison(repo: Path, ref: str) -> str:
        """The comparison ref to use when the caller named none.

        The differential run is on by default (PRD 17.1), so the tool
        compares the claimed ref with the branch the project maintains.
        """
        if not ref:
            return ""
        from ..build.checkout import default_branch

        return default_branch(repo)

    def _existing_verdict(self, report: Report, ref: str) -> VerdictResult | None:
        """The stored verdict for this report at this ref, if there is one.

        Re-running a report that has already been triaged would rebuild the
        target and run the proof of concept again, which is wasteful and
        not what the maintainer asked for (FR-1.5).
        """
        if self.store is None:
            return None
        stored = self.store.get_verdict(report.id)
        if stored is None:
            return None
        if stored.target_ref != ref:
            return None
        return stored

    @staticmethod
    def _timeout_seconds(value: str) -> int:
        """A timeout in the recipe's own notation ("30s", "5m")."""
        text = str(value or "30s").strip().lower()
        try:
            if text.endswith("ms"):
                return max(1, int(float(text[:-2]) / 1000))
            if text.endswith("m"):
                return max(1, int(float(text[:-1]) * 60))
            if text.endswith("h"):
                return max(1, int(float(text[:-1]) * 3600))
            return max(1, int(float(text)))
        except ValueError:
            return 30

    @staticmethod
    def _missing_symbol(claim: Any, source: Path) -> str:
        """Is the symbol the report names present in the target at all?

        A report that describes a defect in a function the target does
        not have cannot be reproduced by a crash in a different one. The
        check is deliberately conservative: it only reports a symbol as
        missing when the target has source files to search and the name
        appears in none of them.
        """
        component = getattr(claim, "component", None)
        if component is None:
            return ""
        name = (getattr(component, "name", "") or "").strip()
        file = (getattr(component, "file", "") or "").strip()
        if not name and not file:
            return ""

        files = [path for path in source.rglob("*") if path.is_file()]
        if not files:
            return ""

        if file:
            # A report may name the file with a different prefix, so the
            # base name is what is compared.
            base = Path(file).name
            if not base:
                return ""
            if not any(path.name == base for path in files):
                return file

        if not name:
            return ""
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            return ""
        sources = [
            path
            for path in files
            if path.suffix in {".c", ".h", ".cc", ".cpp", ".cxx", ".py", ".rs", ".go", ".java"}
        ]
        if not sources:
            return ""
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        # A repository can be very large, and this check is not worth
        # more than a moment: the first few thousand source files are
        # where a function lives.
        for path in sources[:_MAX_FILES_SEARCHED]:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:  # pragma: no cover - an unreadable file
                continue
            if pattern.search(text):
                return ""
        return name

    def _recipe_for(self, source: Path) -> Any:
        """The recipe for a prepared source tree, if it has one."""
        from ..build.recipe import load_recipe_file

        candidate = source / ".verdis" / "recipe.yml"
        if candidate.is_file():
            try:
                return load_recipe_file(candidate)
            except Exception:
                return None
        return None

    def _build(
        self, repo: Path, ref: str, plan: Plan, recipe: Any = None
    ) -> BuildResult:
        builder = Builder(
            backend=self.backend,
            cache=self._cache(),
            image=self._image(),
        )
        if recipe is None:
            recipe = self._recipe_for(repo)
        build_step = plan.build_step
        if build_step is not None and build_step.recipe not in {"auto", "default", ""}:
            from ..build.recipe import load_recipe_file

            candidate = repo / ".verdis" / f"recipe-{build_step.recipe}.yml"
            if candidate.is_file():
                try:
                    recipe = load_recipe_file(candidate)
                except Exception:
                    recipe = None
        return builder.build(repo_path=repo, ref=ref, recipe=recipe, in_place=True)

    def _cache(self) -> BuildCache | None:
        if not self.config.build_cache_dir:
            return None
        return BuildCache(
            root=Path(self.config.build_cache_dir),
            max_bytes=self.config.build_cache_max_bytes,
        )

    def _run_at(
        self, source: Path, plan: Plan, report: Report, recipe: Any = None
    ) -> tuple[RunResult, str, RunResult | None]:
        """Run the PoC in the sandbox against a prepared source tree.

        Returns the run, the canary secret that was planted and the result
        of the maintainer's property script, if the recipe names one.
        """
        run_step = plan.run_step
        # The staging directory is mounted into the sandbox, so it sits in a
        # private parent: the directory itself is opened to the sandbox user,
        # and other local users can reach it only through the parent.
        stage_root = self._temp_dir("verdis-stage-")
        staging = stage_root / "files"
        staging.mkdir()
        staged: set[str] = set()
        try:
            for attachment in report.attachments:
                path = Path(attachment.path)
                if path.is_file():
                    try:
                        (staging / attachment.name).write_bytes(path.read_bytes())
                    except OSError:  # pragma: no cover
                        pass
                    else:
                        staged.add(attachment.name)
            canary_secret = self._plant_canary(staging)
            share_with_sandbox(staging)

            profile = (
                hardened_profile()
                if self.config.sandbox == "hardened"
                else default_profile()
            )
            request = self._build_request(
                source,
                staging,
                run_step,
                profile,
                plan=plan,
                recipe=recipe,
                staged=staged,
            )
            commands: list[CommandResult] = []
            results: list[SandboxResult] = []
            blocked: list[str] = []
            canary_hits: list[str] = []
            changes: list[str] = []
            image_digest = ""
            isolation = ""
            status = RunStatus.COMPLETED
            wall_ms = 0
            for _repetition in range(max(1, run_step.repeat)):
                result = self.backend.run(request)
                results.append(result)
                wall_ms += result.duration_ms
                if result.isolation:
                    isolation = result.isolation
                if result.image_digest:
                    image_digest = result.image_digest
                commands.append(
                    CommandResult(
                        cmd=run_step.cmd,
                        exit_code=result.exit_code,
                        signal=result.signal,
                        stdout=result.stdout,
                        stderr=result.stderr,
                        duration_ms=result.duration_ms,
                        timed_out=result.timed_out,
                        truncated=result.truncated,
                    )
                )
                blocked.extend(result.blocked_network)
                canary_hits.extend(result.canary_hits)
                changes.extend(result.fs_changes)
                image_digest = image_digest or result.image_digest
                if result.timed_out:
                    status = RunStatus.TIMEOUT
                    break
            if status is RunStatus.COMPLETED and commands:
                first = commands[0]
                if first.exit_code is None and not first.stdout and not first.stderr:
                    status = RunStatus.FAILED_TO_RUN

            property_result = self._run_property_script(source, recipe)

            return RunResult(
                status=status,
                ref="",
                runs=tuple(commands),
                sandbox_profile=profile.name,
                sandbox_backend=self.backend.name,
                isolation=isolation,
                resource=ResourceUsage(
                    wall_ms=wall_ms,
                    cpu_ms=sum(result.cpu_ms for result in results),
                    max_rss_kb=max((result.max_rss_kb for result in results), default=0),
                    exit_status=commands[0].exit_code if commands else None,
                ),
                filesystem_changes=tuple(dict.fromkeys(changes)),
                blocked_network=tuple(dict.fromkeys(blocked)),
                canary_hits=tuple(dict.fromkeys(canary_hits)),
                image_digest=image_digest,
            ), canary_secret, property_result
        finally:
            shutil.rmtree(stage_root, ignore_errors=True)

    def _plant_canary(self, staging: Path) -> str:
        """Plant the canary files and return the fake secret.

        The canary makes a file read, a command execution and an outbound
        request attempt into observable events (FR-8.2). The secret is
        random and worthless: it exists to be noticed, not to be used.
        """
        secret = "verdis-canary-" + secrets.token_hex(16)
        try:
            (staging / "canary-secret.txt").write_text(secret, encoding="utf-8")
            (staging / ".env").write_text(f"API_TOKEN={secret}\n", encoding="utf-8")
        except OSError:  # pragma: no cover - defensive
            pass
        return secret

    def _run_property_script(self, source: Path, recipe: Any) -> RunResult | None:
        """Run the maintainer's assertion script, if the recipe names one."""
        script = getattr(recipe, "property_script", "") if recipe is not None else ""
        if not script:
            return None
        script_path = source / script
        if not script_path.is_file():
            return None
        request = SandboxRequest(
            image="",
            command=[str(script_path)],
            workdir=str(source),
            limits=SandboxLimits(timeout_s=self.config.run_timeout, output_bytes=50_000),
            profile=default_profile(),
            workdir_source=str(source),
        )
        result = self.backend.run(request)
        return RunResult(
            status=RunStatus.COMPLETED,
            runs=(
                CommandResult(
                    cmd=str(script_path),
                    exit_code=result.exit_code,
                    signal=result.signal,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    duration_ms=result.duration_ms,
                ),
            ),
            sandbox_profile=self.backend.name,
        )

    def _build_request(
        self,
        source: Path,
        staging: Path,
        run_step: Any,
        profile: Any,
        plan: Plan | None = None,
        recipe: Any = None,
        staged: set[str] | None = None,
    ) -> SandboxRequest:
        """Build the sandbox request for one run.

        Container backends get the source mounted read-only, a staging
        directory mounted read-only and a writable tmpfs workdir. The
        development backend runs the command directly with the artifacts
        beside it. In both cases a bare artifact name in the command is
        rewritten to the place the artifact is actually staged, so the two
        backends behave the same way.
        """
        argv = shlex.split(run_step.cmd)
        # The recipe's run environment is the maintainer's own
        # configuration: it is how a project says "run the proof of
        # concept with these variables set" (ASAN_OPTIONS, MALLOC_CHECK_,
        # a locale, a library path). The plan's own environment comes
        # from the report, so the recipe's is applied on top.
        run_env = dict(run_step.env)
        run_spec = getattr(recipe, "run", None) if recipe is not None else None
        if run_spec is not None:
            run_env.update(run_spec.env)
            # The recipe's run section is the project's own configuration:
            # its timeout and its repeat count are the ones the project
            # asked for.
            timeout_s = self._timeout_seconds(run_spec.default_timeout)
            repeat = max(1, min(int(run_spec.repeat), 20))
        else:
            timeout_s = self.config.run_timeout
            repeat = max(1, int(run_step.repeat))
        run_step = run_step.model_copy(
            update={"env": run_env, "timeout": f"{timeout_s}s", "repeat": repeat}
        )
        if self._is_container_backend():
            argv = self._rewrite_artifacts(
                argv, plan, staging=staging, container=True, staged=staged
            )
            script = (
                'set -e; for f in /staging/*; do [ -e "$f" ] && cp -f "$f" /work/; done; '
                'cd /src; exec "$0" "$@"'
            )
            command = ["/bin/sh", "-c", script, *argv]
            return SandboxRequest(
                image=self._image(),
                command=command,
                workdir="/src",
                scratch="/work",
                env=run_env,
                mounts=[
                    Mount(source=str(source), target="/src", readonly=True),
                    Mount(source=str(staging), target="/staging", readonly=True),
                ],
                limits=SandboxLimits(
                    timeout_s=timeout_s, output_bytes=200_000
                ),
                profile=profile,
            )

        local_argv = [
            arg.replace("/work", str(staging))
            for arg in self._rewrite_artifacts(
                argv, plan, staging=staging, container=False, staged=staged
            )
        ]
        return SandboxRequest(
            image="",
            command=local_argv,
            workdir=str(source),
            env=run_env,
            mounts=[Mount(source=str(source), target=str(source), readonly=False)],
            limits=SandboxLimits(timeout_s=timeout_s, output_bytes=200_000),
            profile=profile,
            workdir_source=str(source),
        )

    @staticmethod
    def _rewrite_artifacts(
        argv: list[str],
        plan: Plan | None,
        *,
        staging: Path,
        container: bool,
        staged: set[str] | None = None,
    ) -> list[str]:
        """Point bare artifact names at the place the artifact is staged.

        The container backend stages artifacts in the workdir (``/work``);
        the development backend stages them in a temporary directory. Either
        way the command must refer to them by their real location.

        Only a name that was *actually* staged is rewritten. A command that
        names a file of the project itself -- ``poc.bin`` sitting in the
        source tree -- must be left alone: the run happens in the source
        directory, so the bare name resolves. Rewriting it to a staged
        path that does not exist makes the command fail for no reason.
        """
        mapping: dict[str, str] = {}
        staged = staged or set()
        if plan is not None:
            for copy_step in plan.copy_steps:
                name = Path(copy_step.artifact).name
                if name not in staged:
                    continue
                destination = copy_step.to if container else str(staging / name)
                mapping[name] = destination
        for name in staged:
            mapping.setdefault(
                name, f"/work/{name}" if container else str(staging / name)
            )
        if not mapping:
            return argv
        out: list[str] = []
        for arg in argv:
            out.append(mapping.get(arg, arg))
        return out

    def _is_container_backend(self) -> bool:
        return self.backend.name in CONTAINER_BACKENDS

    def _environment(
        self, run_result: Any = None, comparison_run: Any = None
    ) -> Any:
        """What actually protected the run, for the evidence bundle.

        The threat model says the bundle records the isolation the run
        *actually* had. That is the runtime's answer, not the one that
        was asked for, so the two can differ and the bundle has to say
        which it was.
        """
        from ..emit.bundle import BundleBuilder
        from ..schemas.bundle import EnvironmentInfo

        base = BundleBuilder.default_environment()
        if run_result is None:
            return base
        digests = tuple(
            digest
            for digest in (run_result.image_digest, getattr(comparison_run, "image_digest", ""))
            if digest
        )
        return EnvironmentInfo(
            image_digests=digests,
            sandbox_profile=run_result.sandbox_profile or base.sandbox_profile,
            sandbox_backend=run_result.sandbox_backend or base.sandbox_backend,
            isolation=run_result.isolation,
            kernel=base.kernel,
            tool_versions=base.tool_versions,
            os=base.os,
        )

    def _image(self) -> str:
        """The image the build and run stages use.

        The operator's own image, pinned by digest, wins: the tool never
        pulls an image at run time (PRD 11.2, 11.4).
        """
        if self.config.base_image:
            return self.config.base_image
        return getattr(self.backend, "default_image", "") or "ghcr.io/usualdork/verdis/base:latest"

    # -- output ---------------------------------------------------------

    def _finish(
        self,
        report: Report,
        verdict: VerdictResult,
        claim: Any,
        plan: Plan | None,
        policy_matches: tuple[PolicyMatch, ...],
        preflight: tuple[PreflightResult, ...],
        model_info: ModelInfo,
        warnings: list[str],
        *,
        run_result: RunResult | None = None,
        build_result: BuildResult | None = None,
        comparison_run: RunResult | None = None,
    ) -> TriageOutcome:
        from ..emit.bundle import BundleBuilder
        from ..emit.card import render_card
        from ..emit.reply import render_reply

        bundle_path = ""
        if self.evidence is not None:
            builder = BundleBuilder(self.evidence)
            builder.build(
                report_id=report.id,
                verdict=verdict,
                claim=claim,
                plan=plan,
                policy_matches=policy_matches,
                build_result=build_result,
                run_result=run_result,
                comparison_run=comparison_run,
                original_body=report.body,
                reporter=report.reporter,
                model=model_info,
                environment=self._environment(run_result, comparison_run),
                extra={"warnings": warnings} if warnings else None,
            )
            bundle_path = str(self.evidence.bundle_dir(report.id))
            verdict = verdict.model_copy(update={"bundle_path": bundle_path})

        if self.store is not None:
            self.store.save_report(report)
            self.store.save_verdict(verdict)

        card = render_card(verdict, bundle_path=bundle_path)
        reply = render_reply(verdict, reporter=report.reporter)
        return TriageOutcome(
            verdict=verdict,
            claim=claim,
            plan=plan,
            policy_matches=policy_matches,
            preflight=preflight,
            bundle_path=bundle_path,
            card=card,
            reply=reply,
            model_info=model_info,
            warnings=warnings,
        )
