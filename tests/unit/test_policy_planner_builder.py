"""Tests for the policy loader, the planner and the builder.

These three sit between the report and the sandbox, so their branches are
worth pinning down: what happens with a malformed policy, with a report
that has no usable plan, and with a build that fails in each of the ways
it can fail.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from verdis.build.builder import DEFAULT_MIRRORS, BuildCache, Builder
from verdis.build.recipe import recipe_from_dict
from verdis.extract.providers import NullProvider
from verdis.planner.planner import Planner, build_plan_from_claim
from verdis.policy.loader import (
    PolicyLoadError,
    derive_policy_from_docs,
    load_policy_file,
    policy_fingerprint,
    policy_from_dict,
    policy_to_dict,
)
from verdis.sandbox.local import LocalBackend
from verdis.schemas.claim import Claim, PoCCommand


class TestPolicyLoader:
    def test_a_malformed_evidence_section_is_rejected(self) -> None:
        with pytest.raises(PolicyLoadError, match="evidence_requirements"):
            policy_from_dict({"evidence_requirements": "yes"})

    def test_a_malformed_sla_section_is_rejected(self) -> None:
        with pytest.raises(PolicyLoadError, match="sla"):
            policy_from_dict({"sla": ["seven days"]})

    def test_a_malformed_list_is_rejected(self) -> None:
        with pytest.raises(PolicyLoadError, match="list of strings"):
            policy_from_dict({"supported_versions": 3})

    def test_a_single_string_is_accepted_as_a_list(self) -> None:
        policy = policy_from_dict({"supported_versions": "2.x"})
        assert policy.supported_versions == ("2.x",)

    def test_a_missing_list_is_empty(self) -> None:
        policy = policy_from_dict({})
        assert policy.supported_versions == ()

    def test_an_exclusion_can_be_a_plain_string(self) -> None:
        policy = policy_from_dict({"excluded_classes": ["Local DoS"]})
        assert policy.excluded_classes[0].description == "Local DoS"

    def test_an_exclusion_can_be_a_mapping(self) -> None:
        policy = policy_from_dict(
            {"excluded_classes": [{"id": "x", "description": "Local DoS"}]}
        )
        assert policy.excluded_classes[0].id == "x"

    def test_a_malformed_exclusion_is_rejected(self) -> None:
        with pytest.raises(PolicyLoadError, match="excluded_classes"):
            policy_from_dict({"excluded_classes": [123]})

    def test_a_policy_that_is_not_a_mapping_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.yml"
        path.write_text("- a\n- b\n", encoding="utf-8")
        with pytest.raises(PolicyLoadError, match="mapping"):
            load_policy_file(path)

    def test_a_policy_round_trips(self) -> None:
        policy = policy_from_dict(
            {
                "supported_versions": ["2.x"],
                "in_scope": ["parser"],
                "excluded_classes": [{"id": "x", "description": "Local DoS"}],
                "evidence_requirements": {"poc_required": True},
            }
        )
        again = policy_from_dict(policy_to_dict(policy))
        assert again.supported_versions == policy.supported_versions
        assert again.excluded_classes[0].description == "Local DoS"

    def test_the_fingerprint_is_stable(self) -> None:
        policy = policy_from_dict({"supported_versions": ["2.x"]})
        assert policy_fingerprint(policy) == policy_fingerprint(policy)
        other = policy_from_dict({"supported_versions": ["3.x"]})
        assert policy_fingerprint(policy) != policy_fingerprint(other)


class TestDerivation:
    def test_the_in_scope_section_is_derived(self, tmp_path: Path) -> None:
        (tmp_path / "SECURITY.md").write_text(
            "# Security\n\n## In scope\n\n- the parser\n- the network client\n",
            encoding="utf-8",
        )
        policy = derive_policy_from_docs(tmp_path)
        assert policy is not None
        assert "the parser" in policy.in_scope
        assert policy.excluded_classes[0].file.endswith("SECURITY.md")

    def test_the_evidence_section_is_derived(self, tmp_path: Path) -> None:
        (tmp_path / "SECURITY.md").write_text(
            "# Security\n\n## Requirements for reports\n\n"
            "- A working proof of concept is required\n"
            "- The default configuration must be affected\n",
            encoding="utf-8",
        )
        policy = derive_policy_from_docs(tmp_path)
        assert policy is not None
        assert policy.evidence.default_config_only is True

    def test_a_missing_file_is_not_an_error(self, tmp_path: Path) -> None:
        (tmp_path / "SECURITY.md").write_text("x", encoding="utf-8")
        # The file is unreadable as a document, but reading it must not raise.
        policy = derive_policy_from_docs(tmp_path)
        assert policy is None or policy.derived


class TestPlanner:
    def test_a_claim_without_a_command_still_gets_a_plan(self) -> None:
        plan = build_plan_from_claim(Claim(), ref="v1")
        assert plan.run_step.cmd
        assert plan.source.value == "heuristic"

    def test_the_command_comes_from_the_claim(self) -> None:
        claim = Claim(poc_commands=(PoCCommand(command="./demo poc.bin"),))
        plan = build_plan_from_claim(claim, ref="v1")
        assert plan.run_step.cmd == "./demo poc.bin"

    def test_the_artifacts_are_copied(self) -> None:
        claim = Claim(poc_artifacts=({"name": "poc.bin"},))
        plan = build_plan_from_claim(claim, ref="v1")
        assert plan.copy_steps[0].artifact == "poc.bin"
        assert plan.copy_steps[0].to == "/work/poc.bin"

    def test_the_comparison_ref_is_added(self) -> None:
        plan = build_plan_from_claim(Claim(), ref="v1", comparison_ref="v2")
        assert plan.compare_steps[0].ref == "v2"

    def test_a_non_default_configuration_is_marked(self) -> None:
        claim = Claim(non_default_config=True)
        plan = build_plan_from_claim(claim, ref="v1")
        assert plan.default_config is False

    def test_the_plan_renders_as_text(self) -> None:
        claim = Claim(poc_commands=(PoCCommand(command="./demo poc.bin"),))
        plan = build_plan_from_claim(claim, ref="v1")
        rendered = plan.to_text()
        assert "checkout ref=v1" in rendered
        assert "run cmd='./demo poc.bin'" in rendered

    def test_the_model_can_draft_a_plan(self) -> None:
        class _Provider:
            name = "fake"
            model = "fake"

            def complete_json(self, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
                return (
                    {
                        "commands": ["./model-demo poc.bin"],
                        "expect_kind": "crash",
                        "expect_signature": "segfault",
                        "comparison_ref": "v2",
                        "build_flags": ["asan"],
                    },
                    {"provider": "fake", "model": "fake"},
                )

        claim = Claim(poc_commands=(PoCCommand(command="./demo poc.bin"),))
        plan = Planner(_Provider()).plan(claim, ref="v1")
        assert plan.run_step.cmd == "./model-demo poc.bin"
        assert plan.source.value == "model"

    def test_a_failing_model_falls_back_to_the_heuristics(self) -> None:
        from verdis.extract.providers import ProviderUnavailable

        class _Broken:
            name = "broken"
            model = "broken"

            def complete_json(self, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
                raise ProviderUnavailable("no model")

        claim = Claim(poc_commands=(PoCCommand(command="./demo poc.bin"),))
        plan = Planner(_Broken()).plan(claim, ref="v1")
        assert plan.run_step.cmd == "./demo poc.bin"
        assert plan.source.value == "heuristic"

    def test_a_model_that_drafts_nothing_falls_back(self) -> None:
        class _Empty:
            name = "empty"
            model = "empty"

            def complete_json(self, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
                return ({"commands": []}, {"provider": "empty", "model": "empty"})

        claim = Claim(poc_commands=(PoCCommand(command="./demo poc.bin"),))
        plan = Planner(_Empty()).plan(claim, ref="v1")
        assert plan.run_step.cmd == "./demo poc.bin"

    def test_the_rrs_block_is_preferred(self) -> None:
        from verdis.schemas.rrs import RRS, RRSPlanStep, RRSTarget

        rrs = RRS(
            target=RRSTarget(repo="r", ref="v9"),
            steps=(RRSPlanStep(action="run", value="./from-rrs poc.bin"),),
        )
        plan = Planner(NullProvider()).plan(Claim(), ref="v1", rrs=rrs)
        assert plan.run_step.cmd == "./from-rrs poc.bin"
        assert plan.source.value == "rrs"


class TestBuilder:
    def _project(self, tmp_path: Path, makefile: str) -> Path:
        project = tmp_path / "project"
        project.mkdir()
        (project / "Makefile").write_text(makefile, encoding="utf-8")
        return project

    def test_a_missing_recipe_is_unsupported(self, tmp_path: Path) -> None:
        result = Builder(backend=LocalBackend()).build(repo_path=tmp_path)
        assert result.status.value == "unsupported"
        assert result.suggested_fix

    def test_a_build_that_fails_suggests_a_fix(self, tmp_path: Path) -> None:
        project = self._project(tmp_path, "all:\n\tfalse\n")
        result = Builder(backend=LocalBackend()).build(repo_path=project)
        assert result.status.value == "failed"
        assert result.failure_step
        assert result.log_excerpt
        assert result.suggested_fix

    def test_a_missing_tool_is_diagnosed(self, tmp_path: Path) -> None:
        project = self._project(tmp_path, "all:\n\tdefinitely-not-a-tool\n")
        result = Builder(backend=LocalBackend()).build(repo_path=project)
        assert "command not found" in result.log_excerpt.lower() or "missing" in (
            result.suggested_fix.lower()
        )

    def test_the_build_environment_carries_the_mirror_allowlist(
        self, tmp_path: Path
    ) -> None:
        builder = Builder(backend=LocalBackend(), mirror_proxy="http://proxy:3128")
        recipe = recipe_from_dict({"language": "c", "build": {"steps": ["true"]}})
        env = builder._build_env(recipe)
        assert env["VERDIS_ALLOWED_MIRRORS"] == ",".join(DEFAULT_MIRRORS)
        assert env["HTTP_PROXY"] == "http://proxy:3128"

    def test_without_a_proxy_there_is_no_proxy_variable(self, tmp_path: Path) -> None:
        builder = Builder(backend=LocalBackend())
        recipe = recipe_from_dict({"language": "c", "build": {"steps": ["true"]}})
        assert "HTTP_PROXY" not in builder._build_env(recipe)

    def test_a_work_directory_inside_the_project_is_not_copied_into_itself(
        self, tmp_path: Path
    ) -> None:
        # An operator may point the work directory inside the project.
        # The staging copy has to leave it out, or it copies itself.
        project = self._project(tmp_path, "all:\n\t@echo built\n")
        work = project / "work"
        work.mkdir()
        builder = Builder(backend=LocalBackend(), work_dir=str(work))
        result = builder.build(repo_path=project)
        assert result.status.value == "ok"

    def test_the_build_is_cached(self, tmp_path: Path) -> None:
        project = self._project(tmp_path, "all:\n\t@echo built\n")
        cache = BuildCache(root=tmp_path / "cache")
        builder = Builder(backend=LocalBackend(), cache=cache)
        first = builder.build(repo_path=project, in_place=True)
        assert first.status.value == "ok"
        assert first.cached is False
        second = builder.build(repo_path=project, in_place=True)
        assert second.cached is True

    def test_the_cache_is_capped(self, tmp_path: Path) -> None:
        cache = BuildCache(root=tmp_path / "cache", max_bytes=1)
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.txt").write_text("x" * 100, encoding="utf-8")
        key = cache.key("v1", recipe_from_dict({"language": "c"}))
        cache.store(key, source)
        assert cache.enforce_cap()

    def test_the_cache_size_is_reported(self, tmp_path: Path) -> None:
        cache = BuildCache(root=tmp_path / "cache")
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.txt").write_text("x" * 100, encoding="utf-8")
        key = cache.key("v1", recipe_from_dict({"language": "c"}))
        cache.store(key, source)
        assert cache.size() > 0

    def test_a_dockerfile_mode_uses_the_base_image(self, tmp_path: Path) -> None:
        from verdis.build.recipe import detect_recipe

        project = tmp_path / "project"
        project.mkdir()
        (project / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
        recipe = detect_recipe(project)
        assert recipe is not None
        assert recipe.build.image == "python:3.12-slim"

    def test_a_dockerfile_without_a_from_has_no_image(self, tmp_path: Path) -> None:
        from verdis.build.recipe import detect_recipe

        project = tmp_path / "project"
        project.mkdir()
        (project / "Dockerfile").write_text("RUN true\n", encoding="utf-8")
        recipe = detect_recipe(project)
        assert recipe is not None
        assert recipe.build.image == ""

    def test_the_recipe_hash_changes_with_the_recipe(self) -> None:
        first = recipe_from_dict({"language": "c", "build": {"steps": ["a"]}})
        second = recipe_from_dict({"language": "c", "build": {"steps": ["b"]}})
        assert first.hash != second.hash
