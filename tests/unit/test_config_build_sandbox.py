"""Tests for configuration, recipes, the builder and the sandbox backends."""

from __future__ import annotations

from pathlib import Path

import pytest

from verdis.build.builder import BuildCache, Builder
from verdis.build.checkout import CheckoutError, checkout_ref
from verdis.build.recipe import (
    RecipeError,
    detect_recipe,
    load_recipe_file,
    recipe_from_dict,
    sanitizer_flags,
)
from verdis.config import Config, ConfigError, config_from_dict, load_config
from verdis.sandbox.base import (
    Mount,
    SandboxLimits,
    SandboxRequest,
    default_profile,
    hardened_profile,
)
from verdis.sandbox.container import build_container_args
from verdis.sandbox.local import LocalBackend


class TestConfig:
    def test_defaults_are_conservative(self) -> None:
        config = Config()
        assert config.mode == "shadow"
        assert config.auto_close is False
        assert config.sandbox == "default"

    def test_auto_close_is_never_enabled(self) -> None:
        config = config_from_dict({"actions": {"auto_close": True}})
        assert config.auto_close is False

    def test_an_invalid_mode_raises(self) -> None:
        with pytest.raises(ConfigError):
            config_from_dict({"mode": "yolo"})

    def test_an_invalid_sandbox_raises(self) -> None:
        with pytest.raises(ConfigError):
            config_from_dict({"sandbox": "chroot"})

    def test_an_out_of_range_threshold_raises(self) -> None:
        with pytest.raises(ConfigError):
            config_from_dict({"dedupe": {"threshold": 2}})

    def test_reads_the_documented_shape(self) -> None:
        config = config_from_dict(
            {
                "mode": "comment",
                "sandbox": "hardened",
                "llm": {"provider": "anthropic", "budget_tokens": 1000},
                "actions": {"post_comment": True, "apply_labels": True},
                "dedupe": {"threshold": 0.9},
            }
        )
        assert config.mode == "comment"
        assert config.llm.provider == "anthropic"
        assert config.llm.budget_tokens == 1000
        assert config.post_comment is True
        assert config.dedupe_threshold == 0.9

    def test_unknown_keys_are_kept_as_extras(self) -> None:
        config = config_from_dict({"mode": "shadow", "future_option": 1})
        assert config.extras["future_option"] == 1

    def test_loads_a_config_file(self, tmp_path: Path) -> None:
        (tmp_path / ".verdis").mkdir()
        (tmp_path / ".verdis" / "config.yml").write_text(
            "mode: label\nsandbox: hardened\n", encoding="utf-8"
        )
        config = load_config(tmp_path)
        assert config.mode == "label"
        assert config.sandbox == "hardened"

    def test_a_missing_config_gives_the_defaults(self, tmp_path: Path) -> None:
        assert load_config(tmp_path).mode == "shadow"

    def test_an_invalid_config_file_raises(self, tmp_path: Path) -> None:
        (tmp_path / ".verdis").mkdir()
        (tmp_path / ".verdis" / "config.yml").write_text("mode: [\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(tmp_path)


class TestRecipes:
    def test_detects_cmake(self, tmp_path: Path) -> None:
        (tmp_path / "CMakeLists.txt").write_text("project(x)\n", encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.language == "c"
        assert "asan" in recipe.build.flags

    def test_detects_make(self, tmp_path: Path) -> None:
        (tmp_path / "Makefile").write_text("all:\n\techo hi\n", encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.build.system == "make"

    def test_detects_go(self, tmp_path: Path) -> None:
        (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.language == "go"
        assert "race" in recipe.build.flags

    def test_detects_python(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.language == "python"

    def test_detects_node(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"name": "x"}', encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.language == "node"
        assert "--ignore-scripts" in recipe.build.steps[0]

    def test_detects_dockerfile_mode(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.build.system == "docker"

    def test_an_empty_directory_has_no_recipe(self, tmp_path: Path) -> None:
        assert detect_recipe(tmp_path) is None

    def test_loads_a_recipe_file(self, tmp_path: Path) -> None:
        path = tmp_path / "recipe.yml"
        path.write_text(
            "language: c\nbuild:\n  system: cmake\n  steps: ['cmake .']\n", encoding="utf-8"
        )
        recipe = load_recipe_file(path)
        assert recipe.language == "c"
        assert recipe.build.steps == ("cmake .",)

    def test_a_broken_recipe_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "recipe.yml"
        path.write_text("build: [unclosed\n", encoding="utf-8")
        with pytest.raises(RecipeError):
            load_recipe_file(path)

    def test_the_hash_is_stable(self) -> None:
        recipe = recipe_from_dict({"language": "c", "build": {"steps": ["a"]}})
        assert recipe.hash == recipe.hash
        other = recipe_from_dict({"language": "c", "build": {"steps": ["b"]}})
        assert recipe.hash != other.hash

    def test_sanitizer_flags(self) -> None:
        flags = sanitizer_flags(("asan", "ubsan"))
        assert "-fsanitize=address" in flags
        assert "-fsanitize=undefined" in flags
        assert sanitizer_flags(("unknown",)) == []


class TestCheckout:
    def test_a_plain_directory_is_used_as_is(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("x", encoding="utf-8")
        checkout = checkout_ref(tmp_path)
        assert checkout.method == "existing"
        assert checkout.path == tmp_path

    def test_a_missing_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(CheckoutError):
            checkout_ref(tmp_path / "nope")

    def test_a_ref_in_a_non_git_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(CheckoutError):
            checkout_ref(tmp_path, "v1.0")


class TestBuildCache:
    def test_stores_and_returns_a_build(self, tmp_path: Path) -> None:
        cache = BuildCache(root=tmp_path / "cache")
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.txt").write_text("x", encoding="utf-8")
        key = cache.key("v1", recipe_from_dict({"language": "c"}))
        assert cache.get(key) is None
        cache.store(key, source)
        assert cache.get(key) is not None

    def test_the_key_depends_on_the_ref(self, tmp_path: Path) -> None:
        cache = BuildCache(root=tmp_path / "cache")
        recipe = recipe_from_dict({"language": "c"})
        assert cache.key("v1", recipe) != cache.key("v2", recipe)

    def test_the_cap_removes_the_oldest_entries(self, tmp_path: Path) -> None:
        cache = BuildCache(root=tmp_path / "cache", max_bytes=1)
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.txt").write_text("x" * 100, encoding="utf-8")
        key = cache.key("v1", recipe_from_dict({"language": "c"}))
        cache.store(key, source)
        removed = cache.enforce_cap()
        assert removed
        assert cache.get(key) is None


class TestBuilder:
    def test_a_repository_without_a_recipe_is_unsupported(self, tmp_path: Path) -> None:
        result = Builder(backend=LocalBackend()).build(repo_path=tmp_path)
        assert result.status.value == "unsupported"
        assert result.suggested_fix

    def test_a_build_failure_is_inconclusive_with_a_suggestion(self, tmp_path: Path) -> None:
        (tmp_path / "Makefile").write_text("all:\n\tfalse\n", encoding="utf-8")
        result = Builder(backend=LocalBackend()).build(repo_path=tmp_path)
        assert result.status.value == "failed"
        assert result.failure_step
        assert result.log_excerpt
        assert result.suggested_fix

    def test_a_successful_build_is_ok(self, tmp_path: Path) -> None:
        (tmp_path / "Makefile").write_text("all:\n\t@echo built\n", encoding="utf-8")
        result = Builder(backend=LocalBackend()).build(repo_path=tmp_path)
        assert result.status.value == "ok"


class TestContainerArguments:
    def _request(self, **kwargs) -> SandboxRequest:
        base = {
            "image": "example@sha256:abc",
            "command": ["/bin/sh", "-c", "true"],
            "workdir": "/src",
            "mounts": [Mount(source="/host/src", target="/src", readonly=True)],
        }
        base.update(kwargs)
        return SandboxRequest(**base)

    def test_the_default_profile_is_hardened(self) -> None:
        args = build_container_args(self._request(), "podman")
        assert "--network" in args
        assert args[args.index("--network") + 1] == "none"
        assert "--read-only" in args
        assert "--cap-drop=ALL" in args
        assert "--security-opt" in args
        assert "no-new-privileges" in args
        assert "--user" in args
        assert "--pids-limit" in args
        assert "--memory" in args
        assert "--cpus" in args
        assert "--tmpfs" in args
        assert "--rm" in args

    def test_the_source_is_mounted_read_only(self) -> None:
        args = build_container_args(self._request(), "docker")
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]
        assert any("target=/src" in mount and "readonly" in mount for mount in mounts)

    def test_a_writable_mount_is_not_marked_read_only(self) -> None:
        request = self._request(
            mounts=[Mount(source="/host/src", target="/src", readonly=False)]
        )
        args = build_container_args(request, "docker")
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]
        assert any("target=/src" in mount and "readonly" not in mount for mount in mounts)

    def test_the_mount_uses_the_key_value_syntax(self) -> None:
        # The -v syntax ("ro", "rw") is rejected by --mount.
        args = build_container_args(self._request(), "docker")
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]
        for mount in mounts:
            assert mount.startswith("type=bind,")
            assert not mount.endswith(",ro")
            assert not mount.endswith(",rw")

    def test_the_hardened_profile_keeps_every_flag(self) -> None:
        request = self._request(profile=hardened_profile())
        args = build_container_args(request, "podman")
        assert "--network" in args
        assert "--read-only" in args

    def test_the_environment_is_explicit(self) -> None:
        request = self._request(env={"FOO": "bar"})
        args = build_container_args(request, "podman")
        assert "--env" in args
        assert "FOO=bar" in args

    def test_the_image_is_pinned(self) -> None:
        args = build_container_args(self._request(), "podman")
        assert "example@sha256:abc" in args


class TestLocalBackend:
    def test_it_runs_a_command(self, tmp_path: Path) -> None:
        backend = LocalBackend()
        request = SandboxRequest(
            image="",
            command=["/bin/sh", "-c", "echo hello"],
            workdir_source=str(tmp_path),
        )
        result = backend.run(request)
        assert result.exit_code == 0
        assert "hello" in result.stdout

    def test_it_scrubs_the_environment(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("SECRET_TOKEN", "hunter2")
        backend = LocalBackend()
        request = SandboxRequest(
            image="",
            command=["/bin/sh", "-c", "echo [$SECRET_TOKEN]"],
            workdir_source=str(tmp_path),
        )
        result = backend.run(request)
        assert "hunter2" not in result.stdout

    def test_it_reports_a_timeout(self, tmp_path: Path) -> None:
        backend = LocalBackend()
        request = SandboxRequest(
            image="",
            command=["/bin/sh", "-c", "sleep 5"],
            workdir_source=str(tmp_path),
            limits=SandboxLimits(timeout_s=1),
        )
        result = backend.run(request)
        assert result.timed_out

    def test_it_reports_a_missing_program(self, tmp_path: Path) -> None:
        backend = LocalBackend()
        request = SandboxRequest(
            image="",
            command=["/nonexistent/program"],
            workdir_source=str(tmp_path),
        )
        result = backend.run(request)
        assert result.exit_code != 0

    def test_it_records_a_network_attempt(self, tmp_path: Path) -> None:
        backend = LocalBackend()
        request = SandboxRequest(
            image="",
            command=[
                "/bin/sh",
                "-c",
                "python3 -c 'import socket;socket.create_connection((\"127.0.0.1\",1),1)'",
            ],
            workdir_source=str(tmp_path),
        )
        result = backend.run(request)
        assert result.blocked_network

    def test_it_warns_that_it_is_not_a_boundary(self) -> None:
        assert LocalBackend().doctor()


class TestProfiles:
    def test_the_default_profile_has_no_network(self) -> None:
        assert default_profile().network == "none"

    def test_the_hardened_profile_is_marked(self) -> None:
        assert hardened_profile().hardened

    def test_the_user_is_not_root(self) -> None:
        assert default_profile().user != "0:0"
