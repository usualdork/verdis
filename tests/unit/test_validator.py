"""Tests for the plan validator, the allowlist enforcement point (FR-6)."""

from __future__ import annotations

import pytest

from verdis.planner.validator import PlanValidator, Severity
from verdis.schemas.plan import (
    BuildStep,
    CheckoutStep,
    CopyStep,
    ExpectStep,
    Plan,
    RunStep,
)


def _plan(cmd: str, **kwargs) -> Plan:
    return Plan(
        steps=(
            CheckoutStep(ref="v1"),
            RunStep(cmd=cmd, **kwargs),
            ExpectStep(oracle="crash"),
        )
    )


class TestNetworkIsForbidden:
    @pytest.mark.parametrize(
        "cmd",
        [
            "curl http://example.org",
            "wget http://example.org/x",
            "nc 10.0.0.1 4444",
            "ssh user@host",
            "scp file host:/tmp",
            "ping 8.8.8.8",
            "dig example.org",
            "git clone https://example.org/x",
            "python3 -c import urllib.request",
        ],
    )
    def test_network_commands_are_forbidden(self, cmd: str) -> None:
        validation = PlanValidator().validate(_plan(cmd))
        assert validation.forbidden
        assert any(issue.code == "network-access" for issue in validation.issues)
        assert not validation.ok

    def test_a_url_anywhere_is_forbidden(self) -> None:
        validation = PlanValidator().validate(_plan("./demo http://example.org"))
        assert any(issue.code == "network-access" for issue in validation.issues)


class TestHostAccessIsForbidden:
    @pytest.mark.parametrize(
        "cmd",
        [
            "mount /dev/sda1 /mnt",
            "nsenter -t 1 -m sh",
            "chroot /host /bin/sh",
            "docker run alpine",
            "podman ps",
            "systemctl status nginx",
            "iptables -L",
            "sudo apt update",
            "kill -9 1",
            "insmod evil.ko",
        ],
    )
    def test_host_commands_are_forbidden(self, cmd: str) -> None:
        validation = PlanValidator().validate(_plan(cmd))
        assert validation.forbidden
        assert any(issue.code == "host-access" for issue in validation.issues)


class TestSecretAccessIsForbidden:
    @pytest.mark.parametrize(
        "cmd",
        [
            "cat /etc/shadow",
            "cat ~/.ssh/id_rsa",
            "cat /root/.ssh/id_ed25519",
            "ls ~/.aws/credentials",
            "cat /proc/self/environ",
            "printenv",
            "echo $AWS_SECRET_ACCESS_KEY",
            "echo ${GITHUB_TOKEN}",
        ],
    )
    def test_secret_access_is_forbidden(self, cmd: str) -> None:
        validation = PlanValidator().validate(_plan(cmd))
        assert validation.forbidden
        assert any(issue.code == "secret-access" for issue in validation.issues)


class TestConfirmationRequired:
    @pytest.mark.parametrize(
        "cmd",
        [
            "pip install numpy",
            "npm install lodash",
            "apt install cowsay",
            "apt-get install cowsay",
            "go get example.org/pkg",
            "cargo add serde",
            "chmod 777 /work/out",
            "rm -rf /work/tmp",
            "mkdir /etc/thing",
            "useradd bob",
            "crontab -",
        ],
    )
    def test_unusual_commands_need_confirmation(self, cmd: str) -> None:
        validation = PlanValidator().validate(_plan(cmd))
        assert validation.needs_confirmation
        assert not validation.forbidden
        assert not validation.ok
        assert validation.runnable


class TestShellSafety:
    @pytest.mark.parametrize(
        "cmd",
        [
            "./demo; rm -rf /",
            "./demo && curl http://x",
            "./demo | tee out",
            "echo `whoami`",
            "echo $(id)",
            "./demo > /etc/passwd",
            "./demo < /etc/passwd",
        ],
    )
    def test_shell_metacharacters_are_forbidden(self, cmd: str) -> None:
        validation = PlanValidator().validate(_plan(cmd))
        assert validation.forbidden
        assert any(issue.code == "shell-metacharacter" for issue in validation.issues)

    def test_path_traversal_in_the_program_is_forbidden(self) -> None:
        validation = PlanValidator().validate(_plan("../../etc/passwd"))
        assert any(issue.code == "path-traversal" for issue in validation.issues)

    def test_an_unparsable_command_is_forbidden(self) -> None:
        validation = PlanValidator().validate(_plan('./demo "unclosed'))
        assert any(issue.code == "unparsable-command" for issue in validation.issues)

    def test_an_empty_command_is_forbidden(self) -> None:
        validation = PlanValidator().validate(_plan("   "))
        assert any(issue.code == "empty-command" for issue in validation.issues)


class TestCopySteps:
    def test_copy_outside_the_workdir_is_forbidden(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                CopyStep(artifact="poc.bin", to="/etc/poc.bin"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert any(issue.code == "copy-outside-workdir" for issue in validation.issues)

    def test_copy_with_traversal_is_forbidden(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                CopyStep(artifact="poc.bin", to="/work/../etc/poc.bin"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert any(issue.code == "copy-path-traversal" for issue in validation.issues)

    def test_copy_source_must_be_a_bare_name(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                CopyStep(artifact="/etc/passwd", to="/work/passwd"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert any(issue.code == "copy-source-escape" for issue in validation.issues)

    def test_a_normal_copy_is_allowed(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo /work/poc.bin"),
                CopyStep(artifact="poc.bin", to="/work/poc.bin"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert validation.ok


class TestRefs:
    def test_an_option_like_ref_is_forbidden(self) -> None:
        plan = Plan(
            steps=(
                CheckoutStep(ref="--upload-pack=evil"),
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert any(issue.code == "option-like-ref" for issue in validation.issues)

    def test_a_ref_with_metacharacters_is_forbidden(self) -> None:
        plan = Plan(
            steps=(
                CheckoutStep(ref="v1; rm -rf /"),
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert any(issue.code == "unsafe-ref" for issue in validation.issues)

    def test_a_normal_ref_is_allowed(self) -> None:
        assert PlanValidator().validate(_plan("./demo")).ok


class TestBuildSteps:
    def test_a_build_step_reaching_the_network_warns(self) -> None:
        plan = Plan(
            steps=(
                BuildStep(recipe="pip", steps=("pip install .",)),
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert any(issue.code == "build-network-access" for issue in validation.issues)

    def test_a_build_step_touching_the_host_is_forbidden(self) -> None:
        plan = Plan(
            steps=(
                BuildStep(recipe="x", steps=("mount /dev/sda /mnt",)),
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert any(issue.code == "build-host-access" for issue in validation.issues)


class TestExpectSteps:
    def test_an_invalid_regex_is_forbidden(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                ExpectStep(oracle="output", regex="([unclosed"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert any(issue.code == "invalid-regex" for issue in validation.issues)


class TestSafePlans:
    @pytest.mark.parametrize(
        "cmd",
        [
            "./build/parse_demo /work/poc.bin",
            "python3 -m pytest tests/test_x.py",
            "node dist/index.js /work/poc.bin",
            "go run . /work/poc.bin",
            "/work/demo --flag value",
        ],
    )
    def test_ordinary_commands_pass(self, cmd: str) -> None:
        validation = PlanValidator().validate(_plan(cmd))
        assert validation.ok
        assert not validation.forbidden
        assert not validation.needs_confirmation

    def test_a_non_default_configuration_warns(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            ),
            default_config=False,
        )
        validation = PlanValidator().validate(plan)
        assert any(issue.severity is Severity.WARNING for issue in validation.issues)
        assert validation.ok


class TestPlanShape:
    def test_a_plan_without_a_run_step_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="run step"):
            Plan(steps=(CheckoutStep(ref="v1"), ExpectStep(oracle="crash")))

    def test_a_plan_without_an_expect_step_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="expect step"):
            Plan(steps=(RunStep(cmd="./demo"),))

    def test_two_run_steps_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="exactly one run step"):
            Plan(steps=(RunStep(cmd="./a"), RunStep(cmd="./b"), ExpectStep(oracle="crash")))

    def test_expect_must_follow_the_run(self) -> None:
        with pytest.raises(ValueError, match="must follow"):
            Plan(steps=(ExpectStep(oracle="crash"), RunStep(cmd="./a")))
