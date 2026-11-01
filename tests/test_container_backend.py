"""ContainerBackend tests against a MOCKED command runner.

These verify argv construction, fail-closed behaviour, error typing, verification logic and cleanup
ORCHESTRATION. They do NOT prove OS-level confinement — a scripted fake CLI cannot. Real isolation is
checked in test_container_real.py, which runs actual containers and is skipped when none are available."""
from __future__ import annotations

import asyncio
import json
import re

import pytest

from app.sandbox.container import ENTRY_SCRIPT, MARKER, CommandResult, ContainerBackend, _parse_marker
from app.sandbox.errors import IsolationFailure, IsolationUnavailableError
from app.sandbox.manager import SandboxManager
from app.sandbox.models import SandboxOperation
from app.sandbox.policy import SandboxPolicy
from tests.improvement_helpers import make_project

GOOD_OBS = {"uid": 65534, "cap_eff": "0000000000000000", "no_new_privs": 1, "net_interfaces": ["lo"], "net_connect_blocked": True,
            "rootfs_writable": False, "snapshot_writable": False, "work_writable": True, "writable_non_tmpfs_mounts": [],
            "control_sockets_present": [], "unexpected_env": []}
IMAGE_ID = "sha256:" + "a" * 64


def marker(payload: dict, before: str = "") -> str:
    return f"{before}\n{MARKER}{json.dumps(payload)}\n"


class FakeRunner:
    """Scripted stand-in for the container CLI. `overrides` maps a predicate on argv to a CommandResult."""

    def __init__(self, obs=None, run_result=None, overrides=None):
        self.calls: list[list[str]] = []
        self.obs = obs if obs is not None else GOOD_OBS
        self.run_result = run_result
        self.overrides = overrides or []
        self.image_id = IMAGE_ID
        self.stale = ""

    def kinds(self):
        out = []
        for a in self.calls:
            for k in ("version", "inspect", "ps", "rm", "run"):
                if k in a:
                    out.append(k)
                    break
        return out

    async def run(self, argv, timeout, max_output):
        argv = list(argv)
        self.calls.append(argv)
        for predicate, result in self.overrides:
            if predicate(argv):
                return result() if callable(result) else result
        if "version" in argv:
            return CommandResult(0, "4.9.3\n")
        if "inspect" in argv:
            return CommandResult(0, self.image_id + "\n")
        if "ps" in argv:
            return CommandResult(0, self.stale)
        if "rm" in argv:
            return CommandResult(0, "")
        if "run" in argv:
            if "JARVISX_OPERATION=probe" in argv:
                return CommandResult(0, marker(self.obs))
            return self.run_result or CommandResult(0, marker({"exit": 0, "counts": {"passed": 3, "failed": 0, "skipped": 0, "errors": 0}}, "...\n3 passed"))
        raise AssertionError(f"unexpected CLI call: {argv}")


def backend(runner=None, tmp_path=None, available=("docker", "podman"), cli="auto", **kw):
    return ContainerBackend(SandboxPolicy(timeout_seconds=30), cli=cli, image="jarvisx-validation:1", scratch_dir=tmp_path,
                            runner=runner or FakeRunner(), which=lambda n: f"/usr/bin/{n}" if n in available else None, **kw)


def sandbox_for(tmp_path, be):
    project = make_project(tmp_path / "rel")
    sm = SandboxManager(tmp_path / "sb", SandboxPolicy(timeout_seconds=30), be)
    sm.create("cand-mock00000001", project)
    return sm


def run(coro):
    return asyncio.run(coro)


# --- argv: the security profile ------------------------------------------------------------------------


def test_profile_contains_every_required_restriction(tmp_path):
    be = backend()
    args = be.security_args("podman", "jarvisx-val-abcdef12", tmp_path.resolve(), "run_test_suite")
    joined = " ".join(args)
    for required in ("--network none", "--user 65534:65534", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                     "--pull=never", "--pids-limit 256", "--memory 2048m", "--memory-swap 2048m", "--label jarvisx.validation=1",
                     "--ulimit nofile=1024:1024", "--ulimit core=0", "--entrypoint python3", "--workdir /work"):
        assert required in joined, required
    assert re.search(r"--tmpfs /work:rw,nosuid,nodev,size=\d+m,mode=1777", joined) and re.search(r"--tmpfs /tmp:rw,noexec,nosuid,nodev,size=\d+m", joined)


def test_profile_never_grants_privileges_or_host_access(tmp_path):
    args = backend().security_args("docker", "jarvisx-val-abcdef12", tmp_path.resolve(), "run_test_suite")
    joined = " ".join(args)
    for forbidden in ("--privileged", "--cap-add", "--device", "--pid host", "--ipc host", "--network host", "--network bridge", "--userns host",
                      "--env-file", "--volume", " -v ", "docker.sock", "podman.sock", "--security-opt seccomp=unconfined",
                      "--security-opt apparmor=unconfined", "--security-opt label=disable", "--net host", "--uts host", "--mount type=volume"):
        assert forbidden not in joined, forbidden
    mounts = [args[i + 1] for i, a in enumerate(args) if a == "--mount"]
    assert mounts == [f"type=bind,src={tmp_path.resolve()},dst=/snapshot,readonly"]
    assert "--user" in args and args[args.index("--user") + 1] == "65534:65534"


def test_every_environment_entry_is_a_constant_never_passed_through(tmp_path):
    args = backend().security_args("podman", "jarvisx-val-abcdef12", tmp_path.resolve(), "run_test_suite")
    envs = [args[i + 1] for i, a in enumerate(args) if a in ("--env", "-e")]
    assert envs and all("=" in e for e in envs)  # KEY=value only; a bare KEY would copy the host value
    assert {e.split("=")[0] for e in envs} == {"HOME", "LANG", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "JARVIS_VALIDATION_SANDBOX", "JARVISX_OPERATION"}


def test_command_after_the_image_is_the_fixed_entry_script_only(tmp_path):
    be = backend()
    argv = be.run_argv("podman", "/usr/bin/podman", "jarvisx-val-abcdef12", tmp_path.resolve(), "run_static_analysis")
    i = argv.index("jarvisx-validation:1")
    assert argv[i + 1:] == ["-c", ENTRY_SCRIPT]
    assert argv[:2] == ["/usr/bin/podman", "run"] and "JARVISX_OPERATION=run_static_analysis" in argv


def test_oci_runtime_flag_placement_differs_by_cli(tmp_path):
    be = backend(oci_runtime="runsc")
    podman = be.run_argv("podman", "/usr/bin/podman", "jarvisx-val-abcdef12", tmp_path.resolve(), "probe")
    docker = be.run_argv("docker", "/usr/bin/docker", "jarvisx-val-abcdef12", tmp_path.resolve(), "probe")
    assert podman[:4] == ["/usr/bin/podman", "--runtime", "runsc", "run"] and "--runtime" not in podman[4:]
    assert docker[:2] == ["/usr/bin/docker", "run"] and docker[docker.index("--runtime") + 1] == "runsc"


@pytest.mark.parametrize("path", ["relative/path", "/tmp/a,b", "/tmp/a b", "/tmp/a\"b", "/tmp/a;rm", "/tmp/a'b", "/tmp/a\nb", "/tmp/a=b,dst=/etc", ""])
def test_unsafe_snapshot_paths_cannot_inject_mount_options(path):
    from pathlib import Path
    with pytest.raises(IsolationUnavailableError) as ei:
        backend().security_args("podman", "jarvisx-val-abcdef12", Path(path), "run_test_suite")
    assert ei.value.reason is IsolationFailure.MISCONFIGURED


@pytest.mark.parametrize("kwargs", [dict(cli="lxc"), dict(image="bad image"), dict(image="--privileged"), dict(image=""), dict(oci_runtime="runc --evil"),
                                    dict(oci_runtime="../x")])
def test_misconfiguration_is_rejected(kwargs):
    base = dict(cli="auto", image="jarvisx-validation:1", oci_runtime=None)
    base.update(kwargs)
    with pytest.raises(IsolationUnavailableError) as ei:
        ContainerBackend(SandboxPolicy(), runner=FakeRunner(), **base)
    assert ei.value.reason is IsolationFailure.MISCONFIGURED


def test_invalid_container_names_are_rejected(tmp_path):
    with pytest.raises(IsolationUnavailableError):
        backend().security_args("podman", "bad name;x", tmp_path.resolve(), "run_test_suite")


# --- missing / broken runtime: fail closed ---------------------------------------------------------------


def test_missing_runtime_fails_closed_without_running_anything(tmp_path):
    runner = FakeRunner()
    be = backend(runner, tmp_path, available=())
    with pytest.raises(IsolationUnavailableError) as ei:
        run(be.preflight())
    assert ei.value.reason is IsolationFailure.NO_CONTAINER_RUNTIME and "nothing was executed" in str(ei.value)
    sm = sandbox_for(tmp_path, be)
    with pytest.raises(IsolationUnavailableError):
        run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert runner.calls == []  # not even a probe


def test_auto_prefers_docker_then_podman_and_explicit_choice_is_honoured(tmp_path):
    assert backend(tmp_path=tmp_path)._resolve_cli() == ("docker", "/usr/bin/docker")
    assert backend(tmp_path=tmp_path, available=("podman",))._resolve_cli() == ("podman", "/usr/bin/podman")
    assert backend(tmp_path=tmp_path, cli="podman")._resolve_cli()[0] == "podman"
    with pytest.raises(IsolationUnavailableError):
        backend(tmp_path=tmp_path, cli="docker", available=("podman",))._resolve_cli()


def test_relative_cli_path_is_not_trusted(tmp_path):
    be = ContainerBackend(SandboxPolicy(), cli="docker", runner=FakeRunner(), which=lambda n: "docker")
    with pytest.raises(IsolationUnavailableError):
        be._resolve_cli()


def test_backend_startup_failure_runtime_not_usable(tmp_path):
    runner = FakeRunner(overrides=[(lambda a: "version" in a, CommandResult(1, "", "Cannot connect to the Docker daemon"))])
    with pytest.raises(IsolationUnavailableError) as ei:
        run(backend(runner, tmp_path).preflight())
    assert ei.value.reason is IsolationFailure.RUNTIME_NOT_USABLE and "daemon" in str(ei.value)
    assert "run" not in runner.kinds()
    assert "Cannot connect" not in str(ei.value)  # raw runtime output is never echoed


def test_cli_cannot_be_executed_is_typed(tmp_path):
    class Exploding(FakeRunner):
        async def run(self, argv, timeout, max_output):
            raise FileNotFoundError("/usr/bin/docker")

    with pytest.raises(IsolationUnavailableError) as ei:
        run(backend(Exploding(), tmp_path).preflight())
    assert ei.value.reason is IsolationFailure.RUNTIME_NOT_USABLE


def test_missing_image_fails_closed(tmp_path):
    runner = FakeRunner(overrides=[(lambda a: "inspect" in a, CommandResult(1, "", "no such image"))])
    with pytest.raises(IsolationUnavailableError) as ei:
        run(backend(runner, tmp_path).preflight())
    assert ei.value.reason is IsolationFailure.IMAGE_NOT_FOUND and "docker/validation.Dockerfile" in str(ei.value)
    assert "run" not in runner.kinds()


def test_unexpected_image_id_is_a_misconfiguration(tmp_path):
    runner = FakeRunner()
    runner.image_id = "not an id; rm -rf"
    with pytest.raises(IsolationUnavailableError) as ei:
        run(backend(runner, tmp_path).preflight())
    assert ei.value.reason is IsolationFailure.MISCONFIGURED


# --- canary: restrictions must be VERIFIED from inside --------------------------------------------------


def test_good_canary_yields_a_satisfying_attestation(tmp_path):
    att = run(backend(FakeRunner(), tmp_path).preflight())
    assert att.satisfies_requirements() and att.backend == "docker" and att.network == "none" and att.user == "65534:65534"
    assert att.image_id == IMAGE_ID and att.host_mounts == ["snapshot:ro"] and att.writable_host_mounts == 0 and att.canary_passed


@pytest.mark.parametrize("key,bad", [
    ("uid", 0), ("uid", 1000), ("cap_eff", "00000000a80425fb"), ("cap_eff", "garbage"), ("no_new_privs", 0), ("net_interfaces", ["lo", "eth0"]),
    ("net_interfaces", None), ("net_connect_blocked", False), ("net_connect_blocked", None), ("rootfs_writable", True), ("rootfs_writable", None),
    ("snapshot_writable", True), ("work_writable", False), ("writable_non_tmpfs_mounts", ["/home/user"]), ("control_sockets_present", ["/var/run/docker.sock"]),
    ("unexpected_env", ["AWS_SECRET_ACCESS_KEY"]),
])
def test_canary_observation_failures_fail_closed(tmp_path, key, bad):
    obs = {**GOOD_OBS, key: bad}
    runner = FakeRunner(obs=obs)
    with pytest.raises(IsolationUnavailableError) as ei:
        run(backend(runner, tmp_path).preflight())
    assert ei.value.reason is IsolationFailure.RESTRICTIONS_NOT_ESTABLISHED and "nothing was executed" in str(ei.value)
    sm = sandbox_for(tmp_path, backend(runner, tmp_path))
    with pytest.raises(IsolationUnavailableError):
        run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert not any("JARVISX_OPERATION=run_test_suite" in a for call in runner.calls for a in call)  # the candidate was never started


def test_missing_observation_keys_fail_closed(tmp_path):
    with pytest.raises(IsolationUnavailableError):
        run(backend(FakeRunner(obs={"uid": 65534}), tmp_path).preflight())


@pytest.mark.parametrize("result", [CommandResult(125, "", "OCI runtime error"), CommandResult(None, timed_out=True), CommandResult(0, "no marker here"),
                                    CommandResult(0, f"{MARKER}{{not json")])
def test_canary_startup_failure_fails_closed(tmp_path, result):
    runner = FakeRunner(overrides=[(lambda a: "JARVISX_OPERATION=probe" in a, result)])
    with pytest.raises(IsolationUnavailableError) as ei:
        run(backend(runner, tmp_path).preflight())
    assert ei.value.reason is IsolationFailure.STARTUP_FAILED
    assert "OCI runtime error" not in str(ei.value)


def test_canary_container_is_removed_even_on_failure(tmp_path):
    runner = FakeRunner(obs={**GOOD_OBS, "uid": 0})
    with pytest.raises(IsolationUnavailableError):
        run(backend(runner, tmp_path).preflight())
    removed = [a for a in runner.calls if "rm" in a and any(x.startswith("jarvisx-canary-") for x in a)]
    assert removed and removed[0][-2:-1] == ["-f"]
    assert list((tmp_path).glob("canary-*")) == []  # the scratch snapshot dir is gone too


def test_check_observations_unit():
    assert ContainerBackend.check_observations(GOOD_OBS) == []
    assert len(ContainerBackend.check_observations({**GOOD_OBS, "uid": 0, "net_connect_blocked": False})) == 2


# --- running an operation ---------------------------------------------------------------------------------


def test_successful_run_carries_the_attestation_and_cleans_up(tmp_path):
    runner = FakeRunner()
    sm = sandbox_for(tmp_path, backend(runner, tmp_path))
    res = run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert res.exit_code == 0 and res.reported["counts"]["passed"] == 3 and res.isolation.satisfies_requirements()
    assert "3 passed" in res.stdout and MARKER not in res.stdout and res.timed_out is False
    run_call = next(a for a in runner.calls if "run" in a and "JARVISX_OPERATION=run_test_suite" in a)
    name = run_call[run_call.index("--name") + 1]
    assert re.match(r"^jarvisx-val-cand-mock00000001-[0-9a-f]{8}$", name)
    assert any(a[-3:] == ["rm", "-f", name] for a in runner.calls)  # deterministic cleanup
    assert str(sm.paths("cand-mock00000001").source) in " ".join(run_call)  # the mounted source is the candidate's


def test_timeout_is_reported_and_the_container_is_still_removed(tmp_path):
    runner = FakeRunner(overrides=[(lambda a: "run" in a and "JARVISX_OPERATION=run_test_suite" in a, CommandResult(None, timed_out=True, truncated=True))])
    sm = sandbox_for(tmp_path, backend(runner, tmp_path))
    res = run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert res.timed_out is True and res.exit_code is None
    assert any(a[-3:-1] == ["rm", "-f"] and a[-1].startswith("jarvisx-val-") for a in runner.calls)


def test_runner_crash_still_triggers_cleanup(tmp_path):
    class Crashing(FakeRunner):
        async def run(self, argv, timeout, max_output):
            if "run" in argv and "JARVISX_OPERATION=run_test_suite" in argv:
                raise RuntimeError("host process crashed")
            return await super().run(argv, timeout, max_output)

    runner = Crashing()
    sm = sandbox_for(tmp_path, backend(runner, tmp_path))
    with pytest.raises(RuntimeError):
        run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert any(a[-3:-1] == ["rm", "-f"] and a[-1].startswith("jarvisx-val-") for a in runner.calls)


@pytest.mark.parametrize("result", [CommandResult(125, "", "cannot start"), CommandResult(126, "no marker"), CommandResult(127, "")])
def test_container_that_cannot_start_is_an_isolation_error_not_a_result(tmp_path, result):
    runner = FakeRunner(overrides=[(lambda a: "run" in a and "JARVISX_OPERATION=run_test_suite" in a, result)])
    sm = sandbox_for(tmp_path, backend(runner, tmp_path))
    with pytest.raises(IsolationUnavailableError) as ei:
        run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert ei.value.reason is IsolationFailure.STARTUP_FAILED and "cannot start" not in str(ei.value)


def test_resource_limit_kill_is_flagged(tmp_path):
    runner = FakeRunner(run_result=CommandResult(137, "partial output"))
    sm = sandbox_for(tmp_path, backend(runner, tmp_path))
    res = run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert res.resource_limit_exit is True and res.exit_code == 137 and res.reported is None


def test_candidate_failure_is_a_normal_result(tmp_path):
    runner = FakeRunner(run_result=CommandResult(1, marker({"exit": 1, "counts": {"passed": 1, "failed": 2, "skipped": 0, "errors": 0}}, "FAILED")))
    sm = sandbox_for(tmp_path, backend(runner, tmp_path))
    res = run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert res.exit_code == 1 and res.reported["counts"]["failed"] == 2 and res.resource_limit_exit is False


def test_attestation_is_reused_within_the_ttl_but_image_changes_force_reverification(tmp_path):
    runner = FakeRunner()
    sm = sandbox_for(tmp_path, backend(runner, tmp_path))
    run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    run(sm.run("cand-mock00000001", SandboxOperation.RUN_STATIC_ANALYSIS))
    probes = lambda: sum(1 for a in runner.calls if "run" in a and "JARVISX_OPERATION=probe" in a)  # noqa: E731
    assert probes() == 1
    runner.image_id = "sha256:" + "b" * 64  # the image was replaced after verification
    res = run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert probes() == 2 and res.isolation.image_id == "sha256:" + "b" * 64


def test_expired_attestation_is_reverified(tmp_path):
    runner = FakeRunner()
    sm = sandbox_for(tmp_path, backend(runner, tmp_path, attestation_ttl_seconds=0.0))
    run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    assert sum(1 for a in runner.calls if "JARVISX_OPERATION=probe" in a) == 2


def test_a_failed_reverification_blocks_the_run(tmp_path):
    runner = FakeRunner()
    sm = sandbox_for(tmp_path, backend(runner, tmp_path))
    run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))
    runner.image_id = "sha256:" + "c" * 64
    runner.obs = {**GOOD_OBS, "net_connect_blocked": False}  # the new image/runtime no longer isolates
    with pytest.raises(IsolationUnavailableError):
        run(sm.run("cand-mock00000001", SandboxOperation.RUN_TEST_SUITE))


def test_stale_containers_are_removed_at_preflight_and_names_are_validated(tmp_path):
    runner = FakeRunner()
    runner.stale = "jarvisx-val-cand-old00001-abcd1234\nevil;name\njarvisx-canary-deadbeef0000\n"
    run(backend(runner, tmp_path).preflight())
    removed = [a[-1] for a in runner.calls if a[-3:-1] == ["rm", "-f"]]
    assert "jarvisx-val-cand-old00001-abcd1234" in removed and "jarvisx-canary-deadbeef0000" in removed and "evil;name" not in removed
    assert run(backend(FakeRunner(), tmp_path).cleanup_stale()) == 0


def test_disallowed_operation_is_refused_by_the_backend(tmp_path):
    be = ContainerBackend(SandboxPolicy(allowed_operations=frozenset({SandboxOperation.RUN_STATIC_ANALYSIS})), runner=FakeRunner(),
                          which=lambda n: "/usr/bin/" + n)
    sm = SandboxManager(tmp_path / "sb", SandboxPolicy(), be)
    sm.create("cand-mock00000001", make_project(tmp_path / "rel"))
    with pytest.raises(IsolationUnavailableError):
        run(be.run(sm.paths("cand-mock00000001"), SandboxOperation.RUN_TEST_SUITE))


def test_marker_parsing_takes_the_last_valid_line():
    text = f"x\n{MARKER}" + '{"exit": 5}' + f"\nnoise\n{MARKER}" + '{"exit": 0}' + f"\n{MARKER}garbage\n"
    assert _parse_marker(text) == {"exit": 0}
    assert _parse_marker("nothing") is None and _parse_marker(f"{MARKER}[1,2]") is None


def test_entry_script_contains_only_the_fixed_operations():
    assert "run_test_suite" in ENTRY_SCRIPT and "run_static_analysis" in ENTRY_SCRIPT and 'sys.executable, "-m", "pytest"' in ENTRY_SCRIPT
    assert "os.system" not in ENTRY_SCRIPT and "shell=True" not in ENTRY_SCRIPT


def test_container_cli_runs_from_a_neutral_directory_not_the_project(tmp_path):
    """Regression: Podman's monitor wrote an `oom` file into the project root (its cwd) after an OOM kill."""
    import os
    import sys
    from app.sandbox.container import SubprocessRunner
    probe = [sys.executable, "-c", "import os; print(os.getcwd())"]
    res = run(SubprocessRunner(cwd=tmp_path / "neutral").run(probe, 30, 10_000))
    assert res.stdout.strip() == str((tmp_path / "neutral").resolve()) and res.stdout.strip() != os.getcwd()
    default = run(SubprocessRunner().run(probe, 30, 10_000))
    assert default.stdout.strip() != os.getcwd()
    real = ContainerBackend(SandboxPolicy(), scratch_dir=tmp_path / "scratch")
    assert real._runner._cwd == str(tmp_path / "scratch") and real._runner._cwd != os.getcwd()  # type: ignore[attr-defined]
