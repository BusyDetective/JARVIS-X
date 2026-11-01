"""REAL isolation integration tests: actual containers, no mocked CLI.

They need a working docker/podman and the validation image (see docker/validation.Dockerfile); otherwise the
`container_backend` fixture SKIPS them (they are never reported as passed without running). What they establish:
properties of the container boundary observed from inside it — NOT that escape is impossible."""
from __future__ import annotations

import socket
import subprocess
import threading
import uuid

import pytest

from app.improvement.models import ChangeFile, ChangeSet, ValidationStatus
from app.improvement.models import ChangeOperation as Op
from app.improvement.validation import ValidationRunner
from app.sandbox.container import LABEL, ContainerBackend
from app.sandbox.errors import IsolationFailure, IsolationUnavailableError
from app.sandbox.manager import SandboxManager
from app.sandbox.models import ChangeOperation, SandboxChange, SandboxOperation
from app.sandbox.policy import SandboxPolicy
from app.versioning.manager import ReleaseStore
from tests.improvement_helpers import make_project, sha, tree_hashes


def backend_like(base: ContainerBackend, **policy_kw) -> ContainerBackend:
    policy = SandboxPolicy(**{"timeout_seconds": 120, "memory_limit_mb": 1024, **policy_kw})
    return ContainerBackend(policy, cli=base._cli_pref, image=base._image, oci_runtime=base._oci_runtime)


def leftovers(base: ContainerBackend) -> list[str]:
    name, path = base._resolve_cli()
    out = subprocess.run([*base._global(path, name), "ps", "-a", "--filter", f"label={LABEL}", "--format", "{{.Names}}"],
                         capture_output=True, text=True, timeout=60)
    return out.stdout.split()


class World:
    def __init__(self, tmp_path, be: ContainerBackend):
        self.project = make_project(tmp_path / "project")
        self.store = ReleaseStore(tmp_path / "store")
        self.version = self.store.bootstrap(self.project)
        self.sandbox = SandboxManager(tmp_path / "store", be.policy, be)
        self.runner = ValidationRunner(self.sandbox, self.store)
        self.n = 0

    def candidate(self, test_source: str, name="test_probe.py"):
        self.n += 1
        sid = f"cand-real{self.n:08d}"
        self.sandbox.create(sid, self.store.release_source(self.version))
        path = f"tests/{name}"
        self.sandbox.apply_changes(sid, [SandboxChange(path=path, operation=ChangeOperation.ADD, proposed_hash=sha(test_source), content=test_source.encode())])
        return sid, ChangeSet(files=[ChangeFile(path=path, operation=Op.ADD, proposed_hash=sha(test_source))])


@pytest.fixture
def world(tmp_path, container_backend):
    return World(tmp_path, backend_like(container_backend))


async def test_real_preflight_verifies_the_restrictions_from_inside_the_container(container_backend):
    att = await backend_like(container_backend).preflight()
    assert att.satisfies_requirements() and att.network == "none" and att.user == "65534:65534"
    assert att.read_only_rootfs and att.capabilities_dropped and att.no_new_privileges and att.host_mounts == ["snapshot:ro"]
    assert att.image_id and att.backend in ("docker", "podman") and att.canary_passed


async def test_real_hostile_candidate_cannot_reach_host_files_secrets_or_network(tmp_path, monkeypatch, world):
    host_secret = tmp_path / "host_only_secret.txt"
    host_secret.write_text("HOST-SECRET")
    monkeypatch.setenv("HOST_API_TOKEN", "ghp_hostsecretvalue000000000000000000000000")

    server = socket.socket()
    server.bind(("0.0.0.0", 0))
    server.listen(5)
    port = server.getsockname()[1]
    stop = threading.Event()
    accepted: list[str] = []

    def accept_loop():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, addr = server.accept()
                accepted.append(addr[0])
                conn.close()
            except OSError:
                continue

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        lan_ip = probe.getsockname()[0]
    except OSError:
        lan_ip = "127.0.0.1"
    finally:
        probe.close()

    hostile = '''
import os, socket, pytest

HOST_SECRET = "@SECRET@"
PORT = @PORT@
TARGETS = ["127.0.0.1", "@LAN@", "host.containers.internal", "host.docker.internal"]

def test_host_paths_are_not_visible():
    assert not os.path.exists(HOST_SECRET)
    for p in ("/home", "/root/.ssh", "/var/run/docker.sock", "/run/podman/podman.sock", "/etc/ssh"):
        assert not (os.path.isdir(p) and os.listdir(p)) or p in ("/home",), p

def test_host_environment_is_not_inherited():
    assert not any("ghp_hostsecret" in v for v in os.environ.values())
    assert "HOST_API_TOKEN" not in os.environ

def test_outbound_network_is_blocked_to_the_host_and_the_internet():
    for host in TARGETS:
        with pytest.raises(OSError):
            socket.create_connection((host, PORT), 2)
    for host in ("1.1.1.1", "8.8.8.8"):
        with pytest.raises(OSError):
            socket.create_connection((host, 53), 2)
    assert sorted(os.listdir("/sys/class/net")) == ["lo"]

def test_filesystem_is_read_only_outside_scratch():
    for p in ("/etc/jarvisx_pwn", "/usr/jarvisx_pwn", "/snapshot/jarvisx_pwn", "/jarvisx_pwn"):
        with pytest.raises(OSError):
            open(p, "w")
    with open("/work/ok.txt", "w") as fh:
        fh.write("scratch is writable")

def test_no_privileges():
    assert os.getuid() == 65534
    with pytest.raises(OSError):
        os.chroot("/tmp")
    with pytest.raises(OSError):
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    status = dict(l.split(":", 1) for l in open("/proc/self/status").read().splitlines() if ":" in l)
    assert int(status["CapEff"].strip(), 16) == 0 and status["NoNewPrivs"].strip() == "1"
'''.replace("@SECRET@", str(host_secret)).replace("@PORT@", str(port)).replace("@LAN@", lan_ip)
    try:
        sid, change_set = world.candidate(hostile, "test_hostile.py")
        summary = await world.runner.validate(uuid.uuid4(), sid, world.version, change_set)
    finally:
        stop.set()
        t.join(timeout=2)
        server.close()
    assert summary.status is ValidationStatus.PASSED, (summary.reasons, summary.results[0].summary)
    assert summary.candidate.passed == summary.baseline.passed + 5  # all five hostile probes really ran inside the container
    assert accepted == []  # the host listener never saw a single connection from the candidate
    assert summary.isolation.satisfies_requirements()


async def test_real_timeout_kills_the_container_and_cleans_up(tmp_path, container_backend):
    w = World(tmp_path, backend_like(container_backend, timeout_seconds=6))
    sid, _ = w.candidate("import time\n\ndef test_hang():\n    time.sleep(300)\n", "test_hang.py")
    res = await w.sandbox.run(sid, SandboxOperation.RUN_TEST_SUITE)
    assert res.timed_out is True and res.exit_code is None and res.duration_seconds < 60
    assert leftovers(container_backend) == []


async def test_real_memory_limit_is_enforced(tmp_path, container_backend):
    w = World(tmp_path, backend_like(container_backend, memory_limit_mb=512))
    sid, change_set = w.candidate("def test_hog():\n    blob = bytearray(2 * 1024 * 1024 * 1024)\n    assert blob\n", "test_hog.py")
    summary = await w.runner.validate(uuid.uuid4(), sid, w.version, change_set)
    assert summary.status is ValidationStatus.FAILED and summary.reasons
    assert leftovers(container_backend) == []


async def test_real_process_limit_is_enforced(tmp_path, container_backend):
    w = World(tmp_path, backend_like(container_backend, max_processes=32))
    bomb = '''
import os, time

def test_fork_bomb_is_bounded():
    children, failed = [], False
    try:
        for _ in range(500):
            pid = os.fork()
            if pid == 0:
                time.sleep(20)
                os._exit(0)
            children.append(pid)
    except OSError:
        failed = True
    finally:
        for pid in children:
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except OSError:
                pass
    assert failed and len(children) < 100
'''
    sid, change_set = w.candidate(bomb, "test_bomb.py")
    summary = await w.runner.validate(uuid.uuid4(), sid, w.version, change_set)
    assert summary.status is ValidationStatus.PASSED, (summary.reasons, summary.results[0].summary)
    assert leftovers(container_backend) == []


async def test_real_output_is_bounded(tmp_path, container_backend):
    w = World(tmp_path, backend_like(container_backend, max_output_bytes=2_000))
    sid, _ = w.candidate("def test_noisy():\n    for _ in range(200000):\n        print('x' * 100)\n    assert False\n", "test_noisy.py")
    res = await w.sandbox.run(sid, SandboxOperation.RUN_TEST_SUITE)
    assert len(res.stdout.encode()) <= 2_000 and res.output_truncated is True
    assert leftovers(container_backend) == []


async def test_real_validation_pass_and_fail_use_the_same_isolated_path(tmp_path, container_backend):
    w = World(tmp_path, backend_like(container_backend))
    ok_sid, ok_set = w.candidate("def test_extra():\n    assert 1 + 1 == 2\n", "test_extra.py")
    ok = await w.runner.validate(uuid.uuid4(), ok_sid, w.version, ok_set)
    assert ok.status is ValidationStatus.PASSED and ok.test_count_delta == 1 and ok.static_analysis_passed is True
    bad_sid, bad_set = w.candidate("def test_fails():\n    assert False\n", "test_bad.py")
    bad = await w.runner.validate(uuid.uuid4(), bad_sid, w.version, bad_set)
    assert bad.status is ValidationStatus.FAILED and bad.isolation is not None and bad.candidate.failed == 1


async def test_real_validation_failure_leaves_the_current_release_unchanged(tmp_path, container_backend):
    from app.improvement.manager import ImprovementManager
    from app.improvement.models import ImprovementState as S
    from app.improvement.proposals import ProposedChange
    from app.improvement.repository import ImprovementRepository
    from tests.improvement_helpers import UTIL_ORIGINAL

    project = make_project(tmp_path / "project")
    store = ReleaseStore(tmp_path / "store")
    sandbox = SandboxManager(tmp_path / "store", container_backend.policy, backend_like(container_backend))
    m = ImprovementManager(ImprovementRepository(tmp_path / "t.db"), store, sandbox)
    v1 = m.ensure_current_release(project)
    before = (store.current_version(), store.hash_release(v1), tree_hashes(project))
    run = m.submit_request("Improve the util module for readability")
    m.evaluate(run.id, ["app/util.py"])
    m.create_plan(run.id)
    m.propose(run.id, "Break util", "oops", [ProposedChange(path="app/util.py", operation=Op.MODIFY, new_content="def add(a, b):\n    return a - b\n",
                                                           original_hash=sha(UTIL_ORIGINAL), reason="r")])
    m.create_sandbox(run.id)
    summary = await m.validate(run.id)
    assert summary.status is ValidationStatus.FAILED and m.get_run(run.id).state is S.FAILED
    assert (store.current_version(), store.hash_release(v1), tree_hashes(project)) == before
    assert leftovers(container_backend) == []


async def test_real_stale_containers_are_cleaned_up_at_preflight(tmp_path, container_backend):
    be = backend_like(container_backend)
    name, path = be._resolve_cli()
    stale = f"jarvisx-val-stale-{uuid.uuid4().hex[:8]}"
    subprocess.run([*be._global(path, name), "run", "-d", "--name", stale, "--label", LABEL, "--network", "none", "--pull=never", "--entrypoint", "python3",
                    be._image, "-c", "import time; time.sleep(600)"], check=True, capture_output=True, timeout=120)
    assert stale in leftovers(be)
    await be.preflight()
    assert leftovers(be) == []


# --- real startup failures: nothing runs --------------------------------------------------------------------


async def test_real_missing_image_fails_closed(container_backend):
    be = ContainerBackend(SandboxPolicy(timeout_seconds=60), cli=container_backend._cli_pref, image="jarvisx-validation-does-not-exist:0",
                          oci_runtime=container_backend._oci_runtime)
    with pytest.raises(IsolationUnavailableError) as ei:
        await be.preflight()
    assert ei.value.reason is IsolationFailure.IMAGE_NOT_FOUND


async def test_real_runtime_that_cannot_start_the_restricted_container_fails_closed(container_backend):
    if container_backend.name == "docker" or container_backend._cli_pref == "docker":
        pytest.skip("uses podman's global --runtime flag")
    be = ContainerBackend(SandboxPolicy(timeout_seconds=60), cli="podman", image=container_backend._image, oci_runtime="no-such-oci-runtime")
    with pytest.raises(IsolationUnavailableError) as ei:
        await be.preflight()
    assert ei.value.reason in (IsolationFailure.STARTUP_FAILED, IsolationFailure.RUNTIME_NOT_USABLE, IsolationFailure.IMAGE_NOT_FOUND)


async def test_real_no_leftover_containers_at_the_end(container_backend):
    assert leftovers(container_backend) == []


async def test_real_runs_leave_no_files_in_the_working_directory(tmp_path, container_backend):
    """An OOM-killed container used to make the runtime drop an `oom` file into the project directory."""
    import os
    from pathlib import Path
    before = sorted(os.listdir(Path.cwd()))
    w = World(tmp_path, backend_like(container_backend, memory_limit_mb=256))
    sid, _ = w.candidate("def test_hog():\n    blob = bytearray(1024 * 1024 * 1024)\n    assert blob\n", "test_hog2.py")
    await w.sandbox.run(sid, SandboxOperation.RUN_TEST_SUITE)
    assert sorted(os.listdir(Path.cwd())) == before and not Path("oom").exists()
