"""Container isolation backend (Docker or Podman CLI).

Candidate code runs ONLY inside a disposable container started with a fixed,
restrictive profile. The only host process this module starts is the container CLI
itself, with an argv built from constants and validated identifiers.

Per run:   --network none, --user 65534:65534, --read-only, --cap-drop ALL,
           no-new-privileges, memory/cpu/pids/nofile limits, in-memory tmpfs for
           /work and /tmp, ONE bind mount: the candidate snapshot, read-only.
Before it: a canary container with the same flags verifies (from the inside) that the
           restrictions really hold; if not, nothing runs (fail closed).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import shutil
import signal
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence

from app.sandbox.errors import IsolationFailure, IsolationUnavailableError
from app.sandbox.isolation import IsolationBackend
from app.sandbox.models import ExecutionResult, IsolationAttestation, SandboxOperation, SandboxPaths
from app.sandbox.policy import SandboxPolicy

logger = logging.getLogger(__name__)

CONTAINER_USER = "65534:65534"
SNAPSHOT_MOUNT = "/snapshot"
WORK_DIR = "/work"
LABEL = "jarvisx.validation=1"
MARKER = "@@JARVISX@@ "
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{7,100}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9_./@+-]+$")  # no commas/spaces/quotes: they could inject --mount options
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,199}$")
_RUNTIME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,30}$")
_IMAGE_ID_RE = re.compile(r"^(sha256:)?[0-9a-f]{12,64}$")
EXIT_RUNTIME_ERROR = 125

# Runs INSIDE the container (passed as `python3 -c`; not read from the image). It is a constant
# of this project: no part of it comes from a model or a caller.
ENTRY_SCRIPT = r'''
import json, os, shutil, subprocess, sys
OP = os.environ.get("JARVISX_OPERATION", "")
SNAP = os.environ.get("JARVISX_SNAPSHOT", "/snapshot")
WORK = os.environ.get("JARVISX_WORK", "/work")
MARK = "@@JARVISX@@ "
TAIL = 60000
ALLOWED_ENV = {"PATH", "HOME", "HOSTNAME", "TERM", "LANG", "LC_ALL", "container", "PYTHONDONTWRITEBYTECODE",
               "PYTHONHASHSEED", "JARVIS_VALIDATION_SANDBOX", "JARVISX_OPERATION", "JARVISX_SNAPSHOT",
               "JARVISX_WORK", "SHLVL", "PWD", "OLDPWD", "_", "LOGNAME", "USER", "TMPDIR"}

def emit(payload):
    sys.stdout.write("\n" + MARK + json.dumps(payload) + "\n")
    sys.stdout.flush()

def can_write(path):
    try:
        with open(path, "w") as fh:
            fh.write("x")
        os.unlink(path)
        return True
    except OSError:
        return False

def probe():
    obs = {"uid": os.getuid()}
    status = {}
    try:
        for line in open("/proc/self/status"):
            key, _, value = line.partition(":")
            status[key] = value.strip()
    except OSError:
        pass
    obs["cap_eff"] = status.get("CapEff")
    obs["no_new_privs"] = int(status.get("NoNewPrivs", "0") or 0)
    try:
        obs["net_interfaces"] = sorted(os.listdir("/sys/class/net"))
    except OSError:
        obs["net_interfaces"] = None
    import socket
    blocked = True
    for host in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        try:
            socket.create_connection((host, 53), 2).close()
            blocked = False
        except OSError:
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("1.1.1.1", 53))
        s.send(b"x")
        s.recv(1)
        blocked = False
    except OSError:
        pass
    obs["net_connect_blocked"] = blocked
    obs["rootfs_writable"] = can_write("/jarvisx_probe")
    obs["snapshot_writable"] = can_write(os.path.join(SNAP, ".jarvisx_probe"))
    obs["work_writable"] = can_write(os.path.join(WORK, ".jarvisx_probe"))
    pseudo = {"tmpfs", "proc", "sysfs", "devpts", "mqueue", "cgroup", "cgroup2", "devtmpfs", "shm", "overlay"}
    rw = []
    try:
        for line in open("/proc/self/mountinfo"):
            left, _, right = line.partition(" - ")
            f = left.split()
            fstype = right.split()[0] if right.split() else ""
            if "rw" in f[5].split(",") and fstype not in pseudo and f[4] not in ("/etc/hosts", "/etc/resolv.conf", "/etc/hostname", "/run/.containerenv"):
                rw.append(f[4])
    except OSError:
        rw = ["<unreadable>"]
    obs["writable_non_tmpfs_mounts"] = rw
    obs["control_sockets_present"] = [p for p in ("/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock",
                                                  "/var/run/podman/podman.sock") if os.path.exists(p)]
    obs["unexpected_env"] = sorted(k for k in os.environ if k not in ALLOWED_ENV)
    return obs

def counts_from_junit(path):
    try:
        import xml.etree.ElementTree as ET
        if os.path.getsize(path) > 2000000:
            return None
        root = ET.parse(path).getroot()
        suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
        t = sum(int(s.get("tests", 0)) for s in suites)
        f = sum(int(s.get("failures", 0)) for s in suites)
        e = sum(int(s.get("errors", 0)) for s in suites)
        k = sum(int(s.get("skipped", 0)) for s in suites)
        return {"passed": max(0, t - f - e - k), "failed": f, "skipped": k, "errors": e}
    except Exception:
        return None

def main():
    if OP == "probe":
        emit(probe())
        return 0
    if OP not in ("run_test_suite", "run_static_analysis"):
        emit({"error": "unknown operation"})
        return 2
    src = os.path.join(WORK, "src")
    shutil.copytree(SNAP, src, symlinks=True)
    log = os.path.join(WORK, "out.log")
    junit = os.path.join(WORK, "junit.xml")
    if OP == "run_test_suite":
        cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "junit_family=xunit2", "--junitxml=" + junit]
    else:
        cmd = [sys.executable, "-m", "pyflakes", "app", "tests"]
    env = {k: v for k, v in os.environ.items() if k in ALLOWED_ENV and not k.startswith("JARVISX_")}
    env["PYTHONPATH"] = src
    with open(log, "wb") as fh:
        rc = subprocess.run(cmd, cwd=src, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env).returncode
    try:
        size = os.path.getsize(log)
        with open(log, "rb") as fh:
            fh.seek(max(0, size - TAIL))
            sys.stdout.write(fh.read().decode("utf-8", "replace"))
    except OSError:
        pass
    emit({"exit": rc, "counts": counts_from_junit(junit) if OP == "run_test_suite" else None})
    return rc if 0 <= rc < 256 else 1

sys.exit(main())
'''


@dataclass
class CommandResult:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False


class CommandRunner(Protocol):
    async def run(self, argv: Sequence[str], timeout: float, max_output: int) -> CommandResult: ...


class SubprocessRunner:
    """Starts the container CLI (never candidate code) with a given argv, bounded in time and output.

    It runs from a neutral working directory (default: the system temp dir, never the project): runtime helper
    processes such as Podman's conmon write marker files (e.g. `oom`) into their cwd."""

    def __init__(self, cwd: Path | str | None = None) -> None:
        self._cwd = str(cwd) if cwd is not None else tempfile.gettempdir()

    async def run(self, argv: Sequence[str], timeout: float, max_output: int) -> CommandResult:
        Path(self._cwd).mkdir(parents=True, exist_ok=True)
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=(os.name == "posix"), cwd=self._cwd)
        state = {"total": 0, "killed": False}

        def kill() -> None:
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:  # pragma: no cover
                    proc.kill()
            except (ProcessLookupError, PermissionError):
                pass

        async def drain(stream) -> tuple[bytes, bool]:
            buf, truncated = bytearray(), False
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                state["total"] += len(chunk)
                room = max_output - len(buf)
                if room > 0:
                    buf.extend(chunk[:room])
                if len(chunk) > room:
                    truncated = True
                if state["total"] > max_output * 4 and not state["killed"]:
                    state["killed"] = True
                    kill()
            return bytes(buf), truncated

        try:
            (out, t1), (err, t2), _ = await asyncio.wait_for(
                asyncio.gather(drain(proc.stdout), drain(proc.stderr), proc.wait()), timeout=timeout)
        except asyncio.TimeoutError:
            kill()
            await proc.wait()
            return CommandResult(None, timed_out=True, truncated=True)
        except BaseException:
            kill()
            raise
        return CommandResult(proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"),
                             truncated=t1 or t2 or state["killed"])


def _fail(reason: IsolationFailure, message: str) -> IsolationUnavailableError:
    return IsolationUnavailableError(reason, message)


class ContainerBackend(IsolationBackend):
    """Docker/Podman backend. See the module docstring for the profile. Resource
    limits are passed to the runtime; whether the runtime can enforce them depends on
    the host (e.g. cgroup delegation) — a runtime that cannot start the container
    makes validation fail, it never relaxes the profile."""

    def __init__(
        self, policy: SandboxPolicy | None = None, cli: str = "auto", image: str = "jarvisx-validation:1",
        oci_runtime: str | None = None, scratch_dir: Path | str | None = None,
        runner: CommandRunner | None = None, which: Callable[[str], str | None] = shutil.which,
        attestation_ttl_seconds: float = 60.0,
    ) -> None:
        self.policy = policy or SandboxPolicy()
        self._cli_pref = cli
        self._image = image
        self._oci_runtime = oci_runtime
        self._scratch = Path(scratch_dir) if scratch_dir else None
        self._runner: CommandRunner = runner or SubprocessRunner(cwd=self._scratch)
        self._which = which
        self._ttl = attestation_ttl_seconds
        self._cached: tuple[float, IsolationAttestation] | None = None
        self.name = cli if cli in ("docker", "podman") else "container"
        if cli not in ("auto", "docker", "podman"):
            raise _fail(IsolationFailure.MISCONFIGURED, "isolation backend must be 'auto', 'docker' or 'podman'")
        if not _IMAGE_RE.match(image):
            raise _fail(IsolationFailure.MISCONFIGURED, "the container image reference is not valid")
        if oci_runtime is not None and not _RUNTIME_RE.match(oci_runtime):
            raise _fail(IsolationFailure.MISCONFIGURED, "the OCI runtime name is not valid")

    def describe(self) -> str:
        return f"container ({self._cli_pref}), image {self._image}, network none, read-only snapshot mount"

    # --- argv construction (pure; unit-tested without any runtime) ---------------------------

    def _resolve_cli(self) -> tuple[str, str]:
        candidates = ["docker", "podman"] if self._cli_pref == "auto" else [self._cli_pref]
        for name in candidates:
            path = self._which(name)
            if path and os.path.isabs(path):
                return name, path
        raise _fail(IsolationFailure.NO_CONTAINER_RUNTIME,
                    "no container runtime (docker or podman) was found; isolated validation is unavailable and nothing was executed")

    def _global(self, cli_path: str, name: str) -> list[str]:
        base = [cli_path]
        if name == "podman" and self._oci_runtime:
            base += ["--runtime", self._oci_runtime]
        return base

    def security_args(self, name: str, container_name: str, snapshot: Path, operation: str) -> list[str]:
        """Everything between `run` and the image. Constants plus validated identifiers only."""
        if not _NAME_RE.match(container_name):
            raise _fail(IsolationFailure.MISCONFIGURED, "invalid container name")
        snap = str(snapshot)
        if not _PATH_RE.match(snap):
            raise _fail(IsolationFailure.MISCONFIGURED,
                        "the sandbox path contains characters that are not allowed in a bind-mount source")
        p = self.policy
        mem = f"{p.memory_limit_mb}m"
        args = [
            "--rm", "--name", container_name, "--label", LABEL, "--pull=never",
            "--network", "none",
            "--user", CONTAINER_USER, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(p.max_processes), "--memory", mem, "--memory-swap", mem, "--cpus", str(p.cpus),
            "--ulimit", f"nofile={p.max_open_files}:{p.max_open_files}", "--ulimit", "core=0",
            "--ulimit", f"cpu={int(p.timeout_seconds) + 30}:{int(p.timeout_seconds) + 30}",
            "--tmpfs", f"{WORK_DIR}:rw,nosuid,nodev,size={p.work_tmpfs_mb}m,mode=1777",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={p.tmp_tmpfs_mb}m,mode=1777",
            "--mount", f"type=bind,src={snap},dst={SNAPSHOT_MOUNT},readonly",
            "--workdir", WORK_DIR,
            "--env", "HOME=/tmp", "--env", "LANG=C.UTF-8", "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONHASHSEED=0",
            "--env", "JARVIS_VALIDATION_SANDBOX=1", "--env", f"JARVISX_OPERATION={operation}",
            "--entrypoint", "python3",
        ]
        if name == "docker" and self._oci_runtime:
            args += ["--runtime", self._oci_runtime]
        return args

    def run_argv(self, name: str, cli_path: str, container_name: str, snapshot: Path, operation: str) -> list[str]:
        return [*self._global(cli_path, name), "run", *self.security_args(name, container_name, snapshot, operation),
                self._image, "-c", ENTRY_SCRIPT]

    # --- verification --------------------------------------------------------------------------

    async def _exec(self, argv: Sequence[str], timeout: float, max_output: int) -> CommandResult:
        try:
            return await self._runner.run(argv, timeout, max_output)
        except OSError as exc:  # the CLI vanished, is not executable, ...
            raise _fail(IsolationFailure.RUNTIME_NOT_USABLE,
                        f"the container runtime could not be executed ({type(exc).__name__}); nothing was executed") from None

    async def _cli(self, cli_path: str, name: str, *args: str, timeout: float = 30.0) -> CommandResult:
        return await self._exec([*self._global(cli_path, name), *args], timeout, 200_000)

    async def cleanup_stale(self) -> int:
        """Remove leftover jarvisx validation containers (e.g. after a crash). Returns how many."""
        name, cli_path = self._resolve_cli()
        res = await self._cli(cli_path, name, "ps", "-a", "--filter", f"label={LABEL}", "--format", "{{.Names}}")
        removed = 0
        if res.returncode == 0:
            for line in res.stdout.split():
                if _NAME_RE.match(line):
                    await self._cli(cli_path, name, "rm", "-f", line)
                    removed += 1
        return removed

    async def preflight(self) -> IsolationAttestation:
        name, cli_path = self._resolve_cli()
        await self.cleanup_stale()
        ver = await self._cli(cli_path, name, "version", "--format", "{{.Client.Version}}")
        if ver.returncode != 0:
            raise _fail(IsolationFailure.RUNTIME_NOT_USABLE,
                        f"the {name} runtime is installed but not usable (is the daemon running?); nothing was executed")
        cli_version = ver.stdout.strip()[:40] or None
        insp = await self._cli(cli_path, name, "image", "inspect", "--format", "{{.Id}}", self._image)
        if insp.returncode != 0:
            raise _fail(IsolationFailure.IMAGE_NOT_FOUND,
                        f"the validation image '{self._image}' is not available locally (build it from docker/validation.Dockerfile)")
        image_id = insp.stdout.strip()
        if not _IMAGE_ID_RE.match(image_id):
            raise _fail(IsolationFailure.MISCONFIGURED, "the container runtime returned an unexpected image id")
        observed = await self._canary(name, cli_path)
        problems = self.check_observations(observed)
        if problems:
            raise _fail(IsolationFailure.RESTRICTIONS_NOT_ESTABLISHED,
                        "the isolation restrictions could not be verified (" + "; ".join(problems) + "); nothing was executed")
        att = IsolationAttestation(
            backend=name, cli_version=cli_version, image=self._image, image_id=image_id, network="none", user=CONTAINER_USER,
            read_only_rootfs=True, capabilities_dropped=True, no_new_privileges=True, host_mounts=["snapshot:ro"],
            writable_host_mounts=0, limits=self.policy.limits_summary(), canary_passed=True)
        self._cached = (time.monotonic(), att)
        return att

    @staticmethod
    def check_observations(obs: dict) -> list[str]:
        """Compare what the canary saw from INSIDE the container with the requirements."""
        problems: list[str] = []
        if obs.get("uid") != 65534:
            problems.append("process is not running as the unprivileged user")
        try:
            if int(str(obs.get("cap_eff")), 16) != 0:
                problems.append("capabilities are not dropped")
        except ValueError:
            problems.append("capability set could not be read")
        if obs.get("no_new_privs") != 1:
            problems.append("no-new-privileges is not set")
        ifaces = obs.get("net_interfaces")
        if ifaces is None or set(ifaces) - {"lo"}:
            problems.append("a network interface other than loopback exists")
        if obs.get("net_connect_blocked") is not True:
            problems.append("outbound network access is possible")
        if obs.get("rootfs_writable") is not False:
            problems.append("the root filesystem is writable")
        if obs.get("snapshot_writable") is not False:
            problems.append("the source snapshot is writable")
        if obs.get("work_writable") is not True:
            problems.append("the scratch area is not usable")
        if obs.get("writable_non_tmpfs_mounts") != []:
            problems.append("a writable host-backed mount exists")
        if obs.get("control_sockets_present") != []:
            problems.append("a container-runtime control socket is visible")
        if obs.get("unexpected_env") != []:
            problems.append("unexpected environment variables are present")
        return problems

    async def _canary(self, name: str, cli_path: str) -> dict:
        scratch_root = self._scratch or Path(tempfile.gettempdir())
        scratch_root.mkdir(parents=True, exist_ok=True)
        empty = Path(tempfile.mkdtemp(prefix="canary-", dir=scratch_root)).resolve()
        cname = f"jarvisx-canary-{secrets.token_hex(6)}"
        try:
            argv = self.run_argv(name, cli_path, cname, empty, "probe")
            res = await self._exec(argv, 60.0, 200_000)
            if res.returncode == EXIT_RUNTIME_ERROR or res.timed_out or res.returncode is None:
                raise _fail(IsolationFailure.STARTUP_FAILED,
                            "the isolation canary container could not be started with the required restrictions; nothing was executed")
            reported = _parse_marker(res.stdout)
            if reported is None:
                raise _fail(IsolationFailure.STARTUP_FAILED, "the isolation canary produced no result; nothing was executed")
            return reported
        finally:
            await self._remove(cli_path, name, cname)
            shutil.rmtree(empty, ignore_errors=True)

    async def _remove(self, cli_path: str, name: str, container_name: str) -> None:
        try:
            await self._cli(cli_path, name, "rm", "-f", container_name, timeout=30.0)
        except Exception:  # noqa: BLE001 — best effort; stale ones are removed at the next preflight
            logger.warning("could not remove container %s", container_name)

    async def _attested(self, name: str, cli_path: str) -> IsolationAttestation:
        """Reuse a recent attestation only if the image is still the verified one."""
        if self._cached and time.monotonic() - self._cached[0] < self._ttl:
            insp = await self._cli(cli_path, name, "image", "inspect", "--format", "{{.Id}}", self._image)
            if insp.returncode == 0 and insp.stdout.strip() == self._cached[1].image_id:
                return self._cached[1]
        return await self.preflight()

    # --- execution --------------------------------------------------------------------------------

    async def run(self, paths: SandboxPaths, operation: SandboxOperation) -> ExecutionResult:
        if operation not in self.policy.allowed_operations:
            raise _fail(IsolationFailure.MISCONFIGURED, "this operation is not allowed")
        name, cli_path = self._resolve_cli()
        attestation = await self._attested(name, cli_path)
        container_name = f"jarvisx-val-{paths.id}-{secrets.token_hex(4)}".lower()
        argv = self.run_argv(name, cli_path, container_name, paths.source.resolve(), operation.value)
        started = time.monotonic()
        try:
            res = await self._exec(argv, self.policy.timeout_seconds, self.policy.max_output_bytes)
        finally:
            await self._remove(cli_path, name, container_name)  # deterministic cleanup, also after timeouts/crashes
        duration = time.monotonic() - started
        reported = _parse_marker(res.stdout)
        if not res.timed_out and (res.returncode == EXIT_RUNTIME_ERROR or (res.returncode in (126, 127) and reported is None)):
            raise _fail(IsolationFailure.STARTUP_FAILED,
                        "the container could not be started for validation; nothing was verified")
        text = res.stdout.split("\n" + MARKER)[0] if reported is not None else res.stdout
        logger.info("container validation: op=%s exit=%s timed_out=%s duration=%.2fs", operation.value, res.returncode,
                    res.timed_out, duration)
        return ExecutionResult(
            operation=operation, exit_code=None if res.timed_out else res.returncode, timed_out=res.timed_out,
            duration_seconds=round(duration, 3), stdout=text, stderr=res.stderr, output_truncated=res.truncated,
            resource_limit_exit=(not res.timed_out and res.returncode == 137), reported=reported,
            isolation=attestation, limits_applied=self.policy.limits_summary())


def _parse_marker(stdout: str) -> dict | None:
    """The LAST marker line wins (the runner prints it last)."""
    found = None
    for line in stdout.splitlines():
        if line.startswith(MARKER):
            try:
                value = json.loads(line[len(MARKER):])
            except ValueError:
                continue
            if isinstance(value, dict):
                found = value
    return found


__all__ = ["ContainerBackend", "CommandResult", "CommandRunner", "SubprocessRunner", "ENTRY_SCRIPT"]
