#!/usr/bin/env python3
"""Profile-aware, loopback-only CVE-2026-123007 compatibility runner.

List is the default action. Run is a dry-run unless --execute and the exact
local-lab acknowledgement are both present. Live mode is deliberately confined
to the isolated nginx2root-avx512 VM and its existing Docker images.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

CVE = "CVE-2026-123007"
ACK = "I-AUTHORIZE-LOCAL-LAB"
EXPECTED_HOSTNAME = "nginx2root-avx512"
DEFAULT_SOURCE = Path("/tmp/rapid7-release-rebuild")
DEFAULT_RESULTS = Path("/tmp/nginx2root-compatibility")
CLIENT_IMAGE = "rapid7-nginx2root-rce-client:3.10"
PATCHED_IMAGE = "nginx:1.31.9"
PROFILE_1316 = "golden-nginx-1.31.6-debian13-amd64"
PROFILE_1318 = "golden-nginx-1.31.8-debian13-amd64"
DEFAULT_PROFILE_1317 = "golden-nginx-1.31.7-debian13-amd64"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
PROFILE_RE = re.compile(r"^golden-nginx-[a-z0-9.-]+-amd64$")
STAT_RE = re.compile(r"^([0-9]+):([0-9]+) ([0-7]{3,4}) ([0-9]+) (/tmp/[a-z0-9-]+)$")
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
OUTPUT_TAIL_BYTES = 4096


class SafetyError(Exception):
    """A validation or execution precondition failed safely."""


@dataclass(frozen=True)
class TargetProfile:
    """An explicitly calibrated image/profile pair."""

    version: str
    image: str
    profile: str | None


@dataclass(frozen=True)
class Trial:
    """One vulnerable attempt or its independent patched negative control."""

    case_id: str
    version: str
    heap_state: str
    image: str
    profile: str
    patched: bool
    transport_only: bool = False


@dataclass
class CommandResult:
    """A bounded subprocess observation; exit zero is never an RCE verdict."""

    argv: list[str]
    returncode: int | None
    duration_seconds: float
    timed_out: bool = False
    output_truncated: bool = False
    log: str = ""
    stderr_tail: str = ""


@dataclass
class TrialResult:
    """Independent evidence and a narrow verdict for one container attempt."""

    case_id: str
    role: str
    version: str
    heap_state: str
    image: str
    profile: str
    attempt: int
    target_container: str
    marker: str
    verdict: str
    rce_verified: bool = False
    control_passed: bool = False
    transport_passed: bool = False
    marker_absent_before: bool = False
    marker_observed: dict[str, Any] | None = None
    marker_mismatches: list[str] = field(default_factory=list)
    target_state: dict[str, Any] | None = None
    reasons: list[str] = field(default_factory=list)
    commands: list[CommandResult] = field(default_factory=list)


class BoundedDocker:
    """Run argv-only Docker commands with wall-clock and output limits."""

    def __init__(self, output_limit: int = MAX_OUTPUT_BYTES) -> None:
        self.output_limit = output_limit

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int,
        deadline: float,
        log_path: Path,
    ) -> CommandResult:
        """Execute without a shell and kill only this command's process group."""
        if not argv or argv[:2] != ("sudo", "docker"):
            raise SafetyError("only 'sudo docker' subprocesses are permitted")
        started = time.monotonic()
        remaining = min(timeout, int(deadline - started))
        if remaining <= 0:
            return CommandResult(list(argv), None, 0, timed_out=True, log=str(log_path))
        log_path.parent.mkdir(parents=True, exist_ok=True)
        combined = bytearray()
        stderr_tail = bytearray()
        timed_out = False
        truncated = False
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env={
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                },
                start_new_session=True,
            )
        except OSError as exc:
            return CommandResult(
                list(argv),
                127,
                time.monotonic() - started,
                log=str(log_path),
                stderr_tail=str(exc)[-OUTPUT_TAIL_BYTES:],
            )
        assert process.stdout is not None and process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        with log_path.open("wb") as log:
            while selector.get_map():
                left = min(
                    timeout - (time.monotonic() - started), deadline - time.monotonic()
                )
                if left <= 0:
                    timed_out = True
                    self._kill(process)
                    break
                for key, _ in selector.select(min(left, 0.2)):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stderr":
                        stderr_tail.extend(chunk)
                        del stderr_tail[:-OUTPUT_TAIL_BYTES]
                    if len(combined) + len(chunk) > self.output_limit:
                        truncated = True
                        self._kill(process)
                        break
                    combined.extend(chunk)
                    log.write(chunk)
                if truncated:
                    break
        selector.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._kill(process)
        process.stdout.close()
        process.stderr.close()
        return CommandResult(
            list(argv),
            process.returncode,
            round(time.monotonic() - started, 3),
            timed_out=timed_out,
            output_truncated=truncated,
            log=str(log_path),
            stderr_tail=stderr_tail.decode("utf-8", errors="replace"),
        )

    @staticmethod
    def _kill(process: subprocess.Popen[bytes]) -> None:
        """Kill the bounded subprocess group, never an unrelated process."""
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            raise SafetyError("unable to stop bounded Docker subprocess") from exc


class CompatibilityRunner:
    """Execute matched vulnerable/control pairs with independent file evidence."""

    def __init__(
        self, args: argparse.Namespace, docker: BoundedDocker | None = None
    ) -> None:
        self.args = args
        self.docker = docker or BoundedDocker()
        self.docker_prefix = ("sudo", "docker")
        self.run_dir = args.results_dir / args.run_id
        self.started = time.monotonic()
        self.deadline = self.started + args.total_timeout
        self.commands: list[CommandResult] = []
        self.current_trial: Trial | None = None

    def command(
        self,
        trial: Trial,
        attempt: int,
        phase: str,
        argv: Sequence[str],
        timeout: int = 30,
    ) -> CommandResult:
        """Record one phase in a per-case evidence log."""
        log = self.run_dir / f"{trial.case_id}-a{attempt}-{phase}.log"
        result = self.docker.run(
            argv, timeout=timeout, deadline=self.deadline, log_path=log
        )
        if self.current_trial is trial:
            self.commands.append(result)
        return result

    @staticmethod
    def output(result: CommandResult) -> str:
        """Read only the bounded log written by this runner."""
        try:
            return Path(result.log).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def require(self, result: CommandResult, message: str) -> str:
        """Fail a trial on setup/evidence errors, not on expected marker absence."""
        if result.returncode != 0 or result.timed_out or result.output_truncated:
            raise SafetyError(
                f"{message} (exit={result.returncode}, timeout={result.timed_out})"
            )
        return self.output(result)

    def cleanup(self, names: Sequence[str]) -> None:
        """Remove only this run's named disposable target/client containers."""
        for name in reversed(names):
            log = self.run_dir / f"cleanup-{name}.log"
            try:
                self.docker.run(
                    (*self.docker_prefix, "rm", "-f", name),
                    timeout=15,
                    deadline=time.monotonic() + 20,
                    log_path=log,
                )
            except (OSError, SafetyError):
                # The final report retains the named container for manual cleanup.
                pass

    def preflight(self, trials: Sequence[Trial]) -> None:
        """Check host isolation and all local inputs before creating a target."""
        if socket.gethostname() != EXPECTED_HOSTNAME:
            raise SafetyError(
                f"live execution is confined to hostname {EXPECTED_HOSTNAME}"
            )
        if os.uname().machine != "x86_64":
            raise SafetyError("native x86-64 execution is required")
        cpu = Path("/proc/cpuinfo").read_text(encoding="utf-8")
        missing_cpu = {"avx512f", "avx512vl"} - set(
            re.findall(r"\bavx512[a-z0-9_]+\b", cpu)
        )
        if missing_cpu:
            raise SafetyError(f"missing required CPU features: {sorted(missing_cpu)}")
        required = [
            self.args.source_root / "nginx.conf",
            self.args.source_root / "exploit/exploit.py",
        ]
        required += [
            self.args.source_root / "exploit/profiles" / f"{profile}.json"
            for profile in sorted({trial.profile for trial in trials})
        ]
        for path in required:
            if not path.is_file():
                raise SafetyError(f"required local source/profile is missing: {path}")
        images = sorted({CLIENT_IMAGE, *(trial.image for trial in trials)})
        for image in images:
            probe = self.docker.run(
                (*self.docker_prefix, "image", "inspect", image),
                timeout=20,
                deadline=self.deadline,
                log_path=self.run_dir / "preflight-images.log",
            )
            self.require(probe, f"local Docker image unavailable: {image}")

    def start_target(
        self, trial: Trial, attempt: int, container: str, marker: str
    ) -> None:
        """Start nginx with no external network and a generated loopback certificate."""
        config = self.args.source_root / "nginx.conf"
        certificate_command = (
            "openssl req -x509 -newkey rsa:2048 -nodes -days 1 "
            "-keyout /tmp/nginx-h2.key -out /tmp/nginx-h2.crt "
            "-subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 "
            "&& exec nginx -g 'daemon off;'"
        )
        result = self.command(
            trial,
            attempt,
            "start",
            (
                *self.docker_prefix,
                "run",
                "-d",
                "--name",
                container,
                "--label",
                f"nginx2root.compatibility={self.args.run_id}",
                "--platform",
                "linux/amd64",
                "--network",
                "none",
                "--mount",
                f"type=bind,src={config},dst=/etc/nginx/nginx.conf,readonly",
                "--entrypoint",
                "sh",
                trial.image,
                "-c",
                certificate_command,
            ),
        )
        self.require(result, "target container failed to start")
        version = self.require(
            self.command(
                trial,
                attempt,
                "version",
                (*self.docker_prefix, "exec", container, "nginx", "-v"),
            ),
            "unable to read target version",
        )
        if f"nginx/{trial.version}" not in version:
            raise SafetyError(
                f"target version mismatch: expected nginx/{trial.version}"
            )
        self.require(
            self.command(
                trial,
                attempt,
                "config-test",
                (*self.docker_prefix, "exec", container, "nginx", "-t"),
            ),
            "nginx configuration test failed",
        )
        absent = self.command(
            trial,
            attempt,
            "pre-marker",
            (*self.docker_prefix, "exec", container, "test", "!", "-e", marker),
        )
        if absent.returncode != 0:
            raise SafetyError("marker was not independently absent before the attempt")

    def client_python(
        self,
        trial: Trial,
        attempt: int,
        phase: str,
        target: str,
        code: str,
        timeout: int,
    ) -> CommandResult:
        """Run a named client in the target's isolated network namespace."""
        client = f"{target}-{phase}"
        try:
            return self.command(
                trial,
                attempt,
                phase,
                (
                    *self.docker_prefix,
                    "run",
                    "--rm",
                    "--name",
                    client,
                    "--label",
                    f"nginx2root.compatibility={self.args.run_id}",
                    "--network",
                    f"container:{target}",
                    "--entrypoint",
                    "python",
                    CLIENT_IMAGE,
                    "-c",
                    code,
                ),
                timeout=timeout,
            )
        finally:
            self.cleanup([client])

    def transport(self, trial: Trial, attempt: int, target: str, host: str) -> None:
        """Check direct TLS, ALPN h2, and an HTTP/1.1 response before exploitation."""
        code = f"""import http.client,json,socket,ssl
host={host!r}
def context(alpn):
    c=ssl._create_unverified_context()
    c.set_alpn_protocols([alpn])
    return c
s=context("h2").wrap_socket(socket.create_connection((host,443),timeout=10),server_hostname="localhost")
assert s.selected_alpn_protocol()=="h2", "ALPN did not negotiate h2"
s.close()
c=http.client.HTTPSConnection(host,443,context=context("http/1.1"),timeout=10)
c.request("GET","/index.html")
r=c.getresponse()
body=r.read()
assert r.status==200 and b"Welcome to nginx" in body, "unexpected HTTP response"
c.close()
print(json.dumps({{"tls":True,"alpn":"h2","http_status":r.status,"http_body_bytes":len(body)}}))
"""
        result = self.client_python(trial, attempt, "transport", target, code, 45)
        self.require(result, "TLS/ALPN/HTTP transport checks failed")

    def exercise(self, trial: Trial, attempt: int, target: str, host: str) -> None:
        """Generate a bounded number of HTTP requests for an exercised heap."""
        if trial.heap_state == "fresh":
            return
        count = self.args.exercise_requests
        code = f"""import http.client,ssl
for i in range({count}):
    c=http.client.HTTPSConnection({host!r},443,context=ssl._create_unverified_context(),timeout=10)
    c.request("GET","/index.html")
    r=c.getresponse()
    assert r.status==200
    r.read()
    c.close()
print({{"exercise_requests": {count}}})
"""
        result = self.client_python(trial, attempt, "exercise", target, code, 120)
        self.require(result, "bounded heap exercise failed")

    def exploit(
        self, trial: Trial, attempt: int, target: str, host: str, marker: str
    ) -> CommandResult:
        """Run the upstream client directly, without a shell or target resolution."""
        url = f"https://[{host}]:443/" if ":" in host else f"https://{host}:443/"
        client = f"{target}-exploit"
        try:
            return self.command(
                trial,
                attempt,
                "exploit",
                (
                    *self.docker_prefix,
                    "run",
                    "--rm",
                    "--name",
                    client,
                    "--label",
                    f"nginx2root.compatibility={self.args.run_id}",
                    "--network",
                    f"container:{target}",
                    "--env",
                    "PYTHONPATH=",
                    "--volume",
                    f"{self.args.source_root}:/src:ro",
                    "--workdir",
                    "/tmp",
                    "--entrypoint",
                    "python",
                    CLIENT_IMAGE,
                    "/src/exploit/exploit.py",
                    "--target",
                    url,
                    "--profile",
                    trial.profile,
                    "--cmd",
                    f"touch {marker}",
                ),
                timeout=self.args.exploit_timeout,
            )
        finally:
            self.cleanup([client])

    def observe_marker(
        self, trial: Trial, attempt: int, container: str, marker: str
    ) -> dict[str, Any] | None:
        """Read UID/GID/mode/size independently of the exploit client."""
        result = self.command(
            trial,
            attempt,
            "post-marker",
            (
                *self.docker_prefix,
                "exec",
                container,
                "stat",
                "-c",
                "%u:%g %a %s %n",
                marker,
            ),
        )
        if result.returncode == 1:
            return None
        text = self.require(result, "independent marker stat failed").strip()
        match = STAT_RE.fullmatch(text)
        if not match:
            raise SafetyError(
                "marker stat output did not match the strict evidence format"
            )
        uid, gid, mode, size, path = match.groups()
        return {
            "uid": int(uid),
            "gid": int(gid),
            "mode": mode.zfill(4),
            "size": int(size),
            "path": path,
        }

    def run_trial(self, trial: Trial, attempt: int) -> TrialResult:
        """Run one fresh container and decide only from independent evidence."""
        suffix = f"{trial.case_id}-a{attempt}"
        target = f"rapid7-compat-{self.args.run_id}-{suffix}"
        marker = f"/tmp/rapid7-compat-{self.args.run_id}-{suffix}"
        result = TrialResult(
            case_id=trial.case_id,
            role="patched_control" if trial.patched else "vulnerable",
            version=trial.version,
            heap_state=trial.heap_state,
            image=trial.image,
            profile=trial.profile,
            attempt=attempt,
            target_container=target,
            marker=marker,
            verdict="not_verified",
        )
        command_start = len(self.commands)
        self.current_trial = trial
        try:
            self.start_target(trial, attempt, target, marker)
            result.marker_absent_before = True
            self.transport(trial, attempt, target, self.args.host)
            result.transport_passed = True
            if trial.transport_only:
                observed = self.observe_marker(trial, attempt, target, marker)
                result.marker_observed = observed
                if observed is None:
                    result.verdict = "transport_verified"
                    result.reasons.append(
                        "transport passed; no exploit traffic was sent"
                    )
                else:
                    result.verdict = "unexpected_marker"
                    result.reasons.append(
                        "marker appeared during a transport-only trial"
                    )
            else:
                self.exercise(trial, attempt, target, self.args.host)
                exploit = self.exploit(trial, attempt, target, self.args.host, marker)
                observed = self.observe_marker(trial, attempt, target, marker)
                result.marker_observed = observed
                if trial.patched:
                    if observed is None:
                        result.control_passed = True
                        result.verdict = "control_passed"
                    else:
                        result.verdict = "control_positive"
                        result.reasons.append("patched target produced the marker")
                elif observed is None:
                    result.reasons.append(
                        f"marker absent; client exit={exploit.returncode} and crashes do not establish RCE"
                    )
                else:
                    expected = {
                        "uid": 101,
                        "gid": 101,
                        "mode": "0644",
                        "size": 0,
                        "path": marker,
                    }
                    result.marker_mismatches = [
                        f"{key}: got {observed[key]!r}, expected {value!r}"
                        for key, value in expected.items()
                        if observed[key] != value
                    ]
                    if result.marker_mismatches:
                        result.reasons.append(
                            "marker metadata did not match the expected nginx worker file"
                        )
                    else:
                        result.rce_verified = True
                        result.verdict = "verified"
        except SafetyError as exc:
            result.verdict = "error"
            result.reasons.append(str(exc))
        finally:
            try:
                state = self.command(
                    trial,
                    attempt,
                    "state",
                    (
                        *self.docker_prefix,
                        "inspect",
                        target,
                        "--format",
                        "{{json .State}}",
                    ),
                )
                if state.returncode == 0:
                    result.target_state = json.loads(self.output(state).strip())
                self.command(
                    trial, attempt, "nginx-log", (*self.docker_prefix, "logs", target)
                )
            except (SafetyError, json.JSONDecodeError) as exc:
                result.reasons.append(f"state/log collection failed: {exc}")
            self.cleanup([target])
        result.commands = self.commands[command_start:]
        self.current_trial = None
        return result

    def execute(self, trials: Sequence[Trial]) -> dict[str, Any]:
        """Run bounded retries and require each vulnerable/control pair to verify."""
        self.run_dir.mkdir(parents=True, exist_ok=False)
        try:
            self.preflight(trials)
        except (SafetyError, OSError, ValueError):
            self.write_report(
                {
                    "schema_version": 1,
                    "cve": CVE,
                    "action": "run",
                    "dry_run": False,
                    "run_id": self.args.run_id,
                    "target": self.args.host,
                    "all_verified": False,
                    "status": "preflight_failed",
                }
            )
            raise
        self.deadline = min(self.deadline, time.monotonic() + self.args.total_timeout)
        if self.args.transport_only:
            results = [
                self.run_trial(Trial(**{**trial.__dict__, "transport_only": True}), 1)
                for trial in trials
                if not trial.patched
            ]
            report = {
                "schema_version": 1,
                "cve": CVE,
                "action": "run",
                "dry_run": False,
                "run_id": self.args.run_id,
                "target": self.args.host,
                "transport_only": True,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "all_transport_verified": all(
                    result.verdict == "transport_verified" for result in results
                ),
                "all_verified": False,
                "results": [asdict(result) for result in results],
                "note": "Transport checks only; no exploit traffic or RCE claim.",
            }
            self.write_report(report)
            return report
        pairs: list[dict[str, Any]] = []
        for index in range(0, len(trials), 2):
            vulnerable, control = trials[index : index + 2]
            pair: dict[str, Any] = {
                "case_id": vulnerable.case_id,
                "version": vulnerable.version,
                "heap_state": vulnerable.heap_state,
                "profile": vulnerable.profile,
                "verified": False,
                "attempts": [],
            }
            for attempt in range(1, self.args.attempts + 1):
                if time.monotonic() >= self.deadline:
                    pair["attempts"].append(
                        {"error": "total execution deadline reached"}
                    )
                    break
                positive = self.run_trial(vulnerable, attempt)
                negative = self.run_trial(control, attempt)
                verified = positive.rce_verified and negative.control_passed
                pair["attempts"].append(
                    {
                        "attempt": attempt,
                        "verified": verified,
                        "vulnerable": asdict(positive),
                        "patched_control": asdict(negative),
                    }
                )
                if verified:
                    pair["verified"] = True
                    break
            pairs.append(pair)
        report = {
            "schema_version": 1,
            "cve": CVE,
            "action": "run",
            "dry_run": False,
            "run_id": self.args.run_id,
            "target": self.args.host,
            "transport_only": False,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "all_verified": bool(pairs) and all(pair["verified"] for pair in pairs),
            "results": pairs,
        }
        self.write_report(report)
        return report

    def write_report(self, report: dict[str, Any]) -> None:
        """Persist a complete JSON result after all selected trials finish."""
        destination = self.run_dir / "result.json"
        temporary = self.run_dir / "result.json.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        temporary.replace(destination)


def profiles(profile_1317: str | None) -> dict[str, TargetProfile]:
    """Return supplied profiles; 1.31.7 remains explicitly gated."""
    return {
        "1.31.6": TargetProfile("1.31.6", "nginx:1.31.6", PROFILE_1316),
        "1.31.7": TargetProfile("1.31.7", "nginx:1.31.7", profile_1317),
        "1.31.8": TargetProfile("1.31.8", "nginx:1.31.8-rapid7-offline", PROFILE_1318),
    }


def build_trials(
    versions: Sequence[str], states: Sequence[str], profile_1317: str | None
) -> list[Trial]:
    """Pair every vulnerable trial with a same-state nginx 1.31.9 control."""
    catalog = profiles(profile_1317)
    trials: list[Trial] = []
    for version in versions:
        target = catalog[version]
        if target.profile is None:
            raise SafetyError(
                "nginx 1.31.7 requires --profile-1317 with a supplied calibrated profile"
            )
        for state in states:
            compact = version.replace(".", "")
            case_id = f"{compact}-{state}"
            trials.append(
                Trial(case_id, version, state, target.image, target.profile, False)
            )
            trials.append(
                Trial(
                    f"{case_id}-patched",
                    "1.31.9",
                    state,
                    PATCHED_IMAGE,
                    target.profile,
                    True,
                )
            )
    return trials


def numeric_loopback(value: str) -> str:
    """Reject DNS, private, public, scoped, and other non-loopback targets."""
    if "%" in value:
        raise argparse.ArgumentTypeError(
            "target must be an unscoped numeric loopback address"
        )
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "target must be numeric; hostnames are forbidden"
        ) from exc
    if not address.is_loopback:
        raise argparse.ArgumentTypeError("target must be a numeric loopback address")
    return value


def run_id(value: str) -> str:
    """Keep Docker names, marker commands, and result paths tightly namespaced."""
    if not NAME_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("run ID must match [a-z0-9][a-z0-9-]{0,23}")
    return value


def profile_name(value: str) -> str:
    """Accept a built-in calibrated profile name, never an arbitrary path."""
    if not PROFILE_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("invalid built-in profile name")
    return value


def parser() -> argparse.ArgumentParser:
    """Build the safe-by-default command-line interface."""
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="action")
    sub.add_parser(
        "list", help="List profiles and heap states without contacting Docker."
    )
    run = sub.add_parser(
        "run", help="Plan (default) or execute matched compatibility trials."
    )
    run.add_argument(
        "--execute",
        action="store_true",
        help="Run selected containers; default is dry-run.",
    )
    run.add_argument(
        "--transport-only",
        action="store_true",
        help="Test TLS/ALPN/HTTP only; never sends exploit traffic or claims RCE.",
    )
    run.add_argument(
        "--acknowledge-local-lab", default=None, help=f"Required with --execute: {ACK}"
    )
    run.add_argument(
        "--host",
        type=numeric_loopback,
        default="127.0.0.1",
        help="Numeric loopback only.",
    )
    run.add_argument(
        "--version",
        dest="versions",
        action="append",
        choices=("1.31.6", "1.31.7", "1.31.8"),
    )
    run.add_argument(
        "--heap", dest="states", action="append", choices=("fresh", "exercised")
    )
    run.add_argument(
        "--profile-1317",
        type=profile_name,
        default=None,
        help=f"Calibrated built-in 1.31.7 profile, e.g. {DEFAULT_PROFILE_1317}",
    )
    run.add_argument("--run-id", type=run_id, default="matrix")
    run.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE)
    run.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    run.add_argument("--attempts", type=int, default=1, metavar="1..3")
    run.add_argument("--exploit-timeout", type=int, default=420, metavar="30..900")
    run.add_argument("--total-timeout", type=int, default=7200, metavar="60..14400")
    run.add_argument("--exercise-requests", type=int, default=40, metavar="1..200")
    return root


def list_document() -> dict[str, Any]:
    """Describe availability without inspecting a host or invoking a process."""
    return {
        "schema_version": 1,
        "cve": CVE,
        "action": "list",
        "dry_run": True,
        "default_run": {
            "versions": ["1.31.6", "1.31.8"],
            "heap_states": ["fresh", "exercised"],
            "patched_control": "1.31.9",
            "attempts": 1,
        },
        "targets": [
            {
                "version": version,
                "image": target.image,
                "profile": target.profile,
                "status": (
                    "supplied" if target.profile else "awaiting_calibrated_profile"
                ),
            }
            for version, target in profiles(None).items()
        ]
        + [
            {
                "version": "1.31.9",
                "image": PATCHED_IMAGE,
                "profile": None,
                "status": "patched_negative_control",
            }
        ],
        "transport_checks": ["TLS", "ALPN h2", "HTTP/1.1 GET /index.html"],
        "safety": {
            "execute_requires": [
                "--execute",
                f"--acknowledge-local-lab {ACK}",
                f"hostname {EXPECTED_HOSTNAME}",
                "native x86-64 AVX512",
            ],
            "target": "numeric loopback only",
            "rce_evidence": "pre-absent marker + independent UID/GID/mode/size/path + patched marker absence",
        },
    }


def main(argv: Sequence[str] | None = None, docker: BoundedDocker | None = None) -> int:
    """List, plan, or execute; return nonzero for any unverified live pair."""
    args = parser().parse_args(argv)
    if args.action in (None, "list"):
        print(json.dumps(list_document(), indent=2))
        return 0
    try:
        versions = args.versions or ["1.31.6", "1.31.8"]
        states = args.states or ["fresh", "exercised"]
        trials = build_trials(versions, states, args.profile_1317)
        bounds = (
            ("attempts", 1, 3),
            ("exploit_timeout", 30, 900),
            ("total_timeout", 60, 14400),
            ("exercise_requests", 1, 200),
        )
        for name, minimum, maximum in bounds:
            value = getattr(args, name)
            if not minimum <= value <= maximum:
                raise SafetyError(
                    f"--{name.replace('_', '-')} must be between {minimum} and {maximum}"
                )
        if args.execute and args.acknowledge_local_lab != ACK:
            raise SafetyError(f"execution requires --acknowledge-local-lab {ACK}")
        if not args.execute:
            document = {
                "schema_version": 1,
                "cve": CVE,
                "action": "run",
                "dry_run": True,
                "run_id": args.run_id,
                "target": args.host,
                "source_root": str(args.source_root),
                "transport_only": args.transport_only,
                "results_dir": str(args.results_dir / args.run_id),
                "attempts_per_pair": args.attempts,
                "exploit_timeout_seconds": args.exploit_timeout,
                "total_timeout_seconds": args.total_timeout,
                "exercise_requests": args.exercise_requests,
                "trials": [asdict(trial) for trial in trials],
                "note": "No subprocesses, containers, network connections, or result files were created.",
            }
            print(json.dumps(document, indent=2))
            return 0
        report = CompatibilityRunner(args, docker).execute(trials)
        print(json.dumps(report, indent=2))
        if args.transport_only:
            return 0 if report["all_transport_verified"] else 1
        return 0 if report["all_verified"] else 1
    except (SafetyError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "cve": CVE,
                    "action": args.action,
                    "dry_run": not args.execute,
                    "status": "refused",
                    "error": str(exc),
                },
                indent=2,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
