"""Safety, parsing, and adapter tests; all process execution is mocked."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from suite.adapters import build_or_run, verify_archived
from suite.cli import cli
from suite.models import (
    Budget,
    CommandResult,
    CommandSpec,
    Evidence,
    Manifest,
    Marker,
    PatchedControl,
    Phase,
    Status,
    SuiteError,
    marker_matches,
    parse_marker_output,
    prepare_command,
)
from suite.runner import BoundedRunner

CVE = "CVE-2026-123634"
MARKER = Marker(path="/tmp/nginx2root-marker-test")
CONTROL = PatchedControl(
    container="nginx-123634-patched", absent_marker="/tmp/nginx2root-marker-control"
)


def spec(argv: list[str], **kwargs: Any) -> CommandSpec:
    """Build concise command fixtures with explicit defaults."""
    return CommandSpec(argv=tuple(argv), **kwargs)


def test_marker_parser_reads_uid_gid_mode_size_path() -> None:
    """The independent observation is parsed as five typed fields."""
    observed = parse_marker_output("101:101 0644 0bytes /tmp/nginx2root-marker-test\n")
    assert observed.uid == 101
    assert observed.gid == 101
    assert observed.mode == "0644"
    assert observed.size == 0
    assert not marker_matches(observed, MARKER)


@pytest.mark.parametrize(
    "line",
    [
        "101:101 644 0bytes /tmp/nginx2root-marker-test",
        "0:0 0644 0bytes /tmp/nginx2root-marker-test trailing",
        "101:101 0644 0bytes /etc/passwd",
        "command dispatched",
        "",
    ],
)
def test_marker_parser_rejects_missing_or_non_namespaced_evidence(line: str) -> None:
    """Client logs and incomplete stat output cannot prove execution."""
    with pytest.raises(SuiteError):
        parse_marker_output(line)


def test_marker_parser_accepts_explicit_archived_path() -> None:
    """Only archived verification can read the baseline's historical marker."""
    observed = parse_marker_output(
        "101:101 644 0bytes /tmp/rapid7-nginx-h2-proof-01", archived=True
    )
    assert observed.mode == "0644"
    with pytest.raises(SuiteError):
        parse_marker_output("101:101 644 0bytes /tmp/rapid7-nginx-h2-proof-01")


def test_archived_size_omission_requires_explicit_declaration() -> None:
    """Live evidence and undeclared archives must include a byte count."""
    line = "101:101 644 /tmp/rapid7-nginx-h2-proof-01"
    with pytest.raises(SuiteError):
        parse_marker_output(line, archived=True)
    observed = parse_marker_output(
        line, archived=True, archived_size_omitted=True
    )
    assert observed.size == 0


def test_marker_mismatches_block_verification() -> None:
    """A matching path but root ownership or wrong mode is not enough."""
    observed = parse_marker_output("0:101 0600 1bytes /tmp/nginx2root-marker-test")
    mismatches = marker_matches(observed, MARKER)
    assert len(mismatches) == 3
    assert any("uid" in item for item in mismatches)
    assert any("mode" in item for item in mismatches)
    assert any("size" in item for item in mismatches)


@pytest.mark.parametrize("target", ["8.8.8.8", "10.128.0.106", "example.com", "::1%eth0"])
@pytest.mark.parametrize("option", ["--target", "--host", "--hostname", "--ip"])
def test_non_loopback_targets_are_refused(target: str, option: str) -> None:
    """Explicit target flags cannot name external, private, or DNS targets."""
    with pytest.raises(SuiteError, match="non-loopback target"):
        prepare_command(
            spec(["python3", "-I", "trigger.py", option, target]),
            cve=CVE,
            marker=MARKER,
            control=CONTROL,
            attempt=1,
            allow_patched_target=False,
        )


def test_loopback_and_allowlisted_patched_container_pass() -> None:
    """Only numeric loopback and a declared patched container are accepted."""
    loopback = prepare_command(
        spec(["python3", "-I", "trigger.py", "--target=127.0.0.2"]),
        cve=CVE,
        marker=MARKER,
        control=CONTROL,
        attempt=1,
        allow_patched_target=False,
    )
    assert loopback[-1] == "--target=127.0.0.2"
    control = prepare_command(
        spec(["python3", "-I", "trigger.py", "--host", "nginx-123634-patched"]),
        cve=CVE,
        marker=MARKER,
        control=CONTROL,
        attempt=1,
        allow_patched_target=True,
    )
    assert control[-1] == "nginx-123634-patched"


def test_docker_names_and_networks_are_allowlisted() -> None:
    """Containers and networks must belong to the selected CVE."""
    with pytest.raises(SuiteError, match="networking"):
        prepare_command(
            spec(
                ["docker", "exec", "--network=bridge", "nginx-123634-target", "true"],
                containers=("nginx-123634-target",),
                networks=("bridge",),
            ),
            cve=CVE,
            marker=MARKER,
            control=CONTROL,
            attempt=1,
            allow_patched_target=False,
        )
    with pytest.raises(SuiteError, match="non-allowlisted container"):
        prepare_command(
            spec(["docker", "exec", "other-container", "true"]),
            cve=CVE,
            marker=MARKER,
            control=CONTROL,
            attempt=1,
            allow_patched_target=False,
        )
    valid = prepare_command(
        spec(
            ["docker", "exec", "nginx-123634-target", "true"],
            containers=("nginx-123634-target",),
            networks=("nginx-123634-net",),
        ),
        cve=CVE,
        marker=MARKER,
        control=CONTROL,
        attempt=1,
        allow_patched_target=False,
    )
    assert valid[2] == "nginx-123634-target"


def test_docker_public_bind_and_shell_are_refused() -> None:
    """Non-loopback published ports and nested shell commands never run."""
    with pytest.raises(SuiteError, match="published"):
        prepare_command(
            spec(["docker", "run", "-p0.0.0.0:8080:80", "nginx-123634-image"]),
            cve=CVE,
            marker=MARKER,
            control=CONTROL,
            attempt=1,
            allow_patched_target=False,
        )
    with pytest.raises(ValueError, match="shell"):
        spec(["sh", "-c", "docker exec nginx-123634-target true"])


def test_manifest_bounds_are_enforced() -> None:
    """Both operator and manifest budgets have finite upper limits."""
    with pytest.raises(ValueError):
        Budget(attempts=4)
    with pytest.raises(ValueError):
        Budget(timeout=901)
    with pytest.raises(ValueError):
        Budget(max_bytes=2 * 1024**3 + 1)
    with pytest.raises(ValueError):
        spec(["python3", "-I", "trigger.py"], timeout=901)


def make_manifest() -> Manifest:
    """Create an in-memory executable adapter using only harmless fixtures."""
    commands = {
        Phase.PREMARKER: spec(
            ["docker", "exec", "nginx-123634-target", "stat", MARKER.path],
            containers=("nginx-123634-target",),
            description="Prove marker absent before trigger",
        ),
        Phase.RUN: spec(
            ["python3", "-I", "trigger.py", "--target=127.0.0.1"],
            description="Run bounded local trigger",
        ),
        Phase.MARKER: spec(
            ["docker", "exec", "nginx-123634-target", "stat", MARKER.path],
            containers=("nginx-123634-target",),
            description="Read independent marker metadata",
        ),
        Phase.CONTROL: spec(
            ["docker", "exec", "nginx-123634-patched", "stat", CONTROL.absent_marker or ""],
            containers=("nginx-123634-patched",),
            description="Prove patched marker absent",
        ),
    }
    return Manifest(
        cve=CVE,
        title="Mocked local test",
        implemented=True,
        directory=CVE.lower(),
        notes="test only",
        commands=commands,
        evidence=Evidence(marker=MARKER, container="nginx-123634-target"),
        patched_control=CONTROL,
    )


def command(phase: Phase, code: int, stdout: str = "", stderr: str = "") -> CommandResult:
    """Create a mocked subprocess result for an adapter stage."""
    return CommandResult(
        phase=phase, argv=("mock",), returncode=code, stdout_tail=stdout, stderr_tail=stderr
    )


def test_zero_trigger_exit_without_marker_is_not_verified(tmp_path: Path) -> None:
    """A successful exploit-client exit cannot substitute for command evidence."""
    responses = [
        command(Phase.PREMARKER, 1),
        command(Phase.RUN, 0, "dispatched"),
        command(Phase.MARKER, 1),
        command(Phase.CONTROL, 1),
    ]
    with (
        patch("suite.adapters.confined_directory", return_value=tmp_path),
        patch("suite.adapters.BoundedRunner.run", side_effect=responses) as run,
    ):
        result = build_or_run(make_manifest(), "run", Budget(), False)
    assert result.status == Status.NOT_VERIFIED
    assert result.verification is not None
    assert not result.verification.rce_verified
    assert run.call_count == 4


def test_uid_gid_mode_marker_and_patched_absence_verify_rce(tmp_path: Path) -> None:
    """Complete independent evidence is required for the sole RCE status."""
    responses = [
        command(Phase.PREMARKER, 1),
        command(Phase.RUN, 0),
        command(
            Phase.MARKER,
            0,
            "101:101 0644 0bytes /tmp/nginx2root-marker-test\n",
        ),
        command(Phase.CONTROL, 1),
    ]
    with (
        patch("suite.adapters.confined_directory", return_value=tmp_path),
        patch("suite.adapters.BoundedRunner.run", side_effect=responses),
    ):
        result = build_or_run(make_manifest(), "run", Budget(), False)
    assert result.status == Status.VERIFIED
    assert result.verification is not None
    assert result.verification.rce_verified
    assert result.verification.patched_control is not None
    assert result.verification.patched_control.marker_absent


def test_marker_on_patched_control_blocks_verification(tmp_path: Path) -> None:
    """A positive patched control invalidates the vulnerability-specific claim."""
    responses = [
        command(Phase.PREMARKER, 1),
        command(Phase.RUN, 0),
        command(
            Phase.MARKER, 0, "101:101 0644 0bytes /tmp/nginx2root-marker-test"
        ),
        command(Phase.CONTROL, 0),
    ]
    with (
        patch("suite.adapters.confined_directory", return_value=tmp_path),
        patch("suite.adapters.BoundedRunner.run", side_effect=responses),
    ):
        result = build_or_run(make_manifest(), "run", Budget(), False)
    assert result.status == Status.NOT_VERIFIED
    assert result.verification is not None
    assert not result.verification.rce_verified


def test_attempts_are_bounded(tmp_path: Path) -> None:
    """Each failed cycle uses one bounded set of subprocesses and then stops."""
    responses = [command(Phase.PREMARKER, 1), command(Phase.RUN, 1)] * 3
    with (
        patch("suite.adapters.confined_directory", return_value=tmp_path),
        patch("suite.adapters.BoundedRunner.run", side_effect=responses) as run,
    ):
        result = build_or_run(make_manifest(), "run", Budget(attempts=3), False)
    assert result.attempts == 3
    assert run.call_count == 6
    assert result.status == Status.FAILED


def test_dry_run_validates_without_subprocesses(tmp_path: Path) -> None:
    """Dry-run validates all stage commands but never invokes a process."""
    with (
        patch("suite.adapters.confined_directory", return_value=tmp_path),
        patch("suite.adapters.BoundedRunner.run") as run,
    ):
        result = build_or_run(make_manifest(), "run", Budget(), True)
    assert result.status == Status.DRY_RUN
    assert len(result.details) == 5
    run.assert_not_called()


def test_runner_applies_smaller_stage_budget_and_process_group(tmp_path: Path) -> None:
    """The runner never widens manifest limits and creates a killable group."""
    process = Mock()
    process.pid = 12345
    process.returncode = 0
    process.stdout = Mock()
    process.stderr = Mock()
    process.stdout.fileno.return_value = 10
    process.stderr.fileno.return_value = 11
    process.poll.return_value = 0
    with (
        patch("suite.runner.subprocess.Popen", return_value=process) as popen,
        patch("suite.runner.os.set_blocking"),
        patch("suite.runner.selectors.DefaultSelector") as selector_type,
    ):
        selector_type.return_value.get_map.return_value = {}
        result = BoundedRunner(Budget(timeout=30, max_bytes=1024 * 1024), tmp_path).run(
            Phase.BUILD,
            spec(["python3", "-I", "build.py"], timeout=60, max_bytes=64 * 1024 * 1024),
            ("python3", "-I", "build.py"),
        )
    assert result.returncode == 0
    assert popen.call_args.kwargs["start_new_session"] is True
    assert "shell" not in popen.call_args.kwargs
    process.stdout.close.assert_called_once()
    process.stderr.close.assert_called_once()


def test_runner_timeout_kills_only_new_process_group(tmp_path: Path) -> None:
    """A timed-out command is group-killed, drained, and reported as timed out."""
    process = Mock()
    process.pid = 23456
    process.returncode = -9
    process.stdout = Mock()
    process.stderr = Mock()
    process.stdout.fileno.return_value = 12
    process.stderr.fileno.return_value = 13
    process.poll.return_value = None
    process.wait.return_value = -9
    with (
        patch("suite.runner.subprocess.Popen", return_value=process),
        patch("suite.runner.os.set_blocking"),
        patch("suite.runner.os.killpg") as killpg,
        patch("suite.runner.time.monotonic", side_effect=[0, 2, 3]),
        patch("suite.runner.selectors.DefaultSelector") as selector_type,
    ):
        selector_type.return_value.get_map.return_value = {1: "stdout"}
        result = BoundedRunner(Budget(timeout=1), tmp_path).run(
            Phase.RUN,
            spec(["python3", "-I", "trigger.py"]),
            ("python3", "-I", "trigger.py"),
        )
    assert result.timed_out
    killpg.assert_called_once_with(23456, 9)


def test_cli_defaults_to_safe_list() -> None:
    """Bare invocation lists all five without reading external targets."""
    result = CliRunner().invoke(cli, ["--json"])
    assert result.exit_code == 0
    assert '"cve": "CVE-2026-123007"' in result.output
    assert result.output.count('"cve":') == 5


def test_cli_execution_requires_exact_acknowledgement() -> None:
    """An --execute request without the acknowledgement fails before adapters."""
    with patch("suite.cli.get_result") as get_result:
        result = CliRunner().invoke(cli, ["run", "cve-2026-123634", "--execute"])
    assert result.exit_code != 0
    assert "I-AUTHORIZE-LOCAL-LAB" in result.output
    get_result.assert_not_called()


def test_cli_unimplemented_selection_is_nonzero_json() -> None:
    """A requested unavailable PoC reports not_implemented, never fake success."""
    result = CliRunner().invoke(cli, ["run", "cve-2026-121810", "--json"])
    assert result.exit_code == 1
    assert '"status": "not_implemented"' in result.output
    assert '"all_verified": false' in result.output


def test_cli_parallel_is_explicit_and_preserves_order() -> None:
    """Parallel mode is opt-in and reports remain aligned with requested IDs."""
    result = CliRunner().invoke(
        cli, ["run", "cve-2026-123633", "cve-2026-113425", "--parallel", "--json"]
    )
    assert result.exit_code == 1
    assert result.output.index("CVE-2026-123633") < result.output.index("CVE-2026-113425")


def test_archived_control_path_cannot_be_used_for_live_runs() -> None:
    """Legacy evidence paths are confined to persisted control records."""
    with pytest.raises(ValueError):
        PatchedControl(
            container="nginx-123634-patched",
            absent_marker="/tmp/rapid7-nginx-h2-release-patched",
        )
    control = PatchedControl(
        container="nginx-123634-patched",
        absent_marker="/tmp/rapid7-nginx-h2-release-patched",
        result_file="evidence/control.json",
        archived_path=True,
    )
    assert control.archived_path


def test_baseline_manifest_reads_original_evidence(tmp_path: Path) -> None:
    """The archived baseline reads its real marker without invoking Docker."""
    root = tmp_path / "investigation"
    evidence_dir = root / "gcp-avx512-results"
    evidence_dir.mkdir(parents=True)
    marker = evidence_dir / "marker.txt"
    marker.write_text("101:101 644 0bytes /tmp/rapid7-nginx-h2-proof-01\n")
    manifest = Manifest(
        cve="CVE-2026-123007",
        title="archived baseline",
        archived=True,
        directory="cve-2026-123007",
        notes="do not rerun",
        evidence=Evidence(
            marker_file="gcp-avx512-results/marker.txt",
            marker=Marker(
                path="/tmp/rapid7-nginx-h2-proof-01",
                archived_path=True,
            ),
        ),
    )
    with patch("suite.adapters.confined_path", return_value=marker):
        result = verify_archived(manifest)
    assert result.status == Status.ARCHIVED
    assert result.verification is not None
    assert result.verification.marker is not None
    assert result.verification.marker.uid == 101
    assert not result.verification.rce_verified
    assert any("patched" in reason for reason in result.verification.reasons)
