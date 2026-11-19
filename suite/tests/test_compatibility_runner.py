"""Safety and verdict tests for the compatibility runner; subprocesses are mocked."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import Mock, patch

import compatibility_runner as runner
import pytest


def test_default_action_lists_without_processes() -> None:
    """Bare invocation lists supplied and unavailable profiles."""
    with patch.object(runner.subprocess, "Popen") as popen:
        assert runner.main([]) == 0
    popen.assert_not_called()


def test_run_defaults_to_dry_run_without_processes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A planned matrix includes fresh/exercised pairs and patched controls."""
    with patch.object(runner.subprocess, "Popen") as popen:
        assert runner.main(["run"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["dry_run"] is True
    assert len(document["trials"]) == 8
    assert sum(trial["patched"] for trial in document["trials"]) == 4
    popen.assert_not_called()


def test_execute_requires_exact_acknowledgement_before_preflight() -> None:
    """The acknowledgement gate precedes host inspection and Docker execution."""
    with patch.object(runner.CompatibilityRunner, "preflight") as preflight:
        assert runner.main(["run", "--execute"]) == 2
    preflight.assert_not_called()


@pytest.mark.parametrize(
    "target", ["localhost", "8.8.8.8", "10.128.0.106", "::1%eth0", "127.0.0.1:443"]
)
def test_only_numeric_loopback_targets_are_accepted(target: str) -> None:
    """No DNS resolution, alternate interface, or non-loopback address is allowed."""
    with pytest.raises(SystemExit):
        runner.parser().parse_args(["run", "--host", target])


@pytest.mark.parametrize("target", ["127.0.0.1", "127.0.0.2", "::1"])
def test_numeric_loopback_targets_are_accepted(target: str) -> None:
    """IPv4 and IPv6 numeric loopback are both valid."""
    args = runner.parser().parse_args(["run", "--host", target])
    assert args.host == target


def test_1317_requires_supplied_calibrated_profile() -> None:
    """An installed nginx image alone does not make a version runnable."""
    with pytest.raises(runner.SafetyError, match="profile-1317"):
        runner.build_trials(["1.31.7"], ["fresh"], None)
    trials = runner.build_trials(["1.31.7"], ["fresh"], runner.DEFAULT_PROFILE_1317)
    assert trials[0].profile == runner.DEFAULT_PROFILE_1317


def test_attempts_and_timeouts_are_bounded(capsys: pytest.CaptureFixture[str]) -> None:
    """Finite retry and wall-clock bounds fail before preflight or execution."""
    for option, value in [
        ("--attempts", "4"),
        ("--exploit-timeout", "901"),
        ("--total-timeout", "14401"),
    ]:
        with patch.object(runner.CompatibilityRunner, "preflight") as preflight:
            assert runner.main(["run", option, value]) == 2
        assert '"status": "refused"' in capsys.readouterr().out
        preflight.assert_not_called()


def test_bad_run_id_and_shell_profile_are_rejected() -> None:
    """Container/marker namespaces and built-in profile names cannot be escaped."""
    with pytest.raises(SystemExit):
        runner.parser().parse_args(["run", "--run-id", "../escape"])
    with pytest.raises(SystemExit):
        runner.parser().parse_args(["run", "--profile-1317", "/tmp/profile.json"])


def make_args(tmp_path: Path) -> argparse.Namespace:
    """Create minimal live arguments for mocked trial execution."""
    return runner.parser().parse_args(
        [
            "run",
            "--execute",
            "--acknowledge-local-lab",
            runner.ACK,
            "--run-id",
            "unit",
            "--results-dir",
            str(tmp_path),
            "--exercise-requests",
            "2",
        ]
    )


def make_trial(patched: bool = False) -> runner.Trial:
    """Build a harmless in-memory profile fixture."""
    return runner.Trial(
        case_id="1318-fresh-patched" if patched else "1318-fresh",
        version="1.31.9" if patched else "1.31.8",
        heap_state="fresh",
        image=runner.PATCHED_IMAGE if patched else "nginx:1.31.8-rapid7-offline",
        profile=runner.PROFILE_1318,
        patched=patched,
    )


def marker_output(run_id: str = "unit", case_id: str = "1318-fresh") -> str:
    """Return strict independent marker evidence."""
    return f"101:101 644 0 /tmp/rapid7-compat-{run_id}-{case_id}-a1\n"


def test_exact_marker_verifies_vulnerable_trial(tmp_path: Path) -> None:
    """Only strict nginx-worker marker metadata establishes the positive trial."""
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    with (
        patch.object(lab, "start_target") as start,
        patch.object(lab, "transport"),
        patch.object(lab, "exploit", return_value=runner.CommandResult([], 0, 1)),
        patch.object(
            lab,
            "observe_marker",
            return_value={
                "uid": 101,
                "gid": 101,
                "mode": "0644",
                "size": 0,
                "path": "/tmp/rapid7-compat-unit-1318-fresh-a1",
            },
        ),
        patch.object(lab, "command", return_value=runner.CommandResult([], 0, 1)),
        patch.object(lab, "cleanup"),
    ):
        result = lab.run_trial(make_trial(), 1)
    start.assert_called_once()
    assert result.rce_verified
    assert result.verdict == "verified"


def test_client_success_without_marker_is_not_rce(tmp_path: Path) -> None:
    """Client dispatch, exit zero, or a crash is never called RCE."""
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    with (
        patch.object(lab, "start_target"),
        patch.object(lab, "transport"),
        patch.object(lab, "exploit", return_value=runner.CommandResult([], 0, 1)),
        patch.object(lab, "observe_marker", return_value=None),
        patch.object(lab, "command", return_value=runner.CommandResult([], 0, 1)),
        patch.object(lab, "cleanup"),
    ):
        result = lab.run_trial(make_trial(), 1)
    assert not result.rce_verified
    assert result.verdict == "not_verified"
    assert "crashes do not establish RCE" in result.reasons[0]


def test_patched_marker_absence_passes_control(tmp_path: Path) -> None:
    """The control has an independent pass/fail verdict."""
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    with (
        patch.object(lab, "start_target"),
        patch.object(lab, "transport"),
        patch.object(lab, "exploit", return_value=runner.CommandResult([], 1, 1)),
        patch.object(lab, "observe_marker", return_value=None),
        patch.object(lab, "command", return_value=runner.CommandResult([], 0, 1)),
        patch.object(lab, "cleanup"),
    ):
        result = lab.run_trial(make_trial(patched=True), 1)
    assert result.control_passed
    assert result.verdict == "control_passed"


def test_positive_patched_control_cannot_verify(tmp_path: Path) -> None:
    """A marker on 1.31.9 invalidates the vulnerability-specific claim."""
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    observed = {
        "uid": 101,
        "gid": 101,
        "mode": "0644",
        "size": 0,
        "path": "/tmp/rapid7-compat-unit-1318-fresh-patched-a1",
    }
    with (
        patch.object(lab, "start_target"),
        patch.object(lab, "transport"),
        patch.object(lab, "exploit", return_value=runner.CommandResult([], 0, 1)),
        patch.object(lab, "observe_marker", return_value=observed),
        patch.object(lab, "command", return_value=runner.CommandResult([], 0, 1)),
        patch.object(lab, "cleanup"),
    ):
        result = lab.run_trial(make_trial(patched=True), 1)
    assert not result.control_passed
    assert result.verdict == "control_positive"


def test_wrong_marker_owner_does_not_verify(tmp_path: Path) -> None:
    """A path match alone is insufficient marker evidence."""
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    observed = {
        "uid": 0,
        "gid": 101,
        "mode": "0644",
        "size": 0,
        "path": "/tmp/rapid7-compat-unit-1318-fresh-a1",
    }
    with (
        patch.object(lab, "start_target"),
        patch.object(lab, "transport"),
        patch.object(lab, "exploit", return_value=runner.CommandResult([], 0, 1)),
        patch.object(lab, "observe_marker", return_value=observed),
        patch.object(lab, "command", return_value=runner.CommandResult([], 0, 1)),
        patch.object(lab, "cleanup"),
    ):
        result = lab.run_trial(make_trial(), 1)
    assert not result.rce_verified
    assert any("uid" in reason for reason in result.marker_mismatches)


def test_strict_marker_stat_parser(tmp_path: Path) -> None:
    """Docker stat is normalized; arbitrary text cannot become marker evidence."""
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    command_result = runner.CommandResult([], 0, 1, log=str(tmp_path / "marker.log"))
    Path(command_result.log).write_text(marker_output())
    with patch.object(lab, "command", return_value=command_result):
        observed = lab.observe_marker(
            make_trial(),
            1,
            "rapid7-compat-unit-1318-fresh-a1",
            "/tmp/rapid7-compat-unit-1318-fresh-a1",
        )
    assert observed is not None
    assert observed["mode"] == "0644"
    Path(command_result.log).write_text("payload dispatched\n")
    with patch.object(lab, "command", return_value=command_result):
        with pytest.raises(runner.SafetyError, match="strict evidence"):
            lab.observe_marker(
                make_trial(), 1, "target", "/tmp/rapid7-compat-unit-1318-fresh-a1"
            )


def test_transport_and_exploit_use_loopback_and_named_containers(
    tmp_path: Path,
) -> None:
    """Live Docker argv uses isolated container networking and direct numeric URLs."""
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    with patch.object(
        lab, "client_python", return_value=runner.CommandResult([], 0, 1)
    ) as client:
        lab.transport(make_trial(), 1, "rapid7-compat-unit-1318-fresh-a1", "127.0.0.1")
    assert "127.0.0.1" in client.call_args.args[4]
    with (
        patch.object(
            lab, "command", return_value=runner.CommandResult([], 0, 1)
        ) as command,
        patch.object(lab.docker, "run"),
    ):
        lab.exploit(
            make_trial(),
            1,
            "rapid7-compat-unit-1318-fresh-a1",
            "127.0.0.1",
            "/tmp/rapid7-compat-unit-1318-fresh-a1",
        )
    argv = command.call_args.args[3]
    assert argv[:2] == ("sudo", "docker")
    assert "shell" not in command.call_args.kwargs
    assert "https://127.0.0.1:443/" in argv
    assert "container:rapid7-compat-unit-1318-fresh-a1" in argv
    assert "--network" in argv and "none" not in argv


def test_execute_requires_positive_and_control(tmp_path: Path) -> None:
    """The pair-level result cannot verify from the positive trial alone."""
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    positive = Mock(rce_verified=True, control_passed=False)
    negative = Mock(rce_verified=False, control_passed=False)
    with (
        patch.object(
            runner, "asdict", side_effect=lambda value: {"verdict": value.rce_verified}
        ),
        patch.object(lab, "preflight"),
        patch.object(lab, "run_trial", side_effect=[positive, negative]),
    ):
        report = lab.execute([make_trial(), make_trial(patched=True)])
    assert not report["all_verified"]
    assert not report["results"][0]["verified"]
    assert (tmp_path / "unit" / "result.json").is_file()


def test_bounded_runner_invokes_subprocess_without_shell(tmp_path: Path) -> None:
    """The only real process call is an argv Docker invocation with its own group."""
    process = Mock()
    process.pid = 1234
    process.returncode = 0
    process.stdout = Mock()
    process.stderr = Mock()
    process.stdout.fileno.return_value = 10
    process.stderr.fileno.return_value = 11
    with (
        patch.object(runner.subprocess, "Popen", return_value=process) as popen,
        patch.object(runner.os, "set_blocking"),
        patch.object(runner.selectors, "DefaultSelector") as selector_type,
    ):
        selector_type.return_value.get_map.return_value = {}
        result = runner.BoundedDocker().run(
            ("sudo", "docker", "ps"),
            timeout=10,
            deadline=runner.time.monotonic() + 20,
            log_path=tmp_path / "command.log",
        )
    assert result.returncode == 0
    assert popen.call_args.kwargs["shell"] is False
    assert popen.call_args.kwargs["start_new_session"] is True
    assert popen.call_args.args[0][:2] == ["sudo", "docker"]


def test_bounded_runner_rejects_non_docker_process(tmp_path: Path) -> None:
    """A caller cannot turn the runner into an arbitrary process executor."""
    with pytest.raises(runner.SafetyError):
        runner.BoundedDocker().run(
            ("sh", "-c", "true"),
            timeout=1,
            deadline=runner.time.monotonic() + 2,
            log_path=tmp_path / "refused.log",
        )


def test_preflight_failure_still_writes_result(tmp_path: Path) -> None:
    """A refused live run leaves a machine-readable failure result."""
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    with (
        patch.object(lab, "preflight", side_effect=runner.SafetyError("missing image")),
        pytest.raises(runner.SafetyError, match="missing image"),
    ):
        lab.execute([make_trial(), make_trial(patched=True)])
    result = json.loads((tmp_path / "unit" / "result.json").read_text())
    assert result["status"] == "preflight_failed"
    assert not result["all_verified"]


def test_transport_only_execute_does_not_call_exploit(tmp_path: Path) -> None:
    """The execute path propagates transport-only mode to each selected trial."""
    args = runner.parser().parse_args(
        [
            "run",
            "--execute",
            "--transport-only",
            "--acknowledge-local-lab",
            runner.ACK,
            "--run-id",
            "unit",
            "--results-dir",
            str(tmp_path),
            "--version",
            "1.31.8",
        ]
    )
    lab = runner.CompatibilityRunner(args)
    transport_result = runner.TrialResult(
        case_id="1318-fresh",
        role="vulnerable",
        version="1.31.8",
        heap_state="fresh",
        image="test",
        profile=runner.PROFILE_1318,
        attempt=1,
        target_container="test",
        marker="/tmp/test",
        verdict="transport_verified",
        transport_passed=True,
    )
    with (
        patch.object(lab, "preflight"),
        patch.object(lab, "run_trial", return_value=transport_result) as run_trial,
        patch.object(lab, "exploit") as exploit,
    ):
        report = lab.execute([make_trial(), make_trial(patched=True)])
    assert run_trial.call_args.args[0].transport_only
    exploit.assert_not_called()
    assert report["all_transport_verified"]
    assert not report["all_verified"]


def test_transport_only_never_invokes_exploit(tmp_path: Path) -> None:
    """A live transport probe cannot send exploit traffic or claim RCE."""
    trial = runner.Trial(**{**make_trial().__dict__, "transport_only": True})
    lab = runner.CompatibilityRunner(make_args(tmp_path))
    with (
        patch.object(lab, "start_target"),
        patch.object(lab, "transport"),
        patch.object(lab, "exploit") as exploit,
        patch.object(lab, "observe_marker", return_value=None),
        patch.object(lab, "command", return_value=runner.CommandResult([], 0, 1)),
        patch.object(lab, "cleanup"),
    ):
        result = lab.run_trial(trial, 1)
    exploit.assert_not_called()
    assert result.verdict == "transport_verified"
    assert not result.rce_verified


def test_timeout_kills_only_new_process_group(tmp_path: Path) -> None:
    """Deadline enforcement uses the new process group rather than shell commands."""
    process = Mock()
    process.pid = 2345
    process.returncode = -9
    process.stdout = Mock()
    process.stderr = Mock()
    process.stdout.fileno.return_value = 12
    process.stderr.fileno.return_value = 13
    with (
        patch.object(runner.subprocess, "Popen", return_value=process),
        patch.object(runner.os, "set_blocking"),
        patch.object(runner.os, "killpg") as killpg,
        patch.object(runner.selectors, "DefaultSelector") as selector_type,
        patch.object(runner.time, "monotonic", side_effect=[0, 0, 20, 20]),
    ):
        selector_type.return_value.get_map.return_value = {1: "stdout"}
        result = runner.BoundedDocker().run(
            ("sudo", "docker", "logs", "target"),
            timeout=1,
            deadline=10,
            log_path=tmp_path / "timeout.log",
        )
    assert result.timed_out
    killpg.assert_called_once_with(2345, runner.signal.SIGKILL)
