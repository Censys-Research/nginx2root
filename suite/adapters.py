"""Manifest adapters and independently recorded command-marker evidence."""

from __future__ import annotations

import json
from pathlib import Path

from .models import (
    Budget,
    CommandResult,
    ControlResult,
    Manifest,
    Phase,
    PocResult,
    Status,
    SuiteError,
    Verification,
    confined_path,
    evidence_sha256,
    load_manifest,
    marker_matches,
    parse_marker_output,
    prepare_command,
)
from .runner import BoundedRunner


def _unavailable(manifest: Manifest, action: str, dry_run: bool) -> PocResult:
    """Report unavailable adapters truthfully, including archived run requests."""
    if manifest.archived and action in {"build", "run"}:
        return PocResult(
            cve=manifest.cve,
            title=manifest.title,
            status=Status.ARCHIVED,
            implemented=False,
            archived=True,
            requested_action=action,
            dry_run=dry_run,
            details=["Archived evidence only; the verified baseline is never rerun."],
        )
    return PocResult(
        cve=manifest.cve,
        title=manifest.title,
        status=Status.NOT_IMPLEMENTED,
        implemented=False,
        archived=manifest.archived,
        requested_action=action,
        dry_run=dry_run,
        details=[manifest.notes],
    )


def _argv(manifest: Manifest, phase: Phase, attempt: int) -> tuple[str, ...]:
    """Validate a stage immediately before use, including its target and names."""
    return prepare_command(
        manifest.commands[phase],
        cve=manifest.cve,
        marker=manifest.evidence.marker if manifest.evidence else None,
        control=manifest.patched_control,
        attempt=attempt,
        allow_patched_target=phase == Phase.CONTROL,
    )


def _read_evidence(relative: str) -> tuple[str, dict[str, str]]:
    """Read a confined text artifact and return its path and content digest."""
    path = confined_path(relative)
    return path.read_text(encoding="utf-8"), {
        "path": str(path),
        "sha256": evidence_sha256(path),
    }


def verify_archived(manifest: Manifest, dry_run: bool = False) -> PocResult:
    """Validate historical marker evidence without inventing fresh checks."""
    result = PocResult(
        cve=manifest.cve,
        title=manifest.title,
        status=Status.NOT_VERIFIED,
        implemented=False,
        archived=True,
        requested_action="verify",
        dry_run=dry_run,
        details=[manifest.notes],
        verification=Verification(),
    )
    if not manifest.evidence or not manifest.evidence.marker_file:
        result.details.append("Archived manifest has no marker evidence.")
        return result
    if not manifest.evidence.marker:
        result.details.append("Archived manifest has no expected marker identity.")
        return result
    try:
        marker_text, provenance = _read_evidence(manifest.evidence.marker_file)
        observation = parse_marker_output(
            marker_text,
            archived=True,
            archived_size_omitted=manifest.evidence.marker.archived_size_omitted,
        )
        result.verification.marker = observation
        result.evidence["marker"] = json.dumps(provenance)
        mismatches = marker_matches(observation, manifest.evidence.marker)
        result.verification.reasons.extend(mismatches)
        if manifest.patched_control and manifest.patched_control.result_file:
            control_text, control_provenance = _read_evidence(
                manifest.patched_control.result_file
            )
            control = ControlResult.model_validate(json.loads(control_text))
            if control.container != manifest.patched_control.container:
                raise SuiteError("persisted control identifies a different container")
            result.verification.patched_control = control
            result.evidence["patched_control"] = json.dumps(control_provenance)
            if not control.checked or not control.marker_absent:
                result.verification.reasons.append("patched control did not prove absence")
        else:
            result.verification.reasons.append(
                "archived baseline has no separate patched-target marker evidence"
            )
        if manifest.evidence.notes_file:
            _, notes_provenance = _read_evidence(manifest.evidence.notes_file)
            result.evidence["notes"] = json.dumps(notes_provenance)
        result.verification.rce_verified = False
        result.status = Status.ARCHIVED
        result.verification.reasons.append("fresh premarker absence was not rerun")
    except (OSError, UnicodeError, json.JSONDecodeError, SuiteError, ValueError) as exc:
        result.details.append(f"evidence validation failed: {exc}")
    return result


def _plan_phases(manifest: Manifest, action: str) -> list[Phase]:
    """Return every stage an action would invoke; verify never triggers traffic."""
    if action == "build":
        return [Phase.BUILD] if Phase.BUILD in manifest.commands else []
    if action == "run":
        phases = [Phase.BUILD] if Phase.BUILD in manifest.commands else []
        phases.extend([Phase.PREMARKER, Phase.RUN, Phase.MARKER, Phase.CONTROL])
        return phases
    return [Phase.MARKER, Phase.CONTROL]


def build_or_run(manifest: Manifest, action: str, budget: Budget, dry_run: bool) -> PocResult:
    """Build, plan, or run an implemented adapter with independent verification."""
    result = PocResult(
        cve=manifest.cve,
        title=manifest.title,
        status=Status.DRY_RUN if dry_run else Status.NOT_VERIFIED,
        implemented=True,
        requested_action=action,
        dry_run=dry_run,
        verification=Verification(),
    )
    runner = BoundedRunner(budget, confined_directory(manifest.directory))
    phases = _plan_phases(manifest, action)
    if action == "build" and not phases:
        result.status = Status.NOT_IMPLEMENTED
        result.implemented = False
        result.details.append("This adapter has no separate build stage.")
        return result
    if dry_run or action == "verify":
        for phase in phases:
            result.details.append(f"{phase.value}: {_argv(manifest, phase, 1)!r}")
        if dry_run:
            result.details.append("No commands executed; evidence was not collected.")
        else:
            result.status = Status.NOT_IMPLEMENTED
            result.implemented = False
            result.details.append(
                "Marker-only verification of an unknown run is disabled; use a bounded run."
            )
        return result
    if Phase.BUILD in manifest.commands:
        failure = _execute_checked(manifest, Phase.BUILD, runner, result, 1)
        if failure:
            return result
    return _verify_fresh(manifest, result, runner, budget)


def _bad_command(command: CommandResult, expect_absence: bool = False) -> bool:
    """Require exit 1 for absence and exit 0 for ordinary successful commands."""
    if command.timed_out or command.output_truncated or command.returncode is None:
        return True
    if expect_absence:
        return command.returncode not in {0, 1}
    return command.returncode != 0


def _record_failure(result: PocResult, command: CommandResult, phase: Phase) -> None:
    """Preserve timeout, output-overflow, and exit failures distinctly."""
    if command.timed_out:
        result.status = Status.TIMED_OUT
    elif command.output_truncated:
        result.status = Status.OUTPUT_LIMIT
    else:
        result.status = Status.FAILED
    result.details.append(f"{phase.value} did not satisfy its command contract")


def _execute_checked(
    manifest: Manifest,
    phase: Phase,
    runner: BoundedRunner,
    result: PocResult,
    attempt: int,
    expect_absence: bool = False,
) -> bool:
    """Run a validated stage and report whether it failed its contract."""
    command = runner.run(phase, manifest.commands[phase], _argv(manifest, phase, attempt))
    result.commands.append(command)
    if not _bad_command(command, expect_absence):
        return False
    _record_failure(result, command, phase)
    return True


def _verify_fresh(
    manifest: Manifest,
    result: PocResult,
    runner: BoundedRunner,
    budget: Budget,
) -> PocResult:
    """Attempt a complete premarker, trigger, marker, and patched-control cycle."""
    assert result.verification is not None
    assert manifest.patched_control is not None
    for attempt in range(1, budget.attempts + 1):
        result.attempts = attempt
        result.status = Status.NOT_VERIFIED
        result.verification = Verification()
        if _execute_checked(
            manifest, Phase.PREMARKER, runner, result, attempt, expect_absence=True
        ):
            continue
        premarker = result.commands[-1]
        result.verification.premarker_absent = premarker.returncode == 1
        if premarker.returncode == 0:
            result.verification.reasons.append("marker existed before the trigger")
            continue
        if _execute_checked(manifest, Phase.RUN, runner, result, attempt):
            continue
        marker_command = runner.run(
            Phase.MARKER,
            manifest.commands[Phase.MARKER],
            _argv(manifest, Phase.MARKER, attempt),
        )
        result.commands.append(marker_command)
        if _bad_command(marker_command):
            result.verification.reasons.append("independent marker stat failed")
        else:
            try:
                marker = parse_marker_output(marker_command.stdout_tail)
                result.verification.marker = marker
                if manifest.evidence and manifest.evidence.marker:
                    result.verification.reasons.extend(
                        marker_matches(marker, manifest.evidence.marker)
                    )
                else:
                    result.verification.reasons.append("no expected marker identity")
            except SuiteError as exc:
                result.verification.reasons.append(str(exc))
        if _execute_checked(
            manifest, Phase.CONTROL, runner, result, attempt, expect_absence=True
        ):
            continue
        control_command = result.commands[-1]
        control = ControlResult(
            checked=True,
            container=manifest.patched_control.container or "unspecified",
            marker_absent=control_command.returncode == 1,
            detail=control_command.stderr_tail or control_command.stdout_tail,
        )
        result.verification.patched_control = control
        if control_command.returncode == 0:
            result.verification.reasons.append("patched control contains the marker")
        result.verification.rce_verified = (
            result.verification.premarker_absent is True
            and not result.verification.reasons
            and control.marker_absent
        )
        if result.verification.rce_verified:
            result.status = Status.VERIFIED
            result.details.append("Independent marker and patched-control evidence verified RCE.")
            return result
    result.details.append("No attempt produced complete independent RCE evidence.")
    return result


def confined_directory(relative: str) -> Path:
    """Resolve a trusted per-CVE working directory without leaving the investigation."""
    return confined_path(relative + "/README.md").parent


def get_result(cve: str, action: str, budget: Budget, dry_run: bool) -> PocResult:
    """Load an adapter and return a safe structured result for every failure."""
    try:
        manifest = load_manifest(cve)
        if not manifest.implemented:
            if manifest.archived and action == "verify":
                return verify_archived(manifest, dry_run)
            return _unavailable(manifest, action, dry_run)
        return build_or_run(manifest, action, budget, dry_run)
    except SuiteError as exc:
        return PocResult(
            cve=cve,
            title=cve,
            status=Status.REFUSED,
            implemented=False,
            requested_action=action,
            dry_run=dry_run,
            details=[str(exc)],
        )
