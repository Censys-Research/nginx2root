"""Typed contracts and safety validation for the isolated nginx2root suite."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SUITE_ROOT = Path(__file__).resolve().parent
INVESTIGATION_ROOT = SUITE_ROOT.parent
CVE_IDS = (
    "CVE-2026-123007",
    "CVE-2026-123633",
    "CVE-2026-123634",
    "CVE-2026-121810",
    "CVE-2026-113425",
)
LAB_ACK = "I-AUTHORIZE-LOCAL-LAB"
MANIFEST_NAME = "poc-manifest.json"
DEFAULT_MAX_ATTEMPTS = 1
MAX_ATTEMPTS_LIMIT = 3
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
MAX_BYTES_LIMIT = 2 * 1024**3
MIN_MAX_BYTES = 64 * 1024
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 15 * 60
NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
MARKER_PATTERN = re.compile(r"^/tmp/nginx2root-marker-[a-z0-9-]{1,80}$")
PLACEHOLDER_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


class SuiteError(Exception):
    """An expected validation or adapter error safe to show to the operator."""


class Phase(StrEnum):
    """Ordered stages in a PoC lifecycle."""

    BUILD = "build"
    RUN = "run"
    CONTROL = "control"
    PREMARKER = "premarker"
    MARKER = "marker"
    VERIFY = "verify"


class Status(StrEnum):
    """Outcome states; none except VERIFIED means RCE was established."""

    READY = "ready"
    ARCHIVED = "archived"
    NOT_IMPLEMENTED = "not_implemented"
    DRY_RUN = "dry_run"
    REFUSED = "refused"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT = "output_limit"
    NOT_VERIFIED = "not_verified"
    VERIFIED = "verified"


class StrictModel(BaseModel):
    """Reject unknown fields so a misspelled safety field cannot be ignored."""

    model_config = ConfigDict(extra="forbid")


class Marker(StrictModel):
    """Independent command-created file identity and ownership requirements."""

    path: str = "/tmp/nginx2root-marker-poc"
    expected_uid: int = Field(default=101, ge=0, le=2**31 - 1)
    expected_gid: int = Field(default=101, ge=0, le=2**31 - 1)
    expected_mode: str = "0644"
    expected_size: int = Field(default=0, ge=0, le=1024)
    archived_path: bool = False
    archived_size_omitted: bool = False
    allow_nonzero_size: bool = False

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        """Constrain markers to one clearly disposable namespace."""
        if not MARKER_PATTERN.fullmatch(value) and not (
            value.startswith("/tmp/") and len(value) < 200 and ".." not in value
        ):
            raise ValueError("marker path must match /tmp/nginx2root-marker-<id>")
        return value

    @field_validator("expected_mode")
    @classmethod
    def validate_mode(cls, value: str) -> str:
        """Accept exactly four octal digits, including the leading zero."""
        if not re.fullmatch(r"0[0-7]{3}", value):
            raise ValueError("expected_mode must be four octal digits")
        return value

    @model_validator(mode="after")
    def validate_archived_path(self) -> Self:
        """Permit a legacy path only for a non-runnable archived adapter."""
        if self.archived_path and MARKER_PATTERN.fullmatch(self.path):
            raise ValueError("archived_path must identify a legacy marker")
        if not self.archived_path and not MARKER_PATTERN.fullmatch(self.path):
            raise ValueError("live marker path must match /tmp/nginx2root-marker-<id>")
        if self.archived_size_omitted and not self.archived_path:
            raise ValueError("omitted size is permitted only for archived evidence")
        return self


class PatchedControl(StrictModel):
    """Required patched-target evidence and its expected negative behavior."""

    required: bool = True
    container: str | None = None
    absent_marker: str | None = None
    result_file: str | None = None
    expected: str = "marker_absent"
    archived_path: bool = False

    @field_validator("expected")
    @classmethod
    def validate_expected(cls, value: str) -> str:
        """Only independent negative-marker controls can verify RCE."""
        if value != "marker_absent":
            raise ValueError("RCE controls must demonstrate marker_absent")
        return value

    @model_validator(mode="after")
    def validate_control(self) -> Self:
        """Require either a fresh probe or an existing machine-readable result."""
        if self.required and not self.container and not self.result_file:
            raise ValueError("patched control needs container or result_file")
        if self.result_file and not self.container:
            raise ValueError("result_file must be paired with its container")
        if not self.absent_marker:
            raise ValueError("absent_marker is required")
        valid_archived = (
            self.archived_path
            and self.result_file is not None
            and self.absent_marker.startswith("/tmp/")
            and ".." not in self.absent_marker
            and "\x00" not in self.absent_marker
        )
        if not MARKER_PATTERN.fullmatch(self.absent_marker) and not valid_archived:
            raise ValueError("absent_marker must match /tmp/nginx2root-marker-<id>")
        if self.archived_path and not self.result_file:
            raise ValueError("archived control paths require a result_file")
        return self


class CommandSpec(StrictModel):
    """An argv-only command with its own timeout, output cap, and container names."""

    argv: tuple[str, ...]
    timeout: int = Field(default=DEFAULT_TIMEOUT, gt=0, le=MAX_TIMEOUT)
    max_bytes: int = Field(default=DEFAULT_MAX_BYTES, ge=MIN_MAX_BYTES, le=MAX_BYTES_LIMIT)
    expect_success: bool = True
    containers: tuple[str, ...] = ()
    networks: tuple[str, ...] = ()
    description: str = ""

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Do not accept empty commands or nested shell interpreters."""
        if not value or any(not item or "\x00" in item for item in value):
            raise ValueError("argv must contain nonempty, NUL-free arguments")
        if Path(value[0]).name in {"sh", "bash", "zsh", "fish", "env"}:
            raise ValueError("shell interpreters are not accepted; expose argv directly")
        return value


class Evidence(StrictModel):
    """Persisted observation for a non-rerunnable or already-completed PoC."""

    marker_file: str | None = None
    patched_control_file: str | None = None
    notes_file: str | None = None
    container: str | None = None
    marker: Marker | None = None


class Manifest(StrictModel):
    """Public per-CVE adapter contract."""

    schema_version: Literal[1] = 1
    cve: str
    title: str
    implemented: bool = False
    archived: bool = False
    notes: str
    directory: str
    commands: dict[Phase, CommandSpec] = Field(default_factory=dict)
    evidence: Evidence | None = None
    patched_control: PatchedControl | None = None

    @field_validator("cve")
    @classmethod
    def validate_cve(cls, value: str) -> str:
        """Only the five authorized suite members are loadable."""
        if value not in CVE_IDS:
            raise ValueError(f"unsupported CVE: {value}")
        return value

    @field_validator("directory")
    @classmethod
    def validate_directory(cls, value: str) -> str:
        """Resolve only direct children of the investigation root."""
        if Path(value).name != value or value != value.lower():
            raise ValueError("directory must be a lowercase direct child")
        return value

    @model_validator(mode="after")
    def validate_stages(self) -> Self:
        """An executable adapter needs trigger and independent control stages."""
        if self.implemented and self.archived:
            raise ValueError("archived evidence adapters cannot be executable")
        if self.implemented:
            required = {Phase.RUN, Phase.PREMARKER, Phase.MARKER, Phase.CONTROL}
            if self.patched_control and self.patched_control.result_file:
                required.remove(Phase.CONTROL)
            missing = required - self.commands.keys()
            if missing:
                raise ValueError(f"implemented manifest missing: {sorted(missing)}")
            if not self.commands[Phase.MARKER].containers:
                raise ValueError("marker must independently query a named container")
            if not self.patched_control:
                raise ValueError("implemented manifest requires patched_control")
        if self.directory != self.cve.lower():
            raise ValueError("directory must exactly match the lowercase CVE ID")
        if len({command.description for command in self.commands.values()}) != len(
            self.commands
        ):
            raise ValueError("every command needs a unique description")
        return self


class Budget(StrictModel):
    """Upper bounds chosen by the operator, further capped by each manifest."""

    attempts: int = Field(default=DEFAULT_MAX_ATTEMPTS, ge=1, le=MAX_ATTEMPTS_LIMIT)
    max_bytes: int = Field(default=DEFAULT_MAX_BYTES, ge=MIN_MAX_BYTES, le=MAX_BYTES_LIMIT)
    timeout: int = Field(default=DEFAULT_TIMEOUT, gt=0, le=MAX_TIMEOUT)
    jobs: int = Field(default=1, ge=1, le=5)


class MarkerObservation(StrictModel):
    """Strict parser output for independent docker stat evidence."""

    uid: int
    gid: int
    mode: str
    size: int
    path: str


class ControlResult(StrictModel):
    """Negative marker check on a separately identified patched container."""

    checked: bool
    container: str
    marker_absent: bool
    detail: str


class CommandResult(StrictModel):
    """Bounded subprocess result with non-sensitive diagnostic tails."""

    phase: Phase
    argv: tuple[str, ...]
    returncode: int | None = None
    duration_seconds: float = 0
    timed_out: bool = False
    output_truncated: bool = False
    stdout_tail: str = ""
    stderr_tail: str = ""


class Verification(StrictModel):
    """Final evidence decision; RCE is never inferred from process exit alone."""

    rce_verified: bool = False
    premarker_absent: bool | None = None
    marker: MarkerObservation | None = None
    patched_control: ControlResult | None = None
    reasons: list[str] = Field(default_factory=list)


class PocResult(StrictModel):
    """Machine-readable outcome for one requested CVE."""

    cve: str
    title: str
    status: Status
    implemented: bool
    archived: bool = False
    requested_action: str
    dry_run: bool = False
    attempts: int = 0
    details: list[str] = Field(default_factory=list)
    commands: list[CommandResult] = Field(default_factory=list)
    verification: Verification | None = None
    evidence: dict[str, str] = Field(default_factory=dict)


class SuiteReport(StrictModel):
    """Top-level JSON document emitted by every non-help CLI invocation."""

    action: str
    dry_run: bool
    results: list[PocResult]
    all_verified: bool


def manifest_path(cve: str) -> Path:
    """Prefer the per-CVE contract, falling back to the suite's archived baseline."""
    canonical = INVESTIGATION_ROOT / cve.lower() / MANIFEST_NAME
    if canonical.is_file():
        return canonical
    archived = SUITE_ROOT / "manifests" / f"{cve.lower()}.json"
    return archived if cve == "CVE-2026-123007" and archived.is_file() else canonical


def load_manifest(cve: str) -> Manifest:
    """Load one manifest, preserving missing manifests as not implemented."""
    path = manifest_path(cve)
    if not path.is_file():
        return Manifest(
            cve=cve,
            title=cve,
            directory=cve.lower(),
            notes=f"No {MANIFEST_NAME}; adapter is not implemented.",
        )
    try:
        if path.stat().st_size > 1024 * 1024:
            raise SuiteError(f"manifest exceeds 1 MiB: {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SuiteError(f"cannot read {path}: {exc}") from exc
    try:
        return Manifest.model_validate(raw)
    except ValueError as exc:
        raise SuiteError(f"invalid manifest {path}: {exc}") from exc


def parse_marker_output(
    text: str, archived: bool = False, archived_size_omitted: bool = False
) -> MarkerObservation:
    """Parse marker metadata; only archived evidence may omit its size."""
    match = re.fullmatch(
        r"([0-9]+):([0-9]+) ([0-7]{3,4})(?: ([0-9]+)(?:bytes)?)? (/tmp/[a-zA-Z0-9._-]+)",
        text.strip(),
    )
    if not match:
        raise SuiteError("marker output must be '<uid>:<gid> <0mode> [<N>bytes] <path>'")
    uid, gid, mode, size_text, path = match.groups()
    if size_text is None and not (archived and archived_size_omitted):
        raise SuiteError("marker size is required except for declared archived evidence")
    if not archived and not re.fullmatch(r"0[0-7]{3}", mode):
        raise SuiteError("live marker output must use a four-digit octal mode")
    mode = mode.zfill(4)
    if not archived and not MARKER_PATTERN.fullmatch(path):
        raise SuiteError("live marker output has a non-allowlisted path")
    if archived and not (
        MARKER_PATTERN.fullmatch(path) or (path.startswith("/tmp/") and ".." not in path)
    ):
        raise SuiteError("archived marker output has an invalid path")
    return MarkerObservation(
        uid=int(uid),
        gid=int(gid),
        mode=mode,
        size=int(size_text or 0),
        path=path,
    )


def confined_path(relative: str) -> Path:
    """Resolve a regular evidence/script file inside the investigation root."""
    candidate = Path(relative)
    if candidate.is_absolute():
        raise SuiteError(f"absolute paths are forbidden in manifests: {relative!r}")
    try:
        resolved = (INVESTIGATION_ROOT / candidate).resolve(strict=True)
        resolved.relative_to(INVESTIGATION_ROOT.resolve())
    except (OSError, ValueError) as exc:
        raise SuiteError(f"path escapes investigation or is missing: {relative!r}") from exc
    if not resolved.is_file():
        raise SuiteError(f"not a regular file: {relative!r}")
    if resolved.stat().st_size > MAX_BYTES_LIMIT:
        raise SuiteError(f"file exceeds the suite evidence cap: {relative!r}")
    return resolved


def marker_matches(observation: MarkerObservation, expected: Marker) -> list[str]:
    """Return every mismatch; caller decides verification only when empty."""
    mismatches: list[str] = []
    expected_values = {
        "uid": expected.expected_uid,
        "gid": expected.expected_gid,
        "mode": expected.expected_mode,
        "path": expected.path,
    }
    for field, wanted in expected_values.items():
        actual = getattr(observation, field)
        if actual != wanted:
            mismatches.append(f"marker {field}: got {actual!r}, expected {wanted!r}")
    if observation.size != expected.expected_size:
        if not (expected.allow_nonzero_size and observation.size > 0):
            mismatches.append(
                f"marker size: got {observation.size}, expected {expected.expected_size}"
            )
    return mismatches


def is_loopback_host(value: str) -> bool:
    """Accept unscoped numeric loopback only; never resolve a supplied hostname."""
    if "%" in value:
        return False
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def validate_network_names(names: tuple[str, ...], cve: str) -> None:
    """Require dedicated per-CVE Docker networks, never host/bridge/default."""
    prefix = f"nginx-{cve.removeprefix('CVE-2026-')}-"
    for name in names:
        if (
            not NAME_PATTERN.fullmatch(name)
            or not name.startswith(prefix)
            or name in {"bridge", "host", "none", "default"}
        ):
            raise SuiteError(f"non-allowlisted network {name!r}; expected prefix {prefix}")


def validate_container_name(name: str, cve: str) -> None:
    """Require the dedicated nginx-<numeric CVE>- prefix on every container."""
    prefix = f"nginx-{cve.removeprefix('CVE-2026-')}-"
    if not NAME_PATTERN.fullmatch(name) or not name.startswith(prefix):
        raise SuiteError(f"non-allowlisted container {name!r}; expected prefix {prefix}")


def _replace_placeholders(item: str, context: dict[str, str]) -> str:
    """Expand only manifest-declared scalar placeholders without shell parsing."""
    for match in re.finditer(r"\{([a-z][a-z0-9_]*)\}", item):
        key = match.group(1)
        if key not in context:
            raise SuiteError(f"unknown command placeholder {{{key}}}")
    for key, value in context.items():
        item = item.replace("{" + key + "}", value)
    if "{" in item or "}" in item:
        raise SuiteError(f"unresolved command placeholder in {item!r}")
    return item


def prepare_command(
    spec: CommandSpec,
    *,
    cve: str,
    marker: Marker | None,
    control: PatchedControl | None,
    attempt: int,
    allow_patched_target: bool,
) -> tuple[str, ...]:
    """Validate every expanded argument, target, Docker name, and file path."""
    allowed_containers = set(spec.containers)
    if control and control.container:
        allowed_containers.add(control.container)
    networks = set(spec.networks)
    context = {"attempt": str(attempt)}
    if marker:
        context["marker"] = marker.path
    if control and control.container:
        context["control_container"] = control.container
    if control and control.absent_marker:
        context["control_marker"] = control.absent_marker
    argv = tuple(_replace_placeholders(arg, context) for arg in spec.argv)
    executable = Path(argv[0]).name
    if executable not in {"docker", "uv"} and not (
        executable.startswith("python") and "/" not in argv[0]
    ):
        raise SuiteError(f"executable {argv[0]!r} is not in the adapter allowlist")
    if executable == "python3" and argv[1:2] != ("-I",):
        raise SuiteError("host Python commands must use -I before the script path")
    if executable == "uv" and argv[1:4] != ("run", "python", "-I"):
        raise SuiteError("uv commands must use exactly 'uv run python -I <script>'")

    target_count = 0
    for index, arg in enumerate(argv):
        if arg.startswith("--network="):
            networks.add(arg.split("=", 1)[1])
        if arg == "--network" and index + 1 < len(argv):
            networks.add(argv[index + 1])
        if arg in {"--network=host", "--network=bridge", "--network=default"}:
            raise SuiteError("shared/host Docker networking is forbidden")
        if arg.startswith("--name="):
            validate_container_name(arg.split("=", 1)[1], cve)
        if arg == "--name" and index + 1 < len(argv):
            validate_container_name(argv[index + 1], cve)
        if executable == "docker" and argv[1:2] in {
            ("exec",),
            ("logs",),
            ("inspect",),
            ("rm",),
            ("stop",),
        }:
            operand_index = 2
            while operand_index < len(argv) and argv[operand_index].startswith("-"):
                if argv[operand_index] in {"-t", "--time", "-w", "--workdir", "-e", "--env"}:
                    operand_index += 1
                operand_index += 1
            if operand_index < len(argv):
                validate_container_name(argv[operand_index], cve)
        if arg.startswith("-p") and arg != "-p" and not arg.startswith("--"):
            publish = arg[2:]
            host = publish.rsplit(":", 2)[0]
            if host and host != "127.0.0.1":
                raise SuiteError(f"non-loopback published address in {arg!r}")
        if arg == "-p" and index + 1 < len(argv):
            host = argv[index + 1].rsplit(":", 2)[0]
            if host != "127.0.0.1":
                raise SuiteError("published Docker ports must bind 127.0.0.1")
        if arg.startswith("--add-host") or arg in {"--privileged", "--pid=host"}:
            raise SuiteError(f"unsafe Docker argument {arg!r}")
        if arg in {"--target", "--host", "--hostname", "--ip"}:
            if index + 1 >= len(argv):
                raise SuiteError(f"missing target after {arg}")
            target_count += 1
            target = argv[index + 1]
            if is_loopback_host(target):
                continue
            if allow_patched_target and target in allowed_containers:
                continue
            raise SuiteError(f"non-loopback target {target!r} refused")
        for prefix in ("--target=", "--host=", "--hostname=", "--ip="):
            if arg.startswith(prefix):
                target_count += 1
                target = arg.split("=", 1)[1]
                if not is_loopback_host(target) and not (
                    allow_patched_target and target in allowed_containers
                ):
                    raise SuiteError(f"non-loopback target {target!r} refused")
        for marker_arg in re.findall(r"/tmp/nginx2root-marker-[a-z0-9-]+", arg):
            if marker and marker_arg != marker.path and (
                not control or marker_arg != control.absent_marker
            ):
                raise SuiteError(f"unapproved marker path {marker_arg!r}")
    if target_count > 1:
        raise SuiteError("a command may select only one target")
    for container in spec.containers:
        validate_container_name(container, cve)
        if executable == "docker" and container not in argv:
            raise SuiteError(f"declared container {container!r} absent from Docker argv")
    validate_network_names(tuple(networks), cve)
    return argv


def redact_command(argv: tuple[str, ...]) -> str:
    """Render validated argv for logs without invoking a shell."""
    return shlex.join(argv)


def evidence_sha256(path: Path) -> str:
    """Hash a bounded evidence file for provenance."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
