"""Offline tests for the compact accounting client's parsing and guards."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import json

import pytest

import h2c_flow_control_test as compact

ACK = "I-AUTHORIZE-LOCAL-LAB"
PING_ACK = (compact.PING, compact.ACK, 0, b"POC-SYNC")


def test_frame_decoder_handles_split_and_coalesced_frames() -> None:
    first = compact.frame(compact.DATA, compact.END_STREAM, 0x80000001, b"abc")
    second = compact.frame(compact.PING, compact.ACK, 0, b"POC-SYNC")
    wire = first + second
    buf = bytearray()
    decoded = []
    for byte in wire:
        decoded.extend(compact.decode_frames(buf, bytes((byte,))))
    assert decoded == [
        (compact.DATA, compact.END_STREAM, 1, b"abc"),
        (compact.PING, compact.ACK, 0, b"POC-SYNC"),
    ]
    assert not buf


def test_frame_decoder_retains_incomplete_payload() -> None:
    encoded = compact.frame(compact.DATA, 0, 157, b"payload")
    buf = bytearray()
    assert compact.decode_frames(buf, encoded[:-1]) == []
    assert compact.decode_frames(buf, encoded[-1:]) == [
        (compact.DATA, 0, 157, b"payload")
    ]


@pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "::1"])
def test_target_guard_accepts_numeric_loopback(host: str) -> None:
    args = compact.parse_args(["--host", host, "--acknowledge-local-lab", ACK])
    assert args.host == host


@pytest.mark.parametrize(
    "host",
    ["localhost", "127.0.0.1.example", "0.0.0.0", "192.0.2.1", "::", "example.com"],
)
def test_target_guard_rejects_non_loopback_and_names(host: str) -> None:
    with (
        patch("socket.socket") as socket_constructor,
        pytest.raises(SystemExit) as error,
    ):
        compact.main(["--host", host, "--acknowledge-local-lab", ACK])
    assert error.value.code == 2
    socket_constructor.assert_not_called()


def test_target_guard_requires_exact_acknowledgement() -> None:
    with (
        patch("socket.socket") as socket_constructor,
        pytest.raises(SystemExit) as error,
    ):
        compact.main(["--acknowledge-local-lab", "yes"])
    assert error.value.code == 2
    socket_constructor.assert_not_called()


@pytest.mark.parametrize("port", ["0", "65536", "-1"])
def test_target_guard_rejects_invalid_ports(port: str) -> None:
    with (
        patch("socket.socket") as socket_constructor,
        pytest.raises(SystemExit) as error,
    ):
        compact.main(["--port", port, "--acknowledge-local-lab", ACK])
    assert error.value.code == 2
    socket_constructor.assert_not_called()


def test_result_requires_complete_positive_exchange() -> None:
    positive, message = compact.summarize_result(
        [PING_ACK], closed=False, probe_sent=True
    )
    assert positive
    assert (
        "does not demonstrate code execution" not in message
    )  # Printed separately by main.


@pytest.mark.parametrize(
    ("events", "closed", "probe_sent"),
    [
        ([], True, True),
        ([], True, False),
        ([], False, False),
        ([], False, True),
        ([(compact.GOAWAY, 0, 0, b"\0" * 8), PING_ACK], False, True),
        ([(compact.PING, compact.ACK, 1, b"POC-SYNC")], False, True),
        ([(compact.PING, compact.ACK, 0, b"OTHER")], False, True),
    ],
)
def test_result_rejects_early_close_goaway_and_wrong_ping(
    events: list[tuple[int, int, int, bytes]], closed: bool, probe_sent: bool
) -> None:
    positive, _ = compact.summarize_result(events, closed=closed, probe_sent=probe_sent)
    assert not positive


def test_patched_wu4m_close_cannot_exit_zero() -> None:
    positive, message = compact.summarize_result([], closed=True, probe_sent=False)
    assert not positive
    assert "INCONCLUSIVE" in message


def test_connection_refused_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class RefusedSocket:
        def __init__(self, *_args: object) -> None:
            pass

        def settimeout(self, _timeout: float) -> None:
            pass

        def connect(self, _address: object) -> None:
            raise ConnectionRefusedError("offline test")

        def close(self) -> None:
            pass

    monkeypatch.setattr(compact.socket, "socket", RefusedSocket)
    assert compact.main(["--acknowledge-local-lab", ACK]) == 2


def test_timeout_options_are_bounded() -> None:
    """Operators cannot remove the per-command and per-client deadlines."""
    args = compact.parse_args(
        [
            "--docker",
            "--command-timeout",
            "120",
            "--client-timeout",
            "1",
            "--acknowledge-local-lab",
            ACK,
        ]
    )
    assert args.command_timeout == 120
    assert args.client_timeout == 1
    for option in ("--command-timeout", "--client-timeout"):
        with pytest.raises(SystemExit):
            compact.parse_args([option, "121", "--acknowledge-local-lab", ACK])
        with pytest.raises(SystemExit):
            compact.parse_args([option, "0", "--acknowledge-local-lab", ACK])


def test_evidence_records_reproducibility_and_scope(tmp_path: Path) -> None:
    """Evidence is typed, serializable, and explicitly accounting-only."""
    evidence = compact.RunEvidence(
        script_sha256=compact.sha256_file(Path(compact.__file__)),
        started_at="2026-11-18T00:00:00+00:00",
        targets=(
            compact.TargetEvidence(
                image="nginx:1.31.8",
                version="1.31.8",
                expected_exit=0,
                actual_exit=0,
                result="passed",
            ),
        ),
        cleanup_attempted=True,
        passed=True,
    )
    destination = tmp_path / "evidence.json"
    destination.write_text(json.dumps(compact.asdict(evidence)))
    parsed = json.loads(destination.read_text())
    assert parsed["scope"] == "accounting_only_not_rce"
    assert parsed["tls_validated"] is False
    assert len(parsed["script_sha256"]) == 64
    assert parsed["targets"][0]["actual_exit"] == 0


def test_single_file_lab_embeds_configuration_and_cleanup() -> None:
    """The public lab needs no auxiliary shell or configuration files."""
    source = Path(compact.__file__).read_text()
    assert "def docker_differential" in source
    assert '"network", "create"' in source
    assert "http2 on" in source
    assert "bs=1048576 count=8" in source
    assert 'docker", "rm", "-f' in source
    assert 'docker", "network", "rm' in source
    assert "sudo docker" not in source
