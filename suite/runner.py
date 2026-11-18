"""Bounded, non-shell subprocess execution for the nginx2root suite."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from pathlib import Path

from .models import Budget, CommandResult, CommandSpec, Phase, SuiteError

TAIL_LIMIT = 2048
READ_SIZE = 16 * 1024


class BoundedRunner:
    """Run argv commands with wall-clock and combined-output bounds."""

    def __init__(self, budget: Budget, cwd: Path) -> None:
        """Store immutable per-invocation bounds and trusted working directory."""
        self.budget = budget
        self.cwd = cwd

    def run(self, phase: Phase, spec: CommandSpec, argv: tuple[str, ...]) -> CommandResult:
        """Execute one stage without a shell or inherited standard input."""
        timeout = min(spec.timeout, self.budget.timeout)
        byte_limit = min(spec.max_bytes, self.budget.max_bytes)
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                argv,
                cwd=self.cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"},
                start_new_session=True,
            )
        except OSError as exc:
            return CommandResult(
                phase=phase,
                argv=argv,
                returncode=127,
                duration_seconds=time.monotonic() - started,
                stderr_tail=str(exc)[-TAIL_LIMIT:],
            )
        assert process.stdout is not None
        assert process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        tails = {"stdout": bytearray(), "stderr": bytearray()}
        total = 0
        truncated = False
        overflow = False
        timed_out = False
        while selector.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                timed_out = True
                self._terminate_group(process)
                break
            for key, _ in selector.select(min(remaining, 0.2)):
                try:
                    chunk = os.read(key.fileobj.fileno(), READ_SIZE)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > byte_limit:
                    overflow = True
                    truncated = True
                    self._terminate_group(process)
                    break
                tail = tails[key.data]
                tail.extend(chunk)
                if len(tail) > TAIL_LIMIT:
                    del tail[:-TAIL_LIMIT]
            if overflow:
                break
        selector.close()
        if not timed_out and not overflow and process.poll() is None:
            try:
                process.wait(timeout=max(0.1, timeout - (time.monotonic() - started)))
            except subprocess.TimeoutExpired:
                timed_out = True
                self._terminate_group(process)
        else:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        process.stdout.close()
        process.stderr.close()
        if spec.expect_success and process.returncode != 0 and not timed_out and not overflow:
            truncated = truncated or total > byte_limit
        return CommandResult(
            phase=phase,
            argv=argv,
            returncode=process.returncode,
            duration_seconds=round(time.monotonic() - started, 3),
            timed_out=timed_out,
            output_truncated=truncated,
            stdout_tail=tails["stdout"].decode("utf-8", errors="replace"),
            stderr_tail=tails["stderr"].decode("utf-8", errors="replace"),
        )

    @staticmethod
    def _terminate_group(process: subprocess.Popen[bytes]) -> None:
        """Kill only the new process group created for this command."""
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            raise SuiteError("unable to terminate bounded subprocess") from exc
