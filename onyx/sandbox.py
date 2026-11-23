"""Running someone else's code, without letting it run the machine.

An emulator pass executes the scripts inside a user's place. That is the point
of the product, and it is also the largest piece of trust in it: `while true do
end`, `while true do Instance.new("Part") end`, or a million-line print loop are
all three lines of Luau that would otherwise take the scanner down with them.

The defence is at the process boundary, not in the language:

* **wall clock** — a hard timeout, then the whole process group is killed, so a
  spawned child cannot outlive the run.
* **CPU time** — an rlimit, so a spin loop cannot survive a scheduling hiccup on
  the wall-clock timer.
* **address space** — an rlimit. Luau allocates; without a cap a `table` grown in
  a loop is an OOM kill for the whole scan process.
* **file size** — an rlimit on what the child may write, so "print forever" hits a
  ceiling on disk instead of filling the volume.
* **output** — the child's stdout goes to a file that is read with a byte cap. The
  marker protocol means a truncated tail is detectable, not silently half-parsed.

None of this makes executing untrusted Luau *safe* in an absolute sense; it makes
the failure bounded, attributable and reported. That distinction is in the docs and
in the error text the caller sees.

The controls here are POSIX controls. On native Windows this module fails closed instead
of spawning the child without CPU, memory and file-size limits; `onyx verify` says to use
WSL, Linux or macOS, while `onyx scan` is unaffected.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

#: Hard wall clock for one emulator run.
TIMEOUT_S = 25
#: CPU seconds for the child. Above the wall clock, so a normal run is bounded by
#: the timer and only a wedged child hits this.
CPU_LIMIT_S = 30
#: Address space for the child: generous for the emulator, small for a fork bomb.
MEMORY_LIMIT_BYTES = 2 * 1024 * 1024 * 1024
#: What the child may write to its temp directory.
FSIZE_LIMIT_BYTES = 256 * 1024 * 1024
#: How much of stdout we will read back. The emulator's marker protocol is compact;
#: anything past this is print-flood, and it is reported rather than parsed.
MAX_OUTPUT_BYTES = 8 * 1024 * 1024


class SandboxError(Exception):
    """The run did not produce a usable result. Message is shown to the user."""


WINDOWS_VERIFY_UNSUPPORTED = (
    "`onyx verify` is not supported on Windows yet. It executes untrusted place code and "
    "needs POSIX CPU, memory and file-size limits; this build refuses to run without them. "
    "`onyx scan` works normally on Windows. Use WSL (Ubuntu), Linux or macOS for `verify`."
)


def is_windows() -> bool:
    """One seam for the Windows branch, so the gate can simulate it without a Windows host."""
    return os.name == "nt"


@dataclass
class Run:
    stdout: str
    stderr: str
    truncated: bool
    exit_code: int | None
    killed: str | None      # "timeout" | "cpu" | "memory" | "signal" | None
    seconds: float


def _limits(cpu: float, memory: int, fsize: int):
    def apply() -> None:  # pragma: no cover - runs in the child
        os.setsid()
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (int(cpu), int(cpu) + 1))
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        except (ImportError, ValueError, OSError):
            pass

    return apply


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def run(program: str, workdir: str | Path, *, binary: str,
        timeout: float = TIMEOUT_S, memory: int = MEMORY_LIMIT_BYTES,
        max_output: int = MAX_OUTPUT_BYTES) -> Run:
    """Execute a Luau program under limits and return bounded output."""
    td = Path(workdir)
    script = td / "run.luau"
    script.write_text(program, encoding="utf-8")
    result = _supervise([binary, str(script)], td, timeout=timeout, memory=memory,
                        max_output=max_output)

    if result.killed == "timeout":
        raise SandboxError(
            f"the place did not finish within {timeout:g}s and was killed. This is the "
            "emulator's hard limit, not a finding: a `while true do` loop, a wait-free "
            "retry, or an enormous loop in the place will do it. Nothing was judged."
        )
    if result.killed == "cpu":
        raise SandboxError(
            "the place was killed for using more CPU time than the limit allows — "
            "a spin loop that never yields. Nothing was judged."
        )
    if result.killed == "memory":
        raise SandboxError(
            f"the place was killed after exceeding the {memory / 1024 ** 3:.0f} GB address "
            "space limit — something in it allocates without bound. Nothing was judged."
        )
    if result.killed == "signal":
        raise SandboxError("the Luau interpreter died on a signal; nothing was judged")

    return result


def run_argv(argv: list[str], workdir: str | Path, *, timeout: float = TIMEOUT_S,
             memory: int = MEMORY_LIMIT_BYTES, max_output: int = MAX_OUTPUT_BYTES,
             env: dict | None = None, what: str = "the program") -> Run:
    """Execute any command under the same limits. The language judges use this.

    A killed judge is never a pass: a timeout or a memory kill raises, because
    "the test did not finish" and "the test passed" are different facts.
    """
    td = Path(workdir)
    result = _supervise(argv, td, timeout=timeout, memory=memory,
                        max_output=max_output, env=env)
    if result.killed == "timeout":
        raise SandboxError(
            f"{what} did not finish within {timeout:g}s and was killed. Nothing was judged."
        )
    if result.killed == "cpu":
        raise SandboxError(f"{what} was killed for exceeding the CPU limit. Nothing was judged.")
    if result.killed == "memory":
        raise SandboxError(
            f"{what} exceeded the {memory / 1024 ** 3:.0f} GB address space limit. "
            "Nothing was judged."
        )
    if result.killed == "signal":
        raise SandboxError(f"{what} died on a signal. Nothing was judged.")
    return result


def _supervise(argv: list[str], workdir: Path, *, timeout: float, memory: int,
               max_output: int, env: dict | None = None) -> Run:
    """Spawn, bound, kill the process group, and report — the shared core."""
    if is_windows():
        # POSIX rlimits are what make running untrusted place code bounded. Windows has no
        # equivalent wired up in this build, and deleting preexec_fn would silently remove
        # the CPU/memory/file-size defence, so fail closed instead.
        raise SandboxError(WINDOWS_VERIFY_UNSUPPORTED)
    td = Path(workdir)
    out_path = td / "stdout.txt"
    err_path = td / "stderr.txt"
    child_env = dict(os.environ if env is None else env)

    started = time.monotonic()
    killed: str | None = None
    with out_path.open("wb") as out_f, err_path.open("wb") as err_f:
        popen_kwargs = {
            "stdout": out_f,
            "stderr": err_f,
            "stdin": subprocess.DEVNULL,
            "cwd": str(td),
            "env": child_env,
        }
        # `preexec_fn` is POSIX-only. The guard above already fails closed on Windows;
        # keeping the keyword out of the Windows call is defence in depth for any future
        # branch that reaches here from a non-POSIX host.
        if not is_windows():
            popen_kwargs["preexec_fn"] = _limits(
                CPU_LIMIT_S, memory, FSIZE_LIMIT_BYTES)
        try:
            proc = subprocess.Popen(argv, **popen_kwargs)
        except OSError as exc:
            raise SandboxError(f"could not start {argv[0]}: {exc}") from exc

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            killed = "timeout"
            _kill_group(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL should suffice
                pass

    elapsed = time.monotonic() - started

    if killed is None and proc.returncode is not None and proc.returncode < 0:
        sig = -proc.returncode
        killed = {
            signal.SIGXCPU: "cpu",
            signal.SIGKILL: None,      # often the kernel's OOM killer
            signal.SIGSEGV: "memory",
            signal.SIGABRT: "memory",
        }.get(sig, "signal")
        if killed is None:
            killed = "memory"

    stdout = _read_capped(out_path, max_output)
    stderr = _read_capped(err_path, 64 * 1024)
    truncated = out_path.stat().st_size > len(stdout.encode("utf-8", "replace"))

    return Run(
        stdout=stdout,
        stderr=stderr,
        truncated=truncated,
        exit_code=proc.returncode,
        killed=killed,
        seconds=round(elapsed, 3),
    )


def _read_capped(path: Path, limit: int) -> str:
    """Read at most `limit` bytes. A print flood must not become our memory."""
    try:
        with path.open("rb") as handle:
            data = handle.read(limit)
    except OSError:
        return ""
    return data.decode("utf-8", "replace")
