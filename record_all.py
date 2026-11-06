"""Start every recorder and restart one if it stops.

  python record_all.py
"""

from __future__ import annotations

import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

RECORDERS = (
    ("br", [sys.executable, "-u", str(ROOT / "br_recorder.py")]),
    ("ecu", [sys.executable, "-u", str(ROOT / "ecu_client.py")]),
    ("lynx", [sys.executable, "-u", str(ROOT / "lynx_recorder.py")]),
)


class Supervisor:
    def __init__(self) -> None:
        self.stopping = False
        self.processes: dict[str, subprocess.Popen[str]] = {}
        self.backoff = {name: 1.0 for name, _command in RECORDERS}
        self.next_start = {name: 0.0 for name, _command in RECORDERS}

    def start(self, name: str, command: list[str]) -> None:
        print("[record] starting %s" % name, flush=True)
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.processes[name] = process
        threading.Thread(target=self.pump, args=(name, process), daemon=True).start()

    def pump(self, name: str, process: subprocess.Popen[str]) -> None:
        stream = process.stdout
        if stream is None:
            return
        for line in stream:
            print("[%s] %s" % (name, line), end="", flush=True)

    def stop(self, _signum: int, _frame: object) -> None:
        if self.stopping:
            return
        self.stopping = True
        print("[record] stopping", flush=True)
        for process in self.processes.values():
            if process.poll() is None:
                process.terminate()

    def run(self) -> int:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        commands = dict(RECORDERS)
        while not self.stopping:
            now = time.monotonic()
            for name, command in commands.items():
                process = self.processes.get(name)
                if process is not None and process.poll() is None:
                    self.backoff[name] = 1.0
                    continue
                if process is not None and self.next_start[name] == 0.0:
                    delay = self.backoff[name]
                    print("[record] %s exited (%s), next start in %.0fs" % (name, process.returncode, delay), flush=True)
                    self.next_start[name] = now + delay
                    self.backoff[name] = min(delay * 2, 30.0)
                    continue
                if now < self.next_start[name]:
                    continue
                self.start(name, command)
                self.next_start[name] = 0.0
            time.sleep(0.5)

        for process in self.processes.values():
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        return 0


if __name__ == "__main__":
    sys.exit(Supervisor().run())
