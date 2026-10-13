"""Build the generated parts of examples/vulnerable-demo (never committed).

- bin/intake-demo-tool[.exe]: real Go binary from examples/go-demo (skipped if Go is missing).
- bin/electron-runtime-stand-in.bin: synthetic bytes carrying an Electron version string and
  fuse wire in the documented layout; it is not an executable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_BIN = ROOT / "examples" / "vulnerable-demo" / "bin"
SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"


def electron_stand_in(version: str = "28.0.0", wire: bytes = b"10110001") -> bytes:
    note = b"FIXTURE: synthetic stand-in for an Electron executable; not runnable.\x00"
    body = note + b"Chrome/120.0.6099.56 Electron/" + version.encode() + b"\x00"
    return b"MZ" + b"\x00" * 62 + body + SENTINEL + bytes([1, len(wire)]) + wire + b"\x00" * 64


def build_go(output: Path, goos: str | None = None, goarch: str | None = None) -> bool:
    go = os.environ.get("INTAKE_GO") or shutil.which("go")
    if not go:
        return False
    env = {**os.environ, "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local"}
    if goos:
        env["GOOS"] = goos
    if goarch:
        env["GOARCH"] = goarch
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [go, "build", "-trimpath", "-buildvcs=false", "-o", str(output), "."],
        cwd=ROOT / "examples" / "go-demo",
        env=env,
        check=True,
    )
    return True


def main() -> int:
    DEMO_BIN.mkdir(parents=True, exist_ok=True)
    (DEMO_BIN / "electron-runtime-stand-in.bin").write_bytes(electron_stand_in())
    suffix = ".exe" if os.name == "nt" else ""
    if build_go(DEMO_BIN / f"intake-demo-tool{suffix}"):
        print("built Go demo binary")
    else:
        print("Go not found; skipped the Go demo binary (set INTAKE_GO or add go to PATH)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
