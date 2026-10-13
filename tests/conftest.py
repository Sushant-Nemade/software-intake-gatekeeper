from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
sys.path.insert(0, str(ROOT / "scripts"))

import build_demo  # noqa: E402


@pytest.fixture(scope="session")
def demo_asar() -> Path:
    return EXAMPLES / "vulnerable-demo" / "resources" / "app.asar"


@pytest.fixture
def demo_target(tmp_path: Path) -> Path:
    """Copy of the committed demo plus a synthetic Electron stand-in (no Go binary)."""
    target = tmp_path / "demo"
    shutil.copytree(EXAMPLES / "vulnerable-demo", target, ignore=shutil.ignore_patterns("bin"))
    (target / "bin").mkdir()
    (target / "bin" / "electron-runtime-stand-in.bin").write_bytes(build_demo.electron_stand_in())
    return target


def _go() -> str | None:
    return os.environ.get("INTAKE_GO") or shutil.which("go")


@pytest.fixture(scope="session")
def go_binaries(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Real Go executables for three object formats, built from examples/go-demo."""
    if _go() is None:
        if os.environ.get("INTAKE_REQUIRE_GO_FIXTURES") == "1":
            pytest.fail("Go fixtures are required in this environment but Go is not installed")
        pytest.skip("Go toolchain not available (set INTAKE_GO or add go to PATH)")
    out = tmp_path_factory.mktemp("go")
    targets = {"pe": ("windows", "amd64"), "elf": ("linux", "amd64"), "macho": ("darwin", "arm64")}
    binaries: dict[str, Path] = {}
    for label, (goos, goarch) in targets.items():
        binaries[label] = out / f"demo-{label}"
        build_demo.build_go(binaries[label], goos, goarch)
    return binaries


def go_version_m(path: Path) -> str:
    go = _go()
    assert go is not None
    return subprocess.run(
        [go, "version", "-m", str(path)], check=True, capture_output=True, text=True
    ).stdout
