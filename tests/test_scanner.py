from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from intake_gatekeeper.model import GatekeeperError
from intake_gatekeeper.scanner import Limits, scan_path


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def test_demo_inventory(demo_target: Path) -> None:
    inventory = scan_path(demo_target)
    purls = {component.purl: component for component in inventory.components}
    assert set(purls) == {
        "pkg:npm/intake-demo-app@1.0.0",
        "pkg:npm/lodash@4.17.15",
        "pkg:npm/minimist@1.2.5",
        "pkg:npm/%40demo/ui-kit@2.0.1",
        "pkg:nuget/Newtonsoft.Json@12.0.1",
        "pkg:nuget/Microsoft.NETCore.App@8.0.0",
        "pkg:npm/electron@28.0.0",
    }
    assert not purls["pkg:npm/intake-demo-app@1.0.0"].queryable
    assert not purls["pkg:nuget/Microsoft.NETCore.App@8.0.0"].queryable
    assert purls["pkg:npm/lodash@4.17.15"].locations[0].path == (
        "resources/app.asar!/node_modules/lodash/package.json"
    )
    rules = sorted(finding.rule_id for finding in inventory.findings)
    assert "EGK-JS-NODE-INTEGRATION" in rules
    assert "EGK-FUSE-RUN-AS-NODE" in rules
    # node_modules/lodash/index.js contains nodeIntegration: true but third-party code is skipped.
    assert all("node_modules" not in (f.location.path if f.location else "") for f in inventory.findings)
    assert inventory.electron[0].version == "28.0.0"
    assert [gap.code for gap in inventory.gaps] == ["host-runtime"]


def test_scan_of_single_asar_file(demo_asar: Path) -> None:
    inventory = scan_path(demo_asar)
    assert inventory.files_examined == 1
    assert inventory.archive_entries_examined == 8
    assert any(f.location and f.location.path == "app.asar!/main.js" for f in inventory.findings)


def test_missing_target() -> None:
    with pytest.raises(GatekeeperError):
        scan_path(Path("does-not-exist-xyz"))


def test_package_json_outside_node_modules_is_not_a_dependency(tmp_path: Path) -> None:
    _write(tmp_path / "package.json", json.dumps({"name": "root", "version": "1.0.0"}))
    _write(tmp_path / "node_modules/a/lib/package.json", json.dumps({"name": "a", "version": "9"}))
    _write(tmp_path / "node_modules/a/package.json", json.dumps({"name": "a", "version": "1.0.0"}))
    _write(
        tmp_path / "node_modules/a/node_modules/b/package.json",
        json.dumps({"name": "b", "version": "2.0.0"}),
    )
    purls = sorted(c.purl for c in scan_path(tmp_path).components)
    assert purls == ["pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"]


def test_duplicate_components_merge_locations(tmp_path: Path) -> None:
    for parent in ("x", "y"):
        _write(
            tmp_path / f"node_modules/{parent}/node_modules/dup/package.json",
            json.dumps({"name": "dup", "version": "1.0.0"}),
        )
    (component,) = scan_path(tmp_path).components
    assert component.occurrences == 2
    assert len(component.locations) == 2


@pytest.mark.parametrize(
    "manifest",
    [
        "{not json",
        json.dumps({"name": "bad name with spaces", "version": "1.0.0"}),
        json.dumps({"name": "ok", "version": "1.0.0\n"}),
    ],
)
def test_malformed_manifests_become_gaps(tmp_path: Path, manifest: str) -> None:
    _write(tmp_path / "node_modules/pkg/package.json", manifest)
    inventory = scan_path(tmp_path)
    assert inventory.components == []
    assert inventory.gaps[0].code == "parse-error"


def test_deps_json_runtime_packs(tmp_path: Path) -> None:
    document = {
        "libraries": {
            "App/1.0.0": {"type": "project"},
            "Serilog/2.10.0": {"type": "package"},
            "runtimepack.Microsoft.NETCore.App.Runtime.win-x64/8.0.1": {"type": "runtimepack"},
        }
    }
    _write(tmp_path / "App.deps.json", json.dumps(document))
    purls = sorted(c.purl for c in scan_path(tmp_path).components)
    assert purls == [
        "pkg:nuget/Microsoft.NETCore.App.Runtime.win-x64@8.0.1",
        "pkg:nuget/Serilog@2.10.0",
    ]


def test_size_and_file_limits(tmp_path: Path) -> None:
    _write(tmp_path / "big.js", "x" * 2048)
    for index in range(3):
        _write(tmp_path / f"f{index}.txt", "x")
    inventory = scan_path(tmp_path, Limits(max_text_bytes=1024, max_files=2))
    codes = [gap.code for gap in inventory.gaps]
    assert "size-limit" in codes
    assert "file-limit" in codes
    assert inventory.files_examined == 2


def test_symlinks_are_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    _write(outside / "node_modules/secret/package.json", json.dumps({"name": "s", "version": "1"}))
    target = tmp_path / "target"
    target.mkdir()
    try:
        os.symlink(outside, target / "link", target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is not permitted on this host")
    inventory = scan_path(target)
    assert inventory.components == []
    assert [gap.code for gap in inventory.gaps] == ["links-skipped"]
    assert not inventory.gaps[0].blocking


def test_go_binary_components(go_binaries: dict[str, Path], tmp_path: Path) -> None:
    target = tmp_path / "app"
    target.mkdir()
    (target / "tool").write_bytes(go_binaries["elf"].read_bytes())
    purls = {c.purl: c for c in scan_path(target).components}
    assert "pkg:golang/golang.org/x/text@v0.3.7" in purls
    stdlib = [c for c in purls.values() if c.name == "stdlib"]
    assert len(stdlib) == 1 and stdlib[0].queryable
    assert not purls["pkg:golang/example.com/intake-demo@%28devel%29"].queryable
