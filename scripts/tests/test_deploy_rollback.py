"""Exercise deployment orchestration with local fake services; never contact a VPS."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def executable(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/bash\nset -eu\n" + contents)
    path.chmod(0o755)


@pytest.mark.parametrize("failure", ["none", "api-health", "api-install"])
def test_release_environment_and_dual_service_rollback(tmp_path: Path, failure: str) -> None:
    fail_api = failure == "api-health"
    fail_install = failure == "api-install"
    # Replace home references in the test copy, keeping the process HOME untouched.
    actor = tmp_path / "actor"
    base = actor / "netsight"
    candidate = base / "releases" / "candidate"
    previous = base / "releases" / "previous"
    for release in (candidate, previous):
        (release / "apps/web").mkdir(parents=True)
        (release / "apps/api").mkdir(parents=True)
        (release / "infrastructure/vps").mkdir(parents=True)
        (release / "apps/api/pyproject.toml").write_text("# fixture")
        for unit in ("netsight-api.service", "netsight-web.service"):
            (release / "infrastructure/vps" / unit).write_text(f"{release.name}-{unit}")
    (base / "shared/api-venv").mkdir(parents=True)
    sentinel = base / "shared/api-venv/previous-runtime"
    sentinel.write_text("untouched")
    (base / "current").symlink_to(previous)
    unit_dir = actor / ".config/systemd/user"
    unit_dir.mkdir(parents=True)
    for unit in ("netsight-api.service", "netsight-web.service"):
        (unit_dir / unit).write_text((previous / "infrastructure/vps" / unit).read_text())
    log = tmp_path / "services.log"
    fake_bin = tmp_path / "bin"
    executable(fake_bin / "pnpm", '''
for last; do :; done
mkdir -p "$last/node_modules/.bin"
printf '#!/bin/bash\nexit 0\n' > "$last/node_modules/.bin/next"
chmod +x "$last/node_modules/.bin/next"
''')
    executable(actor / ".local/bin/uv", 'printf "%s\\n" "$PWD: $*" >> "$TASK_LOG"\nif [ "$TEST_FAIL_INSTALL" = true ]; then exit 42; fi\nmkdir -p .venv\n')
    executable(fake_bin / "systemctl", 'printf "%s\\n" "$*" >> "$TASK_LOG"\n')
    executable(fake_bin / "curl", '''
if [ "$TEST_FAIL_API" = true ] && [[ "$*" == *:8000/api/v1/health* ]]; then exit 1; fi
''')
    for command in ("sleep", "journalctl"):
        executable(fake_bin / command, "exit 0\n")
    executable(fake_bin / "seq", "echo 1\n")
    script = tmp_path / "deploy.sh"
    script.write_text((ROOT / "scripts/deploy-vps.sh").read_text().replace("$HOME", str(actor)))
    result = subprocess.run(
        ["bash", str(script), "candidate"], capture_output=True, text=True, check=False,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}",
             "TASK_LOG": str(log), "TEST_FAIL_API": str(fail_api).lower(),
             "TEST_FAIL_INSTALL": str(fail_install).lower()},
        timeout=15,
    )
    assert result.returncode == (42 if fail_install else 1 if fail_api else 0), result.stdout + result.stderr
    assert (base / "current").resolve() == (previous if fail_api or fail_install else candidate)
    assert sentinel.read_text() == "untouched"
    assert (candidate / "apps/api/.venv").is_dir() is not fail_install
    calls = log.read_text()
    assert "sync --locked --no-dev --no-editable" in calls
    assert calls.count("restart netsight-api.service") == (0 if fail_install else 2 if fail_api else 1)
    assert calls.count("restart netsight-web.service") == (0 if fail_install else 2 if fail_api else 1)
    expected_unit = (previous if fail_api or fail_install else candidate).name + "-netsight-api.service"
    assert (actor / ".config/systemd/user/netsight-api.service").read_text() == expected_unit

    if fail_install:
        assert "daemon-reload" not in calls
        assert "enable " not in calls
        assert not (previous / "apps/api/.venv").exists()
        for unit in ("netsight-api.service", "netsight-web.service"):
            assert (unit_dir / unit).read_text() == f"previous-{unit}"
