"""Build gating checks that do not require GitHub-hosted runners to start.

These are source-level checks only. They NEVER replace running the binaries.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_windows_local_builder_waits_for_each_gui_executable_selftest():
    script = (ROOT / "scripts" / "Build-Krypta-Windows-Local.ps1").read_text(
        encoding="utf-8"
    )
    assert "Start-Process -FilePath $Exe -ArgumentList $arg -PassThru -Wait" in script
    assert "$proc.ExitCode -ne 0" in script
    assert "python -m pytest" not in script or script.count("-m pytest -q") == 1
    for parameter in ("--self-test", "--volume-self-test",
                      "--filesystem-self-test", "--fuse-self-test",
                      "--paged-volume-self-test"):
        assert parameter in script
    assert "SHA256" in script
    assert "DO NOT DISTRIBUTE" in script


def test_release_workflow_requires_new_packaged_pfs2_selftest():
    workflow = (ROOT / ".github" / "workflows" / "publish-preview.yml").read_text(
        encoding="utf-8"
    )
    assert workflow.count("--paged-volume-self-test") >= 2, (
        "Both Windows and Linux packaged builds must test the new backend"
    )
    assert "needs: [tests, desktop, android]" in workflow
    assert "sha256sum --check KRYPTA-Windows-x64.exe.sha256" in workflow
    assert "sha256sum --check KRYPTA-Linux-x64.sha256" in workflow
    assert "sha256sum --check KRYPTA-Android-debug.apk.sha256" in workflow


def test_linux_local_builder_rejects_failed_pytest_and_packaged_tests():
    script = (ROOT / "scripts" / "build-krypta-linux-local.sh").read_text(
        encoding="utf-8"
    )
    assert "set -euo pipefail" in script
    assert "python3 -m pytest -q" in script
    assert "--paged-volume-self-test" in script
    assert "sha256sum KRYPTA-Linux-x64-VolumeLab-DEV" in script


def test_packaged_volume_lab_roundtrip_on_disposable_temp_data():
    # This tests actual Python code (including Argon2id and PVIMG AEAD),
    # not just workflow YAML. Never touches a physical device.
    from krypta.desktop_entry import run_paged_volume_lab_self_test

    assert run_paged_volume_lab_self_test() == 0
