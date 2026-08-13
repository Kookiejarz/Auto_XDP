"""Regression guards for actionable kernel-integration failures."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_xdp_load_failure_prints_normal_and_debug_bpftool_output():
    source = (ROOT / "tests/bash/test_integration.sh").read_text()
    helper = source.split("_load_xdp_program() {", 1)[1].split("\n}\n", 1)[0]

    assert 'cat "$load_log"' in helper
    assert "bpftool -d prog load" in helper
    assert 'pinmaps "$_DEBUG_PIN_DIR"' in helper
    assert ">/dev/null 2>&1" not in helper


def test_setup_failure_stops_before_dependent_integration_cases():
    source = (ROOT / "tests/bash/test_integration.sh").read_text()

    assert '_load_xdp_program "integration setup" || return 1' in source
    assert source.count('_require_setup "') == 8
    assert "fatal: integration setup failed before" in source


def test_action_streams_and_uploads_failed_kernel_log():
    source = (ROOT / ".github/workflows/distro-check.yml").read_text()

    assert 'tee "$integration_log"' in source
    assert "uses: actions/upload-artifact@v4" in source
    assert "if: failure()" in source
    assert "path: kernel-integration.log" in source
