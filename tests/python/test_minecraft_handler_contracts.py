from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(sys.platform != "linux", reason="production BPF headers require Linux")
def test_native_minecraft_session_proof(tmp_path: Path) -> None:
    compiler = shutil.which("clang") or shutil.which("cc")
    if compiler is None or not Path("/usr/include/bpf/bpf_helpers.h").exists():
        pytest.skip("native C compiler and libbpf development headers required")
    binary = tmp_path / "minecraft-session-contract"
    subprocess.run(
        [compiler, "-O2", "-Wall", "-Werror", "-Wno-unknown-attributes", f"-I{ROOT}",
         str(ROOT / "tests/c/minecraft_session_contract.c"), "-o", str(binary)],
        check=True, capture_output=True, text=True,
    )
    subprocess.run([str(binary)], check=True, capture_output=True, text=True)


def test_minecraft_transport_state_belongs_to_linux_conntrack() -> None:
    ingress = (ROOT / "handlers/minecraft_handler.c").read_text()
    egress = (ROOT / "bpf/minecraft_egress.c").read_text()

    for obsolete in (
        "MC_AWAIT_ACK",
        "expected_seq",
        "verified_mc",
        "MC_VERIFIED_IDLE_TIMEOUT_NS",
        "penalize_and_drop",
    ):
        assert obsolete not in ingress
    assert "bpf_xdp_ct_lookup" in ingress
    assert "bpf_skb_ct_lookup" in egress
    assert "bpf_ct_release(ct)" in ingress
    assert "bpf_ct_release(ct)" in egress


def test_login_start_is_not_a_final_proof() -> None:
    ingress = (ROOT / "handlers/minecraft_handler.c").read_text()
    login_branch = ingress.split("pending->state == MC_L7_LOGIN_START", 1)[1]
    login_branch = login_branch.split("pending->state == MC_L7_SERVER_CHALLENGE", 1)[0]

    assert "MC_PROOF_LOGIN_START" in login_branch
    assert "mc_mark_conn" not in login_branch


def test_status_response_cannot_be_treated_as_login_disconnect() -> None:
    egress = (ROOT / "bpf/minecraft_egress.c").read_text()

    assert "packet_id == 0 && pending->intention != 1" in egress


def test_conntrack_api_is_lookup_only() -> None:
    sources = "\n".join(
        (ROOT / path).read_text()
        for path in (
            "bpf/include/linux_conntrack.h",
            "handlers/minecraft_handler.c",
            "bpf/minecraft_egress.c",
        )
    )
    for forbidden in (
        "bpf_xdp_ct_alloc",
        "bpf_skb_ct_alloc",
        "bpf_ct_insert_entry",
        "bpf_ct_change_timeout",
    ):
        assert forbidden not in sources
