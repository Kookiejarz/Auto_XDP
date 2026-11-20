"""Run in the fallback suite's private network namespace with the installed package."""
import subprocess
from pathlib import Path

from auto_xdp import config
from auto_xdp.admin.runtime import _nft_policy_schema
from auto_xdp.backends.nftables import NftablesBackend
from auto_xdp.state import DesiredState, EndpointPolicy


def main() -> None:
    table = "axdp_recovery_fixture"
    settings = config.parse_toml_config({"nftables": {"table": table}})
    key = ("tcp", "127.0.0.1", 8443, "public")
    desired = DesiredState(config=settings, endpoint_policies={key: EndpointPolicy(True, "test grant")})
    # Reserve a fresh fixture name. An existing table belongs to the caller.
    subprocess.run(["nft", "create", "table", "inet", table], check=True)
    try:
        def cutover_ready() -> bool:
            library = Path(__file__).resolve().parents[2] / "lib/setup/backend_nft.sh"
            check = subprocess.run(["bash", "-c", 'source "$1"; NFT_FAMILY=inet NFT_TABLE="$2" verify_nftables_policy',
                                    "check-nft-policy", str(library), table])
            return check.returncode == 0

        subprocess.run(["nft", "-f", "-"], text=True, check=True, input=(
            f"add set inet {table} tcp_ports {{ type inet_service; }}\n"
            f"add set inet {table} udp_ports {{ type inet_service; }}\n"
            f"add set inet {table} sctp_ports {{ type inet_service; }}\n"
            f"add set inet {table} trusted_v4 {{ type ipv4_addr; }}\n"
            f"add chain inet {table} input\n"
            f"add set inet {table} policy_schema_v2_old {{ type mark; }}\n"
        ))
        assert _nft_policy_schema("inet", table) == "legacy"
        assert not cutover_ready()
        with NftablesBackend(settings) as backend:
            assert cutover_ready()
            assert backend.reconcile(desired, False).successful
            subprocess.run(["nft", "delete", "table", "inet", table], check=True)
            recovered = backend.reconcile(desired, False)
            assert recovered.successful, recovered.failures
            assert recovered.applied.endpoint_admission[key] == "admitted"
            subprocess.run(["nft", "get", "element", "inet", table, "tcp_ports", "{", "8443", "}"], check=True)
            subprocess.run(["nft", "list", "chain", "inet", table, "endpoint_admission"], check=True)
            assert _nft_policy_schema("inet", table) == "policy_schema_v2"
            assert cutover_ready()
    finally:
        subprocess.run(["nft", "delete", "table", "inet", table], check=False)
    print("[INFO] nftables rejected the legacy schema and restored the missing table and its service grant")


if __name__ == "__main__":
    main()
