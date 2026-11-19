"""Run in the fallback suite's private network namespace with the installed package."""
import subprocess

from auto_xdp import config
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
        with NftablesBackend(settings) as backend:
            assert backend.reconcile(desired, False).successful
            subprocess.run(["nft", "delete", "table", "inet", table], check=True)
            recovered = backend.reconcile(desired, False)
            assert recovered.successful, recovered.failures
            assert recovered.applied.endpoint_admission[key] == "admitted"
            subprocess.run(["nft", "get", "element", "inet", table, "tcp_ports", "{", "8443", "}"], check=True)
            subprocess.run(["nft", "list", "chain", "inet", table, "endpoint_admission"], check=True)
    finally:
        subprocess.run(["nft", "delete", "table", "inet", table], check=False)
    print("[INFO] nftables controller restored the missing table and its service grant")


if __name__ == "__main__":
    main()
