from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, relative_path: str):
    spec = spec_from_file_location(name, REPO_ROOT / relative_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module: {relative_path}")
    module = module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def desired_for_ports(observed):
    """Build an explicitly allowed native target for legacy map contract tests."""
    from dataclasses import replace
    from auto_xdp import config as cfg, policy
    from auto_xdp.state import RuntimeEndpoint, ExposureDecision, project_endpoint_policies
    config = cfg.snapshot_config()
    desired = policy._global_desired_state(config)
    for proto, ports, processes in (("tcp", observed.tcp, observed.tcp_processes),
                                     ("udp", observed.udp, observed.udp_processes),
                                     ("sctp", observed.sctp, {})):
        for port in ports:
            endpoint = RuntimeEndpoint(proto, "*", port, "wildcard", "public")
            desired.endpoint_policies[endpoint.key] = policy._endpoint_policy(
                endpoint, processes.get(port, ""), config,
                ExposureDecision(endpoint, "allow", "legacy port adapter"))
    projection, _ = project_endpoint_policies(desired)
    return replace(projection, endpoint_policy_enabled=False, endpoint_policies={},
                   tcp_ports=set(observed.tcp), udp_ports=set(observed.udp),
                   sctp_ports=set(observed.sctp), zone_tcp_ports={}, zone_udp_ports={})
