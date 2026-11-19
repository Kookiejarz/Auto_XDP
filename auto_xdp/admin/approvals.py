"""Root-owned exposure approval workflow and management API primitives."""
from __future__ import annotations

import copy
import fcntl
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from auto_xdp.admin.config_file import ConfigDocument, checked_revision, load_toml, read_snapshot, stage_toml
from auto_xdp.install_state import atomic_write_json


APPROVAL_SCHEMA = 1
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_PROTOCOLS = {"tcp", "udp", "sctp"}
_STATUSES = {"pending", "approved", "rejected", "revoked"}


def store_path(run_state_dir: str | Path) -> Path:
    configured = os.environ.get("AUTO_XDP_APPROVAL_STORE")
    if configured:
        return Path(configured)
    return Path(run_state_dir) / "approval_requests.json"


def _empty_state() -> dict[str, Any]:
    return {"schema": APPROVAL_SCHEMA, "revision": 0, "next_id": 1, "requests": [], "history": []}


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot read approval store {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != APPROVAL_SCHEMA:
        raise RuntimeError(f"unsupported approval store schema: {path}")
    data.setdefault("requests", [])
    data.setdefault("history", [])
    data.setdefault("revision", 0)
    data.setdefault("next_id", 1)
    return data


def _sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _save(path: Path, data: dict[str, Any]) -> None:
    atomic_write_json(path, data, mode=0o600)
    _sync_directory(path.parent)


def _finish_policy_change(path: Path, journal: Path, staged: Path, state: dict[str, Any]) -> bool:
    # Renaming the staged TOML is the commit point. Recovery only finishes the
    # ledger, so a later edit to the live configuration is never overwritten.
    try:
        staged.stat()
    except FileNotFoundError:
        published = True
        _sync_directory(staged.parent)
        _save(path, state)
    else:
        published = False
    journal.unlink()
    _sync_directory(journal.parent)
    if not published:
        staged.unlink()
    return published


def _commit_policy_change(path: Path, state: dict[str, Any], document: ConfigDocument) -> None:
    with checked_revision(document.path, document.revision):
        journal = Path(f"{path}.transaction")
        staged = stage_toml(document.path, document.data)
        try:
            _sync_directory(staged.parent)
            _save(journal, {"staged_config": str(staged.absolute()), "state": state})
            staged.replace(document.path)
            _finish_policy_change(path, journal, staged, state)
        finally:
            # Keep an unpublished stage as evidence until its journal is removed.
            if not journal.exists():
                staged.unlink(missing_ok=True)


def _recover_policy_change(path: Path) -> None:
    journal = Path(f"{path}.transaction")
    try:
        fd = os.open(journal, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return
    with os.fdopen(fd, encoding="utf-8") as src:
        info = os.fstat(src.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError(f"Approval transaction has unexpected ownership or permissions: {journal}")
        record = json.load(src)
    if (not isinstance(record, dict) or not isinstance(record.get("staged_config"), str)
            or not isinstance(record.get("state"), dict) or record["state"].get("schema") != APPROVAL_SCHEMA):
        raise RuntimeError(f"Invalid approval transaction: {journal}")
    if _finish_policy_change(path, journal, Path(record["staged_config"]), record["state"]):
        reload_daemon()


@contextmanager
def _locked(path: Path) -> Iterator[dict[str, Any]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = Path(f"{path}.lock")
    lock_path.touch(mode=0o600, exist_ok=True)
    lock_path.chmod(0o600)
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            _recover_policy_change(path)
            yield _load(path)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _actor(value: str | None) -> str:
    return value or f"uid:{os.getuid()}"


def _request_service(request: dict[str, Any]) -> str:
    resolve = request.get("resolve", {})
    if not isinstance(resolve, dict):
        return str(request.get("subject", ""))
    systemd_unit = str(resolve.get("systemd_unit", "")).strip()
    if systemd_unit:
        return systemd_unit
    process_name = str(resolve.get("process_name", "")).strip()
    if process_name:
        return process_name
    runtime = str(resolve.get("container_runtime", "")).strip()
    for key in ("container_name", "container_id", "container_label"):
        value = resolve.get(key)
        if value:
            rendered = json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value)
            return f"{runtime}:{rendered}" if runtime else rendered
    return str(request.get("subject", ""))


def _history_context(request: dict[str, Any]) -> dict[str, Any]:
    raw_ports = request.get("ports", [])
    ports = [int(port) for port in raw_ports] if isinstance(raw_ports, list) else []
    return {
        "subject": str(request.get("subject", "")),
        "service": _request_service(request),
        "zone": str(request.get("zone", "")),
        "protocol": str(request.get("protocol", "")).lower(),
        "ports": ports,
        "reason": str(request.get("reason", "")),
    }


def _ports(values: list[int]) -> list[int]:
    result = sorted({int(value) for value in values})
    if not result or any(port < 1 or port > 65535 for port in result):
        raise ValueError("ports must contain values from 1 to 65535")
    return result


def _has_exposure_policy(subject: object) -> bool:
    if not isinstance(subject, dict):
        return False
    for zone in subject.get("exposure", {}).values():
        if isinstance(zone, dict) and (
            zone.get("deny")
            or any(isinstance(zone.get(proto), dict) and zone[proto].get("ports") for proto in _PROTOCOLS)
        ):
            return True
    return False


def _validate_request(data: dict[str, Any], *, config: dict[str, Any]) -> None:
    subject = str(data.get("subject", ""))
    if not _SUBJECT_RE.fullmatch(subject):
        raise ValueError("subject must contain only letters, digits, _, ., or -")
    zone = str(data.get("zone", ""))
    zones = config.get("zones", {})
    if zone != "public" and zone not in zones:
        raise ValueError(f"unknown ingress zone: {zone}")
    protocol = str(data.get("protocol", "")).lower()
    if protocol not in _PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol}")
    data["protocol"] = protocol
    data["ports"] = _ports([int(value) for value in data.get("ports", [])])
    resolution = data.get("resolve", {})
    if not isinstance(resolution, dict):
        raise ValueError("resolve must be an object")
    allowed = {
        "systemd_unit", "process_name", "container_runtime", "container_id",
        "container_name", "container_label",
    }
    if set(resolution) - allowed:
        raise ValueError("resolve contains an unsupported identity field")
    identity_keys = {"systemd_unit", "process_name", "container_id", "container_name", "container_label"}
    if len([key for key in identity_keys if resolution.get(key)]) > 1:
        raise ValueError("resolve may contain only one identity")
    runtime = str(resolution.get("container_runtime", "")).strip().lower()
    if runtime and runtime not in {"docker", "podman"}:
        raise ValueError("container_runtime must be docker or podman")
    if runtime and not any(resolution.get(key) for key in identity_keys & {"container_id", "container_name", "container_label"}):
        raise ValueError("container_runtime requires a container identity")
    if "container_label" in resolution and not isinstance(resolution["container_label"], (str, dict)):
        raise ValueError("container_label must be a string or object")
    existing = config.get("subjects", {}).get(subject, {})
    if not isinstance(existing, dict):
        existing = {}
    if resolution:
        for other_name, other in config.get("subjects", {}).items():
            if (
                str(other_name) != subject
                and isinstance(other, dict)
                and other.get("resolve") == resolution
                and _has_exposure_policy(other)
            ):
                raise ValueError(f"resolver already belongs to subject {other_name}")
    if not resolution and not isinstance(existing.get("resolve"), dict):
        raise ValueError("new subjects require --systemd-unit or --process-name")
    profile = str(data.get("protection_profile", "")).strip()
    if len(profile) > 128:
        raise ValueError("protection profile is too long")
    data["protection_profile"] = profile


def _history(data: dict[str, Any], request: dict[str, Any], action: str, actor: str) -> None:
    entry = {
        "revision": data["revision"],
        "request_id": request["id"],
        "action": action,
        "actor": actor,
        "at": time.time(),
        "status": request["status"],
    }
    entry.update(_history_context(request))
    if request.get("rejection_reason"):
        entry["decision_reason"] = str(request["rejection_reason"])
    data["history"].append(entry)


def _request(data: dict[str, Any], request_id: int) -> dict[str, Any]:
    for request in data["requests"]:
        if int(request.get("id", -1)) == request_id:
            return request
    raise ValueError(f"approval request not found: {request_id}")


def _last_port_change(
    state: dict[str, Any], subject: str, zone: str, protocol: str, ports: list[int]
) -> tuple[str, dict[str, Any]]:
    # Older history entries only carry the request ID. Use the original
    # request for its scope and history order for the last effective decision.
    requests = {str(item["id"]): item for item in state["requests"] if "id" in item}
    scope = (subject, zone, protocol)
    wanted = set(ports)
    for entry in reversed(state["history"]):
        action = entry.get("action")
        if action not in {"approve", "deny", "revoke"}:
            continue
        previous = requests.get(str(entry.get("request_id")), {})
        previous_scope = (previous.get("subject"), previous.get("zone"), previous.get("protocol"))
        if previous_scope == scope and not wanted.isdisjoint(previous.get("ports", [])):
            return action, previous
    return "", {}


def create_request(
    path: Path,
    config_path: str | Path,
    *,
    subject: str,
    zone: str,
    protocol: str,
    ports: list[int],
    reason: str,
    systemd_unit: str = "",
    process_name: str = "",
    container_runtime: str = "",
    container_id: str = "",
    container_name: str = "",
    container_label: str | dict[str, str] = "",
    resolve: dict[str, Any] | None = None,
    protection_profile: str = "",
    actor: str | None = None,
    reuse_matching: bool = False,
) -> dict[str, Any]:
    if not reason.strip():
        raise ValueError("approval reason is required")
    request: dict[str, Any] = {
        "subject": subject,
        "zone": zone,
        "protocol": protocol,
        "ports": ports,
        "reason": reason.strip(),
        "resolve": {key: value for key, value in {
            "systemd_unit": systemd_unit.strip(),
            "process_name": process_name.strip(),
            "container_runtime": container_runtime.strip(),
            "container_id": container_id.strip().lower(),
            "container_name": container_name.strip(),
            "container_label": container_label,
        }.items() if value},
        "protection_profile": protection_profile.strip(),
    }
    if resolve is not None:
        request["resolve"] = dict(resolve)
    request["requester"] = _actor(actor)
    request["requested_at"] = time.time()
    request["status"] = "pending"
    with _locked(path) as state:
        config = load_toml(Path(config_path))
        if not request["resolve"]:
            existing = config.get("subjects", {}).get(subject, {})
            existing_resolve = existing.get("resolve", {}) if isinstance(existing, dict) else {}
            if isinstance(existing_resolve, dict):
                request["resolve"] = dict(existing_resolve)
        _validate_request(request, config=config)
        retry_fields = ("ports", "resolve", "protection_profile", "reason", "requester")
        for existing in state["requests"]:
            if existing.get("status") == "pending" and all(
                existing.get(key) == request.get(key)
                for key in ("subject", "zone", "protocol", "ports")
            ):
                if reuse_matching and all(existing.get(k) == request[k] for k in retry_fields):
                    return dict(existing)
                raise ValueError(f"matching approval request already pending: {existing['id']}")
        if reuse_matching:
            action, previous = _last_port_change(state, subject, zone, request["protocol"], request["ports"])
            if action == "approve" and all(previous.get(k) == request[k] for k in retry_fields):
                candidate = copy.deepcopy(config)
                _apply_grant(candidate, request)
                if candidate == config:
                    return dict(previous)
        request["id"] = int(state["next_id"])
        state["next_id"] = request["id"] + 1
        state["revision"] = int(state["revision"]) + 1
        state["requests"].append(request)
        _history(state, request, "request", request["requester"])
        _save(path, state)
    return request


def list_requests(path: Path, status: str = "all") -> list[dict[str, Any]]:
    if status != "all" and status not in _STATUSES:
        raise ValueError(f"unsupported approval status: {status}")
    with _locked(path) as state:
        requests = [dict(item) for item in state["requests"]]
    if status != "all":
        requests = [item for item in requests if item.get("status") == status]
    return sorted(requests, key=lambda item: int(item["id"]))


def list_history(path: Path) -> tuple[int, list[dict[str, Any]]]:
    with _locked(path) as state:
        requests = {
            int(item["id"]): item
            for item in state["requests"]
            if isinstance(item, dict) and "id" in item
        }
        history = []
        for item in state["history"]:
            entry = dict(item)
            try:
                request = requests.get(int(item["request_id"]))
            except (KeyError, TypeError, ValueError):
                request = None
            if request is not None:
                for key, value in _history_context(request).items():
                    entry.setdefault(key, value)
                if request.get("rejection_reason"):
                    entry.setdefault("decision_reason", str(request["rejection_reason"]))
            history.append(entry)
        return int(state["revision"]), history


def list_grants(config_path: str | Path) -> list[dict[str, Any]]:
    config = load_toml(Path(config_path))
    rows: list[dict[str, Any]] = []
    for subject, spec in sorted(config.get("subjects", {}).items()):
        if not isinstance(spec, dict):
            continue
        resolve = spec.get("resolve", {})
        protection = spec.get("protection", {})
        profile = str(protection.get("profile", "")) if isinstance(protection, dict) else ""
        for zone, zone_spec in (spec.get("exposure", {}) or {}).items():
            if not isinstance(zone_spec, dict):
                continue
            for protocol in sorted(_PROTOCOLS):
                proto_spec = zone_spec.get(protocol, {})
                if not isinstance(proto_spec, dict) or not proto_spec.get("ports"):
                    continue
                rows.append({
                    "subject": subject,
                    "zone": str(zone),
                    "protocol": protocol,
                    "ports": sorted({int(port) for port in proto_spec["ports"]}),
                    "resolve": dict(resolve) if isinstance(resolve, dict) else {},
                    "protection_profile": profile,
                })
    return rows


def _apply_grant(config: dict[str, Any], request: dict[str, Any]) -> list[int]:
    subjects = config.setdefault("subjects", {})
    subject = subjects.setdefault(request["subject"], {})
    if not isinstance(subject, dict):
        raise ValueError(f"subjects.{request['subject']} must be a table")
    requested_resolve = request.get("resolve", {})
    existing_resolve = subject.get("resolve", {})
    if requested_resolve:
        if existing_resolve and existing_resolve != requested_resolve:
            raise ValueError("approval identity conflicts with the existing subject resolver")
        subject.setdefault("resolve", requested_resolve)
    exposure = subject.setdefault("exposure", {})
    zone = exposure.setdefault(request["zone"], {})
    protocol = zone.setdefault(request["protocol"], {})
    current = {int(port) for port in protocol.get("ports", [])}
    added = sorted(set(request["ports"]) - current)
    protocol["ports"] = sorted(current | set(request["ports"]))
    profile = str(request.get("protection_profile", ""))
    if profile:
        protection = subject.setdefault("protection", {})
        existing_profile = str(protection.get("profile", ""))
        if existing_profile and existing_profile != profile:
            raise ValueError("approval protection profile conflicts with the existing subject")
        protection["profile"] = profile
    return added


def approve_request(path: Path, config_path: str | Path, request_id: int, *, actor: str | None = None) -> dict[str, Any]:
    with _locked(path) as state:
        request = _request(state, request_id)
        if request.get("status") == "approved":
            return dict(request)
        if request.get("status") != "pending":
            raise ValueError(f"approval request {request_id} is {request.get('status')}")
        document = read_snapshot(Path(config_path))
        config = document.data
        _validate_request(dict(request), config=config)
        added = _apply_grant(config, request)
        request.update({
            "status": "approved",
            "approver": _actor(actor),
            "approved_at": time.time(),
            "applied_ports": added,
        })
        state["revision"] = int(state["revision"]) + 1
        _history(state, request, "approve", request["approver"])
        _commit_policy_change(path, state, document)
        result = dict(request)
    return result


def reject_request(path: Path, request_id: int, *, reason: str, actor: str | None = None) -> dict[str, Any]:
    if not reason.strip():
        raise ValueError("rejection reason is required")
    with _locked(path) as state:
        request = _request(state, request_id)
        if request.get("status") != "pending":
            raise ValueError(f"approval request {request_id} is {request.get('status')}")
        request.update({"status": "rejected", "rejector": _actor(actor), "rejected_at": time.time(), "rejection_reason": reason.strip()})
        state["revision"] = int(state["revision"]) + 1
        _history(state, request, "reject", request["rejector"])
        _save(path, state)
        return dict(request)


def revoke_request(path: Path, config_path: str | Path, request_id: int, *, actor: str | None = None) -> dict[str, Any]:
    with _locked(path) as state:
        request = _request(state, request_id)
        if request.get("status") == "revoked":
            return dict(request)
        if request.get("status") != "approved":
            raise ValueError(f"approval request {request_id} is {request.get('status')}")
        document = read_snapshot(Path(config_path))
        config = document.data
        protocol_spec = (
            config.get("subjects", {})
            .get(request["subject"], {})
            .get("exposure", {})
            .get(request["zone"], {})
            .get(request["protocol"], {})
        )
        if isinstance(protocol_spec, dict):
            keep = set(int(port) for port in protocol_spec.get("ports", [])) - set(request.get("applied_ports", []))
            protocol_spec["ports"] = sorted(keep)
        request.update({"status": "revoked", "revoker": _actor(actor), "revoked_at": time.time()})
        state["revision"] = int(state["revision"]) + 1
        _history(state, request, "revoke", request["revoker"])
        _commit_policy_change(path, state, document)
        return dict(request)


def deny_grant(
    path: Path,
    config_path: str | Path,
    *,
    subject: str,
    zone: str,
    protocol: str,
    ports: list[int],
    reason: str,
    actor: str | None = None,
) -> dict[str, Any]:
    """Remove selected ports while retaining the same audit trail as approvals."""
    requested_ports = _ports(ports)
    protocol = protocol.lower()
    if protocol not in _PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol}")
    if not reason.strip():
        raise ValueError("denial reason is required")

    with _locked(path) as state:
        document = read_snapshot(Path(config_path))
        config = document.data
        subject_spec = config.get("subjects", {}).get(subject, {})
        protocol_spec = (
            subject_spec
            .get("exposure", {})
            .get(zone, {})
            .get(protocol, {})
        )
        if not isinstance(protocol_spec, dict):
            raise ValueError(f"no grant found for {subject} {zone} {protocol}")
        current = {int(port) for port in protocol_spec.get("ports", [])}
        removed = sorted(current & set(requested_ports))
        if not removed:
            action, previous = _last_port_change(state, subject, zone, protocol, requested_ports)
            if (action == "deny" and previous.get("ports") == requested_ports
                    and previous.get("reason") == reason.strip() and previous.get("revoker") == _actor(actor)):
                return dict(previous)
            raise ValueError(f"none of the requested ports are granted to {subject}")
        protocol_spec["ports"] = sorted(current - set(removed))

        who = _actor(actor)
        request_id = int(state["next_id"])
        request = {
            "id": request_id,
            "subject": subject,
            "zone": zone,
            "protocol": protocol,
            "ports": requested_ports,
            "applied_ports": removed,
            "reason": reason.strip(),
            "resolve": dict(subject_spec.get("resolve", {}))
            if isinstance(subject_spec, dict) and isinstance(subject_spec.get("resolve", {}), dict)
            else {},
            "requester": who,
            "revoker": who,
            "requested_at": time.time(),
            "revoked_at": time.time(),
            "status": "revoked",
        }
        state["next_id"] = request_id + 1
        state["revision"] = int(state["revision"]) + 1
        state["requests"].append(request)
        _history(state, request, "deny", who)
        _commit_policy_change(path, state, document)
        return dict(request)


class PolicyReloadError(RuntimeError):
    """The policy was saved but the service manager could not apply it."""


def reload_daemon() -> None:
    """Notify the running controller after a policy write. Offline edits are allowed."""
    try:
        if Path("/run/systemd/system").is_dir():
            result = subprocess.run(
                ["systemctl", "show", "-p", "MainPID", "--value", "xdp-port-sync"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 4:  # Unit is not installed.
                return
            result.check_returncode()
            pid = int(result.stdout.strip())
            if pid > 1:
                os.kill(pid, signal.SIGHUP)
        elif shutil.which("rc-service"):
            # These flags leave absent and stopped installations alone.
            subprocess.run(
                ["rc-service", "--ifexists", "--ifstarted", "xdp-port-sync", "restart"],
                check=True, capture_output=True, text=True, timeout=60,
            )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        raise PolicyReloadError(f"Policy saved, but xdp-port-sync reload failed: {detail}") from exc


def run_api(config_path: str | Path, run_state_dir: str | Path, socket_path: str | Path) -> int:
    if os.geteuid() != 0:
        raise PermissionError("approval API requires root")
    from auto_xdp.admin.approval_api import serve

    serve(Path(config_path), store_path(run_state_dir), Path(socket_path))
    return 0
