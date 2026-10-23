"""Sync orchestration: one-shot, event-driven, and periodic reconciliation."""
from __future__ import annotations

import logging
import signal
import time
from collections.abc import Callable

from auto_xdp import config as cfg
from auto_xdp.backends import NftablesBackend, PortBackend, XdpBackend
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.state import ApplyResult
from auto_xdp.discovery.listeners import DiscoveryError, get_listening_ports
from auto_xdp.discovery.notifications import NotificationReceiver
from auto_xdp.policy import resolve_desired_state

log = logging.getLogger(__name__)

TOML_CONFIG_PATH = cfg.TOML_CONFIG_PATH
BACKEND_AUTO = cfg.BACKEND_AUTO
BACKEND_XDP = cfg.BACKEND_XDP
BACKEND_NFTABLES = cfg.BACKEND_NFTABLES
TRUSTED_SRC_IPS = cfg.TRUSTED_SRC_IPS

# Cap debounce so a continuous burst of proc events can't keep deferring sync.
# Without this, busy systems (containers, cron storms) never see a quiet window
# longer than DEBOUNCE_SECONDS and sync stalls for tens of seconds.
DEBOUNCE_MAX_WAIT_SECONDS = 1.0
# A full discovery/reconcile is the safety net for missed proc/socket events.
# Event-triggered reconciles also perform a full discovery, so this interval is
# the maximum time the daemon may go without re-reading the system state.
FULL_RECONCILE_INTERVAL_SECONDS = 30.0


def observe_system_state(*, config: cfg.ConfigSnapshot | None = None):
    return get_listening_ports(config=config)


def _reload_config(config_path: str) -> bool:
    """Reload config without disturbing the last known-good configuration."""
    try:
        apply_toml_config(load_toml_config(config_path, strict=True))
    except Exception as exc:
        log.error("Configuration reload failed; retaining previous configuration: %s", exc)
        return False
    return True


def sync_once(
    backend: PortBackend | None,
    dry_run: bool,
    mode: str | None = None,
    explain: bool = False,
) -> dict[str, object]:
    started = time.monotonic()
    config = cfg.snapshot_config()
    observed = observe_system_state(config=config)
    desired = resolve_desired_state(observed, config=config)
    result = None
    effective_mode = mode or config.POLICY_MODE
    if effective_mode not in {"observe", "audit", "enforce"}:
        raise ValueError(f"Unsupported policy mode: {effective_mode}")
    if explain or desired.exposure_decisions:
        for decision in desired.exposure_decisions:
            endpoint = decision.endpoint
            message = (
                "exposure %s %s/%s %s:%d subject=%s attribution=%s zone=%s reason=%s%s"
                % (
                decision.action.upper(), endpoint.protocol, endpoint.bind_scope,
                endpoint.host_address, endpoint.host_port,
                decision.subject or endpoint.subject or "unknown",
                endpoint.attribution_state, endpoint.ingress_zone, decision.reason,
                f" profile={decision.protection_profile}" if decision.protection_profile else "",
                )
            )
            if explain:
                print(message)
            else:
                log.info(message)
    if effective_mode in {"observe", "audit"}:
        if effective_mode == "audit":
            log.info(
                "exposure audit: %d endpoint(s), %d authorized",
                len(desired.exposure_decisions),
                sum(item.action == "allow" for item in desired.exposure_decisions),
            )
    else:
        if backend is None:
            raise RuntimeError("an enforcement backend is required in enforce mode")
        result = backend.reconcile(desired, dry_run, observed)
        backend.last_apply_result = result
        if isinstance(result, ApplyResult):
            for failure in result.failures:
                log.error("Apply failed stage=%s resource=%s operation=%s reason=%s",
                          failure.operation.stage, failure.operation.resource,
                          failure.operation.operation, failure.reason)
            for endpoint_key, reason in result.blocked_endpoints.items():
                log.warning("Endpoint target blocked %s: %s", endpoint_key, reason)
            for resource, reason in result.unconfirmed.items():
                log.warning("Applied state unconfirmed %s: %s", resource, reason)
    elapsed = time.monotonic() - started
    log.info(
        "reconciliation mode=%s elapsed_ms=%.3f endpoints=%d authorized_endpoints=%d",
        effective_mode, elapsed * 1000, len(desired.exposure_decisions),
        sum(policy.allow for policy in desired.endpoint_policies.values()),
    )
    return {
        "mode": effective_mode,
        "elapsed_seconds": elapsed,
        "config": config,
        "apply_result": result,
        "observed": observed,
        "desired": desired,
    }


def _format_backend_status(status) -> str:
    return status.format_message()


def _probe_backend(backend_cls: type[PortBackend]):
    status = backend_cls.probe()
    if status.available:
        return status
    log.warning("%s backend unavailable (%s).", status.name, _format_backend_status(status))
    return status


def open_backend(name: str) -> PortBackend:
    if name == BACKEND_XDP:
        status = XdpBackend.probe()
        if not status.available:
            raise RuntimeError(_format_backend_status(status))
        return XdpBackend()
    if name == BACKEND_NFTABLES:
        status = NftablesBackend.probe()
        if not status.available:
            raise RuntimeError(_format_backend_status(status))
        return NftablesBackend()
    if name != BACKEND_AUTO:
        raise RuntimeError(f"Unsupported backend: {name}")

    xdp_status = _probe_backend(XdpBackend)
    if xdp_status.available:
        backend: PortBackend = XdpBackend()
        log.info("Backend selected: xdp")
        return backend

    nft_status = _probe_backend(NftablesBackend)
    if not nft_status.available:
        raise RuntimeError(_format_backend_status(nft_status))
    backend = NftablesBackend()
    log.info("Backend selected: nftables")
    return backend


def watch(
    dry_run: bool,
    backend_name: str,
    config_path: str = TOML_CONFIG_PATH,
    cli_trusted_ips: dict[str, str] | None = None,
    cli_log_level: str | None = None,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    mode: str | None = None,
    explain: bool = False,
) -> None:
    backend = None
    last_event_t: float | None = None
    first_event_t: float | None = None
    immediate = False
    last_reconcile_t = 0.0
    last_stale_check_t = 0.0
    reload_requested = False
    mode_only_synced = False

    def _on_sighup(signum: int, frame: object) -> None:
        nonlocal reload_requested
        reload_requested = True

    previous_sighup = signal.signal(signal.SIGHUP, _on_sighup)
    notifications = NotificationReceiver(cfg.RINGBUF_SOCKET_PATH, monotonic=monotonic)

    def _sync() -> dict[str, object]:
        if mode is None and not explain:
            return sync_once(backend, dry_run)
        return sync_once(backend, dry_run, mode=mode, explain=explain)

    try:
        notifications.start()
        while True:
            # Observe/audit are useful without root or an installed backend.
            needs_backend = (mode or cfg.POLICY_MODE) not in {"observe", "audit"}
            if not needs_backend:
                if backend is not None:
                    backend.close()
                    backend = None
                if not mode_only_synced:
                    try:
                        _sync()
                        last_reconcile_t = monotonic()
                        mode_only_synced = True
                    except DiscoveryError as exc:
                        log.error("Initial discovery failed; retrying: %s", exc)
                        last_reconcile_t = monotonic()
                        continue
            # Re-initialize backend if needed
            elif backend is None:
                mode_only_synced = False
                try:
                    backend = open_backend(backend_name)
                    log.info("Backend initialized.")
                    _sync()
                    last_reconcile_t = monotonic()
                    last_event_t = first_event_t = None
                    immediate = False
                except DiscoveryError as exc:
                    log.error("Initial discovery failed; keeping existing policy: %s", exc)
                    last_reconcile_t = monotonic()
                    continue
                except (OSError, RuntimeError) as exc:
                    log.error("Failed to open backend: %s. Retrying in 5s...", exc)
                    time.sleep(5)
                    continue

            now = monotonic()
            timeout = min(1.0, max(0.0, FULL_RECONCILE_INTERVAL_SECONDS - (now - last_reconcile_t)))
            if last_event_t is not None and first_event_t is not None:
                timeout = min(timeout, max(0.0, min(
                    cfg.DEBOUNCE_SECONDS - (now - last_event_t),
                    DEBOUNCE_MAX_WAIT_SECONDS - (now - first_event_t),
                )))
            if immediate:
                timeout = 0.0
            notification = notifications.wait(timeout)
            if notification is not None:
                first_event_t = (notification.first_seen if first_event_t is None
                                 else min(first_event_t, notification.first_seen))
                last_event_t = notification.last_seen
                immediate = immediate or notification.immediate

            if reload_requested:
                reload_requested = False
                log.warning("SIGHUP received — reloading config from %s", config_path)
                _old_pin_dir = cfg.BPF_PIN_DIR
                _old_nft_family = cfg.NFT_FAMILY
                _old_nft_table = cfg.NFT_TABLE
                _old_preferred = cfg.PREFERRED_BACKEND
                _old_resources = {name: value for name, value in cfg.snapshot_config().values.items()
                                  if name.startswith(("ABUSEIPDB_", "NFT_"))}
                if not _reload_config(config_path):
                    continue
                if cli_trusted_ips:
                    TRUSTED_SRC_IPS.update(cli_trusted_ips)
                if cli_log_level is None:
                    _lvl = getattr(logging, cfg.LOG_LEVEL.upper(), logging.WARNING)
                    logging.getLogger().setLevel(_lvl)
                    log.setLevel(_lvl)
                _new_resources = cfg.snapshot_config()
                _backend_stale = (
                    cfg.BPF_PIN_DIR != _old_pin_dir
                    or cfg.NFT_FAMILY != _old_nft_family
                    or cfg.NFT_TABLE != _old_nft_table
                    or any(_new_resources.values[name] != value
                           for name, value in _old_resources.items())
                )
                if cfg.PREFERRED_BACKEND != _old_preferred and backend_name == _old_preferred:
                    backend_name = cfg.PREFERRED_BACKEND
                    _backend_stale = True
                if _backend_stale and backend is not None:
                    log.warning(
                        "Backend-critical config changed; closing backend for rebuild."
                    )
                    backend.close()
                    backend = None
                last_event_t = monotonic() - cfg.DEBOUNCE_SECONDS
                first_event_t = last_event_t
                immediate = True
                continue  # Re-evaluate mode and backend ownership after publishing config.

            if backend is None and needs_backend:
                continue

            now = monotonic()
            event_due = immediate or (
                last_event_t is not None and first_event_t is not None and (
                    now - last_event_t >= cfg.DEBOUNCE_SECONDS
                    or now - first_event_t >= DEBOUNCE_MAX_WAIT_SECONDS
                )
            )
            if event_due or now - last_reconcile_t >= FULL_RECONCILE_INTERVAL_SECONDS:
                log.debug("Sync triggered by %s.", "event" if event_due else "periodic safety check")
                # Consume only this round's hints; the receiver retains new ones during apply.
                last_event_t = first_event_t = None
                immediate = False
                try:
                    _sync()
                    last_reconcile_t = monotonic()
                except DiscoveryError as exc:
                    log.error("Discovery failed; keeping existing policy: %s", exc)
                    last_reconcile_t = monotonic()
                    last_event_t = monotonic()
                    first_event_t = last_event_t
                    continue
                except (OSError, RuntimeError) as exc:
                    log.error("Sync error: %s", exc)
                    log.warning("Backend may be broken; will attempt to re-initialize.")
                    if backend is not None:
                        backend.close()
                    backend = None
                    continue

                result = getattr(backend, "last_apply_result", None)
                apply_failures = len(result.failures) + len(result.unconfirmed) if isinstance(result, ApplyResult) else getattr(backend, "last_apply_failures", 0)
                if backend is not None and apply_failures and hasattr(backend, "verify_kernel_state"):
                    log.warning(
                        "Reconcile had %d failed map update(s); verifying kernel state.",
                        apply_failures,
                    )
                    backend.verify_kernel_state()
                    # Arm debounce so a corrective sync runs shortly.
                    last_event_t = monotonic()
                    first_event_t = last_event_t

            if monotonic() - last_stale_check_t >= 30.0:
                last_stale_check_t = monotonic()
                if backend is not None and hasattr(backend, "is_stale") and backend.is_stale():
                    log.warning(
                        "XDP map FDs are stale (BPF program was reloaded); "
                        "reinitializing backend."
                    )
                    backend.close()
                    backend = None
                elif backend is not None and hasattr(backend, "verify_kernel_state"):
                    if backend.verify_kernel_state():
                        # Drift found: arm debounce to schedule a corrective sync.
                        _now = monotonic()
                        if first_event_t is None:
                            first_event_t = _now
                        last_event_t = _now

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        notifications.close()
        signal.signal(signal.SIGHUP, previous_sighup)
        if backend:
            backend.close()
