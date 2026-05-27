"""Sync orchestration: one-shot sync and event-driven daemon loop."""
from __future__ import annotations

import json as _json
import logging
import select
import signal
import socket as _socket
import time

from auto_xdp import config as cfg
from auto_xdp.backends import NftablesBackend, PortBackend, XdpBackend
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.discovery import get_listening_ports
from auto_xdp.policy import resolve_desired_state
from auto_xdp.proc_events import drain_proc_events, open_proc_connector

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


def observe_system_state():
    return get_listening_ports()


def sync_once(backend: PortBackend, dry_run: bool) -> None:
    observed = observe_system_state()
    desired = resolve_desired_state(observed)
    backend.reconcile(desired, dry_run, observed)


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
        backend = XdpBackend()
        log.info("Backend selected: xdp")
        return backend

    nft_status = _probe_backend(NftablesBackend)
    if not nft_status.available:
        raise RuntimeError(_format_backend_status(nft_status))
    backend = NftablesBackend()
    log.info("Backend selected: nftables")
    return backend


def _open_relay_client(sock_path: str) -> "_socket.socket | None":
    """Connect to pkt_relay Unix socket as a non-blocking subscriber."""
    try:
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.connect(sock_path)
        s.setblocking(False)
        return s
    except OSError:
        return None


def _drain_relay_lines(relay_sock: "_socket.socket") -> bool:
    """Read available lines from the relay socket.

    Returns True if any port_change event was found.
    Raises ConnectionResetError if the relay closed the connection.
    """
    buf = b""
    try:
        while True:
            chunk = relay_sock.recv(4096)
            if not chunk:
                raise ConnectionResetError("relay disconnected")
            buf += chunk
    except BlockingIOError:
        pass

    found = False
    for raw_line in buf.split(b"\n"):
        if not raw_line:
            continue
        try:
            msg = _json.loads(raw_line)
        except _json.JSONDecodeError:
            continue
        if msg.get("type") == "port_change":
            found = True
    return found


def watch(
    dry_run: bool,
    backend_name: str,
    config_path: str = TOML_CONFIG_PATH,
    cli_trusted_ips: dict[str, str] | None = None,
    cli_log_level: str | None = None,
) -> None:
    backend = None
    nl = None

    last_event_t = 0.0
    first_event_t = 0.0
    last_gc_t = 0.0
    last_stale_check_t = 0.0
    reload_requested = False

    def _on_sighup(signum: int, frame: object) -> None:
        nonlocal reload_requested
        reload_requested = True

    signal.signal(signal.SIGHUP, _on_sighup)

    relay_sock: "_socket.socket | None" = None
    last_relay_connect_t = 0.0
    RELAY_RETRY_INTERVAL = 5.0

    try:
        while True:
            # Re-initialize backend if needed
            if backend is None:
                try:
                    backend = open_backend(backend_name)
                    log.info("Backend initialized.")
                    sync_once(backend, dry_run)
                    last_event_t = 0.0
                    first_event_t = 0.0
                except OSError as exc:
                    log.error("Failed to open backend: %s. Retrying in 5s...", exc)
                    time.sleep(5)
                    continue

            # Re-subscribe to netlink if needed
            if nl is None:
                nl = open_proc_connector()
                if nl is None:
                    time.sleep(5)
                    continue

            # Optionally subscribe to pkt_relay for instant port_change triggers.
            now_mono = time.monotonic()
            if relay_sock is None and now_mono - last_relay_connect_t >= RELAY_RETRY_INTERVAL:
                relay_sock = _open_relay_client(cfg.RINGBUF_SOCKET_PATH)
                last_relay_connect_t = now_mono
                if relay_sock:
                    log.info("Connected to pkt_relay for port_change events.")

            debounce_s = cfg.DEBOUNCE_SECONDS
            timeout = max(0.05, debounce_s - (time.monotonic() - last_event_t)) if last_event_t else 1.0

            select_fds = [nl]
            if relay_sock is not None:
                select_fds.append(relay_sock)

            try:
                rdy, _, _ = select.select(select_fds, [], [], timeout)
                if rdy and drain_proc_events(nl):
                    log.debug("Proc event -> debounce armed.")
                    _now = time.monotonic()
                    if not first_event_t:
                        first_event_t = _now
                    last_event_t = _now
                if relay_sock is not None and relay_sock in rdy:
                    try:
                        if _drain_relay_lines(relay_sock):
                            log.debug("port_change from relay → immediate sync.")
                            try:
                                sync_once(backend, dry_run)
                            except (OSError, RuntimeError) as exc:
                                log.error("Sync error (port_change): %s", exc)
                                backend.close()
                                backend = None
                    except (ConnectionResetError, OSError):
                        log.info("pkt_relay disconnected; reverting to proc_connector only.")
                        relay_sock.close()
                        relay_sock = None
                        last_relay_connect_t = time.monotonic()
            except OSError as exc:
                log.warning("Netlink error (%s); reconnecting proc connector.", exc)
                if nl:
                    nl.close()
                nl = None
                continue

            if reload_requested:
                reload_requested = False
                log.warning("SIGHUP received — reloading config from %s", config_path)
                _old_pin_dir = cfg.BPF_PIN_DIR
                _old_nft_family = cfg.NFT_FAMILY
                _old_nft_table = cfg.NFT_TABLE
                _old_preferred = cfg.PREFERRED_BACKEND
                apply_toml_config(load_toml_config(config_path))
                if cli_trusted_ips:
                    TRUSTED_SRC_IPS.update(cli_trusted_ips)
                if cli_log_level is None:
                    _lvl = getattr(logging, cfg.LOG_LEVEL.upper(), logging.WARNING)
                    logging.getLogger().setLevel(_lvl)
                    log.setLevel(_lvl)
                _backend_stale = (
                    cfg.BPF_PIN_DIR != _old_pin_dir
                    or cfg.NFT_FAMILY != _old_nft_family
                    or cfg.NFT_TABLE != _old_nft_table
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
                last_event_t = time.monotonic() - cfg.DEBOUNCE_SECONDS
                first_event_t = last_event_t

            now = time.monotonic()
            if last_event_t and (
                now - last_event_t >= cfg.DEBOUNCE_SECONDS
                or now - first_event_t >= DEBOUNCE_MAX_WAIT_SECONDS
            ):
                if nl:
                    drain_proc_events(nl)
                log.debug("Sync triggered by event.")
                try:
                    sync_once(backend, dry_run)
                except (OSError, RuntimeError) as exc:
                    log.error("Sync error: %s", exc)
                    log.warning("Backend may be broken; will attempt to re-initialize.")
                    backend.close()
                    backend = None

                last_event_t = 0.0
                first_event_t = 0.0

            gc_interval = cfg.XDP_CONNTRACK_GC_INTERVAL_SECONDS
            if gc_interval > 0 and (time.monotonic() - last_gc_t >= gc_interval):
                try:
                    backend.run_ct_gc()
                except OSError as exc:
                    log.warning("Conntrack GC error: %s", exc)
                last_gc_t = time.monotonic()

            if time.monotonic() - last_stale_check_t >= 30.0:
                last_stale_check_t = time.monotonic()
                if hasattr(backend, "is_stale") and backend.is_stale():
                    log.warning(
                        "XDP map FDs are stale (BPF program was reloaded); "
                        "reinitializing backend."
                    )
                    backend.close()
                    backend = None

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        if nl:
            nl.close()
        if relay_sock:
            relay_sock.close()
        if backend:
            backend.close()
