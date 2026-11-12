"""Exercise real SYN Cookie ownership, replacement, rollback and disable.

Called only by the private network/mount namespace kernel fixture.
"""
import os
import shutil
from pathlib import Path
import sys
from unittest import mock

from auto_xdp.admin import handlers, module_runtime as modules
from auto_xdp.admin.handler_catalog import Context
from auto_xdp.bpf.syscall import map_id, obj_get
from auto_xdp.tui.handlers import HandlerCache, collect_handlers


def main() -> None:
    root, xdp, tc, config = map(Path, sys.argv[1:5])
    interfaces = sys.argv[5:]
    live = modules.module_dir(root)
    def ids():
        return (modules.verify_syncookie(root, interfaces), handlers.pinned_program_id(live / "ingress"))
    def shared_ids():
        values = {}
        for name in ("sync_handoff4", "sync_handoff6", "tcp_synck_policy", "sync_run_cfg"):
            fd = obj_get(str(root / name))
            try:
                values[name] = map_id(fd)
            finally:
                os.close(fd)
        return values
    original, shared = ids(), shared_ids()
    assert modules.program_available(root)
    # Configuration belongs on a regular filesystem. RHEL bpffs returns
    # EPERM, rather than ENOENT, when probing ordinary dotted filenames.
    context = Context(config=config, install_dir=xdp.parent,
                      handlers_dir=config.parent / "custom", bpf_pin_dir=root,
                      run_state_dir=config.parent, iface=interfaces[0])
    rows = collect_handlers(str(root), {}, HandlerCache(), context=context).rows
    cookie_rows = [row for row in rows if row.module and row.module.id == "syncookie"]
    assert len(cookie_rows) == 1 and cookie_rows[0].state == "loaded", cookie_rows
    assert all(row.program_id != original[1] for row in rows)
    retained = root / "retain_test"
    modules.retain_syncookie(root, retained)
    assert handlers.pinned_program_id(modules.program_pin(retained)) == original[0]
    assert handlers.pinned_program_id(modules.program_pin(retained, "ingress")) == original[1]
    shutil.rmtree(retained)
    # Flat pins do not authorize the new module manager to take over a hook.
    flat_pins = {"prog": "syncookie_prog", "ingress": "tc_syncookie_handoff_prog"}
    for name, flat in flat_pins.items():
        (live / name).rename(root / flat)
    try:
        assert not modules.program_available(root)
        try:
            modules.load_syncookie(root, xdp, tc, interfaces)
        except RuntimeError as exc:
            assert "ownership pin" in str(exc), str(exc)
        else:
            raise AssertionError("module adopted a flat program pin")
    finally:
        for name, flat in flat_pins.items():
            (root / flat).rename(live / name)
    assert ids() == original and shared_ids() == shared
    modules.load_syncookie(root, xdp, tc, interfaces)
    replaced = ids()
    assert replaced != original and shared_ids() == shared
    update = handlers.prog_array_update
    failed = False
    def fail_after_publication(table, key, pin):
        nonlocal failed
        update(table, key, pin)
        if not failed:
            failed = True
            raise RuntimeError("injected failure after real TC and XDP publication")
    with mock.patch.object(handlers, "prog_array_update", side_effect=fail_after_publication):
        try:
            modules.load_syncookie(root, xdp, tc, interfaces)
        except RuntimeError as exc:
            assert "previous generation restored" in str(exc), str(exc)
        else:
            raise AssertionError("injected module switch succeeded")
    assert failed and ids() == replaced and shared_ids() == shared
    assert not list(live.parent.glob("syncookie_*"))
    modules.remove_syncookie(root, interfaces)
    modules.verify_syncookie(root, interfaces, enabled=False)
    assert not modules.program_available(root)
    assert not live.exists()
    # Restore the enabled module before the fixture sends real TCP handshakes.
    modules.load_syncookie(root, xdp, tc, interfaces)
    assert ids() != replaced and shared_ids() == shared
    print("SYN Cookie module: ownership, shared maps, replacement, rollback, disable and re-enable passed")


if __name__ == "__main__":
    main()
