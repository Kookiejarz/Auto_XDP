"""Namespace hook activation is atomic, owned and fails closed."""
import json
import subprocess
from unittest.mock import patch

import pytest

from auto_xdp.bpf.conntrack import OWNER, TABLE, configure, ensure_active, verify_lookup_abi


@pytest.mark.parametrize("exists,remove", [(False, False), (True, False),
                                          (False, True), (True, True)])
def test_activation_and_removal(exists, remove):
    table = {"table": {"family": "inet", "name": TABLE, "comment": OWNER}}
    replies = [subprocess.CompletedProcess([], 0, json.dumps(
        {"nftables": [table] if exists else []}))]
    if exists:
        replies.append(subprocess.CompletedProcess([], 0, json.dumps({"nftables": [table]})))
    if exists or not remove:
        replies.append(subprocess.CompletedProcess([], 0, ""))
    with patch("auto_xdp.bpf.conntrack.subprocess.run", side_effect=replies) as run:
        configure(remove=remove)
    mutations = [call for call in run.call_args_list if call.args[0] == ["nft", "-f", "-"]]
    assert len(mutations) == int(exists or not remove)
    if mutations:
        commands = mutations[0].kwargs["input"]
        assert (f"delete table inet {TABLE}" in commands) == exists
        assert ("ct state established counter" in commands) == (not remove)
        assert "flush ruleset" not in commands and "nat" not in commands
        assert " drop" not in commands and "counter accept" not in commands


@pytest.mark.parametrize("remove", [False, True])
def test_foreign_table_is_never_changed(remove):
    data = json.dumps({"nftables": [{"table": {"family": "inet", "name": TABLE}}]})
    with patch("auto_xdp.bpf.conntrack.subprocess.run", return_value=
               subprocess.CompletedProcess([], 0, data)) as run:
        with pytest.raises(RuntimeError, match="unowned"):
            configure(remove=remove)
    assert all(call.args[0][:2] == ["nft", "-j"] for call in run.call_args_list)


def test_failed_probe_is_not_treated_as_absence():
    with patch("auto_xdp.bpf.conntrack.subprocess.run", side_effect=
               subprocess.CalledProcessError(1, ["nft"])) as run:
        with pytest.raises(subprocess.CalledProcessError):
            configure()
    assert run.call_count == 1


def test_kernel_rejecting_activation_is_fatal():
    with patch("auto_xdp.bpf.conntrack.subprocess.run", side_effect=[
        subprocess.CompletedProcess([], 0, '{"nftables": []}'),
        subprocess.CalledProcessError(1, ["nft"]),
    ]):
        with pytest.raises(subprocess.CalledProcessError):
            configure()


@pytest.mark.parametrize("direction_offset", [None, 80, 72])
@pytest.mark.parametrize("module", [False, True])
def test_direction_abi_is_required_even_when_lookup_kfunc_exists(direction_offset, module):
    offsets = {"netns_id": 0, "error": 32, "l4proto": 64}
    if direction_offset is not None:
        offsets["dir"] = direction_offset
    data = {"types": [{"kind": "STRUCT", "name": "bpf_ct_opts", "members": [
        {"name": name, "bits_offset": offset} for name, offset in offsets.items()
    ]}]}
    with patch("auto_xdp.bpf.conntrack.Path.exists", return_value=module), \
         patch("auto_xdp.bpf.conntrack.subprocess.run", return_value=
               subprocess.CompletedProcess([], 0, json.dumps(data))) as run:
        if direction_offset == 72:
            verify_lookup_abi()
        else:
            with pytest.raises(RuntimeError, match="REPLY direction ABI"):
                verify_lookup_abi()
    assert run.call_args.args[0][5] == "/sys/kernel/btf/" + ("nf_conntrack" if module else "vmlinux")


def _table_rows(*, owned=True, chain=True, rule=True):
    rows = [{"table": {"family": "inet", "name": TABLE, **({"comment": OWNER} if owned else {})}}]
    if chain:
        rows.append({"chain": {"family": "inet", "table": TABLE, "name": "track", "hook": "output"}})
    if rule:
        rows.append({"rule": {"family": "inet", "table": TABLE, "chain": "track", "expr": []}})
    return json.dumps({"nftables": rows})


def _listing(exists):
    table = {"table": {"family": "inet", "name": TABLE, "comment": OWNER}}
    return subprocess.CompletedProcess([], 0, json.dumps({"nftables": [table] if exists else []}))


def test_intact_activation_table_is_left_alone():
    with patch("auto_xdp.bpf.conntrack.subprocess.run", side_effect=[
        _listing(True), subprocess.CompletedProcess([], 0, _table_rows()),
    ]) as run:
        assert ensure_active() is False
    assert all(call.args[0][:2] == ["nft", "-j"] for call in run.call_args_list)


@pytest.mark.parametrize("damage", ["flushed", "no_chain", "no_rule"])
def test_missing_or_emptied_activation_table_is_recreated(damage):
    if damage == "flushed":
        replies = [_listing(False), _listing(False)]
    else:
        rows = _table_rows(chain=damage != "no_chain", rule=damage == "no_chain")
        replies = [_listing(True), subprocess.CompletedProcess([], 0, rows),
                   _listing(True), subprocess.CompletedProcess([], 0, rows)]
    replies.append(subprocess.CompletedProcess([], 0, ""))
    with patch("auto_xdp.bpf.conntrack.subprocess.run", side_effect=replies) as run:
        assert ensure_active() is True
    mutations = [call for call in run.call_args_list if call.args[0] == ["nft", "-f", "-"]]
    assert len(mutations) == 1
    commands = mutations[0].kwargs["input"]
    assert "ct state established counter" in commands and "flush ruleset" not in commands


def test_unowned_table_is_not_repaired():
    rows = _table_rows(owned=False, chain=False, rule=False)
    with patch("auto_xdp.bpf.conntrack.subprocess.run", side_effect=[
        _listing(True), subprocess.CompletedProcess([], 0, rows),
        _listing(True), subprocess.CompletedProcess([], 0, rows),
    ]) as run:
        with pytest.raises(RuntimeError, match="unowned"):
            ensure_active()
    assert all(call.args[0][:2] == ["nft", "-j"] for call in run.call_args_list)
