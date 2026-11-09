"""Discover, configure and install handler modules for the CLI and TUI.

Discovery never loads BPF or executes a package. A manifest describes editable
values; custom source parameters are integer/bool preprocessor definitions.
Actual activation still goes through the existing handler transactions.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from auto_xdp import config as configuration
from auto_xdp.admin import config_file, handlers, module_runtime


_IDENTIFIER = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$")
_KINDS = ("slot", "tcp", "udp")


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    type: str = "string"
    default: Any = ""
    minimum: int | float | None = None
    maximum: int | float | None = None
    choices: tuple[Any, ...] = ()
    define: str = ""
    help: str = ""
    readonly: bool = False

    def parse(self, value: Any) -> Any:
        if self.type == "bool":
            if isinstance(value, str) and value.lower() in {"true", "false", "yes", "no", "1", "0"}:
                value = value.lower() in {"true", "yes", "1"}
            if type(value) is not bool:
                raise ValueError(f"{self.name}: expected true or false")
        elif self.type in {"int", "number"}:
            if isinstance(value, bool):
                raise ValueError(f"{self.name}: expected a number")
            try:
                if self.type == "int":
                    if isinstance(value, float) and not value.is_integer():
                        raise ValueError("not an integer")
                    value = int(value)
                else:
                    value = float(value)
            except (ValueError, TypeError, OverflowError) as exc:
                raise ValueError(f"{self.name}: expected {self.type}") from exc
            if not float("-inf") < value < float("inf"):
                raise ValueError(f"{self.name}: expected a finite number")
            if self.minimum is not None and value < self.minimum:
                raise ValueError(f"{self.name}: minimum is {self.minimum}")
            if self.maximum is not None and value > self.maximum:
                raise ValueError(f"{self.name}: maximum is {self.maximum}")
        elif self.type == "json":
            if isinstance(value, str):
                value = json.loads(value)
            if not isinstance(value, dict):
                raise ValueError(f"{self.name}: expected a JSON object")
        elif not isinstance(value, str):
            raise ValueError(f"{self.name}: expected text")
        if self.choices and value not in self.choices:
            raise ValueError(f"{self.name}: choose {', '.join(map(str, self.choices))}")
        return value


@dataclass(frozen=True)
class Module:
    id: str
    name: str
    path: str
    kind: str = "custom"
    target: int = 0
    description: str = ""
    fields: tuple[Field, ...] = ()
    error: str = ""
    hooks: str = "XDP; optional TC egress (checked on install/apply)"
    build_error: str = ""
    companions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Context:
    config: Path
    install_dir: Path
    handlers_dir: Path
    bpf_pin_dir: Path
    run_state_dir: Path
    iface: str = ""

    @classmethod
    def from_args(cls, args: Any) -> Context:
        return cls(Path(args.config), Path(getattr(args, "install_dir", "/usr/local/lib/auto_xdp/current")),
                   Path(getattr(args, "handlers_dir", "/etc/auto_xdp/handlers")), Path(args.bpf_pin_dir),
                   Path(getattr(args, "run_state_dir", "/run/auto_xdp")), str(getattr(args, "iface", "")))


_COOKIE_FIELDS = (
    Field("default_mode", "Default mode", default="auto", choices=("off", "auto", "always")),
    Field("activation_percent", "Activation threshold (%)", "int", 90, 1, 99),
    Field("auto_max_percent", "Auto maximum (%)", "int", 200, 100, 10000),
    Field("challenge_cooldown_seconds", "Challenge cooldown (seconds)", "number", 5, 0),
    Field("invalid_ack_rate_pps", "Invalid ACK limit (pps)", "int", 1000, 1),
    Field("port_rate_default", "Port SYN/s (0 = built-in)", "int", 0, 0),
    *(Field(name, label, "json", {}) for name, label in (
        ("by_port", "Modes by port"), ("by_proc", "Modes by process"), ("by_service", "Modes by service"),
        ("port_rate_by_port", "Port SYN/s by port"), ("port_rate_by_proc", "Port SYN/s by process"),
        ("port_rate_by_service", "Port SYN/s by service"))),
)


def _artifact(directory: Path, name: str) -> Path:
    obj = directory / f"{name}.o"
    return obj if obj.is_file() else directory / f"{name}.c"


def _manifest(path: Path) -> tuple[dict[str, Any], tuple[Field, ...]]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise ValueError("handler manifest requires version = 1")
    if not isinstance(data.get("fields", []), list):
        raise ValueError("manifest fields must be an array")
    fields = []
    seen: set[str] = set()
    definitions: set[str] = set()
    for spec in data.get("fields", []):
        if not isinstance(spec, dict):
            raise ValueError("manifest fields must be objects")
        name, define = str(spec.get("name", "")), str(spec.get("define", ""))
        if not _IDENTIFIER.fullmatch(name) or name in seen or name in {"enabled", "kind", "target", "subject", "draft"}:
            raise ValueError(f"invalid/duplicate parameter: {name}")
        if not _IDENTIFIER.fullmatch(define) or define in definitions:
            raise ValueError(f"invalid/duplicate compiler definition: {define}")
        if spec.get("type") not in {"int", "bool"}:
            raise ValueError("custom parameters currently support int and bool compiler definitions")
        if not isinstance(spec.get("choices", []), list):
            raise ValueError("parameter choices must be an array")
        for limit in ("minimum", "maximum"):
            if limit in spec and type(spec[limit]) not in {int, float}:
                raise ValueError(f"parameter {limit} must be numeric")
            if limit in spec and not float("-inf") < spec[limit] < float("inf"):
                raise ValueError(f"parameter {limit} must be finite")
        if "minimum" in spec and "maximum" in spec and spec["minimum"] > spec["maximum"]:
            raise ValueError("parameter minimum exceeds maximum")
        item = Field(name, str(spec.get("label", name)), str(spec["type"]), spec.get("default"),
                     spec.get("minimum"), spec.get("maximum"), tuple(spec.get("choices", [])), define,
                     str(spec.get("help", "")))
        item.parse(item.default)
        for choice in item.choices:
            item.parse(choice)
        fields.append(item)
        seen.add(name)
        definitions.add(define)
    return data, tuple(fields)


def _local_module(path: Path, manifest: Path | None = None) -> Module:
    identifier = path.stem + "-" + hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:8]
    data: dict[str, Any] = {}
    fields: tuple[Field, ...] = ()
    try:
        manifest = manifest or path.with_suffix(".handler.json")
        if manifest.is_file():
            raw = json.loads(manifest.read_text())
            if isinstance(raw, dict) and _NAME.fullmatch(str(raw.get("id", ""))):
                identifier = str(raw["id"])
            data, fields = _manifest(manifest)
            identifier = str(data.get("id", identifier))
        if not _NAME.fullmatch(identifier):
            raise ValueError("invalid module id")
        kind = str(data.get("kind", "custom"))
        if kind not in (*_KINDS, "custom"):
            raise ValueError("custom module kind must be slot, tcp or udp")
        target = data.get("target", 0)
        if type(target) is not int:
            raise ValueError("module target must be an integer")
        if fields and path.suffix != ".c":
            raise ValueError("editable compiler parameters require a .c entry")
        return Module(identifier, str(data.get("name", path.stem)), str(path.resolve()), kind, target,
                      str(data.get("description", "Local handler; ABI is checked before activation.")), fields)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return Module(identifier, path.stem, str(path.resolve()), error=f"Invalid manifest: {exc}")


def _build_records(context: Context) -> dict[str, dict[str, str]]:
    records = {}
    for record in (context.handlers_dir / ".diagnostics").glob("*.json"):
        try:
            entry = json.loads(record.read_text())
            if not isinstance(entry, dict) or not all(isinstance(entry.get(key), str) for key in ("path", "error", "manifest")):
                continue
            if Path(entry["path"]).suffix in {".c", ".o"} and Path(entry["path"]).is_file():
                records[str(Path(entry["path"]).resolve())] = entry
        except (OSError, ValueError):
            continue
    return records


def _record_build(context: Context, source: Path, error: str = "", manifest: Path | None = None, *, retain: bool = False) -> None:
    """Keep the last failed check across CLI/TUI sessions, outside policy state."""
    source = source.resolve()
    directory = context.handlers_dir / ".diagnostics"
    record = directory / (hashlib.sha256(str(source).encode()).hexdigest() + ".json")
    temporary = None
    try:
        if not error and not retain:
            record.unlink(missing_ok=True)
            return
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o644)
            json.dump({"path": str(source), "error": error[:65536], "manifest": str(manifest or "")}, stream)
        temporary.replace(record)
    except OSError:
        pass  # Diagnostics must not replace the compiler error or break a successful build.
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _checked_object(context: Context, module: Module, values: dict[str, Any], *,
                    source: Path | None = None, manifest: Path | None = None) -> Path:
    previous = _build_records(context).get(str(Path(module.path).resolve())) if source is None else None
    source = source or Path(module.path)
    if previous and previous["manifest"]:
        manifest = Path(previous["manifest"])
    try:
        obj = _prepare_object(context, module, values)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        detail = str(exc).replace(str(Path(module.path).parent), str(source.parent)) if str(source) != module.path else str(exc)
        _record_build(context, source, detail, manifest)
        raise
    # Applying an original failed-install candidate may succeed without a
    # package install. Keep its source/manifest discoverable for future edits.
    _record_build(context, source, manifest=manifest, retain=previous is not None)
    return obj


def discover(context: Context, data: dict[str, Any] | None = None) -> list[Module]:
    """Include bundled, installed, local and explicitly configured artifacts."""
    data = config_file.load_toml(context.config) if data is None else data
    sdk = context.install_dir / "handlers"
    modules = [Module(name, name.upper(), str(_artifact(sdk, f"{name}_handler")), "slot", proto,
                      "Protocol admission checks. Existing exposure policy still applies.")
               for name, (proto, _) in handlers.BUILTIN_SLOT_INFO.items()]
    modules.extend((
        Module("minecraft", "Minecraft Java", str(_artifact(sdk, "minecraft_handler")), "minecraft", 1,
               "Protect an existing policy subject. This does not grant network exposure.",
               hooks="XDP + TC egress"),
        Module("syncookie", "SYN Cookie", str(context.install_dir / "xdp_syncookie.o"), "syncookie", 0,
               "TCP handshake protection with Linux listener handoff.", _COOKIE_FIELDS,
               hooks="XDP + TC ingress", companions=(str(context.install_dir / "tc_syncookie_handoff.o"),)),
    ))
    seen = {str(Path(module.path).resolve()) for module in modules}
    # Treat matching source/object peers as one module. Prefer source when its
    # manifest declares compiler parameters, otherwise prefer the object.
    candidates: dict[str, Path] = {}
    for directory in (sdk, context.handlers_dir):
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.suffix not in {".c", ".o"} or not path.is_file():
                continue
            key = str(path.with_suffix("").resolve())
            current = candidates.get(key)
            if current is None or path.suffix == ".o":
                candidates[key] = path
    for path in (context.handlers_dir / "catalog").glob("*/handler.json"):
        if path.parent.name.startswith("."):
            continue
        try:
            metadata, _ = _manifest(path)
            entry = (path.parent / str(metadata["entry"])).resolve()
            if not entry.is_relative_to(path.parent.resolve()) or not entry.is_file():
                raise ValueError("package entry must be a file inside its directory")
            modules.append(_local_module(entry, path))
            seen.add(str(entry))
        except (OSError, ValueError, TypeError, KeyError) as exc:
            modules.append(Module(path.parent.name, path.parent.name, str(path), error=str(exc)))
    configured = data.get("port_handlers", {})
    for proto in ("tcp", "udp"):
        for value in configured.get(proto, {}).values():
            path = Path(str(value))
            candidates.setdefault(str(path.with_suffix("").resolve()), path)
    for value in data.get("slots", {}).get("enabled", []):
        if isinstance(value, dict) and value.get("path"):
            path = Path(str(value["path"]))
            candidates.setdefault(str(path.with_suffix("").resolve()), path)
    for path in candidates.values():
        if any(str(path.with_suffix(suffix).resolve()) in seen for suffix in (".c", ".o")):
            continue
        # Objects produced by this catalog are already represented by their
        # source module, rather than appearing again for every configuration.
        if path.resolve().is_relative_to((context.handlers_dir / "builds").resolve()):
            continue
        manifest = path.with_suffix(".handler.json")
        if manifest.is_file() and path.with_suffix(".c").is_file():
            try:
                if _manifest(manifest)[1]:
                    path = path.with_suffix(".c")
            except (OSError, ValueError, TypeError, KeyError):
                pass
        modules.append(_local_module(path))
    failures = _build_records(context)
    # Failed installs are still identifiable by their original local source,
    # even though no partial package was published to the installed catalog.
    known = {module.path for module in modules}
    for failed_path, failure in failures.items():
        if failed_path not in known:
            failed_manifest = Path(failure["manifest"]) if failure["manifest"] else None
            modules.append(_local_module(Path(failed_path), failed_manifest))
    counts: dict[str, int] = {}
    for module in modules:
        counts[module.id] = counts.get(module.id, 0) + 1
    return [replace(module, build_error=failures.get(str(Path(module.path).resolve()), {}).get("error", ""),
                    error=module.error or ("Duplicate module id; give local manifests distinct ids" if counts[module.id] > 1 else ""))
            for module in modules]


def select(context: Context, name: str) -> Module:
    candidates = [module for module in discover(context)
                  if module.id == name or module.path == str(Path(name).resolve())]
    if len(candidates) != 1:
        raise ValueError(f"No unique handler matches {name!r}; use 'axdp handler list'")
    module = candidates[0]
    if module.error:
        raise ValueError(module.error)
    return module


def fields_for(module: Module) -> tuple[Field, ...]:
    fields = [Field("enabled", "Enabled", "bool", True)]
    if module.kind == "minecraft":
        fields.append(Field("subject", "Existing policy subject", help="Use a subject already defined in the policy config."))
    elif module.kind not in {"syncookie"}:
        if module.kind == "custom":
            fields.append(Field("kind", "Attach to", default="tcp", choices=_KINDS))
        fields.append(Field("target", "IP protocol" if module.kind == "slot" else "Target port / IP protocol", "int", module.target, 0, 65535,
                            readonly=module.id in handlers.BUILTIN_SLOT_INFO))
    return (*fields, *module.fields)


def settings(module: Module, data: dict[str, Any]) -> dict[str, Any]:
    values = {item.name: copy.deepcopy(item.default) for item in fields_for(module)}
    saved = configuration.module_configs(data).get(module.id, {})
    if module.kind in {"syncookie"}:
        values["enabled"] = False
    if module.kind == "minecraft":
        subjects = [name for name, spec in data.get("subjects", {}).items()
                    if spec.get("protection", {}).get("profile") == "minecraft"]
        if len(subjects) == 1:
            values["subject"] = subjects[0]
    values.update({key: value for key, value in saved.items() if key in values})
    values.update(saved.get("draft", {}))
    return values


def validate(module: Module, values: dict[str, Any]) -> dict[str, Any]:
    fields = fields_for(module)
    unknown = set(values) - {item.name for item in fields}
    if unknown:
        raise ValueError(f"Unknown handler parameters: {', '.join(sorted(unknown))}")
    result = {item.name: item.parse(values.get(item.name, item.default)) for item in fields}
    kind = result.get("kind", module.kind)
    if kind in _KINDS:
        if kind == "slot":
            handlers.normalize_handler_protocol(result["target"])
            if result["target"] in {1, 6, 17, 58}:
                raise ValueError("TCP/UDP/ICMP use the main firewall path; choose a TCP/UDP port handler instead")
            if module.id in handlers.BUILTIN_SLOT_INFO and result["target"] != module.target:
                raise ValueError(f"{module.name} uses IP protocol {module.target}")
        else:
            handlers.normalize_handler_port(result["target"])
    if kind == "minecraft" and not result["subject"].strip():
        raise ValueError("Choose an existing policy subject")
    return result


def parse_assignments(items: list[str]) -> dict[str, str]:
    result = {}
    for item in items:
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise ValueError("Parameters use KEY=VALUE, for example --set enabled=true")
        if key in result:
            raise ValueError(f"Duplicate parameter: {key}")
        result[key] = value
    return result


def _prepare_object(context: Context, module: Module, values: dict[str, Any]) -> Path:
    source = Path(module.path)
    if not source.is_file():
        raise ValueError(f"Handler artifact not found: {source}")
    if source.suffix == ".o":
        handlers.handler_object_programs(source)
        return source.resolve()
    if source.suffix != ".c":
        raise ValueError("Handler entry must be a .c source or .o BPF object")
    parent = context.handlers_dir / "builds"
    parent.mkdir(parents=True, exist_ok=True)
    # A fresh directory prevents a failed compile from overwriting an object
    # still referenced by a saved configuration or an active generation.
    build = Path(tempfile.mkdtemp(prefix=module.id + "-", dir=parent))
    try:
        definitions = {item.define: int(values[item.name]) for item in module.fields if item.define}
        obj = handlers.compile_handler_source(source, values.get("kind", module.kind), build,
                                              sdk_dir=context.install_dir / "handlers", defines=definitions)
        handlers.handler_object_programs(obj)
        (build / ".catalog-build.json").write_text(json.dumps({"module": module.id, "object": obj.name}))
        return obj.resolve()
    except Exception:
        shutil.rmtree(build)
        raise


def _referenced_builds(data: dict[str, Any]) -> set[Path]:
    references: set[Path] = set()
    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str) and value.endswith(".o"):
            references.add(Path(value).resolve().parent)
    visit(data)
    return references


def _collect_unused_builds(context: Context, data: dict[str, Any]) -> None:
    """Retire only our marked builds that no saved configuration references."""
    references = _referenced_builds(data)
    for directory in (context.handlers_dir / "builds").glob("*"):
        if directory.is_symlink() or not directory.is_dir() or directory.resolve() in references:
            continue
        try:
            marker = json.loads((directory / ".catalog-build.json").read_text())
            if not isinstance(marker, dict) or not _NAME.fullmatch(str(marker.get("module", ""))):
                continue
            if Path(str(marker.get("object", ""))).name != marker.get("object"):
                continue
            shutil.rmtree(directory)
        except (OSError, ValueError):
            continue  # Cleanup failure must not turn a verified switch into failure.


def _effective_config(module: Module, values: dict[str, Any], data: dict[str, Any], obj: Path | None) -> dict[str, Any]:
    result = copy.deepcopy(data)
    result.setdefault("modules", {})[module.id] = copy.deepcopy(values)
    kind = values.get("kind", module.kind)
    enabled = values["enabled"]
    if kind == "minecraft":
        subject = result.get("subjects", {}).get(values["subject"])
        if not isinstance(subject, dict):
            raise ValueError(f"Unknown policy subject: {values['subject']}")
        current = subject.setdefault("protection", {}).get("profile", "")
        if current not in {"", "minecraft"}:
            raise ValueError(f"Subject already uses protection profile {current}")
        subject["protection"]["profile"] = "minecraft" if enabled else ""
    elif kind not in {"syncookie"}:
        target = values["target"]
        bindings = result.setdefault("handler_bindings", {}).setdefault(kind, {})
        current = bindings.get(str(target), {})
        if not enabled:
            saved = ""
            builtin = ""
            if kind == "slot":
                for entry in result.get("slots", {}).get("enabled", []):
                    if isinstance(entry, str) and handlers.BUILTIN_SLOT_INFO.get(entry, (-1, ""))[0] == target:
                        builtin = entry
                    elif isinstance(entry, dict) and int(entry.get("proto", -1)) == target:
                        saved = str(entry.get("path", ""))
            else:
                saved = str(result.get("port_handlers", {}).get(kind, {}).get(str(target), ""))
            owned = (builtin == module.id or bool(saved) and (
                Path(saved).resolve() == Path(module.path).resolve() or
                current.get("module") == module.id and
                Path(str(current.get("path", ""))).resolve() == Path(saved).resolve()))
            if not owned:
                raise ValueError("No saved binding for this module at the selected target; select its configured handler to disable it")
        if kind == "slot":
            entries = result.setdefault("slots", {}).get("enabled", [])
            matching = lambda item: ((isinstance(item, dict) and int(item.get("proto", -1)) == target)
                                     or (isinstance(item, str) and handlers.BUILTIN_SLOT_INFO.get(item, (-1, ""))[0] == target))
            result["slots"]["enabled"] = [item for item in entries if not matching(item)]
            if enabled:
                result["slots"]["enabled"].append({"proto": target, "path": str(obj)})
        else:
            table = result.setdefault("port_handlers", {}).setdefault(kind, {})
            if enabled:
                table[str(target)] = str(obj)
            else:
                table.pop(str(target), None)
        if enabled:
            bindings[str(target)] = {"module": module.id, "path": str(obj)}
        else:
            bindings.pop(str(target), None)
    configuration.parse_toml_config(result)
    return result


def _daemon_matches(context: Context, pid: int, proc_root: Path = Path("/proc")) -> bool:
    """Never stop a controller for another install or configuration."""
    try:
        args = (proc_root / str(pid) / "cmdline").read_bytes().decode().strip("\0").split("\0")
        script = context.install_dir / "xdp_port_sync.py"
        if "--watch" in args and any(Path(arg).resolve() == script.resolve() for arg in args if arg.endswith("xdp_port_sync.py")):
            config = args[args.index("--config") + 1] if "--config" in args else configuration.TOML_CONFIG_PATH
            return Path(config).resolve() == context.config.resolve()
        # Type=simple reports an active service before the shell launcher has
        # exec'd Python. That launcher is already a writer and must be stopped
        # too; otherwise applying immediately after startup races it.
        launcher = context.install_dir / "auto_xdp_start.sh"
        if any(Path(arg).resolve() == launcher.resolve() for arg in args if arg.endswith("auto_xdp_start.sh")):
            from auto_xdp.admin.runtime import _load_env_file
            entries = (proc_root / str(pid) / "environ").read_bytes().decode().split("\0")
            env = dict(item.split("=", 1) for item in entries if "=" in item)
            runtime = _load_env_file(Path(env.get("CONFIG_FILE", "/etc/auto_xdp/auto_xdp.env")))
            return (Path(runtime.get("TOML_CONFIG", "")).resolve() == context.config.resolve()
                    and Path(runtime.get("BPF_PIN_DIR", "")).resolve() == context.bpf_pin_dir.resolve())
        return False
    except (OSError, UnicodeError, IndexError):
        return False


def _controller_commands(context: Context) -> tuple[list[str], list[str]] | None:
    """Locate the installed supervisor, leaving inactive/unrelated services alone."""
    try:
        result = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", "xdp-port-sync"],
                                capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        result = None
    if result is not None and result.returncode == 0:
        try:
            pid = int(result.stdout.strip() or "0")
        except ValueError:
            return None
        if pid <= 1 or not _daemon_matches(context, pid):
            return None
        start = ["systemctl", "start", "xdp-port-sync"]
        # PartOf=xdp-port-sync stops the relay with its controller.
        # Restore it only if it was running before this operation.
        try:
            relay = subprocess.run(["systemctl", "is-active", "--quiet", "auto-xdp-relay"],
                                   capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"Cannot inspect event relay before stopping controller: {exc}") from exc
        if relay.returncode == 0:
            start.append("auto-xdp-relay")
        return ["systemctl", "stop", "xdp-port-sync"], start
    # The installed OpenRC service records the exec'd sync process here.
    try:
        pid = int(Path("/run/xdp-port-sync.pid").read_text().strip())
        if pid > 1 and _daemon_matches(context, pid) and shutil.which("rc-service"):
            return ["rc-service", "xdp-port-sync", "stop"], ["rc-service", "xdp-port-sync", "start"]
    except (OSError, ValueError):
        pass
    return None


def _runtime_command(command: list[str], *, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=120)
    if result.returncode:
        output = "\n".join(part.strip() for part in (result.stderr, result.stdout) if part and part.strip())
        raise RuntimeError(f"Runtime command failed (exit {result.returncode}): {' '.join(command)}\n{output}".rstrip())


def _refresh_managed_runtime(context: Context) -> dict[str, str]:
    launcher = context.install_dir / "auto_xdp_start.sh"
    env_file = context.config.parent / "auto_xdp.env"
    if not launcher.is_file() or not env_file.is_file():
        raise RuntimeError("Installed runtime launcher/environment is missing; install the runtime before applying this module")
    # The launcher sources its environment. Check the selected paths before
    # invoking it, so a custom CLI/TUI context cannot operate a different root.
    from auto_xdp.admin.runtime import _load_env_file
    env_config = _load_env_file(env_file)
    for key, expected in (("TOML_CONFIG", context.config), ("BPF_PIN_DIR", context.bpf_pin_dir)):
        actual = env_config.get(key)
        if not actual or Path(actual).resolve() != expected.resolve():
            raise ValueError(f"Runtime environment {key} does not match the selected configuration")
    env = dict(os.environ, CONFIG_FILE=str(env_file), INSTALL_DIR=str(context.install_dir))
    controller = _controller_commands(context)
    if controller is None:
        _runtime_command(["bash", str(launcher), "--sync-once"], env=env)
    else:
        # BPF attachments stay active while the watcher is stopped. Run one
        # writer, then restart the controller so it reads the saved policy.
        # A second live writer can otherwise restore its cached old policy
        # during readback, or remove the just-loaded Minecraft profile.
        stop, start = controller
        try:
            _runtime_command(stop)
            _runtime_command(["bash", str(launcher), "--sync-once"], env=env)
        except BaseException as apply_error:
            try:
                _runtime_command(start)
            except (OSError, RuntimeError, subprocess.SubprocessError) as start_error:
                raise RuntimeError(f"{apply_error}\nController restart also failed: {start_error}") from apply_error
            raise
        else:
            _runtime_command(start)
    return env_config


def _managed_result(context: Context, module: Module, values: dict[str, Any], env: dict[str, str]) -> str:
    if module.kind == "syncookie":
        interfaces = env.get("IFACES", env.get("IFACE", "")).split()
        program_id = module_runtime.verify_syncookie(context.bpf_pin_dir, interfaces, enabled=values["enabled"])
        if not values["enabled"]:
            return f"{module.name} disabled; all module hooks were removed."
        return f"{module.name} applied; program {program_id} and TC ingress are active."
    if not values["enabled"]:
        return f"{module.name} disabled in the applied policy."
    root = context.bpf_pin_dir
    pin, table, key = root / "profile_handlers/tcp/1/prog", root / "tcp_profile_handlers", 1
    if not pin.exists():
        return f"Configuration applied; waiting for an eligible TCP endpoint for subject {values['subject']}."
    program_id = handlers.pinned_program_id(pin)
    if handlers._pinned_u32_lookup(table, struct.pack("=I", key)) != program_id:
        raise RuntimeError(f"{module.name} dispatch entry does not match the loaded program")
    return f"{module.name} applied; program {program_id} is in the dispatch table."


def configure(context: Context, module: Module, updates: dict[str, Any], *, apply: bool = False) -> str:
    if os.geteuid() != 0:
        raise PermissionError("Handler changes require root; re-run axdp with sudo")
    if module.error:
        raise ValueError(module.error)
    context.handlers_dir.mkdir(parents=True, exist_ok=True)
    with handlers._handler_lock(context.handlers_dir):
        data = config_file.load_toml(context.config)
        values = validate(module, {**settings(module, data), **updates})
        obj = None
        if apply and values["enabled"] and module.kind not in {"minecraft", "syncookie"}:
            obj = _checked_object(context, module, values)
        try:
            candidate = _effective_config(module, values, data, obj) if apply else copy.deepcopy(data)
            if not apply:
                candidate.setdefault("modules", {}).setdefault(module.id, {})["draft"] = values
                # Validate built-in configuration fields even when saving a draft.
                if module.kind in {"minecraft", "syncookie"}:
                    _effective_config(module, values, data, Path(module.path))
            config_file.write_toml(context.config, candidate)
        except Exception:
            if obj is not None and (obj.parent / ".catalog-build.json").is_file():
                # A writer may have failed after its atomic rename. Retain the
                # object if the resulting file references it (or is unreadable).
                try:
                    references = _referenced_builds(config_file.load_toml(context.config))
                    if Path(module.path).suffix == ".c" and obj.parent not in references:
                        shutil.rmtree(obj.parent)
                except (OSError, ValueError):
                    pass
            raise
        if not apply:
            return "Configuration saved; select Apply to activate it."
        try:
            kind = values.get("kind", module.kind)
            if kind in {"minecraft", "syncookie"}:
                env = _refresh_managed_runtime(context)
                mode = candidate.get("policy", {}).get("mode", "audit")
                if mode != "enforce":
                    return f"Configuration saved; policy mode {mode} does not activate protection."
                return _managed_result(context, module, values, env)
            target = values["target"]
            if kind == "slot":
                if values["enabled"]:
                    assert obj is not None
                    handlers.load_protocol_handler(context.bpf_pin_dir, target, obj)
                else:
                    handlers.unload_protocol_handler(context.bpf_pin_dir, target)
            elif values["enabled"]:
                assert obj is not None
                shared = handlers.handler_shared_maps(obj, context.bpf_pin_dir)
                handlers.load_handler_object(handlers.port_handler_map_path(context.bpf_pin_dir, kind), target,
                                             obj, handlers.port_handler_dir(context.bpf_pin_dir, kind, target), shared)
            else:
                handlers.cleanup_existing_port_handler(context.bpf_pin_dir, kind, target)
            try:
                _collect_unused_builds(context, config_file.load_toml(context.config))
            except (OSError, ValueError):
                pass
            return f"{'Applied' if values['enabled'] else 'Disabled'} {module.name} at {kind}/{target}."
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"Configuration saved, but activation failed: {exc}") from exc


def install(context: Context, source: Path, *, name: str = "", kind: str = "custom", target: int = 0) -> Module:
    """Install a self-contained local package, without activating any target."""
    if os.geteuid() != 0:
        raise PermissionError("Installing handlers requires root")
    source = source.resolve()
    package = source if source.is_dir() else source.parent
    manifest = package / "handler.json" if source.is_dir() else source.with_suffix(".handler.json")
    metadata: dict[str, Any] = {}
    if manifest.is_file():
        metadata, _ = _manifest(manifest)
    if source.is_dir():
        source = (package / str(metadata.get("entry", ""))).resolve()
        if not source.is_relative_to(package) or source.suffix not in {".c", ".o"}:
            raise ValueError("A package requires handler.json with a local .c/.o entry")
    if not source.is_file() or source.suffix not in {".c", ".o"}:
        raise ValueError("Install a .c source, .o BPF object, or directory containing handler.json")
    identifier = name or str(metadata.get("id", source.stem))
    if not _NAME.fullmatch(identifier) or identifier in {*handlers.BUILTIN_SLOT_INFO, "minecraft", "syncookie"}:
        raise ValueError("Choose a valid, non-reserved handler name")
    parent = context.handlers_dir / "catalog"
    parent.mkdir(parents=True, exist_ok=True)
    with handlers._handler_lock(context.handlers_dir):
        destination = parent / identifier
        if destination.exists():
            raise ValueError(f"Handler {identifier} is already installed; choose a new name for another version")
        stage = Path(tempfile.mkdtemp(prefix=".install-", dir=parent))
        try:
            entry = source.relative_to(package)
            selected = {source}
            if source.suffix == ".c":
                # Preserve local quoted includes, including nested directories.
                pending = [source]
                while pending:
                    current = pending.pop()
                    for include in re.findall(r'^\s*#\s*include\s*"([^"\n]+)"', current.read_text(), re.MULTILINE):
                        header = (current.parent / include).resolve()
                        if not header.is_file():
                            continue  # SDK/system header, resolved by the compiler.
                        if not header.is_relative_to(package):
                            raise ValueError(f"Local include escapes package: {include}; install its containing package directory")
                        if header not in selected:
                            selected.add(header)
                            pending.append(header)
            for item in selected:
                output = stage / item.relative_to(package)
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(item, output)
            metadata.update(version=1, id=identifier, entry=str(entry))
            metadata["kind"] = kind if kind != "custom" else metadata.get("kind", kind)
            metadata["target"] = target if target else metadata.get("target", target)
            (stage / "handler.json").write_text(json.dumps(metadata, indent=2) + "\n")
            module = _local_module(stage / entry, stage / "handler.json")
            if module.error:
                raise ValueError(module.error)
            # Installation validates the package but does not require a target
            # binding; the user can choose that later in the configuration page.
            values = {item.name: item.parse(item.default) for item in fields_for(module)}
            obj = _checked_object(context, module, values, source=source, manifest=manifest)
            if obj.resolve() != (stage / "validated.o").resolve():
                shutil.copyfile(obj, stage / "validated.o")
            if obj.parent.parent.resolve() == (context.handlers_dir / "builds").resolve():
                shutil.rmtree(obj.parent)
            stage.rename(destination)
            return _local_module(destination / entry, destination / "handler.json")
        finally:
            if stage.exists():
                shutil.rmtree(stage)
