"""Schema-driven handler configuration page; mutations share the CLI service."""
from __future__ import annotations

import curses
import json
from dataclasses import replace
from typing import Any, Callable

from auto_xdp.admin import config_file, handler_catalog
from auto_xdp.tui.handlers import HandlerRow
from auto_xdp.tui.layout import wrap_cells
from auto_xdp.tui.maps import _field
from auto_xdp.tui.widgets import _add, _box, _color, _CP_MUTED, _CP_SELECTED, _CP_YELLOW


def format_value(value: Any) -> str:
    if isinstance(value, (dict, bool)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def form_values(row: HandlerRow, data: dict[str, Any]) -> dict[str, Any]:
    if row.module is None:
        return {}
    values = handler_catalog.settings(row.module, data)
    kind = row.kind.removeprefix("TC_")
    if kind in {"TCP", "UDP", "SLOT"}:
        values["target"] = row.key
        if row.module.kind == "custom":
            values["kind"] = "slot" if kind == "SLOT" else kind.lower()
    return values


def draw_form(screen: Any, row: HandlerRow, fields: tuple[handler_catalog.Field, ...],
              values: dict[str, Any], cursor: int, message: str = "", *, operation_error: str = "") -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    module = row.module
    _box(screen, f"Handler configuration / {module.name if module else row.name}", focused=True)
    _add(screen, 1, 2, module.description if module else "Runtime program; no matching local module metadata.", _color(_CP_MUTED))
    _add(screen, 2, 2, f"Source: {module.path if module else row.source or row.pin or 'unavailable'}", _color(_CP_MUTED))
    _add(screen, 3, 2, f"{module.hooks if module else row.kind} · observed {row.state} · program {row.program_id or '-'}", _color(_CP_MUTED))
    if fields:
        _add(screen, 4, 2, "Saved settings below may differ from the running program until Apply succeeds.", _color(_CP_MUTED))
    visible = max(1, (height - 9) // 2)
    start = max(0, min(cursor - visible + 1, max(0, len(fields) - visible)))
    label_width = max(18, (width - 6) * 2 // 5)
    for index, item in enumerate(fields[start:start + visible], start):
        y = 5 + (index - start) * 2
        _add(screen, y, 2, _field(item.label, label_width) + " " + _field(format_value(values.get(item.name, "")), max(1, width - label_width - 5)),
             _color(_CP_SELECTED if index == cursor else _CP_MUTED))
        hint = "Fixed by this module" if item.readonly else item.help or ("Options: " + ", ".join(map(str, item.choices)) if item.choices else
                            "true / false" if item.type == "bool" else
                            f"{item.type}" + (f" · minimum {item.minimum}" if item.minimum is not None else "") +
                            (f" · maximum {item.maximum}" if item.maximum is not None else ""))
        _add(screen, y + 1, 4, hint, _color(_CP_MUTED))
    if not fields:
        _add(screen, 6, 2, row.detail or "Install the original .c/.o or a module manifest to enable configuration.", _color(_CP_YELLOW))
    warning = (module.error or module.build_error) if module else ""
    notice = "⚠ Operation failed · e shows full error" if operation_error else message
    _add(screen, height - 3, 2, notice or ("⚠ Last check failed · e shows full errors" if warning else "") or "Saved settings are activated only when you choose Apply.", _color(_CP_YELLOW))
    footer = " ↑↓ select · Enter edit · ←→ change · s save · a apply · Esc back " if fields else " Esc back "
    if warning or operation_error:
        footer = " ↑↓ select · Enter edit · s save · a apply · e errors · Esc back " if fields else " e errors · Esc back "
    _add(screen, height - 1, 2, footer, _color(_CP_MUTED))
    screen.refresh()


def draw_errors(screen: Any, row: HandlerRow, scroll: int, *, operation_error: str = "") -> int:
    """Scrollable diagnostics preserve compiler output that cannot fit a footer."""
    screen.erase()
    height, width = screen.getmaxyx()
    module = row.module
    error = operation_error or ((module.error or module.build_error) if module else row.detail)
    _box(screen, f"⚠ Handler diagnostics / {module.name if module else row.name}", focused=True)
    _add(screen, 1, 2, "Last failed operation; saved configuration may remain. Fix the cause before retrying Apply."
         if operation_error else "Last failed build/check; retry Apply after fixing the source or settings.", _color(_CP_YELLOW))
    lines = wrap_cells(error, max(1, width - 5))
    visible = max(1, height - 5)
    scroll = max(0, min(scroll, max(0, len(lines) - visible)))
    for offset, line in enumerate(lines[scroll:scroll + visible]):
        _add(screen, 3 + offset, 2, line, _color(_CP_MUTED))
    _add(screen, height - 1, 2, f" {scroll + bool(lines)}-{min(scroll + visible, len(lines))}/{len(lines)} · ↑↓ / PgUp PgDn scroll · e / Esc back ", _color(_CP_MUTED))
    screen.refresh()
    return scroll


def edit_handler(screen: Any, row: HandlerRow, context: handler_catalog.Context,
                 prompt: Callable[[Any, str], str]) -> str:
    data = config_file.load_toml(context.config)
    module = row.module
    fields = handler_catalog.fields_for(module) if module else ()
    # Existing subjects are a finite selection, without creating exposure grants.
    fields = tuple(replace(item, choices=tuple(sorted(data.get("subjects", {}))))
                   if item.name == "subject" else item for item in fields)
    values = form_values(row, data)
    cursor = 0
    message = ""
    result = ""
    diagnostics = False
    operation_error = ""
    error_scroll = 0
    previous_delay = screen.getdelay() if hasattr(screen, "getdelay") else 0
    if hasattr(screen, "clearok"):
        screen.clearok(True)
    screen.timeout(150)
    try:
        while True:
            if screen.getmaxyx()[0] < 20 or screen.getmaxyx()[1] < 80:
                screen.erase()
                _add(screen, 0, 0, "Handler configuration · resize to at least 80x20")
                screen.refresh()
                ch = screen.getch()
                if ch in (27, ord("q"), ord("h")):
                    return result
                continue
            if diagnostics:
                error_scroll = draw_errors(screen, row, error_scroll, operation_error=operation_error)
            else:
                draw_form(screen, row, fields, values, cursor, message, operation_error=operation_error)
            ch = screen.getch()
            if diagnostics:
                if ch in (27, ord("q"), ord("h"), ord("e")):
                    diagnostics = False
                elif ch in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_PPAGE, curses.KEY_NPAGE):
                    step = max(1, screen.getmaxyx()[0] - 5) if ch in (curses.KEY_PPAGE, curses.KEY_NPAGE) else 1
                    error_scroll += -step if ch in (curses.KEY_UP, curses.KEY_PPAGE) else step
                continue
            if ch in (27, ord("q"), ord("h")):
                return result
            if ch == ord("e") and (operation_error or module and (module.error or module.build_error)):
                diagnostics = True
                continue
            if not fields:
                continue
            if ch in (curses.KEY_UP, curses.KEY_DOWN):
                cursor = max(0, min(len(fields) - 1, cursor + (-1 if ch == curses.KEY_UP else 1)))
            elif ch in (curses.KEY_PPAGE, curses.KEY_NPAGE):
                cursor = max(0, min(len(fields) - 1, cursor + (-5 if ch == curses.KEY_PPAGE else 5)))
            elif ch in (10, 13, curses.KEY_ENTER, ord(" "), curses.KEY_LEFT, curses.KEY_RIGHT):
                item = fields[cursor]
                if item.readonly:
                    message = "This value is fixed by the module."
                    continue
                current = values[item.name]
                try:
                    choices = (False, True) if item.type == "bool" else item.choices
                    if choices:
                        index = choices.index(current) if current in choices else -1
                        values[item.name] = choices[(index + (-1 if ch == curses.KEY_LEFT else 1)) % len(choices)]
                    else:
                        text = prompt(screen, f"{item.name} (blank keeps current): ")
                        if text:
                            values[item.name] = item.parse(text)
                        screen.timeout(150)
                    message = "Unsaved changes. s saves; a saves and applies."
                except (ValueError, TypeError) as exc:
                    message = str(exc)
            elif ch in (ord("s"), ord("a")) and module is not None:
                try:
                    draw_form(screen, row, fields, values, cursor, "Applying…" if ch == ord("a") else "Saving…")
                    result = handler_catalog.configure(context, module, values, apply=ch == ord("a"))
                    message = result
                    # Saving a draft does not resolve a failed activation.
                    if ch == ord("a"):
                        operation_error = ""
                except (OSError, RuntimeError, ValueError) as exc:
                    message = str(exc)
                    result = message
                    operation_error = message
                    error_scroll = 0
                # Reload only diagnostics, retaining the user's unsaved form.
                fresh = next((item for item in handler_catalog.discover(context) if item.path == module.path), None)
                if fresh is not None:
                    module = fresh
                    row = replace(row, module=fresh)
                # libbpf can write directly to the terminal while checking or
                # loading an object. Repaint from a known cursor position.
                if hasattr(screen, "clearok"):
                    screen.clearok(True)
    finally:
        if hasattr(screen, "clearok"):
            screen.clearok(True)
        screen.timeout(previous_delay)
