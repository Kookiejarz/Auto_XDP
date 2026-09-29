"""Shared management functions for axdp clients.

config_file owns TOML file I/O; handlers owns compilation and program swaps;
ports and stats collect backend data; formatting renders shared display units.
These modules must not import the CLI or TUI entry points.
"""
