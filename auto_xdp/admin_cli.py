"""Compatibility entry point; management commands live in auto_xdp.admin.cli."""
from auto_xdp.admin.cli import build_parser as build_parser, main as main

if __name__ == "__main__":
    raise SystemExit(main())
