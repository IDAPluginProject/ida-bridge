"""Allow running as `python -m ida_bridge`."""

from ida_bridge.cli import main_cli

raise SystemExit(main_cli())
