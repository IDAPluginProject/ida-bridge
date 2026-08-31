"""IDA Bridge supervisor — process lifecycle management for IDA instances."""

from ida_bridge.proc import terminate_pid
from ida_bridge.supervisor.cli import main
from ida_bridge.supervisor.commands import IdalibStartResult, StartError, default_idalib_python, start_idalib

__all__ = ["IdalibStartResult", "StartError", "default_idalib_python", "main", "start_idalib", "terminate_pid"]
