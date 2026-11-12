"""agent-config-scan: offline scanner for agent tool/config files.

Finds prompt-injection and unsafe-wiring patterns in agent tool and
configuration files: shell tools that execute raw input, permission-skip
flags, leaked-looking secrets, unrestricted network fetch tools, wildcard
file-write scope, eval/exec-named tools, and undocumented tools.
Standard library only.
"""

__version__ = "0.1.0"
__all__ = ["main", "scan_directory", "scan_file", "Finding"]
