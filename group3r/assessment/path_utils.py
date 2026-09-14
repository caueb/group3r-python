"""Path helpers for GPO setting analysis (UNC vs local vs relative)."""

from __future__ import annotations

import os


def is_unc(path: str) -> bool:
    """True if path is a Windows UNC path."""
    if not path:
        return False
    return path.startswith("\\\\") or path.startswith("//")


def is_drive_letter_path(path: str) -> bool:
    """True if path starts with a Windows drive letter (C:\\...)."""
    if not path or len(path) < 2:
        return False
    return path[0].isalpha() and path[1] == ":"


def is_rooted(path: str) -> bool:
    """True if the path is UNC, drive-letter, or otherwise absolute."""
    if not path:
        return False
    return is_unc(path) or is_drive_letter_path(path) or path.startswith("/")


def dirname(path: str) -> str:
    """Directory name that works for both UNC backslash and POSIX paths."""
    if not path:
        return ""
    norm = path.replace("\\", "/")
    if "/" not in norm:
        return ""
    parent = norm.rsplit("/", 1)[0]
    if "\\" in path:
        return parent.replace("/", "\\")
    return parent


def join_path(*parts: str) -> str:
    """Join path parts, preserving UNC backslash style if any part uses it."""
    nonempty = [p for p in parts if p]
    if not nonempty:
        return ""
    use_backslash = any("\\" in p for p in parts)
    sep = "\\" if use_backslash else "/"
    result = nonempty[0]
    for p in nonempty[1:]:
        result = result.rstrip("/\\") + sep + p.strip("/\\")
    return result


def resolve_script_path(cmd_line: str, source: str, script_type: str) -> str:
    """Resolve a GPO script CmdLine the way Group3r does.

    Relative paths are under {GPO source dir}/{ScriptType}/{CmdLine}.
    """
    if not cmd_line:
        return ""
    if is_rooted(cmd_line):
        return cmd_line
    base = dirname(source)
    if script_type:
        return join_path(base, script_type, cmd_line)
    return join_path(base, cmd_line)


def path_exists(path: str) -> bool:
    """True if path exists on the local filesystem (offline SYSVOL)."""
    if not path or is_unc(path):
        return False
    return os.path.isfile(path) or os.path.isdir(path)
