"""Shared parser helpers: encoding detection and INF field splitting."""

from __future__ import annotations


def decode_bytes(data: bytes) -> str:
    """Decode GPO file bytes, preferring UTF-16 when that is what SYSVOL used.

    BOM-less UTF-16LE is common on SYSVOL. Naive utf-8 first can "succeed"
    on those files and produce garbage that no heading regex will match.
    """
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16-le")
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16-be")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig")

    # Heuristic: UTF-16LE without BOM (NUL on odd indexes)
    if len(data) >= 4 and data[1] == 0 and data[3] == 0:
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            pass

    for enc in ("utf-8-sig", "utf-16-le", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def split_inf_fields(line: str) -> list[str]:
    """Split an INF line on commas, respecting double-quoted fields.

    SecEdit ACL lines look like: \"path\",inheritance,\"SDDL,with,commas\"
    A naive str.split(',') truncates the SDDL.
    """
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '"':
            in_quotes = not in_quotes
            i += 1
            continue
        if ch == "," and not in_quotes:
            parts.append("".join(current).strip())
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    parts.append("".join(current).strip())
    return parts
