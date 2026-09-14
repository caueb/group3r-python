"""Convert a Windows self-relative security descriptor to SDDL."""

from __future__ import annotations

_ACE_TYPE = {
    0x00: "A",
    0x01: "D",
    0x05: "OA",
    0x06: "OD",
}

_ACE_FLAGS = (
    (0x01, "OI"),
    (0x02, "CI"),
    (0x04, "NP"),
    (0x08, "IO"),
    (0x10, "ID"),
    (0x40, "SA"),
    (0x80, "FA"),
)


def security_descriptor_to_sddl(data: bytes) -> str:
    """Build an SDDL string from raw nTSecurityDescriptor / SMB security bytes."""
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(data)
    parts: list[str] = []

    owner = _sid_str(sd["OwnerSid"])
    if owner:
        parts.append(f"O:{_sid_token(owner)}")
    group = _sid_str(sd["GroupSid"])
    if group:
        parts.append(f"G:{_sid_token(group)}")

    dacl = sd["Dacl"]
    if dacl not in (b"", None) and hasattr(dacl, "aces"):
        aces = "".join(_ace_sddl(ace) for ace in dacl.aces)
        parts.append(f"D:{aces}")
    return "".join(parts)


def _sid_str(sid) -> str:
    if sid in (b"", None):
        return ""
    try:
        return sid.formatCanonical()
    except Exception:
        return ""


def _sid_token(sid: str) -> str:
    """Keep canonical SIDs; SDDL well-known aliases are optional."""
    return sid


def _ace_sddl(ace) -> str:
    ace_type = _ACE_TYPE.get(int(ace["AceType"]), "A")
    flags = "".join(tok for bit, tok in _ACE_FLAGS if int(ace["AceFlags"]) & bit)
    body = ace["Ace"]
    try:
        mask = int(body["Mask"]["Mask"])
    except Exception:
        try:
            mask = int(body["Mask"])
        except Exception:
            mask = 0
    try:
        sid = body["Sid"].formatCanonical()
    except Exception:
        sid = ""
    return f"({ace_type};{flags};0x{mask:X};;;{sid})"
