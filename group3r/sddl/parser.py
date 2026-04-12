"""SDDL (Security Descriptor Definition Language) parser.

Parses SDDL strings into structured Sddl/Acl/Ace/Sid objects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .constants import (
    ACE_ALIAS_RIGHTS, ACE_FLAGS, ACE_TYPES, ACE_UINT_RIGHTS,
    ACE_UINT_SPECIFIC_RIGHTS, BIGRAM_TO_ALIAS, KNOWN_SID_ALIASES,
    NT_SERVICE_ACE_ALIAS_RIGHTS, SD_CONTROLS, SecurableObjectType,
)


@dataclass
class Sid:
    """A Security Identifier, resolved to a human-readable alias."""
    raw: str = ""
    alias: str = ""

    def __init__(self, sid_string: str):
        self.raw = sid_string
        self.alias = self._resolve(sid_string)

    def _resolve(self, sid: str) -> str:
        # First try bigram lookup
        if len(sid) <= 2 and sid in BIGRAM_TO_ALIAS:
            return BIGRAM_TO_ALIAS[sid]

        # Try regex match against well-known SIDs
        for bigram, pattern, alias in KNOWN_SID_ALIASES:
            if bigram and bigram == sid:
                return alias
            if re.match(pattern, sid):
                return alias

        # Unknown SID - return raw
        return f"Unknown({sid})"

    def __str__(self) -> str:
        return self.alias


@dataclass
class Ace:
    """An Access Control Entry."""
    raw: str = ""
    ace_type: str = ""
    ace_flags: list[str] = field(default_factory=list)
    rights: list[str] = field(default_factory=list)
    object_guid: str = ""
    inherit_object_guid: str = ""
    ace_sid: Optional[Sid] = None

    def __init__(self, ace_string: str,
                 object_type: SecurableObjectType = SecurableObjectType.UNKNOWN):
        self.raw = ace_string
        self.ace_flags = []
        self.rights = []

        parts = ace_string.split(";")

        # ace_type
        if len(parts) > 0 and parts[0]:
            self.ace_type = _match_one_by_prefix(parts[0], ACE_TYPES) or f"Unknown({parts[0]})"

        # ace_flags
        if len(parts) > 1 and parts[1]:
            self.ace_flags = _match_many_by_prefix(parts[1], ACE_FLAGS)

        # rights
        if len(parts) > 2 and parts[2]:
            self.rights = self._parse_rights(parts[2], object_type)

        # object_guid
        if len(parts) > 3 and parts[3]:
            self.object_guid = parts[3]

        # inherit_object_guid
        if len(parts) > 4 and parts[4]:
            self.inherit_object_guid = parts[4]

        # account_sid
        if len(parts) > 5 and parts[5]:
            self.ace_sid = Sid(parts[5])

    def _parse_rights(self, rights_str: str,
                      object_type: SecurableObjectType) -> list[str]:
        """Parse rights from either hex access mask or alias bigrams."""
        access_mask = _try_parse_hex(rights_str)

        if access_mask is not None:
            rights = []
            # Try object-specific rights first
            specific = ACE_UINT_SPECIFIC_RIGHTS.get(object_type, {})
            if specific:
                access_mask, specific_rights = _match_many_by_uint(access_mask, specific)
                rights.extend(specific_rights)

            # Then generic rights
            access_mask, generic_rights = _match_many_by_uint(access_mask, ACE_UINT_RIGHTS)
            rights.extend(generic_rights)

            if access_mask > 0:
                rights.append(f"Unknown(0x{access_mask:X})")
            return rights
        else:
            # Alias-based parsing
            if object_type == SecurableObjectType.WINDOWS_SERVICE:
                return _match_many_by_prefix(rights_str, NT_SERVICE_ACE_ALIAS_RIGHTS)
            else:
                return _match_many_by_prefix(rights_str, ACE_ALIAS_RIGHTS)

    def __str__(self) -> str:
        parts = []
        if self.ace_sid:
            parts.append(f"SID: {self.ace_sid}")
        parts.append(f"Type: {self.ace_type}")
        if self.ace_flags:
            parts.append(f"Flags: {', '.join(self.ace_flags)}")
        if self.rights:
            parts.append(f"Rights: {', '.join(self.rights)}")
        return "; ".join(parts)


@dataclass
class Acl:
    """An Access Control List (DACL or SACL)."""
    raw: str = ""
    flags: list[str] = field(default_factory=list)
    aces: list[Ace] = field(default_factory=list)

    def __init__(self, acl_string: str,
                 object_type: SecurableObjectType = SecurableObjectType.UNKNOWN):
        self.raw = acl_string
        self.flags = []
        self.aces = []

        # Find first '(' to separate flags from ACEs
        begin = acl_string.find("(")

        # Parse flags
        flags_str = acl_string if begin == -1 else acl_string[:begin]
        if flags_str:
            self.flags = _match_many_by_prefix(flags_str, SD_CONTROLS)

        # Parse ACEs
        if begin != -1:
            balance = 0
            ace_start = begin
            for i, ch in enumerate(acl_string):
                if ch == "(":
                    if balance == 0:
                        ace_start = i
                    balance += 1
                elif ch == ")":
                    balance -= 1
                    if balance == 0:
                        ace_content = acl_string[ace_start + 1:i]
                        self.aces.append(Ace(ace_content, object_type))

    def __str__(self) -> str:
        parts = []
        if self.flags:
            parts.append(f"Flags: {', '.join(self.flags)}")
        for i, ace in enumerate(self.aces):
            parts.append(f"Ace[{i:02d}]: {ace}")
        return "\n".join(parts)


@dataclass
class SddlDescriptor:
    """A parsed SDDL security descriptor."""
    raw: str = ""
    owner: Optional[Sid] = None
    group: Optional[Sid] = None
    dacl: Optional[Acl] = None
    sacl: Optional[Acl] = None

    def __init__(self, sddl_string: str,
                 object_type: SecurableObjectType = SecurableObjectType.UNKNOWN):
        self.raw = sddl_string

        # Parse O:, G:, D:, S: components
        components: dict[str, str] = {}
        idx = 0
        positions: list[tuple[int, str]] = []

        # Find all component markers (X:)
        i = 0
        while i < len(sddl_string):
            if i + 1 < len(sddl_string) and sddl_string[i + 1] == ":":
                marker = sddl_string[i]
                if marker in ("O", "G", "D", "S"):
                    positions.append((i, marker))
            i += 1

        # Extract component values
        for idx, (pos, marker) in enumerate(positions):
            start = pos + 2  # skip "X:"
            if idx + 1 < len(positions):
                end = positions[idx + 1][0]
            else:
                end = len(sddl_string)
            components[marker] = sddl_string[start:end]

        if "O" in components:
            self.owner = Sid(components["O"])
        if "G" in components:
            self.group = Sid(components["G"])
        if "D" in components:
            self.dacl = Acl(components["D"], object_type)
        if "S" in components:
            self.sacl = Acl(components["S"], object_type)

    def __str__(self) -> str:
        parts = []
        if self.owner:
            parts.append(f"Owner: {self.owner}")
        if self.group:
            parts.append(f"Group: {self.group}")
        if self.dacl:
            parts.append(f"DACL:\n  {self.dacl}")
        if self.sacl:
            parts.append(f"SACL:\n  {self.sacl}")
        return "\n".join(parts)


# --- Utility functions ---

def _match_one_by_prefix(s: str, mapping: dict[str, str]) -> Optional[str]:
    """Match the string against a dict of prefixes, longest match first."""
    # Sort by key length descending to match longest first
    for key in sorted(mapping, key=len, reverse=True):
        if s.startswith(key):
            return mapping[key]
    return None


def _match_many_by_prefix(s: str, mapping: dict[str, str]) -> list[str]:
    """Match multiple consecutive prefixes from the string."""
    results = []
    remaining = s
    sorted_keys = sorted(mapping, key=len, reverse=True)

    while remaining:
        matched = False
        for key in sorted_keys:
            if remaining.startswith(key):
                results.append(mapping[key])
                remaining = remaining[len(key):]
                matched = True
                break
        if not matched:
            results.append(f"Unknown({remaining})")
            break
    return results


def _match_many_by_uint(mask: int, mapping: dict[int, str]) -> tuple[int, list[str]]:
    """Match access mask bits against a dict of bitmask->name. Returns (remaining_mask, matched_names)."""
    results = []
    remaining = mask
    # Sort by value descending to match combined masks first
    for bitmask in sorted(mapping, reverse=True):
        if bitmask != 0 and (remaining & bitmask) == bitmask:
            results.append(mapping[bitmask])
            remaining &= ~bitmask
    return remaining, results


def _try_parse_hex(s: str) -> Optional[int]:
    """Try to parse a hex string like '0x1F01FF' or '&H1F01FF'. Returns None if not hex."""
    if s.startswith(("0x", "0X", "&H", "&h")):
        try:
            return int(s[2:], 16)
        except ValueError:
            return None
    return None
