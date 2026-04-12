"""Trustee and TrusteeOption data models."""

from __future__ import annotations

from dataclasses import dataclass

# Well-known SID to display name mapping (subset of most common)
WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority\\Local Service",
    "S-1-5-20": "NT Authority\\Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

# Domain-relative RID suffixes
DOMAIN_RELATIVE_SIDS: dict[str, str] = {
    "-500": "Administrator",
    "-501": "Guest",
    "-502": "KRBTGT",
    "-512": "Domain Admins",
    "-513": "Domain Users",
    "-514": "Domain Guests",
    "-515": "Domain Computers",
    "-516": "Domain Controllers",
    "-517": "Cert Publishers",
    "-518": "Schema Admins",
    "-519": "Enterprise Admins",
    "-520": "Group Policy Creator Owners",
    "-521": "Read-only Domain Controllers",
    "-522": "Cloneable Domain Controllers",
    "-525": "Protected Users",
    "-526": "Key Admins",
    "-527": "Enterprise Key Admins",
    "-553": "RAS and IAS Servers",
    "-571": "Allowed RODC Password Replication Group",
    "-572": "Denied RODC Password Replication Group",
}


@dataclass
class Trustee:
    """Represents a security principal (user, group, or well-known identity)."""
    sid: str = ""
    display_name: str = ""
    distinguished_name: str = ""

    def resolve_display_name(self) -> str:
        """Attempt to resolve SID to a display name using well-known SIDs."""
        if self.display_name:
            return self.display_name

        if self.sid in WELL_KNOWN_SIDS:
            self.display_name = WELL_KNOWN_SIDS[self.sid]
            return self.display_name

        # Check domain-relative SIDs
        for suffix, name in DOMAIN_RELATIVE_SIDS.items():
            if self.sid.endswith(suffix):
                self.display_name = name
                return self.display_name

        return self.sid


@dataclass
class TrusteeOption:
    """A trustee being targeted for assessment."""
    sid: str = ""
    display_name: str = ""
    low_priv: bool = True
    target: bool = False
