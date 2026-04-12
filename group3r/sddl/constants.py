"""SDDL parsing constants - ACE types, rights, flags, well-known SIDs."""

from __future__ import annotations

from enum import Enum


class SecurableObjectType(Enum):
    UNKNOWN = "Unknown"
    FILE = "File"
    DIRECTORY = "Directory"
    PIPE = "Pipe"
    PROCESS = "Process"
    THREAD = "Thread"
    ACCESS_TOKEN = "AccessToken"
    REGISTRY_KEY = "RegistryKey"
    WINDOWS_SERVICE = "WindowsService"


# ACE type bigrams -> display names
ACE_TYPES: dict[str, str] = {
    "A": "ACCESS_ALLOWED",
    "D": "ACCESS_DENIED",
    "OA": "OBJECT_ACCESS_ALLOWED",
    "OD": "OBJECT_ACCESS_DENIED",
    "AU": "AUDIT",
    "AL": "ALARM",
    "OU": "OBJECT_AUDIT",
    "OL": "OBJECT_ALARM",
    "ML": "MANDATORY_LABEL",
    "TL": "PROCESS_TRUST_LABEL",
    "XA": "CALLBACK_ACCESS_ALLOWED",
    "XD": "CALLBACK_ACCESS_DENIED",
    "RA": "RESOURCE_ATTRIBUTE",
    "SP": "SCOPED_POLICY_ID",
    "XU": "CALLBACK_AUDIT",
    "ZA": "CALLBACK_OBJECT_ACCESS_ALLOWED",
}

# ACE flags
ACE_FLAGS: dict[str, str] = {
    "CI": "CONTAINER_INHERIT",
    "OI": "OBJECT_INHERIT",
    "NP": "NO_PROPAGATE",
    "IO": "INHERIT_ONLY",
    "ID": "INHERITED",
    "SA": "AUDIT_SUCCESS",
    "FA": "AUDIT_FAILURE",
}

# Access rights aliases (generic)
ACE_ALIAS_RIGHTS: dict[str, str] = {
    "GA": "GENERIC_ALL",
    "GR": "GENERIC_READ",
    "GW": "GENERIC_WRITE",
    "GX": "GENERIC_EXECUTE",
    "RC": "READ_CONTROL",
    "SD": "STANDARD_DELETE",
    "WD": "WRITE_DAC",
    "WO": "WRITE_OWNER",
    "RP": "READ_PROPERTY",
    "WP": "WRITE_PROPERTY",
    "CC": "CREATE_CHILD",
    "DC": "DELETE_CHILD",
    "LC": "LIST_CHILDREN",
    "SW": "SELF_WRITE",
    "LO": "LIST_OBJECT",
    "DT": "DELETE_TREE",
    "CR": "CONTROL_ACCESS",
    "FA": "FILE_ALL",
    "FR": "FILE_READ",
    "FW": "FILE_WRITE",
    "FX": "FILE_EXECUTE",
    "KA": "KEY_ALL",
    "KR": "KEY_READ",
    "KW": "KEY_WRITE",
    "KX": "KEY_EXECUTE",
    "NR": "NO_READ_UP",
    "NW": "NO_WRITE_UP",
    "NX": "NO_EXECUTE_UP",
}

# NT Service specific rights aliases
NT_SERVICE_ACE_ALIAS_RIGHTS: dict[str, str] = {
    "CC": "SERVICE_QUERY_CONFIG",
    "LC": "SERVICE_QUERY_STATUS",
    "SW": "SERVICE_ENUMERATE_DEPENDENTS",
    "LO": "SERVICE_INTERROGATE",
    "RC": "READ_CONTROL",
    "RP": "SERVICE_START",
    "DT": "SERVICE_PAUSE_CONTINUE",
    "CR": "SERVICE_USER_DEFINED_CONTROL",
    "WD": "WRITE_DAC",
    "WO": "WRITE_OWNER",
    "WP": "SERVICE_STOP",
    "DC": "SERVICE_CHANGE_CONFIG",
    "SD": "DELETE",
}

# Numeric (hex) access rights - generic
ACE_UINT_RIGHTS: dict[int, str] = {
    0x80000000: "GENERIC_READ",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",
    0x02000000: "MAXIMUM_ALLOWED",
    0x01000000: "ACCESS_SYSTEM_SECURITY",
    0x001F0000: "STANDARD_RIGHTS_ALL",
    0x00100000: "SYNCHRONIZE",
    0x00080000: "WRITE_OWNER",
    0x00040000: "WRITE_DAC",
    0x00020000: "READ_CONTROL",
    0x00010000: "DELETE",
}

# Object-specific numeric rights
ACE_UINT_SPECIFIC_RIGHTS: dict[SecurableObjectType, dict[int, str]] = {
    SecurableObjectType.FILE: {
        0x001F01FF: "ALL_ACCESS",
        0x001200A0: "GENERIC_EXECUTE",
        0x00120116: "GENERIC_WRITE",
        0x00120089: "GENERIC_READ",
        0x00000100: "WRITE_ATTRIBUTES",
        0x00000080: "READ_ATTRIBUTES",
        0x00000020: "EXECUTE",
        0x00000010: "WRITE_PROPERTIES",
        0x00000008: "READ_PROPERTIES",
        0x00000004: "APPEND_DATA",
        0x00000002: "WRITE_DATA",
        0x00000001: "READ_DATA",
    },
    SecurableObjectType.DIRECTORY: {
        0x001F01FF: "ALL_ACCESS",
        0x001200A0: "GENERIC_EXECUTE",
        0x00120116: "GENERIC_WRITE",
        0x00120089: "GENERIC_READ",
        0x00000100: "WRITE_ATTRIBUTES",
        0x00000080: "READ_ATTRIBUTES",
        0x00000040: "DELETE_CHILD",
        0x00000020: "TRAVERSE",
        0x00000010: "WRITE_PROPERTIES",
        0x00000008: "READ_PROPERTIES",
        0x00000004: "ADD_SUBDIRECTORY",
        0x00000002: "ADD_FILE",
        0x00000001: "LIST_DIRECTORY",
    },
    SecurableObjectType.REGISTRY_KEY: {
        0x000201FF: "ALL_ACCESS",
        0x000200E0: "WRITE",
        0x00020008: "READ",
        0x00020000: "EXECUTE",
        0x00000300: "WOW64_RES",
        0x00000200: "WOW64_32KEY",
        0x00000100: "WOW64_64KEY",
        0x00000020: "CREATE_LINK",
        0x00000010: "NOTIFY",
        0x00000008: "ENUMERATE_SUB_KEYS",
        0x00000004: "CREATE_SUB_KEY",
        0x00000002: "SET_VALUE",
        0x00000001: "QUERY_VALUE",
    },
    SecurableObjectType.WINDOWS_SERVICE: {
        # No specific uint rights for services - they use alias-based parsing
    },
}

# SD control flags
SD_CONTROLS: dict[str, str] = {
    "P": "PROTECTED",
    "AR": "AUTO_INHERIT_REQ",
    "AI": "AUTO_INHERITED",
    "NO_ACCESS_CONTROL": "NULL_ACL",
}

# Well-known SID aliases: (bigram, sid_regex, display_name)
KNOWN_SID_ALIASES: list[tuple[str | None, str, str]] = [
    (None, r"^S-1-0$", "Null Authority"),
    (None, r"^S-1-0-0$", "Nobody"),
    (None, r"^S-1-1$", "World Authority"),
    ("WD", r"^S-1-1-0$", "Everyone"),
    (None, r"^S-1-2$", "Local Authority"),
    (None, r"^S-1-2-0$", "Local"),
    (None, r"^S-1-2-1$", "Console Logon"),
    (None, r"^S-1-3$", "Creator Authority"),
    ("CO", r"^S-1-3-0$", "Creator Owner"),
    ("CG", r"^S-1-3-1$", "Creator Group"),
    (None, r"^S-1-3-2$", "Creator Owner Server"),
    (None, r"^S-1-3-3$", "Creator Group Server"),
    ("OW", r"^S-1-3-4$", "Owner Rights"),
    (None, r"^S-1-4$", "Non-unique Authority"),
    (None, r"^S-1-5$", "NT Authority"),
    (None, r"^S-1-5-1$", "Dialup"),
    ("NU", r"^S-1-5-2$", "Network"),
    (None, r"^S-1-5-3$", "Batch"),
    ("IU", r"^S-1-5-4$", "Interactive"),
    (None, r"^S-1-5-5-(.+)-(.+)$", "Logon Session"),
    ("SU", r"^S-1-5-6$", "Service"),
    ("AN", r"^S-1-5-7$", "Anonymous"),
    (None, r"^S-1-5-8$", "Proxy"),
    ("ED", r"^S-1-5-9$", "Enterprise Domain Controllers"),
    ("PS", r"^S-1-5-10$", "Principal Self"),
    ("AU", r"^S-1-5-11$", "Authenticated Users"),
    ("RC", r"^S-1-5-12$", "Restricted Code"),
    (None, r"^S-1-5-13$", "Terminal Server Users"),
    (None, r"^S-1-5-14$", "Remote Interactive Logon"),
    (None, r"^S-1-5-15$", "This Organization"),
    (None, r"^S-1-5-17$", "IUSR"),
    ("SY", r"^S-1-5-18$", "Local System"),
    ("LS", r"^S-1-5-19$", "Local Service"),
    ("NS", r"^S-1-5-20$", "Network Service"),
    ("LA", r"^S-1-5-21(.*)-500$", "Administrator"),
    ("LG", r"^S-1-5-21(.*)-501$", "Guest"),
    (None, r"^S-1-5-21(.*)-502$", "KRBTGT"),
    ("DA", r"^S-1-5-21(.*)-512$", "Domain Admins"),
    ("DU", r"^S-1-5-21(.*)-513$", "Domain Users"),
    ("DG", r"^S-1-5-21(.*)-514$", "Domain Guests"),
    ("DC", r"^S-1-5-21(.*)-515$", "Domain Computers"),
    ("DD", r"^S-1-5-21(.*)-516$", "Domain Controllers"),
    ("CA", r"^S-1-5-21(.*)-517$", "Cert Publishers"),
    ("SA", r"^S-1-5-21(.*)-518$", "Schema Admins"),
    ("EA", r"^S-1-5-21(.*)-519$", "Enterprise Admins"),
    ("PA", r"^S-1-5-21(.*)-520$", "Group Policy Creator Owners"),
    ("RO", r"^S-1-5-21(.*)-498$", "Enterprise Read-only Domain Controllers"),
    (None, r"^S-1-5-21(.*)-521$", "Read-only Domain Controllers"),
    ("CN", r"^S-1-5-21(.*)-522$", "Cloneable Domain Controllers"),
    ("AP", r"^S-1-5-21(.*)-525$", "Protected Users"),
    ("KA", r"^S-1-5-21(.*)-526$", "Key Admins"),
    ("EK", r"^S-1-5-21(.*)-527$", "Enterprise Key Admins"),
    ("RS", r"^S-1-5-21(.*)-553$", "RAS and IAS Servers"),
    (None, r"^S-1-5-21(.*)-571$", "Allowed RODC Password Replication Group"),
    (None, r"^S-1-5-21(.*)-572$", "Denied RODC Password Replication Group"),
    ("BA", r"^S-1-5-32-544$", "Administrators"),
    ("BU", r"^S-1-5-32-545$", "Users"),
    ("BG", r"^S-1-5-32-546$", "Guests"),
    ("PU", r"^S-1-5-32-547$", "Power Users"),
    ("AO", r"^S-1-5-32-548$", "Account Operators"),
    ("SO", r"^S-1-5-32-549$", "Server Operators"),
    ("PO", r"^S-1-5-32-550$", "Print Operators"),
    ("BO", r"^S-1-5-32-551$", "Backup Operators"),
    ("RE", r"^S-1-5-32-552$", "Replicators"),
    ("WR", r"^S-1-5-33$", "Write Restricted Code"),
    (None, r"^S-1-5-64-10$", "NTLM Authentication"),
    (None, r"^S-1-5-64-14$", "SChannel Authentication"),
    (None, r"^S-1-5-64-21$", "Digest Authentication"),
    (None, r"^S-1-5-80$", "NT Service"),
    (None, r"^S-1-5-80-0$", "All Services"),
    (None, r"^S-1-5-83-0$", "NT VIRTUAL MACHINE\\Virtual Machines"),
    (None, r"^S-1-16-0$", "Untrusted Mandatory Level"),
    (None, r"^S-1-16-4096$", "Low Mandatory Level"),
    (None, r"^S-1-16-8192$", "Medium Mandatory Level"),
    (None, r"^S-1-16-8448$", "Medium Plus Mandatory Level"),
    (None, r"^S-1-16-12288$", "High Mandatory Level"),
    (None, r"^S-1-16-16384$", "System Mandatory Level"),
    (None, r"^S-1-16-20480$", "Protected Process Mandatory Level"),
    (None, r"^S-1-16-28672$", "Secure Process Mandatory Level"),
    ("RU", r"^S-1-5-32-554$", "BUILTIN\\Pre-Windows 2000 Compatible Access"),
    ("RD", r"^S-1-5-32-555$", "BUILTIN\\Remote Desktop Users"),
    ("NO", r"^S-1-5-32-556$", "BUILTIN\\Network Configuration Operators"),
    (None, r"^S-1-5-32-557$", "BUILTIN\\Incoming Forest Trust Builders"),
    ("MU", r"^S-1-5-32-558$", "BUILTIN\\Performance Monitor Users"),
    ("LU", r"^S-1-5-32-559$", "BUILTIN\\Performance Log Users"),
    (None, r"^S-1-5-32-560$", "BUILTIN\\Windows Authorization Access Group"),
    (None, r"^S-1-5-32-561$", "BUILTIN\\Terminal Server License Servers"),
    (None, r"^S-1-5-32-562$", "BUILTIN\\Distributed COM Users"),
    ("IS", r"^S-1-5-32-568$", "IIS_IUSRS"),
    ("CY", r"^S-1-5-32-569$", "BUILTIN\\Cryptographic Operators"),
    ("ER", r"^S-1-5-32-573$", "BUILTIN\\Event Log Readers"),
    ("CD", r"^S-1-5-32-574$", "BUILTIN\\Certificate Service DCOM Access"),
    ("RA", r"^S-1-5-32-575$", "BUILTIN\\RDS Remote Access Servers"),
    ("ES", r"^S-1-5-32-576$", "BUILTIN\\RDS Endpoint Servers"),
    ("MS", r"^S-1-5-32-577$", "BUILTIN\\RDS Management Servers"),
    ("HA", r"^S-1-5-32-578$", "BUILTIN\\Hyper-V Administrators"),
    ("AA", r"^S-1-5-32-579$", "BUILTIN\\Access Control Assistance Operators"),
    ("RM", r"^S-1-5-32-580$", "BUILTIN\\Remote Management Users"),
    ("UD", r"^S-1-5-84-0-0-0-0-0$", "User-Mode Driver Process"),
    ("AC", r"^S-1-15-2-1$", "All App Package"),
    ("AS", r"^S-1-18-1$", "Authentication Authority Asserted Identity"),
    ("SS", r"^S-1-18-2$", "Service Asserted Identity"),
]

# Build bigram -> alias lookup for fast access
BIGRAM_TO_ALIAS: dict[str, str] = {
    bigram: alias for bigram, _, alias in KNOWN_SID_ALIASES if bigram
}
