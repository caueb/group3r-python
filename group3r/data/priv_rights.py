"""Privilege rights assessment options.

Ported from Group3r/Options/AssessmentOptions/PrivRights.cs

Reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
"""

PRIV_RIGHTS = [
    {
        "privilege": "SeTakeOwnershipPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": "Can be used to grant yourself ownership on any file, registry key, etc.",
        "ms_description": "Take ownership of files or other objects",
    },
    {
        "privilege": "SeSyncAgentPrivilege",
        "grants_remote_access": True,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": "",
        "ms_description": "Synchronize directory service data",
    },
    {
        "privilege": "SeShutdownPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Shut down the system",
    },
    {
        "privilege": "SeRelabelPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": "",
        "ms_description": "",
    },
    {
        "privilege": "SeRestorePrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": "Can be used to overwrite/modify any file.",
        "ms_description": "Restore files and directories",
    },
    {
        "privilege": "SeTrustedCredManAccessPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": (
            "Microsoft provides the following additional detail: If an account is "
            "given this user right, the user of the account may create an application "
            "that calls into Credential Manager and is returned the credentials for "
            "another user."
        ),
        "ms_description": "Access Credential Manager as a trusted caller",
    },
    {
        "privilege": "SeNetworkLogonRight",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Access this computer from the network",
    },
    {
        "privilege": "SeTcbPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": "Lets you impersonate any other user.",
        "ms_description": "Act as part of the operating system",
    },
    {
        "privilege": "SeAssignPrimaryTokenPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": (
            "Lets you impersonate accounts (after some backflips) look at the various "
            "'potato' attacks, i.e. Rotten, Juicy, etc."
        ),
        "ms_description": "Replace a process level token",
    },
    {
        "privilege": "SeUndockPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Remove computer from docking station",
    },
    {
        "privilege": "SeSystemProfilePrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Profile system performance",
    },
    {
        "privilege": "SeProfileSingleProcessPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Profile single process",
    },
    {
        "privilege": "SeMachineAccountPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": (
            "Add workstations to domain - l0ss note: This can be leveraged as one "
            "part of that Resource Based Constrained Delegation kerberos backflip attack."
        ),
    },
    {
        "privilege": "SeRemoteInteractiveLogonRight",
        "grants_remote_access": True,
        "remote_access_desc": "It's RDP. Good old RDP.",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Allow log on through Remote Desktop Services",
    },
    {
        "privilege": "SeIncreaseQuotaPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Adjust memory quotas for a process",
    },
    {
        "privilege": "SeInteractiveLogonRight",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Allow log on locally",
    },
    {
        "privilege": "SeBackupPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": "Lets you override file and directory permissions to read any file on the FS.",
        "ms_description": "Back up files and directories",
    },
    {
        "privilege": "SeChangeNotifyPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Bypass traverse checking",
    },
    {
        "privilege": "SeSystemtimePrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Change the system time",
    },
    {
        "privilege": "SeCreatePagefilePrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Create a pagefile",
    },
    {
        "privilege": "SeCreateTokenPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": "Lets you grant yourself any access you want. Locally.",
        "ms_description": "Create a token object",
    },
    {
        "privilege": "SeCreateGlobalPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Create global objects",
    },
    {
        "privilege": "SeCreatePermanentPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Create permanent shared objects",
    },
    {
        "privilege": "SeCreateSymbolicLinkPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": "",
        "ms_description": "Create symbolic links",
    },
    {
        "privilege": "SeDebugPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": (
            "Lets you do the mimikatz thing, you know, dump lsass.exe, cool stuff like that."
        ),
        "ms_description": "Debug programs",
    },
    {
        "privilege": "SeDenyNetworkLogonRight",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Deny access to this computer from the network",
    },
    {
        "privilege": "SeDenyBatchLogonRight",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Deny log on as a batch job",
    },
    {
        "privilege": "SeDenyServiceLogonRight",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Deny log on as a service",
    },
    {
        "privilege": "SeDenyInteractiveLogonRight",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Deny log on locally",
    },
    {
        "privilege": "SeDenyRemoteInteractiveLogonRight",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Deny log on through Remote Desktop Services",
    },
    {
        "privilege": "SeRemoteShutdownPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Force shutdown from a remote system",
    },
    {
        "privilege": "SeAuditPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Generate security audits",
    },
    {
        "privilege": "SeImpersonatePrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": (
            "Lets you impersonate accounts (after some backflips) look at the various "
            "'potato' attacks, i.e. Rotten, Juicy, etc."
        ),
        "ms_description": "Impersonate a client after authentication",
    },
    {
        "privilege": "SeIncreaseWorkingSetPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Increase a process working set",
    },
    {
        "privilege": "SeIncreaseBasePriorityPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Increase scheduling priority",
    },
    {
        "privilege": "SeLoadDriverPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": True,
        "local_privesc_desc": (
            "Lets you load device drivers. Privesc in this case is usually going to "
            "mean loading a known-vulnerable driver and then exploiting the known "
            "vulnerability."
        ),
        "ms_description": "Load and unload device drivers",
    },
    {
        "privilege": "SeLockMemoryPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Lock pages in memory",
    },
    {
        "privilege": "SeBatchLogonRight",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Log on as a batch job",
    },
    {
        "privilege": "SeServiceLogonRight",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Log on as a service",
    },
    {
        "privilege": "SeSecurityPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Manage auditing and security log",
    },
    {
        "privilege": "SeSystemEnvironmentPrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Modify firmware environment values",
    },
    {
        "privilege": "SeManageVolumePrivilege",
        "grants_remote_access": False,
        "remote_access_desc": "",
        "local_privesc": False,
        "local_privesc_desc": "",
        "ms_description": "Perform volume maintenance tasks",
    },
]

# Convenience lookup: privilege name -> entry
PRIV_RIGHTS_BY_NAME = {entry["privilege"]: entry for entry in PRIV_RIGHTS}
