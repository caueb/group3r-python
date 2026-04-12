"""Command-line interface for Group3r."""

from __future__ import annotations

import argparse

from .models.enums import Triage


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="group3r",
        description="Group3r - AD Group Policy enumeration and exploitation tool (Python port)",
    )

    # Mode
    parser.add_argument("-o", "--offline", action="store_true",
                        help="Offline mode (parse local SYSVOL only)")
    parser.add_argument("-y", "--sysvol-path", default="",
                        help="Path to SYSVOL directory (required for offline mode)")

    # Network options
    parser.add_argument("-d", "--domain", default="",
                        help="Target domain to enumerate GPOs from")
    parser.add_argument("--dc-ip", default="",
                        help="Domain controller IP address")
    parser.add_argument("--dc-host", default="",
                        help="Domain controller FQDN (required for Kerberos, "
                             "e.g. dc01.corp.local)")
    parser.add_argument("-u", "--username", default="",
                        help="Username for authentication (user@domain or domain\\user)")
    parser.add_argument("-p", "--password", default="",
                        help="Password for authentication")
    parser.add_argument("--hashes", default="",
                        help="NTLM hashes (LMHASH:NTHASH)")
    parser.add_argument("-k", "--kerberos", action="store_true",
                        help="Use Kerberos authentication (ccache from KRB5CCNAME)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output (show LDAP/SMB debug info)")

    # Output options
    parser.add_argument("-s", "--stdout", action="store_true", default=True,
                        help="Output to stdout (default)")
    parser.add_argument("-f", "--outfile", default="",
                        help="Write output to file")
    parser.add_argument("-j", "--json", nargs="?", const=True, default=False,
                        metavar="FILE",
                        help="Output in JSON format (optionally to FILE, default: stdout)")
    parser.add_argument("-w", "--findings-only", action="store_true",
                        help="Only show settings with findings")
    parser.add_argument("-e", "--enabled-only", action="store_true",
                        help="Only show enabled policies")
    parser.add_argument("-r", "--current-only", action="store_true",
                        help="Skip morphed/NTFRS policies")
    parser.add_argument("-a", "--min-triage", type=int, default=0, choices=[0, 1, 2, 3],
                        help="Minimum triage level (0=Green, 1=Yellow, 2=Red, 3=Black)")

    # Performance
    parser.add_argument("--threads", type=int, default=10,
                        help="Max SYSVOL processing threads")

    parsed = parser.parse_args(args)
    return parsed


def args_to_options(parsed: argparse.Namespace):
    """Convert parsed CLI args to GrouperOptions."""
    from .options import AssessmentOptions, GrouperOptions

    assessment_options = AssessmentOptions(
        min_triage=Triage(parsed.min_triage),
    )

    # Parse UPN (user@domain) and DOMAIN\user formats
    username = parsed.username
    auth_domain = ""
    if "@" in username:
        # UPN format: user@domain
        username, domain_part = username.rsplit("@", 1)
        if not auth_domain:
            auth_domain = domain_part
    elif "\\" in username:
        # DOMAIN\user format
        domain_part, username = username.split("\\", 1)
        if not auth_domain:
            auth_domain = domain_part

    return GrouperOptions(
        offline_mode=parsed.offline,
        sysvol_path=parsed.sysvol_path,
        target_domain=parsed.domain,
        target_dc=parsed.dc_ip,
        dc_host=parsed.dc_host,
        username=username,
        password=parsed.password,
        hashes=parsed.hashes,
        use_kerberos=parsed.kerberos,
        auth_domain=auth_domain,
        verbose=parsed.verbose,
        stdout=parsed.stdout,
        outfile=parsed.json if isinstance(parsed.json, str) else parsed.outfile,
        findings_only=parsed.findings_only,
        enabled_only=parsed.enabled_only,
        current_only=parsed.current_only,
        min_triage=Triage(parsed.min_triage),
        json_output=bool(parsed.json),
        max_sysvol_threads=parsed.threads,
        assessment_options=assessment_options,
    )
