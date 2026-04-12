# Group3r (Python)

Python port of [Group3r](https://github.com/Group3r/Group3r) - a tool for enumerating and identifying exploitable misconfigurations in Active Directory Group Policy.

## Installation

If you have impacket installed on your system it should not require any additional installation. Otherwise, you can use the following to install dependencies:

Using pipx:
```bash
pipx install git+https://github.com/caueb/group3r-python
group3r -h
```

Using python venv:
```bash
git clone https://github.com/caueb/group3r-python.git
cd group3r-python
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python group3r.py --help
```

## Usage

### Online mode (LDAP + SMB)

```bash
# Basic - authenticate to target domain
python group3r.py -d corp.local --dc-ip 10.0.0.1 -u 'user@contoso.local' -p 'password'

# Pass-the-hash
python group3r.py -d corp.local --dc-ip 10.0.0.1 -u 'user@contoso.local' --hashes :ntlmhash

# Kerberos (uses KRB5CCNAME ccache)
python group3r.py -d corp.local --dc-ip 10.0.0.1 -k --dc-host dc01.contoso.local
```

### Offline mode (local SYSVOL)

```bash
python group3r.py -o -y /path/to/sysvol
```

### Output options

```bash
# Write to file
python group3r.py -d corp.local --dc-ip 10.0.0.1 -u user -p pass -f results.txt

# JSON output
python group3r.py -d corp.local --dc-ip 10.0.0.1 -u user -p pass -j

# Only show settings with findings
python group3r.py -d corp.local --dc-ip 10.0.0.1 -u user -p pass -w

# Only show enabled policies
python group3r.py -d corp.local --dc-ip 10.0.0.1 -u user -p pass -e

# Minimum triage level (0=Green, 1=Yellow, 2=Red, 3=Black)
python group3r.py -d corp.local --dc-ip 10.0.0.1 -u user -p pass -w -a 2

# Verbose (LDAP/SMB debug)
python group3r.py -d corp.local --dc-ip 10.0.0.1 -u user -p pass -v
```

> [!TIP]
> Load the `results.txt` into [Chimas](https://github.com/caueb/chimas) for better visualisation!

## Triage Levels

| Level | Meaning |
|-------|---------|
| Black | Critical - GPP passwords, writable scripts on SYSVOL |
| Red | High - writable command paths, low-priv in admin groups |
| Yellow | Medium - DLL sideloading, weak registry ACLs, credential hints |
| Green | Low - non-default policy settings, informational |

## Credits

- [Group3r](https://github.com/Group3r/Group3r) by [@l0ss](https://github.com/l0ss) - the original C# tool this project is a port of
- [Impacket](https://github.com/fortra/impacket) by Fortra - used for LDAP, SMB, and Kerberos authentication
