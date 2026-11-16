"""
Platform profiles: what kind of system a STIG is for, and how ARES checks it.

A profile answers three questions for the pipeline:
- shell:    which command language the Check Text uses (posix, powershell,
            network CLI, or none for policy/manual STIGs)
- backends: which connections can run checks on that platform
- sudo:     whether commands are normally elevated with sudo

classify() maps a benchmark (by its id and title) to a profile. It is keyword
based and deliberately conservative: anything it does not recognise becomes
"other", which still imports, matches and exports but is not auto-checked.
"""

import re
from typing import Any, Dict, List

PROFILES: Dict[str, Dict[str, Any]] = {
    "linux": {
        "label": "Linux", "shell": "posix", "sudo": True,
        "backends": ["ssh", "local"],
        "style": "POSIX shell on Linux (bash). Typical tools: grep, cat, awk, stat, ls, find, "
                 "systemctl status / is-enabled, sysctl, auditctl -l, rpm -q or dpkg -l, ss, getent.",
    },
    "solaris": {
        "label": "Solaris", "shell": "posix", "sudo": False,
        "backends": ["ssh", "local"],
        "style": "POSIX shell on Oracle Solaris. Use Solaris tools, not Linux ones: svcs (not systemctl), "
                 "pkg list / pkg info (not rpm), svcprop, zfs get, zonename, ipadm show-*, dladm show-*, "
                 "auditconfig -get*, logins, profiles, auths, pfexec for privileged reads. "
                 "/usr/xpg4/bin/grep supports -E; avoid GNU-only flags.",
    },
    "aix": {
        "label": "IBM AIX", "shell": "posix", "sudo": False,
        "backends": ["ssh", "local"],
        "style": "POSIX shell (ksh) on IBM AIX. Use AIX tools: lssec, lsuser, lsattr, lssrc, lslpp -l, "
                 "oslevel, audit query, lsfs. Avoid GNU-only flags.",
    },
    "hpux": {
        "label": "HP-UX", "shell": "posix", "sudo": False,
        "backends": ["ssh", "local"],
        "style": "POSIX shell on HP-UX. Use HP-UX tools: swlist, getprpw, kctune, ch_rc -l, ioscan (read-only). "
                 "Avoid GNU-only flags.",
    },
    "macos": {
        "label": "macOS", "shell": "posix", "sudo": True,
        "backends": ["ssh", "local"],
        "style": "POSIX shell (zsh/bash) on macOS. Typical tools: defaults read, profiles -P, "
                 "system_profiler, pwpolicy getaccountpolicies, spctl --status, csrutil status, launchctl print.",
    },
    "esxi": {
        "label": "VMware ESXi", "shell": "posix", "sudo": False,
        "backends": ["ssh"],
        "style": "ESXi shell (busybox). Use esxcli ... get/list, vim-cmd ... get, and read files under /etc. "
                 "PowerCLI commands in the Check Text cannot be run here; say so if a rule needs them.",
    },
    "windows": {
        "label": "Windows", "shell": "powershell", "sudo": False,
        "backends": ["winrm", "local"],
        "style": "Windows PowerShell. Read-only cmdlets and tools only: Get-ItemProperty / Get-ItemPropertyValue "
                 "for registry values, Get-LocalUser, Get-LocalGroupMember, Get-Service, Get-WindowsFeature, "
                 "Get-ADUser/Get-ADDefaultDomainPasswordPolicy where available, auditpol /get /category:*, "
                 "net accounts, reg query, Get-NetFirewallProfile, Get-BitLockerVolume, Get-Acl, "
                 "Get-CimInstance. Security policy (user rights, password policy) is not in the registry: "
                 "say so if a rule can only be checked in the Group Policy editor.",
    },
    "network_ios": {
        "label": "Cisco IOS / IOS XE / NX-OS / ASA", "shell": "network", "sudo": False,
        "backends": ["config", "ssh"],
        "style": "Cisco CLI, show commands only: show running-config, show running-config | include <text>, "
                 "show running-config | section <text>, show version, show ip ssh, show logging, show ntp status.",
    },
    "network_junos": {
        "label": "Juniper Junos", "shell": "network", "sudo": False,
        "backends": ["config", "ssh"],
        "style": "Junos CLI, show commands only: show configuration, show configuration | display set, "
                 "show configuration | match <text>, show version, show system users.",
    },
    "network": {
        "label": "Network device", "shell": "network", "sudo": False,
        "backends": ["config", "ssh"],
        "style": "Vendor network CLI, show/display commands only. Never enter configuration mode.",
    },
    "other": {
        "label": "Application or policy", "shell": "none", "sudo": False,
        "backends": [],
        "style": "",
    },
}

# First match wins; order matters (specific before general).
_RULES: List[tuple] = [
    ("esxi", r"esxi|vsphere|vmware"),
    ("network_junos", r"juniper|junos"),
    ("network_ios", r"cisco|ios[-_ ]?xe|nx[-_ ]?os|\basa\b"),
    ("windows", r"windows|\bwin(?:dows)?[-_ ]?(?:10|11|server)|\bms[-_ ]|microsoft|active[-_ ]directory|"
                r"\biis\b|sql[-_ ]server|dot[-_ ]?net|defender|exchange|sharepoint"),
    ("network", r"router|switch|firewall(?!d)|palo[-_ ]?alto|fortigate|fortinet|arista|f5[-_ ]big|"
                r"network[-_ ]device|\bndm\b|\bl2s\b|\brtr\b|aruba|brocade|infoblox"),
    ("solaris", r"solaris"),
    ("aix", r"\baix\b"),
    ("hpux", r"hp[-_ ]?ux"),
    ("macos", r"mac[-_ ]?os|apple[-_ ]os[-_ ]x|os[-_ ]x"),
    ("linux", r"rhel|red[-_ ]?hat|linux|ubuntu|\bsles\b|suse|oracle[-_ ]linux|\bol[-_ ]?\d|centos|debian|"
              r"alma|rocky|amazon[-_ ]linux|photon|container[-_ ]platform|kubernetes|docker|podman|"
              r"apache|tomcat|postgres|mysql|mariadb|nginx|mongodb|jboss|openshift"),
]
_COMPILED = [(family, re.compile(pattern, re.IGNORECASE)) for family, pattern in _RULES]
_OS_STIG = re.compile(
    r"(rhel|red[-_ ]hat[-_ ]enterprise[-_ ]linux|ubuntu|sles|suse[-_ ]linux|oracle[-_ ]linux|solaris|aix|hp-?ux|"
    r"windows[-_ ](server|10|11)|macos|apple[-_ ]macos|esxi)[-_ ]?[\d.]*", re.IGNORECASE)


def classify(key: str, title: str = "") -> str:
    """Platform family for a benchmark id and title."""
    text = f"{key} {title}".replace("_", " ")
    for family, pattern in _COMPILED:
        if pattern.search(text):
            return family
    return "other"


def is_operating_system(key: str, title: str = "") -> bool:
    """True for an operating-system STIG (as opposed to an application on it)."""
    text = f"{key} {title}".replace("_", " ")
    lowered = text.lower()
    if any(word in lowered for word in ("apache", "tomcat", "postgres", "mysql", "iis", "sql server", "firefox",
                                        "chrome", "edge", "office", "defender", "dns", "docker", "kubernetes")):
        return False
    return bool(_OS_STIG.search(text))


def profile(family: str) -> Dict[str, Any]:
    data = dict(PROFILES.get(family, PROFILES["other"]))
    data["family"] = family if family in PROFILES else "other"
    return data


def families() -> List[Dict[str, Any]]:
    return [profile(name) for name in PROFILES]
