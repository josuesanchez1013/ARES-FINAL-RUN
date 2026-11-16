"""
Per-platform command safety rules.

The POSIX validator is the existing blocklist (security/command_validator.py)
with extra patterns for Solaris, AIX, HP-UX, macOS and ESXi. PowerShell and
network-device commands use an ALLOWLIST instead: every command in the
pipeline must start with a known read-only verb or tool, and anything that
can change state, run other code or reach the network is refused outright.

validator_for(shell, family) returns an object with validate_command(str) -> bool
and a `reason` attribute describing the last rejection.
"""

import re
from typing import List, Optional

from .command_validator import CommandValidator


class PosixValidator(CommandValidator):
    """Existing blocklist plus state-changing commands of other UNIX families."""

    EXTRA_DANGEROUS = [
        # Solaris
        "svcadm", "svccfg", "pkg install", "pkg uninstall", "pkg update", "pkgadd", "pkgrm",
        "zfs destroy", "zfs create", "zfs set", "zpool destroy", "zpool create", "zoneadm", "zonecfg",
        "ipadm create-", "ipadm delete-", "ipadm set-", "dladm create-", "dladm delete-", "dladm set-",
        "auditconfig -set", "usermod", "roleadd", "roledel", "rolemod", "beadm",
        # AIX
        "chsec", "chuser", "chdev", "mkuser", "rmuser", "chgroup", "installp", "startsrc", "stopsrc",
        "refresh -s", "chfs", "rmfs", "mkfs",
        # HP-UX
        "swinstall", "swremove", "modprpw", "kctune -", "ch_rc -a",
        # macOS
        "defaults write", "defaults delete", "launchctl load", "launchctl unload", "launchctl bootout",
        "launchctl bootstrap", "csrutil enable", "csrutil disable", "spctl --master", "pwpolicy -set",
        "systemsetup -set", "dscl . -create", "dscl . -delete", "dscl . -change", "softwareupdate -i",
        # ESXi
        "esxcli system shutdown", "esxcli system maintenancemode set", "vim-cmd vmsvc/power",
        # Linux package managers and services not in the original list
        "apt install", "apt remove", "apt-get install", "apt-get remove", "apt-get purge", "dpkg -i",
        "dpkg -r", "dpkg -P", "zypper install", "zypper remove", "zypper in", "zypper rm",
        "systemctl daemon-reload", "systemctl unmask", "systemctl reload", "sysctl -w", "auditctl -D",
        "auditctl -a", "auditctl -w", "auditctl -e", "setenforce", "setsebool", "semanage", "restorecon",
        "chcon", "mount -o", "mount -a", "mount -t", "mount --", "mount /", "umount", "modprobe", "rmmod", "insmod", "ln", "truncate", "shred", "wget", "curl",
        "crontab -r", "crontab -e", "visudo", "vi", "vim", "nano", "su",
    ]
    _SET_VERBS = re.compile(r"\besxcli\b.*\b(set|add|remove)\b|\bvim-cmd\b.*\b(set|remove|destroy)\b", re.I)

    def __init__(self):
        self.DANGEROUS_COMMANDS = list(CommandValidator.DANGEROUS_COMMANDS) + self.EXTRA_DANGEROUS
        super().__init__()
        self.reason: Optional[str] = None

    def validate_command(self, command: str) -> bool:
        self.reason = None
        if command and self._SET_VERBS.search(command):
            self.reason = "esxcli/vim-cmd set, add and remove operations are not read-only"
            return False
        ok = super().validate_command(command)
        if not ok:
            self.reason = "blocked by the read-only command rules"
        return ok


def _split_pipeline(command: str, separators: str) -> Optional[List[str]]:
    """Split on separators outside quotes. None when quotes are unbalanced."""
    parts, current, quote = [], [], None
    for char in command:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
            current.append(char)
        elif char in separators:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if quote:
        return None
    parts.append("".join(current))
    return [p.strip() for p in parts]


class PowerShellValidator:
    """Allowlist for read-only PowerShell on Windows targets."""

    ALLOWED_VERBS = ("get", "test", "select", "where", "sort", "format", "measure", "compare", "group",
                     "convertto", "convertfrom", "out-string", "foreach-object", "resolve-path",
                     "resolve-dnsname", "write-output", "join-path", "split-path", "import-module",
                     "search-adaccount", "show-netfirewallrule")
    ALLOWED_ALIASES = {"select", "where", "sort", "ft", "fl", "fw", "gci", "dir", "ls", "gc", "cat", "type",
                       "gp", "gi", "gwmi", "gcim", "gsv", "gps", "measure", "echo", "findstr", "foreach", "%", "?"}
    # native tools -> regex the rest of the command must match (None = any arguments are read-only)
    ALLOWED_TOOLS = {
        "auditpol": r"^/get\b|^/list\b",
        "auditpol.exe": r"^/get\b|^/list\b",
        "reg": r"^query\b",
        "reg.exe": r"^query\b",
        "net": r"^(accounts|localgroup|user|share|config|session|use)(\s+[\w$\"' .-]+)?(\s+/domain)?$",
        "net.exe": r"^(accounts|localgroup|user|share|config|session|use)(\s+[\w$\"' .-]+)?(\s+/domain)?$",
        "netsh": r"\bshow\b",
        "netsh.exe": r"\bshow\b",
        "sc": r"^(query|queryex|qc|sdshow|qfailure)\b",
        "sc.exe": r"^(query|queryex|qc|sdshow|qfailure)\b",
        "wmic": r"\b(get|list)\b",
        "w32tm": r"^/query\b",
        "w32tm.exe": r"^/query\b",
        "bcdedit": r"^(/enum\b.*)?$",
        "bcdedit.exe": r"^(/enum\b.*)?$",
        "gpresult": r"^/[rvz]\b(\s+/scope\s+\w+)?$",
        "gpresult.exe": r"^/[rvz]\b(\s+/scope\s+\w+)?$",
        "certutil": r"^-(store|verifystore|viewstore|dump)\b",
        "certutil.exe": r"^-(store|verifystore|viewstore|dump)\b",
        "manage-bde": r"^-status\b",
        "manage-bde.exe": r"^-status\b",
        "fsutil": r"^(fsinfo|behavior query|volume diskfree)\b",
        "dism": r"^/online /get-",
        "dism.exe": r"^/online /get-",
        "whoami": None, "whoami.exe": None, "hostname": None, "hostname.exe": None,
        "systeminfo": None, "systeminfo.exe": None, "ipconfig": None, "ipconfig.exe": None,
        "ver": None, "qwinsta": None, "query": None, "tasklist": None, "tasklist.exe": None,
        "driverquery": None, "icacls": r"^[^/]*$",   # icacls with no /grant /deny /setowner etc.
        "icacls.exe": r"^[^/]*$",
    }
    FORBIDDEN = re.compile(
        r"(?i)invoke-expression|\biex\b|invoke-command|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|"
        r"start-process|start-job|start-bitstransfer|new-object|add-type|\[system\.|\[reflection\.|\[io\.|"
        r"downloadstring|downloadfile|frombase64string|-encodedcommand|\b-enc\b|"
        r"\bset-\w+|\bnew-\w+|\bremove-\w+|\badd-\w+|\bclear-\w+|\bstop-\w+|\brestart-\w+|\bdisable-\w+|"
        r"\benable-\w+|\binstall-\w+|\buninstall-\w+|\brename-\w+|\bmove-\w+|\bcopy-\w+|\bout-file\b|"
        r"\bexport-\w+|\btee-object\b|\bstart-\w+|\binvoke-\w+|\bregister-\w+|\bunregister-\w+|"
        r"\bgrant-\w+|\brevoke-\w+|\bformat-volume\b|\binitialize-\w+|\bmount-\w+|\bdismount-\w+|"
        r"\bcmd(\.exe)?\s+/c\b|\bpowershell(\.exe)?\b|\bpwsh\b|\bwscript\b|\bcscript\b|\bmshta\b|\brundll32\b|"
        r"\bsecedit\b|\bshutdown\b|\bschtasks\b|\bdel\b|\berase\b|\brd\b|\brmdir\b|\bformat\b\s+[a-z]:|"
        r"`")
    _REDIRECT = re.compile(r"(?<![0-9*&])>(?!\s*\$null)|[0-9*]>(?!\s*(\$null|&1))")

    def __init__(self):
        self.reason: Optional[str] = None

    def _reject(self, why: str) -> bool:
        self.reason = why
        return False

    def validate_command(self, command: str) -> bool:
        self.reason = None
        if not command or not command.strip():
            return self._reject("empty command")
        if len(command) > 4000:
            return self._reject("command is too long")
        match = self.FORBIDDEN.search(command)
        if match:
            return self._reject(f"'{match.group(0).strip()}' can change the system or run other code")
        unquoted = re.sub(r"\"[^\"]*\"|'[^']*'", "", command)
        if self._REDIRECT.search(unquoted):
            return self._reject("output redirection to a file is not allowed")
        if "&" in unquoted.replace("2>&1", ""):
            return self._reject("the call operator (&) is not allowed")
        for name in self._METHOD_CALL.findall(unquoted):
            if name.lower() not in self.ALLOWED_METHODS:
                return self._reject(f"method call .{name}() is not on the read-only allowlist")
        if self._BAD_TYPES.search(unquoted):
            return self._reject("that .NET type is not allowed")
        # Every command position is checked: statements, pipeline stages, and the
        # contents of script blocks { } and sub-expressions ( ).
        pieces = _split_pipeline(command, ";\n|{}()")
        if pieces is None:
            return self._reject("unbalanced quotes")
        for piece in filter(None, pieces):
            if not self._segment_ok(piece):
                return False
        return True

    _METHOD_CALL = re.compile(r"(?:\.|::)\s*([A-Za-z_]\w*)\s*\(")
    ALLOWED_METHODS = {
        "tostring", "contains", "startswith", "endswith", "trim", "trimstart", "trimend", "split", "replace",
        "getvalue", "getvaluenames", "getsubkeynames", "tolower", "toupper", "substring", "indexof", "gettype",
        "equals", "compareto", "padleft", "padright", "join", "getaccessrules", "getowner", "translate",
        "where", "foreach", "round", "parse", "isnullorempty", "isnullorwhitespace", "getcurrent", "format",
        "toint32", "toint64", "adddays", "addhours", "tofiletime", "fromfiletime", "touniversaltime",
        "tolocaltime", "isinrole", "getenumerator", "containskey", "matches", "ismatch", "match",
    }
    _BAD_TYPES = re.compile(r"(?i)\[[^\]]*(diagnostics|net\.|activator|runtime|automation|scriptblock|"
                            r"wmiclass|assembly|marshal|process|file|directory|registry)[^\]]*\]")
    _KEYWORDS = re.compile(r"(?i)^(if|elseif|else|foreach|try|catch|finally|return|in|switch|default)\b\s*")

    def _segment_ok(self, segment: str) -> bool:
        segment = self._KEYWORDS.sub("", segment.strip())
        segment = re.sub(r"^\$[\w:.]+\s*=\s*", "", segment)     # $x = ...
        segment = re.sub(r"^[A-Za-z]\w*\s*=\s*", "", segment)    # hashtable key = ...
        segment = segment.strip()
        if not segment or segment[0] in "$@['\"-.,+*/!%?<=" or segment[0].isdigit():
            if segment[:1] in "%?" and len(segment) > 1 and not segment[1].isspace():
                return self._reject(f"'{segment[:20]}' is not on the read-only PowerShell allowlist")
            return True   # an expression over earlier results, e.g. $_.Name -eq 'x'
        head, _, rest = segment.partition(" ")
        word = head.lower()
        if word in self.ALLOWED_TOOLS:
            pattern = self.ALLOWED_TOOLS[word]
            if pattern is None or re.search(pattern, rest.strip(), re.IGNORECASE):
                return True
            return self._reject(f"'{head} {rest.strip()[:40]}' is not a read-only use of {head}")
        if word in self.ALLOWED_ALIASES or any(
                word == verb or word.startswith(verb + "-") for verb in self.ALLOWED_VERBS):
            return True
        if re.fullmatch(r"[\w.]+", head) and not rest and word in ("true", "false", "null", "enabled", "installed"):
            return True
        return self._reject(f"'{head}' is not on the read-only PowerShell allowlist")


class NetworkCliValidator:
    """Allowlist for network devices: show/display commands only."""

    ALLOWED = re.compile(r"(?i)^(show|display|sh|get system status|get system)\b")
    PIPES = re.compile(r"(?i)^(include|inc|i|exclude|exc|begin|beg|section|sec|count|match|except|find|"
                       r"display set|display inherit\w*|no-more|grep|last \d+|trim \d+)\b")

    def __init__(self):
        self.reason: Optional[str] = None

    def validate_command(self, command: str) -> bool:
        self.reason = None
        text = (command or "").strip()
        if not text:
            self.reason = "empty command"
            return False
        if "\n" in text or ";" in text or ">" in text:
            self.reason = "one show command at a time, with no redirection"
            return False
        head, *filters = [part.strip() for part in text.split("|")]
        if not self.ALLOWED.match(head):
            self.reason = "only show/display commands are allowed on network devices"
            return False
        for item in filters:
            if not self.PIPES.match(item):
                self.reason = f"'| {item[:30]}' is not an allowed output filter"
                return False
        return True


class NoCommandsValidator:
    """For platforms ARES has no way to run checks on."""

    reason = "this target has no command access; assess the Check Text from the evidence already provided"

    def validate_command(self, command: str) -> bool:
        return False


def validator_for(shell: str, family: str = ""):
    if shell == "powershell":
        return PowerShellValidator()
    if shell == "network":
        return NetworkCliValidator()
    if shell == "posix":
        return PosixValidator()
    return NoCommandsValidator()
