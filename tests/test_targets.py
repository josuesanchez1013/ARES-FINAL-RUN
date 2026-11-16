"""
Offline tests for multi-platform targets: connection backends, the shared
run_on_target path, the targets API, discovery, result-file conversion,
platform-aware prompts, and OpenSCAP scans (with a stand-in oscap).
"""

import io
import shutil
import json
import sys
import time
import types
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient

from ares_api import prompts, scap, targets
from ares_api.app import create_app
from cli_executor import target_context
from cli_executor.backends import BackendError, ConfigBackend, LocalBackend, WinRMBackend, build_backend
from stig_library import StigLibrary
from stig_library.convert import ConvertError, cklb_to_ckl, to_ckl, xccdf_results_to_ckl
from tests.test_stig_library import (FORM, library_zip, manual_rule, manual_xccdf, sample_scans,
                                     scap_datastream, wait_done, windows_xccdf)

IOS_CONFIG = """version 17.9
service password-encryption
hostname EDGE-RTR-01
!
aaa new-model
aaa authentication login default group tacacs+ local
!
interface GigabitEthernet0/0
 description uplink
 ip address 10.0.0.1 255.255.255.0
 no ip redirects
!
interface GigabitEthernet0/1
 shutdown
!
ip ssh version 2
line vty 0 4
 exec-timeout 5 0
 transport input ssh
!
end
"""


needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell on this machine")


def posix_target(**extra):
    return dict({"id": "a" * 12, "name": "this-host", "family": "linux", "backend": "local", "shell": "posix",
                 "platform_label": "Linux", "style": "", "use_sudo": False, "timeout": 20}, **extra)


# ---------------------------------------------------------------- backends

class TestBackends:
    @needs_sh
    def test_local_runs_a_command(self):
        result = LocalBackend(posix_target()).run("echo ares_ping")
        assert result["exit_code"] == 0 and result["output"].strip() == "ares_ping"

    @needs_sh
    def test_local_nonzero_exit_is_a_result_not_a_failure(self):
        assert LocalBackend(posix_target()).run("grep -c nothing /dev/null")["exit_code"] == 1

    def test_config_backend_filters(self, tmp_path):
        path = tmp_path / "rtr.cfg"
        path.write_text(IOS_CONFIG)
        backend = ConfigBackend({"config_path": str(path)})
        assert "hostname EDGE-RTR-01" in backend.run("show running-config")["output"]
        assert backend.run("show run | include aaa")["output"].splitlines() == [
            "aaa new-model", "aaa authentication login default group tacacs+ local"]
        section = backend.run("sh run | section line vty")["output"].splitlines()
        assert section == ["line vty 0 4", " exec-timeout 5 0", " transport input ssh"]
        assert backend.run("show running-config | begin ip ssh")["output"].startswith("ip ssh version 2")
        assert "shutdown" not in backend.run("show run | exclude shutdown")["output"]
        assert backend.run("show run | include interface | count")["output"].endswith("= 2")
        live = backend.run("show ip interface brief")
        assert live["exit_code"] == 1 and "not a live device" in live["error"]

    def test_config_backend_needs_a_file(self):
        with pytest.raises(BackendError):
            ConfigBackend({"config_path": "/nonexistent"})

    def test_winrm_backend(self, monkeypatch):
        seen = {}

        class Session:
            def __init__(self, endpoint, auth, **options):
                seen.update(endpoint=endpoint, auth=auth, options=options)

            def run_ps(self, script):
                seen["script"] = script
                return types.SimpleNamespace(std_out=b"WIN-01\r\n", std_err=b"", status_code=0)

        monkeypatch.setitem(sys.modules, "winrm", types.SimpleNamespace(Session=Session))
        monkeypatch.setenv("ARES_PW_WIN01", "s3cret")
        backend = WinRMBackend({"host": "win01.lab", "user": "LAB\\\\auditor", "password_env": "ARES_PW_WIN01"})
        result = backend.run("hostname")
        assert result["exit_code"] == 0 and result["output"].strip() == "WIN-01"
        assert seen["endpoint"] == "https://win01.lab:5986/wsman"
        assert seen["auth"][1] == "s3cret"
        assert seen["options"]["server_cert_validation"] == "validate"   # TLS is always verified

    def test_winrm_requires_credentials(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "winrm", types.SimpleNamespace(Session=object))
        with pytest.raises(BackendError, match="password environment variable"):
            WinRMBackend({"host": "h", "user": "u", "password_env": "ARES_PW_UNSET_XYZ"})

    def test_ssh_requires_credentials(self):
        with pytest.raises(BackendError):
            build_backend({"backend": "ssh", "host": "h", "user": "u"})

    def test_unknown_backend(self):
        with pytest.raises(BackendError):
            build_backend({"backend": "telnet"})


class TestRunOnTarget:
    def test_validates_before_running(self):
        ran = []
        backend = types.SimpleNamespace(run=lambda *a, **k: ran.append(a) or {}, close=lambda: None)
        result = target_context.run_on_target(posix_target(), "rm -rf /tmp/x", backend=backend, audit=False)
        assert result["exit_code"] == -2 and result["status"] == "error" and ran == []

    def test_platform_rules_follow_the_target(self):
        windows = posix_target(family="windows", shell="powershell", backend="winrm")
        backend = types.SimpleNamespace(
            run=lambda command, **k: {"output": "ok", "exit_code": 0, "error": None, "duration_ms": 1},
            close=lambda: None)
        assert target_context.run_on_target(windows, "Get-Service", backend=backend, audit=False)["exit_code"] == 0
        assert target_context.run_on_target(windows, "Stop-Service x", backend=backend, audit=False)["exit_code"] == -2
        # a Linux command is not on the PowerShell allowlist
        assert target_context.run_on_target(windows, "grep x /etc/passwd", backend=backend, audit=False)["exit_code"] == -2

    def test_sudo_only_when_the_target_allows_it(self):
        calls = []
        backend = types.SimpleNamespace(
            run=lambda command, use_sudo=False, rule_id="": calls.append(use_sudo) or
            {"output": "", "exit_code": 0, "error": None, "duration_ms": 1}, close=lambda: None)
        target_context.run_on_target(posix_target(use_sudo=False), "id", use_sudo=True, backend=backend, audit=False)
        target_context.run_on_target(posix_target(use_sudo=True), "id", use_sudo=True, backend=backend, audit=False)
        assert calls == [False, True]

    def test_backend_setup_failure_is_reported(self):
        target = posix_target(backend="config", shell="network", family="network_ios", config_path="")
        result = target_context.run_on_target(target, "show running-config", audit=False)
        assert result["exit_code"] == -1 and "configuration file" in result["error"]

    @needs_sh
    def test_execute_command_tool_uses_the_active_target(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)   # the audit log is written under ./data/logs
        from cli_executor.ares_mcp_tool import ARESCliMcpTool
        target = posix_target()
        target_context.set_active_target(target)
        try:
            result = ARESCliMcpTool().run(command="echo from-target", rule_id="V-1")
        finally:
            target_context.set_active_target(None)
        assert result["status"] == "success" and "from-target" in result["output"]
        [log] = list((tmp_path / "data" / "logs").glob("audit_*.jsonl"))
        entry = json.loads(log.read_text().splitlines()[0])
        assert entry["command"] == "echo from-target" and entry["agent"] == "CLI_Executor/local"


# ---------------------------------------------------------------- conversion

def xccdf_results(with_benchmark=True):
    bench = scap_datastream().decode()
    start, end = bench.index("<Benchmark"), bench.index("</Benchmark>")
    benchmark = bench[start:end]
    result = """
      <TestResult id="xccdf_mil.disa.stig_testresult_scc" version="2">
        <benchmark id="xccdf_mil.disa.stig_benchmark_RHEL_8_STIG"/>
        <target>prod-db-01</target><target-address>10.9.8.7</target-address>
        <rule-result idref="xccdf_mil.disa.stig_rule_SV-230221r1017040_rule" severity="high" time="2026-11-01T10:00:00">
          <result>fail</result></rule-result>
        <rule-result idref="xccdf_mil.disa.stig_rule_SV-230222r627750_rule" severity="medium">
          <result>pass</result></rule-result>
      </TestResult>"""
    if with_benchmark:
        return (benchmark + result + "</Benchmark>").encode()
    return ('<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"' + result.strip()[len("<TestResult"):]).encode()


def statuses(ckl: bytes):
    root = ET.fromstring(ckl)
    out = {}
    for vuln in root.iter("VULN"):
        data = {d.findtext("VULN_ATTRIBUTE"): d.findtext("ATTRIBUTE_DATA") for d in vuln.iter("STIG_DATA")}
        out[data["Vuln_Num"]] = vuln.findtext("STATUS")
    return out


class TestConvert:
    def test_cklb_sample_matches_ckl_sample(self, tmp_path):
        from mcp_server.parsers.ckl_parser import CKLParser
        with open("data/input/rhel8-prestige-auto.cklb", "rb") as handle:
            converted = cklb_to_ckl(handle.read())
        assert b"<HOST_NAME>" not in converted and b"<HOST_IP>" not in converted
        out = tmp_path / "converted.ckl"
        out.write_bytes(converted)
        from_cklb = {f.group_id: f.status for f in CKLParser().parse(str(out))}
        from_ckl = {f.group_id: f.status for f in CKLParser().parse("data/input/rhel8-prestige-auto.ckl")}
        assert len(from_cklb) == 366 and from_cklb == from_ckl

    def test_xccdf_results_with_benchmark(self):
        ckl = xccdf_results_to_ckl(xccdf_results())
        assert statuses(ckl) == {"V-230221": "Open", "V-230222": "NotAFinding"}
        assert b"RHEL_8_STIG" in ckl and b"prod-db-01" not in ckl and b"10.9.8.7" not in ckl

    def test_xccdf_results_filled_from_library(self, tmp_path):
        library = StigLibrary(tmp_path)
        library.import_upload("lib.zip", io.BytesIO(library_zip()))
        ckl = xccdf_results_to_ckl(xccdf_results(with_benchmark=False), library)
        # the third rule is not in the SCAP content: listed as Not_Reviewed so both scans line up
        assert statuses(ckl) == {"V-230221": "Open", "V-230222": "NotAFinding", "V-230223": "Not_Reviewed"}
        assert b"Run: grep x /etc/x" in ckl     # Check Text comes from the manual STIG

    def test_rejects_other_xml_and_bad_cklb(self):
        with pytest.raises(ConvertError):
            to_ckl("x.xml", manual_xccdf())
        with pytest.raises(ConvertError):
            to_ckl("x.cklb", b"{}")
        assert to_ckl("x.ckl", b"<CHECKLIST/>") is None


# ---------------------------------------------------------------- API

@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ARES_USE_MOCK", "true")
    monkeypatch.setenv("ARES_MOCK_STEP_DELAY", "0")
    monkeypatch.setenv("ARES_LLM_MODELS", "model-a,model-b")
    monkeypatch.setenv("ARES_STIG_LIBRARY_DIR", str(tmp_path / "stig_library"))
    monkeypatch.setenv("ARES_TARGETS_DIR", str(tmp_path / "targets"))
    monkeypatch.setenv("ARES_SCAP_DIR", str(tmp_path / "scap"))
    monkeypatch.chdir(tmp_path)      # audit logs go under the test folder
    app = create_app(tmp_path / "runs")
    return TestClient(app)


LOCAL_LINUX = {"name": "this host", "family": "linux", "backend": "local"}
WINDOWS = {"name": "WIN-01", "family": "windows", "backend": "winrm", "host": "win01.lab",
           "user": "LAB\\auditor", "password_env": "ARES_PW_WIN01"}
ROUTER = {"name": "edge-rtr-01", "family": "network_ios", "backend": "config"}


class TestTargetsApi:
    def test_crud(self, client):
        listing = client.get("/api/targets").json()
        assert listing["targets"] == [] and listing["default"]["id"] == "default"
        assert {p["family"] for p in listing["platforms"]} >= {"linux", "solaris", "aix", "windows", "network_ios"}
        created = client.post("/api/targets", json=WINDOWS).json()
        assert created["shell"] == "powershell" and created["platform_label"] == "Windows"
        assert created["use_sudo"] is False
        updated = client.put(f"/api/targets/{created['id']}", json=dict(WINDOWS, name="WIN-02")).json()
        assert updated["name"] == "WIN-02" and updated["id"] == created["id"]
        assert len(client.get("/api/targets").json()["targets"]) == 1
        assert client.delete(f"/api/targets/{created['id']}").status_code == 204
        assert client.delete(f"/api/targets/{created['id']}").status_code == 404

    def test_no_password_is_ever_stored(self, client, tmp_path):
        client.post("/api/targets", json=WINDOWS)
        stored = (tmp_path / "targets" / "targets.json").read_text()
        assert "ARES_PW_WIN01" in stored and "password\"" not in stored

    @pytest.mark.parametrize("change,code", [
        ({"family": "other"}, "family"),
        ({"backend": "ssh"}, "backend"),                       # Windows does not connect by SSH
        ({"host": ""}, "host"),
        ({"host": "bad host; rm"}, "host"),
        ({"password_env": "hunter2!"}, "password_env"),        # looks like a password, not a variable name
        ({"password_env": ""}, "credentials"),
        ({"winrm_transport": "basic", "winrm_https": False}, "transport"),
    ])
    def test_validation(self, client, change, code):
        response = client.post("/api/targets", json=dict(WINDOWS, **change))
        assert response.status_code == 422 and response.json()["detail"]["code"] == code

    def test_ssh_needs_key_or_password_variable(self, client):
        body = {"name": "sol11", "family": "solaris", "backend": "ssh", "host": "sol11.lab", "user": "audit"}
        assert client.post("/api/targets", json=body).json()["detail"]["code"] == "credentials"
        assert client.post("/api/targets", json=dict(body, key_path="~/.ssh/id_ed25519")).status_code == 201

    @needs_sh
    def test_connection_test_and_discovery_on_this_host(self, client):
        client.post("/api/stigs/import", files={"file": ("lib.zip", library_zip(), "application/zip")})
        target = client.post("/api/targets", json=LOCAL_LINUX).json()
        check = client.post(f"/api/targets/{target['id']}/test").json()
        assert check["ok"] and "Linux" in check["detail"]
        found = client.post(f"/api/targets/{target['id']}/discover").json()
        assert found["reachable"] and found["errors"] == []

    def test_config_upload_and_show_commands(self, client):
        router = client.post("/api/targets", json=ROUTER).json()
        assert router["has_config"] is False
        bad = client.post("/api/runs", data=dict(FORM, target=router["id"]), files=sample_scans())
        assert bad.json()["detail"]["code"] == "target_no_config"
        uploaded = client.post(f"/api/targets/{router['id']}/config",
                               files={"file": ("rtr.cfg", IOS_CONFIG.encode(), "text/plain")}).json()
        assert uploaded["has_config"] is True
        check = client.post(f"/api/targets/{router['id']}/test").json()
        assert check["ok"] is False        # 'show version' needs a live device; the file cannot answer it
        target = targets.get(router["id"])
        result = target_context.run_on_target(target, "show running-config | include ip ssh", audit=False)
        assert result["output"] == "ip ssh version 2"

    def test_config_upload_only_for_config_targets(self, client):
        target = client.post("/api/targets", json=LOCAL_LINUX).json()
        response = client.post(f"/api/targets/{target['id']}/config", files={"file": ("x", b"x", "text/plain")})
        assert response.json()["detail"]["code"] == "backend"


class TestSuggest:
    ENTRIES = [
        {"id": "a", "kind": "manual", "latest": True, "key": "RHEL_8_STIG", "platform_label": "Linux",
         "title": "Red Hat Enterprise Linux 8 Security Technical Implementation Guide", "version_label": "V2R7"},
        {"id": "b", "kind": "manual", "latest": True, "key": "RHEL_9_STIG", "platform_label": "Linux",
         "title": "Red Hat Enterprise Linux 9 Security Technical Implementation Guide", "version_label": "V2R5"},
        {"id": "c", "kind": "manual", "latest": True, "key": "MS_Windows_Server_2022_STIG",
         "platform_label": "Windows", "title": "Microsoft Windows Server 2022 STIG", "version_label": "V2R4"},
        {"id": "d", "kind": "manual", "latest": True, "key": "Apache_Server_2-4_UNIX_Server_STIG",
         "platform_label": "Linux", "title": "Apache Server 2.4 UNIX Server STIG", "version_label": "V3R2"},
        {"id": "e", "kind": "manual", "latest": True, "key": "Solaris_11_SPARC_STIG", "platform_label": "Solaris",
         "title": "Solaris 11 SPARC STIG", "version_label": "V3R1"},
        {"id": "f", "kind": "manual", "latest": True, "key": "Cisco_IOS-XE_Router_NDM_STIG",
         "platform_label": "Cisco", "title": "Cisco IOS XE Router NDM STIG", "version_label": "V3R2"},
        {"id": "g", "kind": "scap", "latest": True, "key": "RHEL_9_STIG", "platform_label": "Linux",
         "title": "Red Hat Enterprise Linux 9 STIG SCAP Benchmark", "version_label": "V2R4"},
        {"id": "h", "kind": "manual", "latest": True, "key": "MS_IIS_10-0_Server_STIG", "platform_label": "Windows",
         "title": "Microsoft IIS 10.0 Server STIG", "version_label": "V3R2"},
    ]

    def ids(self, output):
        return [s["id"] for s in targets.suggest(output, self.ENTRIES)]

    def test_rhel9_with_apache(self):
        output = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="9.4"\nID="rhel"\nLinux 5.14.0\n/usr/sbin/httpd\n'
        assert self.ids(output) == ["b", "d"]

    def test_rhel8(self):
        assert self.ids('ID="rhel"\nVERSION_ID="8.10"\nLinux 4.18.0\n') == ["a"]

    def test_windows_server_with_iis(self):
        output = "Caption : Microsoft Windows Server 2022 Standard\nVersion : 10.0.20348\n\nW3SVC Running\n"
        assert self.ids(output) == ["c", "h"]

    def test_solaris_and_cisco(self):
        assert self.ids("SunOS 5.11\n") == ["e"]
        assert self.ids("Cisco IOS XE Software, Version 17.09.04a\n") == ["f"]

    def test_nothing_recognised(self):
        assert self.ids("Plan 9 from Bell Labs\n") == []


class TestPrompts:
    BASE = "Gap Coverage Agent - RHEL 8 STIG Validation via CLI\nexecuting validation commands via SSH\n"

    def target(self, **extra):
        return dict(posix_target(), **extra)

    def test_windows_prompt(self):
        target = self.target(family="windows", shell="powershell", backend="winrm", platform_label="Windows",
                             style="Windows PowerShell.")
        text = prompts.adapt_prompt(self.BASE, target)
        assert text.startswith("═") and "TARGET PLATFORM: Windows" in text
        assert "RHEL 8" not in text.replace("overrides any RHEL 8", "")
        assert "Do NOT send Linux commands" in text and "use_sudo=false" in text
        assert text.count("TARGET PLATFORM: Windows") == 2      # top and bottom

    def test_config_prompt_sends_live_checks_to_review(self):
        target = self.target(family="network_ios", shell="network", backend="config",
                             platform_label="Cisco IOS / IOS XE / NX-OS / ASA")
        text = prompts.adapt_prompt(self.BASE, target)
        assert "SAVED CONFIGURATION FILE" in text and "requires_human_review" in text

    def test_solaris_prompt_keeps_ssh_and_names_native_tools(self):
        target = self.target(family="solaris", platform_label="Solaris", backend="ssh",
                             style="POSIX shell on Oracle Solaris. Use svcs (not systemctl).")
        text = prompts.adapt_prompt(self.BASE, target)
        assert "via SSH" in text and "svcs (not systemctl)" in text and "sudo is not available" in text

    def test_tool_definition(self):
        tools = [{"type": "function", "function": {"name": "execute_command", "description": "RHEL 8 via SSH",
                  "parameters": {"properties": {"command": {"description": "x"},
                                                "use_sudo": {"description": "y", "default": True}}}}}]
        target = self.target(family="windows", shell="powershell", backend="winrm", platform_label="Windows")
        adapted = prompts.adapt_tools(tools, target)
        function = adapted[0]["function"]
        assert "Windows" in function["description"] and "RHEL" not in function["description"]
        assert function["parameters"]["properties"]["use_sudo"]["default"] is False
        assert tools[0]["function"]["description"] == "RHEL 8 via SSH"      # original untouched


class TestRunsWithTargets:
    def test_run_records_target_and_exports_name_it(self, client):
        target = client.post("/api/targets", json=LOCAL_LINUX).json()
        run = client.post("/api/runs", data=dict(FORM, target=target["id"]), files=sample_scans()).json()
        assert run["target"]["name"] == "this host" and run["target"]["platform_label"] == "Linux"
        wait_done(client, run["id"])
        assert "<HOST_NAME>this host</HOST_NAME>" in client.get(f"/api/runs/{run['id']}/export/ckl").text

    def test_default_target_is_unchanged(self, client):
        run = client.post("/api/runs", data=FORM, files=sample_scans()).json()
        assert run["target"]["id"] == "default" and run["target"]["note"] == ""
        wait_done(client, run["id"])
        assert "<HOST_NAME>rhel8-stig-lab</HOST_NAME>" in client.get(f"/api/runs/{run['id']}/export/ckl").text

    def test_unknown_target(self, client):
        response = client.post("/api/runs", data=dict(FORM, target="f" * 12), files=sample_scans())
        assert response.json()["detail"]["code"] == "target_not_found"

    def test_mismatch_between_stig_and_target_is_flagged(self, client):
        client.post("/api/stigs/import", files={"file": ("lib.zip", library_zip(), "application/zip")})
        target = client.post("/api/targets", json=LOCAL_LINUX).json()
        form = dict(FORM, target=target["id"], stig="MS_Windows_Server_2022_STIG~V2R4~manual")
        run = client.post("/api/runs", data=form, files=sample_scans()).json()
        assert "is a Windows STIG" in run["target"]["note"]
        wait_done(client, run["id"])

    def test_cklb_and_scc_results_are_accepted(self, client):
        client.post("/api/stigs/import", files={"file": ("lib.zip", library_zip(), "application/zip")})
        with open("%s/data/input/rhel8-prestige-auto.cklb" % ROOT, "rb") as handle:
            cklb = handle.read()
        files = {"tool1": ("prestige.cklb", cklb, "application/json"),
                 "tool2": ("scc_results.xml", xccdf_results(), "application/xml")}
        run = client.post("/api/runs", data=FORM, files=files).json()
        assert [f["name"] for f in run["files"]] == ["prestige.ckl", "scc_results.ckl"]
        assert [f["converted_from"] for f in run["files"]] == ["prestige.cklb", "scc_results.xml"]
        assert run["stig"]["entry_ids"] == ["RHEL_8_STIG~V2R7~manual"]
        assert wait_done(client, run["id"])["status"] == "completed"

    def test_bad_uploads(self, client):
        files = {"tool1": ("notes.txt", b"x", "text/plain"), "tool2": ("b.csv", b"a,b\n", "text/csv")}
        assert client.post("/api/runs", data=FORM, files=files).json()["detail"]["code"] == "file_type"
        files = {"tool1": ("stig.xml", manual_xccdf(), "application/xml"), "tool2": ("b.csv", b"a,b\n", "text/csv")}
        assert client.post("/api/runs", data=FORM, files=files).json()["detail"]["code"] == "file_unreadable"
        only_one = {"tool1": ("a.csv", b"a,b\n", "text/csv")}
        assert client.post("/api/runs", data=FORM, files=only_one).json()["detail"]["code"] == "file_required"


import os  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_bridge_gives_the_agent_the_target_and_its_prompt(monkeypatch, tmp_path):
    """Production path: a run on a saved Windows target hands the agent an adapted prompt,
    an adapted tool definition, and routes execute_command through the target's rules."""
    from ares_api.pipeline import STEPS, BridgePipeline
    from ares_api.runs import RunStore

    monkeypatch.setenv("ARES_TARGETS_DIR", str(tmp_path / "targets"))
    monkeypatch.setenv("ARES_PW_WIN01", "pw")
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app(tmp_path / "runs0"))
    monkeypatch.setenv("ARES_USE_MOCK", "true")
    target_id = client.post("/api/targets", json=WINDOWS).json()["id"]

    prompt = tmp_path / "gap_prompt.txt"
    prompt.write_text("Gap Coverage Agent - RHEL 8 STIG Validation via SSH\n")
    seen = {}

    class Executor:
        def __init__(self, agent_prompt_file, model="m", **kwargs):
            seen["prompt"] = open(agent_prompt_file, encoding="utf-8").read()
            seen["model"] = model

        def _get_tool_definitions(self):
            return [{"type": "function", "function": {"name": "execute_command", "description": "RHEL 8 via SSH",
                     "parameters": {"properties": {"command": {"description": "c"},
                                                   "use_sudo": {"description": "s", "default": True}}}}}]

    orch = types.ModuleType("ui.orchestrator_runner")
    orch.st, orch.AGENT_IDS, orch.LocalAgentExecutor = None, {"parser": "a"}, Executor

    def execute_next_step(use_mock=True):
        agent = orch.LocalAgentExecutor(agent_prompt_file=str(prompt), model="hardcoded")
        seen["tool"] = agent._get_tool_definitions()[0]["function"]
        seen["active"] = target_context.active_target()["name"]
        from cli_executor.ares_mcp_tool import ARESCliMcpTool
        seen["blocked"] = ARESCliMcpTool().run(command="Remove-Item C:\\x", rule_id="V-1")
        orch.st.session_state.parser_output = {"tool1_findings": [], "tool2_findings": []}

    orch.execute_next_step = execute_next_step
    package = types.ModuleType("ui")
    package.orchestrator_runner = orch
    monkeypatch.setitem(sys.modules, "ui", package)
    monkeypatch.setitem(sys.modules, "ui.orchestrator_runner", orch)

    run = RunStore(tmp_path / "runs").create(steps=STEPS, files=[], declaration={},
                                             models={"primary": "model-a"}, mock=False)
    run.meta["target"] = targets.resolve_choice(target_id)
    BridgePipeline().run_step(0, run)

    assert "TARGET PLATFORM: Windows" in seen["prompt"] and seen["model"] == "model-a"
    assert "Windows" in seen["tool"]["description"]
    assert seen["active"] == "WIN-01"
    assert seen["blocked"]["exit_code"] == -2
    assert target_context.active_target() is None                 # cleared after the step
    assert (run.folder / "prompts" / "gap_prompt.txt").is_file()
    assert prompt.read_text().startswith("Gap Coverage Agent - RHEL 8")   # shipped prompt untouched


# ---------------------------------------------------------------- OpenSCAP

FAKE_OSCAP = """
import sys
args = sys.argv[1:]
out = args[args.index("--results") + 1]
open(out, "wb").write(open(sys.argv[0] + ".results", "rb").read())
sys.exit(2)       # oscap returns 2 when at least one rule fails
"""


class TestScap:
    def prepare(self, client, monkeypatch, tmp_path, exit_ok=True):
        client.post("/api/stigs/import", files={"file": ("lib.zip", library_zip(), "application/zip")})
        script = tmp_path / "fake_oscap.py"
        script.write_text(FAKE_OSCAP if exit_ok else "import sys; sys.stderr.write('boom'); sys.exit(1)")
        (tmp_path / "fake_oscap.py.results").write_bytes(xccdf_results())
        real = scap.build_command
        seen = {}

        def fake(datastream, results, profile, target):
            seen["argv"] = real(datastream, results, profile, target)
            return [sys.executable, str(script)] + seen["argv"][1:]

        monkeypatch.setattr(scap, "build_command", fake)
        monkeypatch.setattr(scap, "tools", lambda: {"oscap": "/usr/bin/oscap", "oscap_ssh": "/usr/bin/oscap-ssh"})
        return seen

    def wait(self, client, scan_id):
        deadline = time.time() + 15
        while time.time() < deadline:
            meta = client.get(f"/api/scap/scans/{scan_id}").json()
            if meta["status"] != "running":
                return meta
            time.sleep(0.02)
        raise AssertionError("scan did not finish")

    def test_local_scan_end_to_end(self, client, monkeypatch, tmp_path):
        seen = self.prepare(client, monkeypatch, tmp_path)
        status = client.get("/api/scap").json()
        assert [b["id"] for b in status["benchmarks"]] == ["RHEL_8_STIG~V2R6~scap"]
        scan = client.post("/api/scap/scans", json={"entry_id": "RHEL_8_STIG~V2R6~scap"}).json()
        done = self.wait(client, scan["id"])
        assert done["status"] == "completed", done
        assert done["counts"] == {"Open": 1, "NotAFinding": 1, "Not_Applicable": 0, "Not_Reviewed": 1}
        assert seen["argv"][:3] == ["oscap", "xccdf", "eval"]
        assert seen["argv"][-1].endswith("RHEL_8_STIG__V2R6__scap.datastream.xml")
        ckl = client.get(f"/api/scap/scans/{scan['id']}/ckl")
        assert ckl.status_code == 200 and b"OpenSCAP result: fail" in ckl.content

        # the finished scan can stand in for an uploaded scan file
        with open(f"{ROOT}/data/input/rhel8-prestige-auto.ckl", "rb") as handle:
            files = {"tool1": ("prestige.ckl", handle.read(), "application/xml")}
        run = client.post("/api/runs", data=dict(FORM, tool2_scan=scan["id"]), files=files).json()
        assert run["files"][1]["scap_scan"] == scan["id"]
        assert wait_done(client, run["id"])["status"] == "completed"
        assert client.delete(f"/api/scap/scans/{scan['id']}").status_code == 204

    def test_failed_scan_reports_why(self, client, monkeypatch, tmp_path):
        self.prepare(client, monkeypatch, tmp_path, exit_ok=False)
        scan = client.post("/api/scap/scans", json={"entry_id": "RHEL_8_STIG~V2R6~scap"}).json()
        done = self.wait(client, scan["id"])
        assert done["status"] == "failed" and "boom" in done["error"]
        bad = client.post("/api/runs", data=dict(FORM, tool1_scan=scan["id"], tool2_scan=scan["id"]))
        assert bad.json()["detail"]["code"] == "scan_not_ready"

    def test_ssh_scan_command(self, client, monkeypatch, tmp_path):
        seen = self.prepare(client, monkeypatch, tmp_path)
        body = {"name": "rhel8-web", "family": "linux", "backend": "ssh", "host": "10.1.2.3", "port": 2222,
                "user": "audit", "key_path": "/keys/audit", "use_sudo": True}
        target = client.post("/api/targets", json=body).json()
        scan = client.post("/api/scap/scans",
                           json={"entry_id": "RHEL_8_STIG~V2R6~scap", "target": target["id"]}).json()
        self.wait(client, scan["id"])
        assert seen["argv"][:6] == ["oscap-ssh", "--sudo", "audit@10.1.2.3", "2222", "xccdf", "eval"]

    def test_refusals(self, client, monkeypatch, tmp_path):
        self.prepare(client, monkeypatch, tmp_path)
        post = lambda body: client.post("/api/scap/scans", json=body).json()["detail"]["code"]  # noqa: E731
        assert post({"entry_id": "RHEL_8_STIG~V2R7~manual"}) == "not_scap"
        assert post({"entry_id": "RHEL_8_STIG~V2R6~scap", "profile": "nope"}) == "profile"
        windows = client.post("/api/targets", json=WINDOWS).json()
        assert post({"entry_id": "RHEL_8_STIG~V2R6~scap", "target": windows["id"]}) == "target_backend"
        monkeypatch.setattr(scap, "tools", lambda: {"oscap": None, "oscap_ssh": None})
        assert post({"entry_id": "RHEL_8_STIG~V2R6~scap"}) == "oscap_missing"
