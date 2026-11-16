"""
Offline tests for STIG import (stig_library/ and the /api/stigs endpoints).

The fixtures are built here in the same shapes DISA publishes: a "Manual"
XCCDF 1.1 benchmark, a SCAP 1.3 source data stream with XCCDF 1.2 + OVAL,
single STIG zips, and a library compilation zip whose bundles are zips.
"""

import io
import json
import os
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from ares_api.app import create_app
from genesis_integration import stig_loader as loader_module
from stig_library import LibraryStigLoader, StigImportError, StigLibrary
from stig_library.archive import Budget, iter_documents
from stig_library.library import detect_scan_stigs
from stig_library.xccdf import XccdfError, parse_document, version_label

X11 = "http://checklists.nist.gov/xccdf/1.1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def manual_rule(vuln, rule, stig_id, severity="medium", title="Rule title", check="Run: grep x /etc/x",
                fix="Set x."):
    return f"""
  <Group id="{vuln}"><title>SRG-OS-000480-GPOS-00227</title>
    <Rule id="{rule}" weight="10.0" severity="{severity}">
      <version>{stig_id}</version><title>{title}</title>
      <description>&lt;VulnDiscussion&gt;Why {vuln} matters.&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;&lt;/FalsePositives&gt;</description>
      <reference><dc:publisher xmlns:dc="http://purl.org/dc/elements/1.1/">DISA</dc:publisher></reference>
      <ident system="http://cyber.mil/legacy">{vuln}</ident>
      <ident system="http://cyber.mil/cci">CCI-000366</ident>
      <fixtext fixref="F-1">{fix}</fixtext><fix id="F-1" />
      <check system="C-1_chk"><check-content-ref href="x" name="M" /><check-content>{check}</check-content></check>
    </Rule></Group>"""


def manual_xccdf(bench="RHEL_8_STIG", title="Red Hat Enterprise Linux 8 Security Technical Implementation Guide",
                 version="2", release="7", rules=None):
    rules = rules if rules is not None else [
        manual_rule("V-230221", "SV-230221r1017040_rule", "RHEL-08-010000", "high", "RHEL 8 must be supported."),
        manual_rule("V-230222", "SV-230222r627750_rule", "RHEL-08-010010", "medium", "Patches installed."),
        manual_rule("V-230223", "SV-230223r627750_rule", "RHEL-08-010020", "low", "FIPS mode."),
    ]
    return f"""<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:cpe="http://cpe.mitre.org/language/2.0" xmlns:xhtml="http://www.w3.org/1999/xhtml"
  xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" id="{bench}" xml:lang="en" xmlns="{X11}">
  <status date="2026-04-01">accepted</status><title>{title}</title>
  <description>This STIG is published as a tool to improve security.</description>
  <notice id="terms-of-use" xml:lang="en"></notice>
  <front-matter xml:lang="en"></front-matter><rear-matter xml:lang="en"></rear-matter>
  <reference href="https://cyber.mil"><dc:publisher>DISA</dc:publisher></reference>
  <plain-text id="release-info">Release: {release} Benchmark Date: 01 Apr 2026</plain-text>
  <plain-text id="generator">3.4.1.229</plain-text>
  <version>{version}</version>
  <Profile id="MAC-1_Classified"><title>I - Mission Critical Classified</title></Profile>
  {''.join(rules)}
</Benchmark>""".encode()


def scap_datastream():
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"
    id="scap_mil.disa.stig_collection_U_RHEL_8_V2R6_STIG_SCAP_1-3_Benchmark" schematron-version="1.3">
  <ds:component id="scap_mil.disa.stig_comp_U_RHEL_8_V2R6_STIG_SCAP_1-3_Benchmark-xccdf.xml">
    <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_mil.disa.stig_benchmark_RHEL_8_STIG">
      <status date="2026-01-01">accepted</status>
      <title>Red Hat Enterprise Linux 8 STIG SCAP Benchmark</title>
      <plain-text id="release-info">Release: 6 Benchmark Date: 01 Jan 2026</plain-text>
      <platform idref="cpe:/o:redhat:enterprise_linux:8" />
      <version>2</version>
      <Group id="xccdf_mil.disa.stig_group_V-230221"><title>SRG-OS-000480-GPOS-00227</title>
        <Rule id="xccdf_mil.disa.stig_rule_SV-230221r1017040_rule" severity="high">
          <version>RHEL-08-010000</version><title>RHEL 8 must be supported.</title>
          <ident system="http://cyber.mil/cci">CCI-000366</ident>
          <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
            <check-content-ref href="#scap_mil.disa.stig_cref_U_RHEL_8-oval.xml" name="oval:mil.disa.stig.rhel8os:def:1" />
          </check>
        </Rule></Group>
      <Group id="xccdf_mil.disa.stig_group_V-230222"><title>SRG</title>
        <Rule id="xccdf_mil.disa.stig_rule_SV-230222r627750_rule" severity="medium">
          <version>RHEL-08-010010</version><title>Patches installed.</title>
          <check system="http://scap.nist.gov/schema/ocil/2"><check-content-ref href="#ocil" name="ocil:1" /></check>
        </Rule></Group>
    </Benchmark>
  </ds:component>
  <ds:component id="oval"><oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" /></ds:component>
</ds:data-stream-collection>"""


def zip_of(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def windows_xccdf():
    return manual_xccdf("MS_Windows_Server_2022_STIG", "Microsoft Windows Server 2022 STIG", "2", "4", [
        manual_rule("V-254238", "SV-254238r1016300_rule", "WN22-00-000010", "high", "Admins limited."),
        manual_rule("V-254239", "SV-254239r958384_rule", "WN22-00-000020", "medium", "Passwords."),
    ])


def library_zip():
    """Shaped like the DISA STIG Library compilation: bundles are zips inside the zip."""
    rhel = zip_of({"U_RHEL_8_V2R7_STIG/U_RHEL_8_STIG_V2R7_Manual-xccdf.xml": manual_xccdf(),
                   "U_RHEL_8_V2R7_STIG/U_RHEL_8_V2R7_Revision_History.pdf": b"%PDF-1.4",
                   "U_RHEL_8_V2R7_STIG/U_STIG_Viewer.xsl": b"<xsl/>"})
    win = zip_of({"U_MS_Windows_Server_2022_V2R4_Manual_STIG/U_MS_Windows_Server_2022_STIG_V2R4_Manual-xccdf.xml":
                  windows_xccdf()})
    scap = zip_of({"U_RHEL_8_V2R6_STIG_SCAP_1-3_Benchmark.xml": scap_datastream(),
                   "U_RHEL_8_V2R6_STIG_SCAP_1-3_Benchmark-oval.xml":
                   b"<oval_definitions xmlns='http://oval.mitre.org/XMLSchema/oval-definitions-5'/>"})
    return zip_of({"U_SRG-STIG_Library_2026_10/U_RHEL_8_V2R7_STIG.zip": rhel,
                   "U_SRG-STIG_Library_2026_10/U_MS_Windows_Server_2022_V2R4_STIG.zip": win,
                   "U_SRG-STIG_Library_2026_10/U_RHEL_8_V2R6_STIG_SCAP_1-3_Benchmark.zip": scap,
                   "U_SRG-STIG_Library_2026_10/README.txt": b"readme"})


# ---------------------------------------------------------------- parsing

class TestXccdf:
    def test_manual_benchmark(self):
        [bench] = parse_document(manual_xccdf(), "file.xml")
        assert bench["key"] == "RHEL_8_STIG"
        assert bench["version_label"] == "V2R7"
        assert bench["benchmark_date"] == "01 Apr 2026"
        assert bench["kind"] == "manual"
        assert bench["rule_count"] == 3
        assert bench["severity_counts"] == {"CAT I": 1, "CAT II": 1, "CAT III": 1}
        rule = bench["rules"][0]
        assert rule["vuln_id"] == "V-230221"
        assert rule["rule_id"] == "SV-230221r1017040_rule"
        assert rule["stig_id"] == "RHEL-08-010000"
        assert rule["severity"] == "CAT I"
        assert rule["discussion"] == "Why V-230221 matters."
        assert rule["check_text"] == "Run: grep x /etc/x"
        assert rule["cci"] == ["CCI-000366"]
        assert rule["automated"] is False

    def test_scap_datastream(self):
        [bench] = parse_document(scap_datastream(), "scap.xml")
        assert bench["key"] == "RHEL_8_STIG"          # prefix stripped, matches the manual STIG
        assert bench["kind"] == "scap"
        assert bench["version_label"] == "V2R6"
        assert bench["platforms"] == ["cpe:/o:redhat:enterprise_linux:8"]
        assert [r["vuln_id"] for r in bench["rules"]] == ["V-230221", "V-230222"]
        assert bench["rules"][0]["rule_id"] == "SV-230221r1017040_rule"
        assert bench["automated_count"] == 1        # OVAL yes, OCIL (questionnaire) no

    def test_refuses_entities(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE b [<!ENTITY x "y">]><Benchmark id="a">&x;</Benchmark>'
        with pytest.raises(XccdfError, match="DOCTYPE"):
            parse_document(evil)

    def test_refuses_non_stig_xml(self):
        with pytest.raises(XccdfError):
            parse_document(b"<root/>")
        with pytest.raises(XccdfError):
            parse_document(b"<Benchmark")

    def test_version_label(self):
        assert version_label("2", "7") == "V2R7"
        assert version_label("1", "0.1") == "V1R0"
        assert version_label("3", "") == "V3"
        assert version_label("", "") == "unversioned"


# ---------------------------------------------------------------- archives

class TestArchive:
    def test_walks_nested_library_zip(self):
        docs = list(iter_documents("lib.zip", io.BytesIO(library_zip()), Budget()))
        names = [p.rsplit("/", 1)[-1] for p, _ in docs]
        assert sorted(names) == ["U_MS_Windows_Server_2022_STIG_V2R4_Manual-xccdf.xml",
                                 "U_RHEL_8_STIG_V2R7_Manual-xccdf.xml",
                                 "U_RHEL_8_V2R6_STIG_SCAP_1-3_Benchmark.xml"]   # OVAL-only file skipped

    def test_plain_xml_upload(self):
        docs = list(iter_documents("a.xml", io.BytesIO(manual_xccdf()), Budget()))
        assert len(docs) == 1

    def test_nesting_limit(self):
        data = zip_of({"inner.xml": manual_xccdf()})
        for level in range(6):
            data = zip_of({f"level{level}.zip": data})
        budget = Budget()
        assert list(iter_documents("deep.zip", io.BytesIO(data), budget)) == []
        assert any("nested too deeply" in why for _, why in budget.skipped)

    def test_bad_zip(self):
        from stig_library.archive import ArchiveError
        with pytest.raises(ArchiveError):
            list(iter_documents("x.zip", io.BytesIO(b"PK\x03\x04garbage"), Budget()))


# ---------------------------------------------------------------- library

@pytest.fixture
def library(tmp_path):
    return StigLibrary(tmp_path / "lib")


class TestLibrary:
    def test_import_full_library(self, library):
        report = library.import_upload("U_SRG-STIG_Library.zip", io.BytesIO(library_zip()))
        assert sorted(report["imported"]) == ["MS_Windows_Server_2022_STIG~V2R4~manual",
                                              "RHEL_8_STIG~V2R6~scap", "RHEL_8_STIG~V2R7~manual"]
        assert report["errors"] == []
        rows = {r["id"]: r for r in library.list()}
        assert rows["RHEL_8_STIG~V2R7~manual"]["scap_available"] is True
        assert rows["MS_Windows_Server_2022_STIG~V2R4~manual"]["scap_available"] is False
        assert all(r["latest"] for r in rows.values())
        assert rows["RHEL_8_STIG~V2R7~manual"]["source_upload"] == "U_SRG-STIG_Library.zip"
        assert len(library.get("RHEL_8_STIG~V2R7~manual")["rules"]) == 3

    def test_reimport_is_unchanged(self, library):
        library.import_upload("a.zip", io.BytesIO(library_zip()))
        again = library.import_upload("a.zip", io.BytesIO(library_zip()))
        assert again["imported"] == [] and len(again["unchanged"]) == 3
        assert (library.root / "imports.jsonl").read_text().count("\n") == 2

    def test_new_release_keeps_old_and_reports_changes(self, library):
        library.import_upload("v2r7.xml", io.BytesIO(manual_xccdf()))
        newer = manual_xccdf(release="8", rules=[
            manual_rule("V-230221", "SV-230221r1099999_rule", "RHEL-08-010000", "high", "RHEL 8 must be supported.",
                        check="Run: cat /etc/redhat-release"),
            manual_rule("V-230223", "SV-230223r627750_rule", "RHEL-08-010020", "low", "FIPS mode."),
            manual_rule("V-299999", "SV-299999r1_rule", "RHEL-08-099999", "medium", "A new rule."),
        ])
        report = library.import_upload("v2r8.xml", io.BytesIO(newer))
        [change] = report["changes"]
        assert (change["from"], change["to"]) == ("V2R7", "V2R8")
        assert (change["added_count"], change["removed_count"], change["changed_count"]) == (1, 1, 1)
        rows = {r["id"]: r for r in library.list()}
        assert rows["RHEL_8_STIG~V2R7~manual"]["latest"] is False
        assert rows["RHEL_8_STIG~V2R8~manual"]["latest"] is True
        diff = library.diff(library.get("RHEL_8_STIG~V2R7~manual"), library.get("RHEL_8_STIG~V2R8~manual"))
        assert diff["changed"][0]["fields"] == ["rule_id", "check_text"]
        assert diff["removed"][0]["vuln_id"] == "V-230222"

    def test_nothing_found(self, library):
        with pytest.raises(StigImportError, match="No STIG benchmarks"):
            library.import_upload("empty.zip", io.BytesIO(zip_of({"readme.txt": b"x"})))

    def test_bad_documents_are_reported_not_fatal(self, library):
        upload = zip_of({"good-xccdf.xml": manual_xccdf(), "broken-Benchmark.xml": b"<Benchmark id='x'"})
        report = library.import_upload("mixed.zip", io.BytesIO(upload))
        assert report["imported"] == ["RHEL_8_STIG~V2R7~manual"]
        assert report["errors"][0]["file"].endswith("broken-Benchmark.xml")

    def test_match_prefers_exact_manual_release(self, library):
        library.import_upload("lib.zip", io.BytesIO(library_zip()))
        library.import_upload("v2r8.xml", io.BytesIO(manual_xccdf(release="8")))
        entry, exact = library.match("RHEL_8_STIG", "2", "7")
        assert entry["id"] == "RHEL_8_STIG~V2R7~manual" and exact
        entry, exact = library.match("RHEL_8_STIG", "2", "9")
        assert entry["id"] == "RHEL_8_STIG~V2R8~manual" and not exact
        assert library.match("Unknown_STIG") == (None, False)

    def test_delete_and_unsafe_ids(self, library):
        library.import_upload("a.xml", io.BytesIO(manual_xccdf()))
        assert library.get("../../etc/passwd") is None
        assert library.delete("RHEL_8_STIG~V2R7~manual") is True
        assert library.list() == []
        assert library.delete("RHEL_8_STIG~V2R7~manual") is False


class TestLoader:
    def test_same_interface_as_builtin_loader(self, library):
        library.import_upload("a.xml", io.BytesIO(manual_xccdf()))
        loader = LibraryStigLoader([library.get("RHEL_8_STIG~V2R7~manual")])
        assert loader.get_all_vuln_ids() == ["V-230221", "V-230222", "V-230223"]
        assert loader.get_check_text("V-230221") == "Run: grep x /etc/x"
        rule = loader.get_rule_data("V-230221")
        for key in ("vuln_id", "rule_id", "stig_id", "severity", "rule_title", "discussion",
                    "check_text", "fix_text"):
            assert key in rule
        assert rule["severity"] == "CAT I"
        assert loader.get_rule_data("V-000000") is None

    def test_override_reaches_get_stig_loader(self, library):
        library.import_upload("a.xml", io.BytesIO(windows_xccdf()))
        loader = LibraryStigLoader([library.get("MS_Windows_Server_2022_STIG~V2R4~manual")])
        loader_module.set_stig_loader_override(loader)
        try:
            assert loader_module.get_stig_loader() is loader
        finally:
            loader_module.set_stig_loader_override(None)
        assert loader_module.get_stig_loader() is not loader


class TestDetectScanStigs:
    def test_sample_scans(self):
        for name in ("rhel8-prestige-auto.ckl", "rhel8-prestige-auto.cklb", "rhel8-prestige-auto.csv"):
            with open(f"{ROOT}/data/input/{name}", "rb") as handle:
                found = detect_scan_stigs(name, handle.read())
            assert found and found[0]["stig_id"] == "RHEL_8_STIG", name
            assert (found[0]["version"], found[0]["release"]) == ("2", "7"), name

    def test_unknown_or_broken(self):
        assert detect_scan_stigs("a.ckl", b"<CHECKLIST/>") == []
        assert detect_scan_stigs("a.ckl", b"<CHECK") == []
        assert detect_scan_stigs("a.csv", b"Vuln_ID,Status\nV-1,Open\n") == []


# ---------------------------------------------------------------- API

FORM = {"classification": "CUI", "sensitivity": "None", "primary_model": "model-a", "secondary_model": ""}


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ARES_USE_MOCK", "true")
    monkeypatch.setenv("ARES_MOCK_STEP_DELAY", "0")
    monkeypatch.setenv("ARES_LLM_MODELS", "model-a,model-b")
    monkeypatch.setenv("ARES_STIG_LIBRARY_DIR", str(tmp_path / "stig_library"))
    return TestClient(create_app(tmp_path / "runs"))


def sample_scans():
    with open(f"{ROOT}/data/input/rhel8-prestige-auto.ckl", "rb") as a, \
            open(f"{ROOT}/data/input/rhel8-evaluatestig-remote-ansible.ckl", "rb") as b:
        return {"tool1": ("a.ckl", a.read(), "application/xml"),
                "tool2": ("b.ckl", b.read(), "application/xml")}


def wait_done(client, run_id):
    deadline = time.time() + 15
    while time.time() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in ("completed", "failed"):
            return run
        time.sleep(0.02)
    raise AssertionError("run did not finish")


class TestStigApi:
    def test_import_list_detail_delete(self, client):
        assert client.get("/api/stigs").json()["entries"] == []
        response = client.post("/api/stigs/import",
                               files={"file": ("U_SRG-STIG_Library.zip", library_zip(), "application/zip")})
        assert response.status_code == 200, response.text
        assert len(response.json()["imported"]) == 3
        listing = client.get("/api/stigs").json()
        assert len(listing["entries"]) == 3
        assert listing["builtin"]["version"]
        detail = client.get("/api/stigs/RHEL_8_STIG~V2R7~manual").json()
        assert detail["rule_count"] == 3 and "check_text" not in detail["rules"][0]
        assert detail["changes"] is None
        assert client.get("/api/settings").json()["stig_library"]["count"] == 3
        assert client.delete("/api/stigs/RHEL_8_STIG~V2R7~manual").status_code == 204
        assert client.get("/api/stigs/RHEL_8_STIG~V2R7~manual").status_code == 404

    def test_import_rejects(self, client):
        bad_type = client.post("/api/stigs/import", files={"file": ("x.pdf", b"%PDF", "application/pdf")})
        assert bad_type.json()["detail"]["code"] == "file_type"
        empty = client.post("/api/stigs/import", files={"file": ("x.zip", b"", "application/zip")})
        assert empty.json()["detail"]["code"] == "file_empty"
        nothing = client.post("/api/stigs/import",
                              files={"file": ("x.zip", zip_of({"a.txt": b"a"}), "application/zip")})
        assert nothing.status_code == 422 and nothing.json()["detail"]["code"] == "no_stig_content"

    def test_run_auto_detects_imported_stig(self, client):
        client.post("/api/stigs/import", files={"file": ("lib.zip", library_zip(), "application/zip")})
        run = client.post("/api/runs", data=FORM, files=sample_scans()).json()
        assert run["stig"]["mode"] == "auto"
        assert run["stig"]["entry_ids"] == ["RHEL_8_STIG~V2R7~manual"]
        assert run["stig"]["note"] == ""
        done = wait_done(client, run["id"])
        assert done["status"] == "completed"
        cklb = json.loads(client.get(f"/api/runs/{run['id']}/export/cklb").content)
        assert cklb["stigs"][0]["stig_id"] == "RHEL_8_STIG"
        assert cklb["stigs"][0]["version"] == "V2R7"
        ckl = client.get(f"/api/runs/{run['id']}/export/ckl").text
        assert "Red Hat Enterprise Linux 8 Security Technical Implementation Guide" in ckl

    def test_run_auto_falls_back_to_builtin(self, client):
        run = client.post("/api/runs", data=FORM, files=sample_scans()).json()
        assert run["stig"]["mode"] == "builtin"
        assert run["stig"]["note"].startswith("RHEL_8_STIG V2R7 is not in the STIG library")
        assert run["stig"]["detected"][0]["stig_id"] == "RHEL_8_STIG"
        wait_done(client, run["id"])

    def test_run_with_explicit_choice(self, client):
        client.post("/api/stigs/import", files={"file": ("lib.zip", library_zip(), "application/zip")})
        form = dict(FORM, stig="MS_Windows_Server_2022_STIG~V2R4~manual")
        run = client.post("/api/runs", data=form, files=sample_scans()).json()
        assert run["stig"]["title"] == "Microsoft Windows Server 2022 STIG"
        wait_done(client, run["id"])
        missing = client.post("/api/runs", data=dict(FORM, stig="Nope~V1R1~manual"), files=sample_scans())
        assert missing.json()["detail"]["code"] == "stig_not_found"

    def test_run_builtin_choice_matches_previous_behaviour(self, client):
        run = client.post("/api/runs", data=dict(FORM, stig="builtin"), files=sample_scans()).json()
        assert run["stig"]["mode"] == "builtin" and run["stig"]["entry_ids"] == []
        wait_done(client, run["id"])
        cklb = json.loads(client.get(f"/api/runs/{run['id']}/export/cklb").content)
        assert cklb["stigs"][0]["stig_id"] == "RHEL_8_STIG"   # same as before this feature


def test_bridge_serves_library_content_to_the_orchestrator(monkeypatch, tmp_path):
    """The real pipeline reads STIG content through get_stig_loader(); a run that
    chose imported content must see it there, and only for that step."""
    import sys
    import types

    from ares_api import stigs
    from ares_api.pipeline import STEPS, BridgePipeline
    from ares_api.runs import RunStore

    monkeypatch.setenv("ARES_STIG_LIBRARY_DIR", str(tmp_path / "lib"))
    StigLibrary(tmp_path / "lib").import_upload("win.xml", io.BytesIO(windows_xccdf()))

    seen = {}
    orch = types.ModuleType("ui.orchestrator_runner")
    orch.st, orch.AGENT_IDS, orch.LocalAgentExecutor = None, {"parser": "a"}, object

    def execute_next_step(use_mock=True):
        from genesis_integration.stig_loader import get_stig_loader
        loader = get_stig_loader()
        seen["ids"] = loader.get_all_vuln_ids()
        seen["title"] = loader.get_rule_data("V-254238")["rule_title"]
        orch.st.session_state.parser_output = {"tool1_findings": [], "tool2_findings": []}

    orch.execute_next_step = execute_next_step
    package = types.ModuleType("ui")
    package.orchestrator_runner = orch
    monkeypatch.setitem(sys.modules, "ui", package)
    monkeypatch.setitem(sys.modules, "ui.orchestrator_runner", orch)

    run = RunStore(tmp_path / "runs").create(steps=STEPS, files=[], declaration={},
                                             models={"primary": ""}, mock=False)
    run.meta["stig"] = stigs.resolve_choice("MS_Windows_Server_2022_STIG~V2R4~manual", [])
    BridgePipeline().run_step(0, run)
    assert seen == {"ids": ["V-254238", "V-254239"], "title": "Admins limited."}
    assert loader_module._stig_loader_override is None
