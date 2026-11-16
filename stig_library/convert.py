"""
Turn other result formats into a CKL so the existing pipeline can read them.

- CKLB  (STIG Viewer 3 JSON checklist)
- XCCDF results (what DISA SCC and OpenSCAP write: a TestResult with one
  rule-result per rule, usually with the Benchmark in the same file)

Host identity (name, IP, MAC, FQDN) is deliberately not carried over.
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from . import xccdf

CKLB_STATUS = {"open": "Open", "not_a_finding": "NotAFinding", "notafinding": "NotAFinding",
               "not_applicable": "Not_Applicable", "not_reviewed": "Not_Reviewed"}
XCCDF_STATUS = {"pass": "NotAFinding", "fixed": "NotAFinding", "fail": "Open",
                "notapplicable": "Not_Applicable"}   # everything else: Not_Reviewed
SEVERITY_WORD = {"CAT I": "high", "CAT II": "medium", "CAT III": "low"}


class ConvertError(ValueError):
    """The file is not a usable checklist or result file."""


def _attr(name: str, value: Any) -> str:
    return (f"        <STIG_DATA><VULN_ATTRIBUTE>{name}</VULN_ATTRIBUTE>"
            f"<ATTRIBUTE_DATA>{escape(str(value or ''))}</ATTRIBUTE_DATA></STIG_DATA>")


def build_ckl(stig: Dict[str, str], rules: List[Dict[str, Any]]) -> bytes:
    """rules: vuln_id, rule_id, stig_id, severity (high/medium/low), rule_title, status, plus
    optional discussion, check_text, fix_text, cci, finding_details, comments."""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<CHECKLIST>", "  <ASSET>",
             "    <ROLE>None</ROLE>", "    <ASSET_TYPE>Computing</ASSET_TYPE>", "  </ASSET>",
             "  <STIGS>", "    <iSTIG>", "      <STIG_INFO>"]
    for name in ("version", "stigid", "releaseinfo", "title"):
        lines.append(f"        <SI_DATA><SID_NAME>{name}</SID_NAME>"
                     f"<SID_DATA>{escape(stig.get(name, ''))}</SID_DATA></SI_DATA>")
    lines.append("      </STIG_INFO>")
    for rule in rules:
        lines.extend([
            "      <VULN>",
            _attr("Vuln_Num", rule["vuln_id"]), _attr("Severity", rule.get("severity") or "medium"),
            _attr("Rule_ID", rule.get("rule_id")), _attr("Rule_Ver", rule.get("stig_id")),
            _attr("Rule_Title", rule.get("rule_title") or "No title"),
            _attr("Vuln_Discuss", rule.get("discussion")), _attr("Check_Content", rule.get("check_text")),
            _attr("Fix_Text", rule.get("fix_text")), _attr("CCI_REF", rule.get("cci")),
            f"        <STATUS>{rule.get('status') or 'Not_Reviewed'}</STATUS>",
            f"        <FINDING_DETAILS>{escape(rule.get('finding_details') or '')}</FINDING_DETAILS>",
            f"        <COMMENTS>{escape(rule.get('comments') or '')}</COMMENTS>",
            "      </VULN>",
        ])
    lines.extend(["    </iSTIG>", "  </STIGS>", "</CHECKLIST>"])
    return "\n".join(lines).encode("utf-8")


def cklb_to_ckl(data: bytes) -> bytes:
    try:
        checklist = json.loads(data)
        stigs = checklist["stigs"]
        first = stigs[0]
    except (ValueError, KeyError, IndexError, TypeError):
        raise ConvertError("not a CKLB checklist (no stigs found)") from None
    rules = []
    for stig in stigs:
        for rule in stig.get("rules", []):
            if not rule.get("group_id"):
                continue
            ccis = rule.get("ccis") or []
            rules.append({
                "vuln_id": rule["group_id"], "rule_id": rule.get("rule_id_src") or rule.get("rule_id"),
                "stig_id": rule.get("rule_version"), "severity": rule.get("severity") or "medium",
                "rule_title": rule.get("rule_title"), "discussion": rule.get("discussion"),
                "check_text": rule.get("check_content"), "fix_text": rule.get("fix_text"),
                "cci": ", ".join(ccis) if isinstance(ccis, list) else str(ccis),
                "status": CKLB_STATUS.get(str(rule.get("status", "")).lower(), "Not_Reviewed"),
                "finding_details": rule.get("finding_details"), "comments": rule.get("comments"),
            })
    if not rules:
        raise ConvertError("the CKLB checklist has no rules")
    return build_ckl({"stigid": first.get("stig_id", ""), "version": str(first.get("version", "")),
                      "releaseinfo": first.get("release_info", ""), "title": first.get("stig_name", "")}, rules)


def is_xccdf_results(data: bytes) -> bool:
    return b"TestResult" in data[:2_000_000] and b"rule-result" in data


def xccdf_results_to_ckl(data: bytes, library=None, tool: str = "SCAP") -> bytes:
    """Convert SCC / OpenSCAP XCCDF results. `library` (a StigLibrary) fills in rules the
    SCAP content does not cover as Not_Reviewed, so both scans list the same rules."""
    if b"<!DOCTYPE" in data[:65536] or b"<!ENTITY" in data:
        raise ConvertError("the results file declares a DOCTYPE or entities")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ConvertError(f"not well-formed XML: {exc}") from None
    results = [e for e in root.iter() if xccdf._local(e.tag) == "TestResult"]
    if not results:
        raise ConvertError("no XCCDF TestResult in this file")
    result = results[-1]

    known: Dict[str, Dict[str, Any]] = {}     # rule id -> rule
    stig = {"stigid": "", "version": "", "releaseinfo": "", "title": ""}
    bench_elems = [e for e in root.iter() if xccdf._local(e.tag) == "Benchmark"]
    if bench_elems:
        try:
            bench = xccdf._benchmark(bench_elems[0], "", "", None)
            stig = {"stigid": bench["key"], "version": bench["version"],
                    "releaseinfo": bench["release_info"], "title": bench["title"]}
            known = {r["rule_id"]: r for r in bench["rules"]}
        except xccdf.XccdfError:
            pass
    if not stig["stigid"]:
        ref = next((c for c in result if xccdf._local(c.tag) == "benchmark"), None)
        raw = (ref.get("id") or ref.get("href") or "") if ref is not None else ""
        stig["stigid"] = xccdf._BENCH_PREFIX.sub("", raw)
        stig["version"] = result.get("version", "")

    full: Optional[Dict[str, Any]] = None
    if library is not None and stig["stigid"]:
        release = xccdf._RELEASE.search(stig["releaseinfo"] or "")
        summary, _ = library.match(stig["stigid"], stig["version"], release.group(1) if release else "")
        if summary and summary["kind"] == "manual":
            full = library.get(summary["id"])
    by_vuln = {r["vuln_id"]: r for r in (full["rules"] if full else [])}
    by_rule = {r["rule_id"]: r for r in (full["rules"] if full else [])}

    rows: Dict[str, Dict[str, Any]] = {}
    for item in result:
        if xccdf._local(item.tag) != "rule-result":
            continue
        rule_id = xccdf._RULE_PREFIX.sub("", item.get("idref", ""))
        outcome = xccdf._text(xccdf._child(item, "result")).lower()
        if outcome == "notselected":
            continue
        rule = known.get(rule_id) or by_rule.get(rule_id) or {}
        vuln_id = rule.get("vuln_id")
        if not vuln_id:
            match = re.match(r"SV-(\d+)", rule_id)   # SV-230221r1017040_rule -> V-230221
            vuln_id = f"V-{match.group(1)}" if match else None
        if not vuln_id:
            continue
        better = by_vuln.get(vuln_id, {})
        severity = item.get("severity") or SEVERITY_WORD.get(rule.get("severity", ""), "medium")
        rows[vuln_id] = {
            "vuln_id": vuln_id, "rule_id": rule_id, "stig_id": rule.get("stig_id") or better.get("stig_id"),
            "severity": severity, "rule_title": rule.get("rule_title") or better.get("rule_title"),
            "discussion": better.get("discussion") or rule.get("discussion"),
            "check_text": better.get("check_text"), "fix_text": better.get("fix_text") or rule.get("fix_text"),
            "cci": ", ".join(better.get("cci") or rule.get("cci") or []),
            "status": XCCDF_STATUS.get(outcome, "Not_Reviewed"),
            "finding_details": f"{tool} result: {outcome}" + (f" at {item.get('time')}" if item.get("time") else ""),
        }
    if not rows:
        raise ConvertError("the results file has no rule results")
    for vuln_id, rule in by_vuln.items():      # rules the automated content does not cover
        rows.setdefault(vuln_id, {
            "vuln_id": vuln_id, "rule_id": rule["rule_id"], "stig_id": rule["stig_id"],
            "severity": SEVERITY_WORD.get(rule["severity"], "medium"), "rule_title": rule["rule_title"],
            "discussion": rule["discussion"], "check_text": rule["check_text"], "fix_text": rule["fix_text"],
            "cci": ", ".join(rule.get("cci") or []), "status": "Not_Reviewed",
            "finding_details": f"Not covered by the {tool} content.",
        })
    if full:
        stig = {"stigid": full["key"], "version": full["version"],
                "releaseinfo": full["release_info"], "title": full["title"]}
    return build_ckl(stig, list(rows.values()))


def to_ckl(name: str, data: bytes, library=None) -> Optional[bytes]:
    """CKL bytes for a .cklb or XCCDF-results .xml upload; None when no conversion applies."""
    lower = name.lower()
    if lower.endswith(".cklb"):
        return cklb_to_ckl(data)
    if lower.endswith(".xml"):
        if not is_xccdf_results(data):
            raise ConvertError("this .xml file is not an SCC or OpenSCAP XCCDF results file")
        return xccdf_results_to_ckl(data, library)
    return None
