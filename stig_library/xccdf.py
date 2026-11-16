"""
Parse DISA XCCDF content into plain dictionaries.

Handles the three shapes DISA publishes:
- "Manual" STIG benchmarks (U_<Product>_STIG_V#R#_Manual-xccdf.xml, XCCDF 1.1)
- SCAP 1.2/1.3 benchmarks (XCCDF 1.2 inside a source data stream with OVAL)
- plain XCCDF 1.2 benchmarks

Only the standard library is used. Documents with a DOCTYPE or entity
declarations are refused (DISA content never has one), which rules out
entity-expansion and external-entity attacks without adding a dependency.
"""

import hashlib
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

SEVERITY = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
OVAL_SYSTEM = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
CCI_SYSTEM = "http://cyber.mil/cci"   # older content uses http://iase.disa.mil/cci

_BENCH_PREFIX = re.compile(r"^xccdf_[^_]+(?:\.[^_]+)*_benchmark_")
_GROUP_PREFIX = re.compile(r"^xccdf_[^_]+(?:\.[^_]+)*_group_")
_RULE_PREFIX = re.compile(r"^xccdf_[^_]+(?:\.[^_]+)*_rule_")
_RELEASE = re.compile(r"Release:\s*([0-9.]+)", re.IGNORECASE)
_DATE = re.compile(r"Benchmark Date:\s*(.+)$", re.IGNORECASE)


class XccdfError(ValueError):
    """The document is not usable STIG content."""


def _local(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _child(elem: ET.Element, name: str) -> Optional[ET.Element]:
    for child in elem:
        if _local(child.tag) == name:
            return child
    return None


def _children(elem: ET.Element, name: str) -> List[ET.Element]:
    return [child for child in elem if _local(child.tag) == name]


def _text(elem: Optional[ET.Element]) -> str:
    return "".join(elem.itertext()).strip() if elem is not None else ""


def _tagged(description: str, tag: str) -> str:
    """DISA puts <VulnDiscussion> etc. inside <description> as escaped text."""
    match = re.search(rf"<{tag}>(.*?)</{tag}>", description, re.DOTALL)
    return match.group(1).strip() if match else ""


def looks_like_content(head: bytes) -> bool:
    """Cheap check on the first bytes of a .xml file found in an archive."""
    sample = head.decode("utf-8", errors="ignore")
    return "Benchmark" in sample or "data-stream-collection" in sample


def parse_document(data: bytes, source: str = "") -> List[Dict[str, Any]]:
    """Return every benchmark found in one XML document (usually one)."""
    head = data[:65536]
    if b"<!DOCTYPE" in head or b"<!ENTITY" in data:
        raise XccdfError("document declares a DOCTYPE or entities, which STIG content never does")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise XccdfError(f"not well-formed XML: {exc}") from None
    benchmarks = [root] if _local(root.tag) == "Benchmark" else \
        [e for e in root.iter() if _local(e.tag) == "Benchmark"]
    if not benchmarks:
        raise XccdfError("no XCCDF Benchmark in this document")
    kind = "scap" if _local(root.tag) == "data-stream-collection" else None
    digest = hashlib.sha256(data).hexdigest()
    return [_benchmark(b, source, digest, kind) for b in benchmarks]


def _benchmark(bench: ET.Element, source: str, digest: str, kind: Optional[str]) -> Dict[str, Any]:
    source_is_datastream = kind == "scap"
    raw_id = bench.get("id", "").strip()
    if not raw_id:
        raise XccdfError("benchmark has no id")
    key = _BENCH_PREFIX.sub("", raw_id)
    release_info = ""
    for plain in _children(bench, "plain-text"):
        if plain.get("id") == "release-info":
            release_info = _text(plain)
    version = _text(_child(bench, "version"))
    release_match = _RELEASE.search(release_info)
    date_match = _DATE.search(release_info)
    release = release_match.group(1) if release_match else ""
    status = _child(bench, "status")

    rules = [r for r in (_rule(g) for g in bench.iter() if _local(g.tag) == "Group") if r]
    automated = sum(1 for r in rules if r["automated"])
    if kind is None:
        kind = "scap" if automated else "manual"
    severity_counts = {label: 0 for label in SEVERITY.values()}
    for rule in rules:
        severity_counts[rule["severity"]] = severity_counts.get(rule["severity"], 0) + 1
    return {
        "key": key,
        "benchmark_id": raw_id,
        "title": _text(_child(bench, "title")) or key,
        "description": _text(_child(bench, "description")),
        "version": version,
        "release": release,
        "version_label": version_label(version, release),
        "release_info": release_info,
        "benchmark_date": date_match.group(1).strip() if date_match else "",
        "status_date": status.get("date", "") if status is not None else "",
        "kind": kind,
        "platforms": [p.get("idref", "") for p in _children(bench, "platform") if p.get("idref")],
        "profiles": [{"id": p.get("id", ""), "title": _text(_child(p, "title"))}
                     for p in _children(bench, "Profile") if p.get("id")],
        "datastream": kind == "scap" and source_is_datastream,
        "rule_count": len(rules),
        "automated_count": automated,
        "severity_counts": severity_counts,
        "source_file": source,
        "sha256": digest,
        "rules": rules,
    }


def _rule(group: ET.Element) -> Optional[Dict[str, Any]]:
    rule = _child(group, "Rule")
    if rule is None:
        return None
    vuln_id = _GROUP_PREFIX.sub("", group.get("id", ""))
    rule_id = _RULE_PREFIX.sub("", rule.get("id", ""))
    description = _text(_child(rule, "description"))
    check = _child(rule, "check")
    check_system = check.get("system", "") if check is not None else ""
    check_text = _text(_child(check, "check-content")) if check is not None else ""
    ccis = [_text(i) for i in _children(rule, "ident")
            if "cci" in (i.get("system") or "").lower()]
    fix = _child(rule, "fixtext")
    return {
        "vuln_id": vuln_id,
        "rule_id": rule_id,
        "stig_id": _text(_child(rule, "version")),
        "srg_id": _text(_child(group, "title")),
        "severity": SEVERITY.get((rule.get("severity") or "medium").lower(), "CAT II"),
        "rule_title": _text(_child(rule, "title")),
        "discussion": _tagged(description, "VulnDiscussion") or description,
        "check_text": check_text,
        "fix_text": _text(fix),
        "cci": ccis,
        "automated": check_system == OVAL_SYSTEM,
    }


def _number(value: str) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def version_label(version: str, release: str) -> str:
    if version and release:
        return f"V{_number(version)}R{_number(release)}"
    return f"V{version}" if version else "unversioned"


def version_order(entry: Dict[str, Any]) -> tuple:
    return (_number(entry.get("version", "")), _number(entry.get("release", "")),
            entry.get("status_date", ""))
