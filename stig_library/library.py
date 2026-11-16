"""
Versioned on-disk STIG library.

Layout under the library folder (default data/stig_library, git-ignored):

    index.json                 one summary per imported benchmark
    entries/<entry id>.json    the full benchmark, rules included
    imports.jsonl              one line per import, for provenance

An entry id is <benchmark key>~<version label>~<kind>, for example
RHEL_8_STIG~V2R7~manual. Importing never overwrites an older release: every
version is kept, so runs and change reports can refer to any of them.
"""

import csv
import hashlib
import io
import json
import re
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from . import archive, platforms, xccdf

SUMMARY_FIELDS = [
    "id", "key", "benchmark_id", "title", "version", "release", "version_label",
    "release_info", "benchmark_date", "status_date", "kind", "platforms", "rule_count",
    "automated_count", "severity_counts", "profiles", "datastream", "source_file", "source_upload", "sha256", "imported_at",
]
DIFF_FIELDS = ["rule_id", "severity", "rule_title", "check_text", "fix_text"]
_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")
_ENTRY = re.compile(r"[A-Za-z0-9_.-]+~[A-Za-z0-9_.-]+~(manual|scap)")


class ImportError_(ValueError):
    """An upload that could not be imported at all."""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def entry_id(key: str, label: str, kind: str) -> str:
    return "~".join(_SAFE.sub("_", part) for part in (key, label, kind))


class StigLibrary:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.lock = threading.RLock()

    # -- storage ---------------------------------------------------------------
    @property
    def _index_path(self) -> Path:
        return self.root / "index.json"

    def _read_index(self) -> Dict[str, Dict[str, Any]]:
        try:
            return json.loads(self._index_path.read_text())
        except (OSError, ValueError):
            return {}

    def _write_index(self, index: Dict[str, Dict[str, Any]]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self._index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(index, indent=1, sort_keys=True))
        tmp.replace(self._index_path)

    def _entry_path(self, ident: str) -> Path:
        if not _ENTRY.fullmatch(ident or ""):
            raise KeyError(ident)
        return self.root / "entries" / f"{ident.replace('~', '__')}.json"

    def datastream_path(self, ident: str) -> Path:
        """Where the original SCAP data stream of a scap entry is kept."""
        return self._entry_path(ident).with_suffix(".datastream.xml")

    # -- import ----------------------------------------------------------------
    def import_upload(self, filename: str, stream: BinaryIO) -> Dict[str, Any]:
        """Import every benchmark in an uploaded .zip or .xml. Returns a report."""
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        stream.seek(0)
        report: Dict[str, Any] = {
            "upload": filename, "sha256": digest.hexdigest(), "imported_at": now_iso(),
            "documents": 0, "imported": [], "unchanged": [], "errors": [], "changes": [],
        }
        budget = archive.Budget()
        found: List[Dict[str, Any]] = []
        try:
            for path, data in archive.iter_documents(filename, stream, budget):
                report["documents"] += 1
                try:
                    parsed = xccdf.parse_document(data, path)
                    for bench in parsed:
                        if bench.get("datastream"):
                            bench["_raw"] = data      # kept so OpenSCAP can run it
                    found.extend(parsed)
                except xccdf.XccdfError as exc:
                    report["errors"].append({"file": path, "error": str(exc)})
        except archive.ArchiveError as exc:
            raise ImportError_(str(exc)) from None
        report["errors"].extend({"file": p, "error": why} for p, why in budget.skipped)
        if not found:
            raise ImportError_(
                "No STIG benchmarks were found. Upload a STIG zip, a SCAP benchmark zip, the "
                "STIG Library compilation zip, or an XCCDF .xml file from DoD Cyber Exchange.")

        with self.lock:
            index = self._read_index()
            for bench in found:
                ident = entry_id(bench["key"], bench["version_label"], bench["kind"])
                existing = index.get(ident)
                if existing and existing.get("sha256") == bench["sha256"]:
                    raw = bench.pop("_raw", None)
                    if raw is not None and not self.datastream_path(ident).exists():
                        self.datastream_path(ident).write_bytes(raw)   # imported before this was kept
                    report["unchanged"].append(ident)
                    continue
                if ident in report["imported"]:
                    continue   # the same release twice in one upload
                previous = self._previous(index, bench)
                bench.update(id=ident, source_upload=filename, imported_at=report["imported_at"])
                raw = bench.pop("_raw", None)
                path = self._entry_path(ident)
                path.parent.mkdir(parents=True, exist_ok=True)
                if raw is not None:
                    self.datastream_path(ident).write_bytes(raw)
                path.write_text(json.dumps(bench))
                index[ident] = {k: bench.get(k) for k in SUMMARY_FIELDS}
                report["imported"].append(ident)
                if previous:
                    change = self.diff(previous, bench)
                    report["changes"].append({k: change[k] for k in (
                        "key", "title", "from", "to", "added_count", "removed_count", "changed_count")})
            self._write_index(index)
            with (self.root / "imports.jsonl").open("a") as log:
                log.write(json.dumps({k: report[k] for k in (
                    "upload", "sha256", "imported_at", "documents", "imported", "unchanged")}) + "\n")
        report["imported_entries"] = [index[i] for i in report["imported"]]
        return report

    def _previous(self, index: Dict[str, Dict], bench: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        older = [e for e in index.values()
                 if e["key"] == bench["key"] and e["kind"] == bench["kind"]
                 and xccdf.version_order(e) < xccdf.version_order(bench)]
        if not older:
            return None
        return self.get(max(older, key=xccdf.version_order)["id"])

    # -- queries ---------------------------------------------------------------
    def list(self) -> List[Dict[str, Any]]:
        index = self._read_index()
        latest: Dict[Tuple[str, str], Dict] = {}
        for entry in index.values():
            slot = (entry["key"], entry["kind"])
            if slot not in latest or xccdf.version_order(entry) > xccdf.version_order(latest[slot]):
                latest[slot] = entry
        scap_keys = {e["key"] for e in index.values() if e["kind"] == "scap"}
        rows = []
        for entry in index.values():
            row = dict(entry)
            row["latest"] = latest[(entry["key"], entry["kind"])]["id"] == entry["id"]
            row["scap_available"] = entry["key"] in scap_keys
            row["platform"] = platforms.classify(entry["key"], entry["title"])
            row["platform_label"] = platforms.PROFILES[row["platform"]]["label"]
            rows.append(row)
        rows.sort(key=lambda e: (e["title"].lower(), e["kind"],
                                 [-n for n in xccdf.version_order(e)[:2]]))
        return rows

    def get(self, ident: str) -> Optional[Dict[str, Any]]:
        if not _ENTRY.fullmatch(ident or "") or ident not in self._read_index():
            return None
        try:
            return json.loads(self._entry_path(ident).read_text())
        except (OSError, ValueError):
            return None

    def summary(self, ident: str) -> Optional[Dict[str, Any]]:
        return self._read_index().get(ident)

    def delete(self, ident: str) -> bool:
        with self.lock:
            index = self._read_index()
            if ident not in index:
                return False
            index.pop(ident)
            self._entry_path(ident).unlink(missing_ok=True)
            self.datastream_path(ident).unlink(missing_ok=True)
            self._write_index(index)
            return True

    def previous_of(self, ident: str) -> Optional[Dict[str, Any]]:
        index = self._read_index()
        entry = index.get(ident)
        return self._previous(index, entry) if entry else None

    @staticmethod
    def diff(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        """What changed between two releases, matched by Vuln ID."""
        before = {r["vuln_id"]: r for r in old["rules"]}
        after = {r["vuln_id"]: r for r in new["rules"]}
        brief = lambda r: {"vuln_id": r["vuln_id"], "rule_id": r["rule_id"],  # noqa: E731
                           "severity": r["severity"], "rule_title": r["rule_title"]}
        added = [brief(after[v]) for v in sorted(after.keys() - before.keys())]
        removed = [brief(before[v]) for v in sorted(before.keys() - after.keys())]
        changed = []
        for vuln in sorted(after.keys() & before.keys()):
            fields = [f for f in DIFF_FIELDS if before[vuln].get(f) != after[vuln].get(f)]
            if fields:
                row = brief(after[vuln])
                row.update(fields=fields, previous_rule_id=before[vuln]["rule_id"],
                           previous_severity=before[vuln]["severity"])
                changed.append(row)
        return {"key": new["key"], "title": new["title"],
                "from": old["version_label"], "to": new["version_label"],
                "from_id": old.get("id"), "to_id": new.get("id"),
                "added": added, "removed": removed, "changed": changed,
                "added_count": len(added), "removed_count": len(removed),
                "changed_count": len(changed)}

    # -- matching scans to content ----------------------------------------------
    def match(self, stig_id: str, version: str = "", release: str = "") -> Tuple[Optional[Dict], bool]:
        """Best manual entry for a STIG named in a scan. Returns (summary, exact)."""
        key = xccdf._BENCH_PREFIX.sub("", stig_id or "").strip()
        if not key:
            return None, False
        candidates = [e for e in self._read_index().values() if e["key"].lower() == key.lower()]
        if not candidates:
            return None, False
        candidates.sort(key=lambda e: (e["kind"] == "manual", xccdf.version_order(e)), reverse=True)
        wanted = xccdf.version_label(version, release) if version else None
        for entry in candidates:
            if wanted and entry["version_label"] == wanted and entry["kind"] == "manual":
                return entry, True
        return candidates[0], False


# ---------------------------------------------------------------------------
# Which STIGs does a scan file belong to?
# ---------------------------------------------------------------------------

def _release(text: str) -> str:
    match = xccdf._RELEASE.search(text or "")
    return match.group(1) if match else ""


def detect_scan_stigs(name: str, data: bytes) -> List[Dict[str, str]]:
    """Read the STIG id, version and release a CKL, CKLB or CSV scan declares."""
    lower = name.lower()
    found: List[Dict[str, str]] = []
    try:
        if lower.endswith(".ckl"):
            if b"<!DOCTYPE" in data[:65536] or b"<!ENTITY" in data:
                return []
            root = ET.fromstring(data)
            for istig in root.iter("STIG_INFO"):
                info = {}
                for si in istig.iter("SI_DATA"):
                    info[(si.findtext("SID_NAME") or "").strip()] = (si.findtext("SID_DATA") or "").strip()
                if info.get("stigid"):
                    found.append({"stig_id": info["stigid"], "version": info.get("version", ""),
                                  "release": _release(info.get("releaseinfo", "")),
                                  "title": info.get("title", "")})
        elif lower.endswith(".cklb"):
            for stig in json.loads(data).get("stigs", []):
                if stig.get("stig_id"):
                    found.append({"stig_id": stig["stig_id"], "version": str(stig.get("version", "")),
                                  "release": _release(stig.get("release_info", "")),
                                  "title": stig.get("stig_name", "")})
        elif lower.endswith(".csv"):
            text = data.decode("utf-8-sig", errors="replace")
            lines = text.splitlines()
            start = next((i for i, l in enumerate(lines) if "Benchmark ID" in l), None)
            if start is not None:
                seen = set()
                for row in csv.DictReader(io.StringIO("\n".join(lines[start:]))):
                    ident = (row.get("Benchmark ID") or "").strip()
                    if ident and ident not in seen:
                        seen.add(ident)
                        found.append({"stig_id": ident, "version": (row.get("Version") or "").strip(),
                                      "release": _release(row.get("Release Info") or ""),
                                      "title": (row.get("Benchmark Name") or "").strip()})
    except (ET.ParseError, ValueError, UnicodeError, csv.Error):
        return []
    return found
