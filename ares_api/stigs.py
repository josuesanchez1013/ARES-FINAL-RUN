"""
STIG library endpoints and per-run STIG selection.

Content comes from DoD Cyber Exchange downloads that an operator uploads:
a single STIG zip, a SCAP benchmark zip, the full STIG Library compilation
zip, or one XCCDF .xml. See stig_library/ for parsing and storage.
"""

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile

from stig_library import LibraryStigLoader, StigImportError, StigLibrary
from stig_library.library import detect_scan_stigs

from . import config

AUTO, BUILTIN = "auto", "builtin"
BRIEF_RULE = ("vuln_id", "rule_id", "stig_id", "severity", "rule_title", "automated")


def _fail(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def get_library() -> StigLibrary:
    return StigLibrary(config.stig_library_dir())


def _sentence(parts: List[str]) -> str:
    text = "; ".join(parts)
    return text[:1].upper() + text[1:] + "."


def builtin_choice(note: str = "") -> Dict[str, Any]:
    stig = config.stig()
    return {"mode": BUILTIN, "entry_ids": [], "title": stig["title"], "version": stig["version"],
            "stig_id": "", "source": stig["source"], "detected": [], "note": note}


def _from_entries(mode: str, entries: List[Dict], detected: List[Dict], note: str) -> Dict[str, Any]:
    first = entries[0]
    return {"mode": mode, "entry_ids": [e["id"] for e in entries],
            "title": " + ".join(e["title"] for e in entries),
            "version": ", ".join(e["version_label"] for e in entries),
            "stig_id": first["key"], "source": "Imported STIG library",
            "detected": detected, "note": note}


def resolve_choice(choice: str, uploads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Turn the Run form's STIG choice into what the run records and uses.

    uploads: [{"name": ..., "data": bytes}] for the two scan files.
    Raises HTTPException for a choice that does not exist.
    """
    choice = (choice or AUTO).strip()
    library = get_library()
    if choice == BUILTIN:
        return builtin_choice()
    if choice != AUTO:
        entry = library.summary(choice)
        if entry is None:
            raise _fail(422, "stig_not_found", "The chosen STIG is not in the library. Refresh and choose again.")
        return _from_entries("library", [entry], [], "")

    detected: List[Dict[str, str]] = []
    for upload in uploads:
        for item in detect_scan_stigs(upload["name"], upload["data"]):
            if not any(d["stig_id"] == item["stig_id"] for d in detected):
                detected.append(item)
    if not detected:
        return builtin_choice("The scan files do not name a STIG, so the built-in STIG content is used.")
    matched, notes = [], []
    for item in detected:
        entry, exact = library.match(item["stig_id"], item["version"], item["release"])
        label = item["stig_id"] + (f" V{item['version']}R{item['release']}" if item["release"] else "")
        if entry is None:
            notes.append(f"{label} is not in the STIG library")
            continue
        if entry["id"] not in [m["id"] for m in matched]:
            matched.append(entry)
        if not exact:
            notes.append(f"the scans are for {label}; the closest imported release is {entry['version_label']}")
    if not matched:
        return dict(builtin_choice(_sentence(notes) + " The built-in STIG content is used."),
                    detected=detected)
    note = _sentence(notes) if notes else ""
    return _from_entries(AUTO, matched, detected, note)


def loader_for(choice: Optional[Dict[str, Any]]) -> Optional[LibraryStigLoader]:
    """The content a run should use, or None for the built-in loader."""
    if not choice or not choice.get("entry_ids"):
        return None
    library = get_library()
    entries = [library.get(i) for i in choice["entry_ids"]]
    missing = [i for i, e in zip(choice["entry_ids"], entries) if e is None]
    if missing:
        raise RuntimeError("STIG content used by this run was removed from the library: " + ", ".join(missing))
    return LibraryStigLoader(entries)


def register(app: FastAPI) -> None:
    @app.get("/api/stigs")
    def list_stigs() -> Dict[str, Any]:
        stig = config.stig()
        return {"builtin": {"title": stig["title"], "version": stig["version"], "source": stig["source"]},
                "entries": get_library().list(),
                "max_upload_mb": config.stig_import_max_bytes() // (1024 * 1024)}

    @app.post("/api/stigs/import")
    def import_stigs(file: UploadFile = File(...)) -> Dict[str, Any]:
        name = (file.filename or "upload").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if not name.lower().endswith((".zip", ".xml")):
            raise _fail(422, "file_type", f"{name}: upload a STIG .zip or an XCCDF .xml file.")
        stream = file.file
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(0)
        if size == 0:
            raise _fail(422, "file_empty", f"{name} is empty.")
        if size > config.stig_import_max_bytes():
            raise _fail(422, "file_too_large",
                        f"{name} is larger than {config.stig_import_max_bytes() // (1024 * 1024)} MB "
                        "(ARES_STIG_IMPORT_MAX_MB).")
        try:
            report = get_library().import_upload(name, stream)
        except StigImportError as exc:
            raise _fail(422, "no_stig_content", str(exc))
        return report

    @app.get("/api/stigs/{entry_id}")
    def stig_detail(entry_id: str) -> Dict[str, Any]:
        library = get_library()
        entry = library.get(entry_id)
        if entry is None:
            raise _fail(404, "stig_not_found", f"{entry_id} is not in the STIG library.")
        previous = library.previous_of(entry_id)
        detail = {k: v for k, v in entry.items() if k != "rules"}
        detail["rules"] = [{k: r.get(k) for k in BRIEF_RULE} for r in entry["rules"]]
        detail["changes"] = library.diff(previous, entry) if previous else None
        return detail

    @app.delete("/api/stigs/{entry_id}", status_code=204)
    def delete_stig(entry_id: str) -> None:
        if not get_library().delete(entry_id):
            raise _fail(404, "stig_not_found", f"{entry_id} is not in the STIG library.")
