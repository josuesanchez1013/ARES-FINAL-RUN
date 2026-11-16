"""
Walk an uploaded STIG download and yield the XML documents worth parsing.

Accepts a single .xml file, a STIG zip, a SCAP benchmark zip, or the full
STIG Library compilation zip, whose bundles are zips inside the zip.
Nothing is extracted to disk (so no path traversal), and size limits stop
zip bombs: per file, in total, by entry count and by nesting depth.
"""

import io
import zipfile
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator, List, Tuple

from .xccdf import looks_like_content

MAX_DEPTH = 4
MAX_MEMBER_BYTES = 256 * 1024 * 1024        # one XML or nested zip
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024    # everything read from one upload
MAX_ENTRIES = 50_000


class ArchiveError(ValueError):
    """The upload cannot be read as STIG content."""


@dataclass
class Budget:
    total: int = 0
    entries: int = 0
    skipped: List[Tuple[str, str]] = field(default_factory=list)

    def spend(self, size: int) -> None:
        self.total += size
        self.entries += 1
        if self.total > MAX_TOTAL_BYTES:
            raise ArchiveError("the upload expands to more than 8 GB; refusing to read further")
        if self.entries > MAX_ENTRIES:
            raise ArchiveError(f"the upload holds more than {MAX_ENTRIES} files; refusing to read further")


def iter_documents(name: str, stream: BinaryIO, budget: Budget) -> Iterator[Tuple[str, bytes]]:
    """Yield (path inside the upload, XML bytes) for every candidate document."""
    head = stream.read(4)
    stream.seek(0)
    if head.startswith(b"PK"):
        try:
            archive = zipfile.ZipFile(stream)
        except zipfile.BadZipFile:
            raise ArchiveError(f"{name} is not a readable zip file") from None
        yield from _walk_zip(name, archive, budget, 0)
        return
    data = stream.read(MAX_MEMBER_BYTES + 1)
    if len(data) > MAX_MEMBER_BYTES:
        raise ArchiveError(f"{name} is larger than {MAX_MEMBER_BYTES // (1024 * 1024)} MB")
    budget.spend(len(data))
    yield name, data


def _walk_zip(prefix: str, archive: zipfile.ZipFile, budget: Budget, depth: int) -> Iterator[Tuple[str, bytes]]:
    for info in archive.infolist():
        if info.is_dir():
            continue
        path = f"{prefix}/{info.filename}"
        lower = info.filename.lower()
        is_zip, is_xml = lower.endswith(".zip"), lower.endswith(".xml")
        if not (is_zip or is_xml):
            continue
        if info.file_size > MAX_MEMBER_BYTES:
            budget.skipped.append((path, "larger than the per-file limit"))
            continue
        if is_xml:
            with archive.open(info) as member:
                if not looks_like_content(member.read(4096)):
                    continue   # OVAL, CPE dictionaries and other support files
        try:
            with archive.open(info) as member:
                data = member.read(MAX_MEMBER_BYTES + 1)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:  # encrypted, corrupt
            budget.skipped.append((path, f"could not be read: {exc}"))
            continue
        if len(data) > MAX_MEMBER_BYTES:
            budget.skipped.append((path, "larger than the per-file limit"))
            continue
        budget.spend(len(data))
        if is_xml:
            yield path, data
            continue
        if depth + 1 >= MAX_DEPTH:
            budget.skipped.append((path, "zips nested too deeply"))
            continue
        try:
            nested = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            budget.skipped.append((path, "not a readable zip file"))
            continue
        yield from _walk_zip(path, nested, budget, depth + 1)
