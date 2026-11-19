"""Bomb protection (Module 1) - limits and checks."""
import io
import zipfile
from dataclasses import dataclass
from xml.parsers import expat

from .errors import BombError, CDRError


@dataclass
class Limits:
    max_file_bytes: int = 100 * 1024 * 1024
    max_zip_ratio: int = 100            # uncompressed:compressed
    zip_ratio_min_bytes: int = 1 << 20  # ratio only enforced above 1 MiB (tiny files compress wildly)
    max_zip_total: int = 512 << 20
    max_zip_entries: int = 10_000
    max_entry_bytes: int = 256 << 20
    max_xml_depth: int = 100
    max_pixels: int = 100_000_000
    max_pdf_objects: int = 50_000
    max_pdf_pages: int = 2_000
    max_archive_depth: int = 3
    max_gif_frames: int = 500


DEFAULT_LIMITS = Limits()


class ReadBudget:
    """Cumulative cap on bytes actually inflated (declared sizes in ZIP headers can lie)."""

    def __init__(self, total):
        self.left = total

    def take(self, n):
        self.left -= n
        if self.left < 0:
            raise BombError("decompressed data exceeds total budget")


def open_zip(data, limits=DEFAULT_LIMITS):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise CDRError(f"invalid ZIP container: {e}")
    infos = zf.infolist()
    if len(infos) > limits.max_zip_entries:
        raise BombError(f"ZIP has {len(infos)} entries (limit {limits.max_zip_entries})")
    total = 0
    for i in infos:
        if i.flag_bits & 0x1:
            raise CDRError("encrypted ZIP entries cannot be sanitized")
        total += i.file_size
        if i.file_size > limits.max_entry_bytes:
            raise BombError(f"entry '{i.filename[:60]}' is {i.file_size} bytes uncompressed")
        if i.file_size > limits.zip_ratio_min_bytes and i.file_size / max(i.compress_size, 1) > limits.max_zip_ratio:
            raise BombError(
                f"entry '{i.filename[:60]}' compression ratio "
                f"{i.file_size // max(i.compress_size, 1)}:1 exceeds {limits.max_zip_ratio}:1"
            )
    if total > limits.max_zip_total:
        raise BombError(f"ZIP expands to {total} bytes (limit {limits.max_zip_total})")
    if total > limits.zip_ratio_min_bytes and total / max(len(data), 1) > limits.max_zip_ratio:
        raise BombError(f"ZIP total ratio {total // max(len(data), 1)}:1 exceeds {limits.max_zip_ratio}:1")
    return zf


def safe_read(zf, info, budget, limits=DEFAULT_LIMITS):
    """Inflate incrementally and abort when the *real* size exceeds the declared one."""
    cap = min(info.file_size + 1024, limits.max_entry_bytes)
    out = bytearray()
    with zf.open(info) as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            out += chunk
            budget.take(len(chunk))
            if len(out) > cap:
                raise BombError(f"entry '{info.filename[:60]}' inflates beyond its declared size")
    return bytes(out)


def check_xml(data, limits=DEFAULT_LIMITS):
    """Reject entity declarations (Billion Laughs / XXE) and absurd nesting. Uses expat, so
    UTF-16 and other encodings are handled the same way the real parser will see them."""
    depth = [0]

    def start(name, attrs):
        depth[0] += 1
        if depth[0] > limits.max_xml_depth:
            raise BombError(f"XML nesting deeper than {limits.max_xml_depth}")

    def end(name):
        depth[0] -= 1

    def doctype(name, sysid, pubid, has_internal):
        if has_internal:
            raise BombError("XML DOCTYPE with internal subset (entity bomb / XXE risk)")

    def entity(*a):
        raise BombError("XML entity declaration (entity bomb / XXE risk)")

    p = expat.ParserCreate()
    p.StartElementHandler = start
    p.EndElementHandler = end
    p.StartDoctypeDeclHandler = doctype
    p.EntityDeclHandler = entity
    p.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        p.Parse(data, True)
    except expat.ExpatError as e:
        raise CDRError(f"malformed XML: {e}")


def check_pixels(width, height, frames=1, limits=DEFAULT_LIMITS):
    if width * height * max(frames, 1) > limits.max_pixels:
        raise BombError(f"image decodes to {width}x{height}x{frames} pixels (limit {limits.max_pixels})")
