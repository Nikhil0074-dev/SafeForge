"""SafeForge engine: detect -> bomb-check -> disarm/reconstruct -> verify -> score -> chain."""
import hashlib
import io
import posixpath
import re
import time
import uuid
from dataclasses import dataclass, field

import pikepdf

from . import (
    __version__,
    archive_cdr,
    convert,
    email_cdr,
    fidelity,
    image_cdr,
    media_cdr,
    office_cdr,
    pdf_cdr,
    svg_cdr,
    text_cdr,
)
from .errors import BlockedError, BombError, CDRError, SafeForgeError, VerificationError
from .limits import DEFAULT_LIMITS
from .policy import build_policy, to_dict
from .threats import ThreatLog
from .typedetect import BLOCKED, MIME, OOXML, detect

EXT_OUT = {"jpeg": "jpg", "text": "txt"}
RASTER = {"png", "jpeg", "gif", "webp", "bmp", "tiff"}
LEGACY = {"doc", "xls", "ppt"}


@dataclass
class Result:
    status: str                      # completed | blocked | failed
    reason: str = ""
    data: bytes | None = None
    out_name: str = ""
    mime: str = "application/octet-stream"
    out_type: str = ""
    threats: list = field(default_factory=list)
    report: dict = field(default_factory=dict)
    previews: dict = field(default_factory=dict)

    @property
    def ok(self):
        return self.status == "completed"


def _clean_name(name):
    n = (name or "file").replace("\\", "/").split("/")[-1]
    n = re.sub(r"[\x00-\x1f\"<>|:*?]", "_", n).strip(". ") or "file"
    return n[:150]


def _verify(out, out_kind, opts):
    if out_kind == "pdf":
        if opts.remove_active or opts.remove_hidden:
            return pdf_cdr.verify_pdf(out, paranoid=opts.flatten)
        pdf = pikepdf.open(io.BytesIO(out))
        return [x for x in ("/Info" in pdf.trailer and "trailer /Info", "/Metadata" in pdf.Root and "XMP") if x]
    if out_kind in OOXML:
        return office_cdr.verify_office(out, opts)
    if out_kind in RASTER:
        return image_cdr.verify_raster(out, opts)
    if out_kind == "svg":
        return svg_cdr.verify_svg(out)
    if out_kind in ("mp4", "mp3", "wav"):
        return media_cdr.verify_media(out, out_kind)
    if out_kind == "eml":
        return email_cdr.verify_eml(out)
    if out_kind == "text":
        return text_cdr.verify_text(out)
    return []


def _dispatch(data, kind, opts, log, limits, depth, nested):
    if kind == "pdf":
        out = pdf_cdr.flatten_pdf(data, opts, log, limits) if opts.flatten else pdf_cdr.disarm_pdf(data, opts, log, limits)
        return out, "pdf"
    if kind in OOXML:
        out, out_kind = office_cdr.disarm_office(data, kind, opts, log, limits)
        if opts.flatten:
            if not convert.soffice_available():
                raise BlockedError("paranoid Office mode needs LibreOffice (not installed); refusing to downgrade silently")
            pdf = convert.office_to_pdf(out, out_kind)  # converts the already-disarmed package only
            return pdf_cdr.flatten_pdf(pdf, opts, ThreatLog(), limits), "pdf"
        return out, out_kind
    if kind in LEGACY:
        if not convert.soffice_available():
            raise BlockedError("legacy binary Office formats need LibreOffice for conversion (not installed)")
        log.add("LegacyOffice", "high", "binary OLE format cannot be disarmed structurally; converted to image-only PDF (run in a sandbox)")
        pdf = convert.office_to_pdf(data, kind)
        return pdf_cdr.flatten_pdf(pdf, opts, ThreatLog(), limits), "pdf"
    if kind in RASTER:
        return image_cdr.scrub_raster(data, kind, opts, log, limits)
    if kind == "svg":
        return svg_cdr.sanitize_svg(data, opts, log, limits), "svg"
    if kind in ("mp4", "mp3", "wav"):
        return media_cdr.strip_media(data, kind, opts, log), kind
    if kind == "eml":
        return email_cdr.sanitize_eml(data, opts, log, nested, depth), "eml"
    if kind == "zip":
        return archive_cdr.sanitize_zip(data, opts, log, nested, depth, limits), "zip"
    if kind == "text":
        return text_cdr.clean_text(data, log), "text"
    raise BlockedError(f"file type '{kind}' is not supported")


def sanitize(data, filename="file", mode="balanced", overrides=None, limits=DEFAULT_LIMITS, previews=False, chain=None):
    opts = build_policy(mode, overrides)  # ValueError -> caller (API returns 400)
    return _run(data, filename, opts, limits, 0, previews, chain)


def _run(data, filename, opts, limits, depth, previews=False, chain=None):
    t0 = time.time()
    job_id = str(uuid.uuid4())
    name = _clean_name(filename)
    log = ThreatLog()
    orig_sha = hashlib.sha256(data).hexdigest()
    det = {"type": "unknown", "mime": MIME["unknown"], "extension_mismatch": False}
    original = {"name": name, "size": len(data), "sha256": orig_sha}

    def nested(d, n, dep):
        return _run(d, n, opts, limits, dep)

    def fail(status, reason):
        rep = {"job_id": job_id, "status": status, "reason": reason, "mode": opts.mode,
               "original": {**original, "true_type": det["type"], "mime": det["mime"]},
               "threats_removed": log.to_list(), "processing_time_ms": int((time.time() - t0) * 1000)}
        return Result(status=status, reason=reason, threats=log.to_list(), report=rep)

    try:
        if len(data) > limits.max_file_bytes:
            raise BombError(f"file is {len(data)} bytes (limit {limits.max_file_bytes})")
        if not data:
            raise CDRError("empty file")
        det = detect(data, name)
        kind = det["type"]
        if det["extension_mismatch"]:
            log.add("TypeSpoofing", "high", f"extension .{det['claimed_ext']} but content is {kind}")
        if kind in BLOCKED or kind in opts.block_types:
            disguised = f" (disguised as .{det['claimed_ext']})" if det["extension_mismatch"] else ""
            raise BlockedError(f"file type '{kind}' is blocked{disguised}")
        out, out_kind = _dispatch(data, kind, opts, log, limits, depth, nested)
        violations = _verify(out, out_kind, opts)
        if violations:
            raise VerificationError("; ".join(violations[:5]))
    except BombError as e:
        log.add("Bomb", "critical", str(e))
        return fail("blocked", f"bomb protection: {e}")
    except BlockedError as e:
        return fail("blocked", str(e))
    except VerificationError as e:
        return fail("failed", f"output failed independent verification: {e}")
    except SafeForgeError as e:
        return fail("failed", str(e))
    except Exception as e:  # fail closed, never leak internals
        return fail("failed", f"internal error ({type(e).__name__}); file rejected")

    stem = posixpath.splitext(name)[0] or "file"
    out_name = f"safe_{stem}.{EXT_OUT.get(out_kind, out_kind)}"
    out_sha = hashlib.sha256(out).hexdigest()
    fid = {"score": None, "method": "skipped (nested)", "original_png": None, "sanitized_png": None, "diff_png": None}
    if depth == 0:
        fid = fidelity.measure(data, out, kind, out_kind, previews)
    report = {
        "job_id": job_id, "status": "completed", "engine_version": __version__, "mode": opts.mode,
        "policy": to_dict(opts),
        "original": {**original, "true_type": kind, "mime": det["mime"]},
        "sanitized": {"name": out_name, "size": len(out), "sha256": out_sha, "mime": MIME.get(out_kind, "application/octet-stream"), "true_type": out_kind},
        "threats_removed": log.to_list(), "threat_total": log.total(),
        "fidelity_score": fid["score"], "fidelity_method": fid["method"],
        "verification": {"result": "clean", "note": "output re-parsed and re-scanned by an independent verifier"},
        "processing_time_ms": int((time.time() - t0) * 1000),
    }
    if opts.mode == "metadata_only":
        report["verification"]["note"] = "metadata_only mode does NOT remove active content"
        report["warnings"] = ["metadata_only mode leaves active content (scripts, macros) intact"]
    if chain is not None and depth == 0:
        chain_entry = chain.append(job_id, orig_sha, out_sha, opts.mode, log.total())
        report["chain_of_custody"] = {"entry_hash": chain_entry["entry_hash"], "prev_hash": chain_entry["prev_hash"]}
    return Result(status="completed", data=out, out_name=out_name, mime=report["sanitized"]["mime"], out_type=out_kind,
                  threats=log.to_list(), report=report,
                  previews={k: fid[k] for k in ("original_png", "sanitized_png", "diff_png") if fid.get(k)})
