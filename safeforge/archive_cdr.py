"""ZIP archive sanitiser: bounded extraction, every member sanitised recursively, zip-slip names dropped."""
import io
import posixpath
import zipfile

from .errors import BlockedError
from .limits import DEFAULT_LIMITS, ReadBudget, open_zip, safe_read


def sanitize_zip(data, opts, log, sanitize_fn, depth, limits=DEFAULT_LIMITS):
    if depth >= min(opts.max_depth, limits.max_archive_depth):
        raise BlockedError(f"archive nesting deeper than {opts.max_depth} levels")
    zf = open_zip(data, limits)
    budget = ReadBudget(limits.max_zip_total)
    out, used = io.BytesIO(), set()
    kept = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for info in zf.infolist():
            if info.filename.endswith("/"):
                continue
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                log.add("PathTraversal", "high", f"zip-slip name: {info.filename[:80]}")
                continue
            payload = safe_read(zf, info, budget, limits)
            r = sanitize_fn(payload, posixpath.basename(name), depth + 1)
            if r.status != "completed":
                log.add("ArchiveEntryBlocked", "high", f"{name[:80]}: {r.reason}")
                continue
            for t in r.threats:
                if t["type"] == "Info":
                    continue
                log.add(t["type"] if t["type"].startswith("Member:") else f"Member:{t['type']}", t["risk"], f"{name[:60]}: " + "; ".join(t["details"][:2]), t["count"])
            new = posixpath.join(posixpath.dirname(name), r.out_name)
            base, n = new, 1
            while new.lower() in used:
                stem, dot, ext = base.rpartition(".")
                new = f"{stem}_{n}.{ext}" if dot else f"{base}_{n}"
                n += 1
            used.add(new.lower())
            zi = zipfile.ZipInfo(new, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o600 << 16
            z.writestr(zi, r.data)
            kept += 1
    log.add("Info", "info", f"{kept} archive member(s) sanitised")
    return out.getvalue()
