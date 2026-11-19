"""Conversion engine (Module 6): every conversion runs on already-sanitised bytes."""
import io
import os
import shutil
import subprocess
import tempfile
import zlib

import pikepdf
from pikepdf import Array, Dictionary, Name
from PIL import Image

from .errors import BlockedError, CDRError
from .office_cdr import visible_text

TIMEOUT = 180


def soffice_available():
    return bool(shutil.which("soffice"))


def office_to_pdf(data, kind):
    """LibreOffice headless. ONLY call this with data that already went through disarm_office()."""
    exe = shutil.which("soffice")
    if not exe:
        raise BlockedError("LibreOffice not installed; cannot convert Office documents")
    ext = {"docx": ".docx", "xlsx": ".xlsx", "pptx": ".pptx", "doc": ".doc", "xls": ".xls", "ppt": ".ppt"}[kind]
    with tempfile.TemporaryDirectory(prefix="sf_lo_") as d:
        src, outdir = os.path.join(d, "input" + ext), os.path.join(d, "out")
        os.mkdir(outdir)
        with open(src, "wb") as f:
            f.write(data)
        cmd = [exe, "--headless", "--norestore", "--nolockcheck", "--nodefault", "--nologo",
               f"-env:UserInstallation=file://{d}/profile", "--convert-to", "pdf", "--outdir", outdir, src]
        env = {"PATH": os.environ.get("PATH", ""), "HOME": d, "LANG": "C.UTF-8"}
        try:
            subprocess.run(cmd, capture_output=True, timeout=TIMEOUT, env=env, cwd=d)
        except subprocess.TimeoutExpired:
            raise CDRError("LibreOffice conversion timed out")
        out = os.path.join(outdir, "input.pdf")
        if not os.path.exists(out):
            raise CDRError("LibreOffice produced no output")
        with open(out, "rb") as f:
            return f.read()


def image_to_pdf(data):
    im = Image.open(io.BytesIO(data))
    im.seek(0)
    im = im.convert("RGB")
    pdf = pikepdf.new()
    img = pdf.make_stream(zlib.compress(im.tobytes(), 6))
    img.Type, img.Subtype, img.Width, img.Height = Name.XObject, Name.Image, im.width, im.height
    img.ColorSpace, img.BitsPerComponent, img.Filter = Name.DeviceRGB, 8, Name.FlateDecode
    w, h = im.width * 0.75, im.height * 0.75
    pg = Dictionary(Type=Name.Page, MediaBox=Array([0, 0, w, h]), Resources=Dictionary(XObject=Dictionary(Im0=img)),
                    Contents=pdf.make_stream(f"q {w:.2f} 0 0 {h:.2f} 0 0 cm /Im0 Do Q".encode()))
    pdf.pages.append(pikepdf.Page(pg))
    b = io.BytesIO()
    pdf.save(b, deterministic_id=True)
    return b.getvalue()


def pdf_to_png(data, page=0, dpi=150):
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(data)
    if not 0 <= page < len(doc):
        raise CDRError(f"page {page} out of range (document has {len(doc)})")
    im = doc[page].render(scale=dpi / 72).to_pil().convert("RGB")
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


def pdf_to_text(data):
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(data)
    out = []
    for i in range(len(doc)):
        tp = doc[i].get_textpage()
        out.append(tp.get_text_range())
        tp.close()
    return "\n".join(out).encode("utf-8")


def to_text(data, kind):
    if kind == "pdf":
        return pdf_to_text(data)
    if kind in ("docx", "xlsx", "pptx"):
        return visible_text(data, kind).encode("utf-8")
    if kind in ("text", "svg", "eml"):
        return data
    raise CDRError(f"text extraction not supported for {kind}")


def convert_sanitized(data, kind, target, page=0, dpi=150):
    """Convert ALREADY-SANITISED bytes. Returns (bytes, mime, extension). PDFs produced by LibreOffice are
    re-run through the PDF disarmer by the caller (engine.sanitize) before release."""
    if target == "txt":
        return to_text(data, kind), "text/plain; charset=utf-8", "txt"
    if target == "pdf":
        if kind == "pdf":
            return data, "application/pdf", "pdf"
        if kind in ("png", "jpeg", "gif", "webp"):
            return image_to_pdf(data), "application/pdf", "pdf"
        if kind in ("docx", "xlsx", "pptx"):
            return office_to_pdf(data, kind), "application/pdf", "pdf"
        raise CDRError(f"cannot convert {kind} to pdf")
    if target == "png":
        if kind == "pdf":
            return pdf_to_png(data, page, dpi), "image/png", "png"
        if kind in ("png", "jpeg", "gif", "webp"):
            im = Image.open(io.BytesIO(data))
            im.seek(0)
            b = io.BytesIO()
            im.convert("RGBA" if "A" in im.getbands() else "RGB").save(b, "PNG")
            return b.getvalue(), "image/png", "png"
        if kind in ("docx", "xlsx", "pptx"):
            return pdf_to_png(office_to_pdf(data, kind), page, dpi), "image/png", "png"
        raise CDRError(f"cannot convert {kind} to png")
    raise CDRError(f"unknown target '{target}' (use pdf, png, txt)")
