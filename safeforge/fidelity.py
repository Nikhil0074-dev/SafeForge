"""Fidelity scoring + visual diff (Module 7). Pure Pillow - no numpy."""
import io
import re
from collections import Counter

from PIL import Image, ImageChops, ImageFilter, ImageOps

from .office_cdr import visible_text

THRESH = 24


def render_pdf(data, pages=5, scale=1.0):
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(data)
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            doc.init_forms()
    except Exception:
        pass
    out = []
    for i in range(min(len(doc), pages)):
        p = doc[i]
        out.append(p.render(scale=scale).to_pil().convert("RGB"))
        p.close()
    return out, len(doc)


def load_image(data):
    im = Image.open(io.BytesIO(data))
    im.seek(0)
    im = ImageOps.exif_transpose(im)
    if im.mode in ("RGBA", "LA", "P"):
        im = im.convert("RGBA")
        bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
        im = Image.alpha_composite(bg, im)
    return im.convert("RGB")


def compare(a, b):
    """Return (score 0-100, diff overlay image). Score = share of 'ink' pixels that match."""
    a, b = a.convert("RGB"), b.convert("RGB")
    if b.size != a.size:
        b = b.resize(a.size)
    # 1px blur makes the metric tolerant of anti-aliasing differences between two renders of the same page
    ab, bb = a.filter(ImageFilter.GaussianBlur(1)), b.filter(ImageFilter.GaussianBlur(1))
    mask = ImageChops.difference(ab, bb).convert("L").point(lambda v: 255 if v > THRESH else 0)
    bad = mask.histogram()[255]
    ink_a = a.convert("L").point(lambda v: 255 if v < 232 else 0)
    ink_b = b.convert("L").point(lambda v: 255 if v < 232 else 0)
    ink = ImageChops.lighter(ink_a, ink_b).histogram()[255]
    score = 100.0 if ink == 0 and bad == 0 else max(0.0, 100.0 * (1 - bad / max(ink, bad, 1)))
    over = a.copy()
    over.paste(Image.new("RGB", a.size, (255, 59, 48)), mask=mask)
    return score, over


def _png(im, max_w=900):
    if im.width > max_w:
        im = im.resize((max_w, int(im.height * max_w / im.width)))
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


def text_score(orig, out):
    ta, tb = Counter(re.findall(r"\w+", orig.lower())), Counter(re.findall(r"\w+", out.lower()))
    total = sum(ta.values())
    if total == 0:
        return 100.0
    return 100.0 * sum((ta & tb).values()) / total


def measure(orig, out, kind, out_kind, previews=False):
    """Returns dict(score, method, original_png, sanitized_png, diff_png). Never raises."""
    res = {"score": None, "method": None, "original_png": None, "sanitized_png": None, "diff_png": None}
    try:
        if kind == "pdf" and out_kind == "pdf":
            a, na = render_pdf(orig)
            b, nb = render_pdf(out)
            if na != nb:
                res.update(score=0.0, method="page-count mismatch")
                return res
            scores, first = [], None
            for x, y in zip(a, b):
                s, d = compare(x, y)
                scores.append(s)
                first = first or (x, y, d)
            res.update(score=round(sum(scores) / len(scores), 2), method="pixel comparison of rendered pages")
            if previews and first:
                res.update(original_png=_png(first[0]), sanitized_png=_png(first[1]), diff_png=_png(first[2]))
        elif kind in ("png", "jpeg", "gif", "webp", "bmp", "tiff"):
            a, b = load_image(orig), load_image(out)
            s, d = compare(a, b)
            res.update(score=round(s, 2), method="pixel comparison")
            if previews:
                res.update(original_png=_png(a), sanitized_png=_png(b), diff_png=_png(d))
        elif kind in ("docx", "docm", "xlsx", "xlsm", "pptx", "pptm") and out_kind in ("docx", "xlsx", "pptx"):
            res.update(score=round(text_score(visible_text(orig, kind), visible_text(out, out_kind)), 2),
                       method="visible-text retention")
        elif kind == "pdf":
            res.update(method="not comparable")
    except Exception as e:  # fidelity is advisory; never break the pipeline
        res.update(score=None, method=f"unavailable ({type(e).__name__})")
    return res
