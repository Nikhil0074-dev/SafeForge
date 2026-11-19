"""PDF Content Disarm & Reconstruction (Modules 2-5).

balanced  : build a brand-new PDF, copy only page content, strip actions/annotations/forms/metadata.
paranoid  : rasterise every page with pdfium and rebuild a PDF containing only images.
"""
import io
import zlib

import pikepdf
from pikepdf import Array, Dictionary, Name, Stream

from .errors import BombError, CDRError
from .limits import DEFAULT_LIMITS

SAFE_URI = ("http://", "https://", "mailto:")
ANNOT_KEEP_MARKUP = {"/Highlight", "/Underline", "/StrikeOut", "/Squiggly", "/Square", "/Circle",
                     "/Line", "/Ink", "/FreeText", "/Stamp", "/Polygon", "/PolyLine", "/Caret"}
ANNOT_STRIP_KEYS = ["/Popup", "/IRT", "/RC", "/Contents", "/T", "/Subj", "/A", "/AA", "/P", "/Parent", "/RT", "/NM"]
DANGEROUS_KEYS = ["/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EF", "/EmbeddedFiles", "/XFA",
                  "/RichMedia", "/RichMediaContent", "/Movie", "/Sound", "/Rendition", "/3D", "/3DD", "/AcroForm"]
METADATA_KEYS = ["/Metadata", "/PieceInfo", "/Thumb", "/LastModified"]
BAD_ACTIONS = {"/JavaScript", "/Launch", "/GoToR", "/GoToE", "/SubmitForm", "/ImportData", "/Rendition",
               "/Movie", "/Sound", "/Hide", "/SetOCGState", "/RichMediaExecute", "/GoTo3DView", "/ResetForm"}
MEDIA_SUBTYPES = {"/Movie", "/Sound", "/Screen", "/RichMedia", "/3D"}


def _isdict(o):
    return isinstance(o, (Dictionary, Stream))


def _snippet(v):
    try:
        if isinstance(v, Stream):
            return v.read_bytes()[:200].decode("latin-1")
        return str(v)[:200]
    except Exception:
        return "<unreadable>"


def _objnum(o):
    try:
        return o.objgen[0]
    except Exception:
        return 0


# ----------------------------------------------------------------------------- detection
def scan_source(src, data, log, opts):
    """Report everything dangerous or private in the ORIGINAL file (no mutation)."""
    if src.is_encrypted:
        log.add("Encryption", "info", "encryption removed in output")
    if data.count(b"%%EOF") > 1:
        log.add("HiddenData", "medium", f"{data.count(b'%%EOF')} incremental revisions (older versions discarded)")
    try:
        for k, v in src.docinfo.items():
            log.add("Metadata", "low", f"{str(k)[1:]}: {str(v)[:120]}")
    except Exception:
        pass
    if "/Metadata" in src.Root:
        log.add("Metadata", "low", "XMP metadata packet")
    try:
        for name in src.attachments.keys():
            log.add("EmbeddedFile", "high", f"attachment: {name}", count=0)   # name only; the stream below is what gets counted
    except Exception:
        pass
    def fn(obj):
        keys = set(obj.keys())
        n = _objnum(obj)
        where = f"object {n}" if n else "inline"
        if "/JS" in keys:
            log.add("JavaScript", "critical", f"{where}: {_snippet(obj.get('/JS'))}")
        s = str(obj.get("/S")) if "/S" in keys else ""
        if s == "/Launch":
            log.add("Launch", "critical", f"{where}: {_snippet(obj.get('/F', obj.get('/Win', '')))}")
        elif s in BAD_ACTIONS and s != "/JavaScript":
            log.add("ExternalAction", "high", f"{where}: {s[1:]}")
        elif s == "/URI":
            uri = str(obj.get("/URI", ""))
            if not uri.lower().startswith(SAFE_URI):
                log.add("DangerousURI", "high", f"{where}: {uri[:100]}")
        if str(obj.get("/Type")) == "/EmbeddedFile":
            log.add("EmbeddedFile", "high", f"{where}: {obj.get('/Subtype', 'embedded stream')}")
        sub = str(obj.get("/Subtype")) if "/Subtype" in keys else ""
        if sub in MEDIA_SUBTYPES or "/RichMedia" in keys:
            log.add("ActiveMedia", "high", f"{where}: {sub[1:] or 'RichMedia'}")
        if "/XFA" in keys:
            log.add("XFA", "high", f"{where}: XFA forms (scriptable XML)")
        if "/AA" in keys:
            log.add("AdditionalActions", "medium", f"{where}: automatic triggers")
        if "/Filter" in keys and "JBIG2Decode" in str(obj.get("/Filter")):
            log.add("DecoderRisk", "medium", f"{where}: JBIG2 stream (decoder exploit surface; use paranoid mode)")

    _walk_all(src, fn)


def _walk_all(pdf, fn):
    """Visit every dictionary/stream in the file: trailer graph, direct objects AND unreachable stale objects."""
    seen = set()
    _walk(pdf.trailer, fn, seen)
    for obj in pdf.objects:
        _walk(obj, fn, seen)


# ----------------------------------------------------------------------------- cleaning
def _off_ocgs(src):
    off = set()
    try:
        ocp = src.Root.get("/OCProperties")
        if ocp is None:
            return off
        d = ocp.get("/D", {})
        for o in d.get("/OFF", []):
            off.add(o.objgen)
        if str(d.get("/BaseState")) == "/OFF":
            on = {o.objgen for o in d.get("/ON", [])}
            for o in ocp.get("/OCGs", []):
                if o.objgen not in on:
                    off.add(o.objgen)
    except Exception:
        pass
    return off


def _filter_content(src, page, off, opts, log):
    res = page.obj.get("/Resources")
    props = res.get("/Properties") if res is not None else None
    xobjs = res.get("/XObject") if res is not None else None
    if not opts.remove_hidden:
        return
    try:
        instrs = pikepdf.parse_content_stream(page)
    except Exception as e:
        raise CDRError(f"cannot parse page content stream: {e}")
    out, skip, tr, stack = [], 0, 0, []
    hidden_layer = invisible = 0
    for it in instrs:
        if not isinstance(it, pikepdf.ContentStreamInstruction):
            out.append(it)
            continue
        op, args = str(it.operator), it.operands
        if skip:
            if op in ("BDC", "BMC"):
                skip += 1
            elif op == "EMC":
                skip -= 1
            continue
        if op == "BDC" and len(args) == 2 and str(args[0]) == "/OC" and props is not None:
            ocg = props.get(str(args[1]))
            if ocg is not None and ocg.objgen in off:
                skip, hidden_layer = 1, hidden_layer + 1
                continue
        if op == "Do" and xobjs is not None and args:
            xo = xobjs.get(str(args[0]))
            if xo is not None and "/OC" in xo and xo.get("/OC").objgen in off:
                hidden_layer += 1
                continue
        if op == "q":
            stack.append(tr)
        elif op == "Q" and stack:
            tr = stack.pop()
        elif op == "Tr" and args:
            tr = int(args[0])
        if opts.remove_hidden and tr == 3 and op in ("Tj", "TJ", "'", '"'):
            invisible += 1
            if op in ("'", '"'):
                out.append(pikepdf.ContentStreamInstruction([], pikepdf.Operator("T*")))
            continue
        out.append(it)
    if hidden_layer or invisible:
        page.obj["/Contents"] = src.make_stream(pikepdf.unparse_content_stream(out))
        if hidden_layer:
            log.add("HiddenLayer", "medium", f"{hidden_layer} content block(s) in hidden optional-content layers", hidden_layer)
        if invisible:
            log.add("HiddenText", "medium", f"{invisible} invisible text run(s) (render mode 3)", invisible)


def _clean_annot(a, opts, log):
    if not _isdict(a):
        return None
    sub = str(a.get("/Subtype", ""))
    if sub == "/Link":
        act = a.get("/A")
        if opts.keep_links and act is not None and _isdict(act) and str(act.get("/S")) == "/URI":
            uri = str(act.get("/URI", ""))
            if uri.lower().startswith(SAFE_URI):
                return Dictionary(Type=Name.Annot, Subtype=Name.Link, Rect=a.get("/Rect", Array([0, 0, 0, 0])),
                                  Border=Array([0, 0, 0]), A=Dictionary(S=Name.URI, URI=pikepdf.String(uri)))
        return None
    if sub == "/Widget":
        ap = a.get("/AP")
        n = ap.get("/N") if ap is not None else None
        if n is not None and not isinstance(n, Stream) and isinstance(n, Dictionary):
            st = a.get("/AS")
            n = n.get(str(st)) if st is not None else None
        if n is None or not isinstance(n, Stream):
            return None
        log.add("FormField", "info", "interactive form field flattened to static appearance")
        return Dictionary(Type=Name.Annot, Subtype=Name.Stamp, Rect=a.get("/Rect", Array([0, 0, 0, 0])),
                          F=4, AP=Dictionary(N=n))
    if sub in ANNOT_KEEP_MARKUP:
        for k in ANNOT_STRIP_KEYS:
            if k in a:
                del a[k]
        return a
    if sub in ("/Text", "/Popup"):
        log.add("Comment", "medium", "PDF comment/sticky note removed")
    return None


def _clean_page(src, page, off, opts, log):
    obj = page.obj
    for k in ("/AA", *METADATA_KEYS):
        if k in obj:
            del obj[k]
    annots = obj.get("/Annots")
    if annots is not None:
        keep = Array()
        for a in annots:
            c = _clean_annot(a, opts, log)
            if c is not None:
                keep.append(c)
        if len(keep):
            obj["/Annots"] = keep
        else:
            del obj["/Annots"]
    _filter_content(src, page, off, opts, log)


def _walk(obj, fn, seen, depth=0):
    if depth > 200:
        raise CDRError("PDF object nesting too deep")
    if isinstance(obj, Array):
        for x in obj:
            _walk(x, fn, seen, depth + 1)
    elif _isdict(obj):
        try:
            og = obj.objgen
        except Exception:
            og = (0, 0)
        if og != (0, 0):
            if og in seen:
                return
            seen.add(og)
        fn(obj)
        for k in list(obj.keys()):
            _walk(obj.get(k), fn, seen, depth + 1)


def _global_strip(pdf, opts):
    def fn(d):
        if opts.remove_active:
            for k in DANGEROUS_KEYS:
                if k in d:
                    del d[k]
        if opts.remove_metadata:
            for k in METADATA_KEYS:
                if k in d:
                    del d[k]
    seen = set()
    for page in pdf.pages:
        _walk(page.obj, fn, seen)


def disarm_pdf(data, opts, log, limits=DEFAULT_LIMITS):
    """Return sanitized PDF bytes (balanced / metadata_only)."""
    try:
        src = pikepdf.open(io.BytesIO(data))
    except pikepdf.PasswordError:
        raise CDRError("password-protected PDF cannot be sanitized")
    except Exception as e:
        raise CDRError(f"unparseable PDF: {e}")
    if len(src.objects) > limits.max_pdf_objects:
        raise BombError(f"PDF has {len(src.objects)} objects (limit {limits.max_pdf_objects})")
    if len(src.pages) > limits.max_pdf_pages:
        raise BombError(f"PDF has {len(src.pages)} pages (limit {limits.max_pdf_pages})")
    scan_source(src, data, log, opts)
    out = io.BytesIO()
    if not opts.remove_active and not opts.remove_hidden:
        # metadata_only: keep structure, drop metadata
        if "/Metadata" in src.Root:
            del src.Root["/Metadata"]
        if "/Info" in src.trailer:
            del src.trailer["/Info"]
        _global_strip(src, opts)
        src.save(out, deterministic_id=True)
        return out.getvalue()
    off = _off_ocgs(src)
    new = pikepdf.new()
    for page in src.pages:
        _clean_page(src, page, off, opts, log)
        new.pages.append(page)
    _global_strip(new, opts)
    new.save(out, deterministic_id=True)
    return out.getvalue()


# ----------------------------------------------------------------------------- flatten
def flatten_pdf(data, opts, log, limits=DEFAULT_LIMITS, dpi=None):
    """Paranoid mode: output contains only raster images (no text, no actions, nothing parsed later)."""
    import pypdfium2 as pdfium
    dpi = dpi or opts.dpi
    try:
        doc = pdfium.PdfDocument(data)
    except Exception as e:
        raise CDRError(f"cannot open PDF for rendering: {e}")
    try:  # draw filled-in form fields (no scripting engine in this pdfium build)
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            doc.init_forms()
    except Exception:
        pass
    n = len(doc)
    if n > limits.max_pdf_pages:
        raise BombError(f"PDF has {n} pages (limit {limits.max_pdf_pages})")
    if n == 0:
        raise CDRError("PDF has no pages")
    scan_pdf = None
    try:
        scan_pdf = pikepdf.open(io.BytesIO(data))
        scan_source(scan_pdf, data, log, opts)
    except Exception:
        log.add("Unparsed", "info", "structure scan unavailable; rendered with pdfium only")
    out = pikepdf.new()
    for i in range(n):
        page = doc[i]
        w, h = page.get_size()
        scale = dpi / 72.0
        while w * scale * h * scale > limits.max_pixels / 2:
            scale *= 0.8
        im = page.render(scale=scale).to_pil().convert("RGB")
        page.close()
        raw = zlib.compress(im.tobytes(), 6)
        img = out.make_stream(raw)
        img.Type, img.Subtype = Name.XObject, Name.Image
        img.Width, img.Height = im.width, im.height
        img.ColorSpace, img.BitsPerComponent, img.Filter = Name.DeviceRGB, 8, Name.FlateDecode
        content = f"q {w:.2f} 0 0 {h:.2f} 0 0 cm /Im0 Do Q".encode()
        pg = pikepdf.Dictionary(
            Type=Name.Page, MediaBox=Array([0, 0, round(w, 2), round(h, 2)]),
            Resources=Dictionary(XObject=Dictionary(Im0=img)), Contents=out.make_stream(content))
        out.pages.append(pikepdf.Page(pg))
    buf = io.BytesIO()
    out.save(buf, deterministic_id=True)
    log.add("Flattened", "info", f"{n} page(s) rasterised at {dpi:.0f} DPI")
    return buf.getvalue()


# ----------------------------------------------------------------------------- verification
def verify_pdf(data, paranoid=False):
    """Independent re-scan of the OUTPUT. Returns list of violation strings (empty = clean)."""
    v = []
    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except Exception as e:
        return [f"output is not a parseable PDF: {e}"]
    if "/Info" in pdf.trailer:
        v.append("trailer still has /Info")
    for k in pdf.Root.keys():
        if k not in ("/Type", "/Pages", "/Version", "/Extensions"):
            v.append(f"catalog key {k} survived")
    def fn(obj):
        for k in DANGEROUS_KEYS + METADATA_KEYS:
            if k in obj:
                v.append(f"object {_objnum(obj)} has {k}")
        s = str(obj.get("/S", ""))
        if s in BAD_ACTIONS:
            v.append(f"object {_objnum(obj)} action {s}")
        if s == "/URI" and not str(obj.get("/URI", "")).lower().startswith(SAFE_URI):
            v.append(f"object {_objnum(obj)} unsafe URI")
        if str(obj.get("/Type")) == "/EmbeddedFile":
            v.append("embedded file stream")
        if str(obj.get("/Subtype", "")) in MEDIA_SUBTYPES and str(obj.get("/Type", "")) == "/Annot":
            v.append("active media annotation")

    try:
        _walk_all(pdf, fn)
    except CDRError as e:
        v.append(str(e))
    if paranoid:
        for page in pdf.pages:
            if "/Annots" in page.obj:
                v.append("annotations in flattened output")
    return v
