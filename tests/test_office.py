import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile

import pytest

from safeforge.engine import sanitize
from safeforge.office_cdr import load_package, verify_office, visible_text
from safeforge.policy import build_policy

OFFICE = ["docm_macro", "docx_dde_fields", "docx_template_injection", "docx_hidden_text_trackchanges_comments",
          "docx_activex_ole", "docx_dangerous_hyperlinks", "docx_external_image_tracker", "xlsx_hidden_sheet_rows_cols",
          "xlsx_external_link", "xlsx_formula_injection", "xlsm_vba_and_xlm", "pptx_notes_hidden_slide_ole"]


def parts(r):
    return load_package(r.data)


@pytest.mark.parametrize("name", OFFICE)
def test_independent_verifier_passes_on_every_output(run, name):
    r = run(name)
    assert r.ok, r.reason
    assert verify_office(r.data, build_policy("balanced")) == []
    assert not any(p.lower().endswith((".bin", ".exe")) for p in parts(r))


@pytest.mark.parametrize("name", OFFICE)
def test_no_metadata_parts_and_no_external_rels_except_safe_links(run, name):
    p = parts(run(name))
    assert not any(n.startswith("docProps/") for n in p)
    for n, d in p.items():
        if n.endswith(".rels"):
            for m in re.finditer(rb'<Relationship [^>]*TargetMode="External"[^>]*>', d):
                assert b"hyperlink" in m.group(0) and re.search(rb'Target="(https?://|mailto:)', m.group(0)), m.group(0)


def test_macro_docm_becomes_plain_docx(run):
    r = run("docm_macro")
    assert r.out_name.endswith(".docx") and r.out_type == "docx"
    ct = parts(r)["[Content_Types].xml"]
    assert b"macroEnabled" not in ct and b"vbaProject" not in ct
    assert next(t for t in r.threats if t["type"] == "Macro")["risk"] == "critical"


def test_dde_fields_neutralised_but_cached_result_kept(run):
    doc = parts(run("docx_dde_fields"))["word/document.xml"]
    assert b"DDE" not in doc and b"calc" not in doc
    assert b"cached" in doc and b"simple" in doc


def test_track_changes_hidden_text_comments(run):
    r = run("docx_hidden_text_trackchanges_comments")
    doc = parts(r)["word/document.xml"]
    assert b"INSERTED-KEPT" in doc and b"VISIBLE-PARA" in doc and b"COMMENTED" in doc
    for gone in (b"DELETED-SECRET", b"HIDDEN-VANISH", b"w:del ", b"w:ins ", b"commentReference", b"commentRange"):
        assert gone not in doc
    assert "word/comments.xml" not in parts(r)
    assert r.report["fidelity_score"] == 100.0


def test_hyperlinks_policy(run):
    p = parts(run("docx_dangerous_hyperlinks"))
    rels = p["word/_rels/document.xml.rels"]
    assert b"https://example.com/ok" in rels and b"attacker" not in rels and b"javascript" not in rels
    doc = p["word/document.xml"]
    assert doc.count(b"<w:hyperlink") == 1                       # unsafe ones unwrapped, text kept
    assert b"UNCLINK-TEXT" in doc and b"JSLINK-TEXT" in doc
    paranoid_links = run("docx_dangerous_hyperlinks", "balanced", keep_links=False)
    assert b"example.com" not in parts(paranoid_links)["word/_rels/document.xml.rels"]


def test_template_injection_and_dangling_references_removed(run):
    p = parts(run("docx_template_injection"))
    assert b"attachedTemplate" not in p["word/settings.xml"] and "word/_rels/settings.xml.rels" not in p
    img = parts(run("docx_external_image_tracker"))
    assert b"r:id=\"rIdImg\"" not in img["word/document.xml"]


def test_excel_hidden_content_and_formulas(run):
    r = run("xlsx_hidden_sheet_rows_cols")
    p = parts(r)
    blob = b"".join(p.values())
    for gone in (b"TOP-SECRET-SHEET-DATA", b"ROWSECRET", b"colsecret", b"veryHidden"):
        assert gone not in blob
    assert "xl/worksheets/sheet2.xml" not in p
    assert "Region" in visible_text(r.data, "xlsx")
    f = parts(run("xlsx_formula_injection"))["xl/worksheets/sheet1.xml"]
    assert b"WEBSERVICE" not in f and b"calc" not in f and b"cached" in f   # cached values survive


def test_defined_name_index_shifted_when_sheet_removed():
    import openpyxl
    wb = openpyxl.Workbook()
    wb.active.title = "Hidden1"
    wb.active.sheet_state = "hidden"
    s2 = wb.create_sheet("Visible")
    s2["A1"] = "keep"
    from openpyxl.workbook.defined_name import DefinedName
    s2.defined_names["LocalName"] = DefinedName("LocalName", attr_text="Visible!$A$1")
    b = io.BytesIO()
    wb.save(b)
    r = sanitize(b.getvalue(), "n.xlsx")
    wbx = load_package(r.data)["xl/workbook.xml"]
    assert b"Hidden1" not in wbx and b'localSheetId="0"' in wbx


def test_xlsm_macros_and_xlm_removed(run):
    r = run("xlsm_vba_and_xlm")
    p = parts(r)
    assert r.out_name.endswith(".xlsx") and not any("macrosheet" in n or "vba" in n.lower() for n in p)


def test_pptx_notes_hidden_slide_ole(run):
    r = run("pptx_notes_hidden_slide_ole")
    p = parts(r)
    blob = b"".join(p.values())
    assert b"NOTES-PASSWORD" not in blob and b"HIDDEN-SLIDE-SECRET" not in blob
    assert not any("notesSlide" in n or "embeddings" in n for n in p)
    assert "Public roadmap" in visible_text(r.data, "pptx")


def test_zip_slip_and_duplicate_entries(run):
    assert run("docx_zip_slip_entry").ok and not any(".." in n for n in parts(run("docx_zip_slip_entry")))
    assert run("docx_duplicate_entries").status == "failed"
    assert run("docx_xml_bomb").status == "blocked"


def test_metadata_only_keeps_macros_by_design(corpus):
    f = corpus["docm_macro"]
    r = sanitize(f.data, f.filename, "metadata_only")
    p = parts(r)
    assert r.ok and any("vbaProject" in n for n in p) and not any(n.startswith("docProps/") for n in p)
    assert r.out_name.endswith(".docm")


def test_verifier_catches_tampered_output(run):
    r = run("docx_hidden_text_trackchanges_comments")
    z = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(r.data)) as src, zipfile.ZipFile(z, "w") as dst:
        for n in src.namelist():
            dst.writestr(n, src.read(n))
        dst.writestr("word/vbaProject.bin", b"x")
    assert any("vbaProject" in v for v in verify_office(z.getvalue(), build_policy("balanced")))


@pytest.mark.skipif(not shutil.which("soffice"), reason="LibreOffice not installed")
@pytest.mark.parametrize("name", ["docx_hidden_text_trackchanges_comments", "xlsx_hidden_sheet_rows_cols", "pptx_notes_hidden_slide_ole", "docm_macro"])
def test_sanitized_office_files_open_in_libreoffice(run, name):
    r = run(name)
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "f." + r.out_name.rsplit(".", 1)[1])
        open(src, "wb").write(r.data)
        subprocess.run(["soffice", "--headless", "--norestore", f"-env:UserInstallation=file://{d}/p", "--convert-to", "pdf", "--outdir", d, src],
                       capture_output=True, timeout=180)
        assert os.path.exists(os.path.join(d, "f.pdf"))


def test_real_documents_with_embedded_images_and_binary_parts_pass():
    """Regression: verifier once tried to XML-parse every part, rejecting any docx containing a picture."""
    import docx
    from PIL import Image
    img = io.BytesIO()
    Image.new("RGB", (30, 30), (10, 200, 10)).save(img, "PNG")
    d = docx.Document()
    d.add_paragraph("Doc with a picture")
    d.add_picture(io.BytesIO(img.getvalue()))
    b = io.BytesIO()
    d.save(b)
    r = sanitize(b.getvalue(), "pic.docx")
    assert r.ok, r.reason
    assert any(n.startswith("word/media/") for n in parts(r)) and "Doc with a picture" in visible_text(r.data, "docx")
