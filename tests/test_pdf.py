import io
import shutil
import subprocess
import tempfile

import pikepdf
import pytest
from pikepdf import Dictionary, Name, String

from safeforge.engine import sanitize
from safeforge.limits import Limits
from safeforge.pdf_cdr import verify_pdf


def pdftotext(data):
    return subprocess.run(["pdftotext", "-", "-"], input=data, capture_output=True).stdout.decode("utf-8", "replace")


def qpdf_ok(data):
    executable = shutil.which("qpdf")
    if executable is None:
        return None  # qpdf CLI is optional; pikepdf verification still runs below.
    with tempfile.NamedTemporaryFile(suffix=".pdf") as f:
        f.write(data)
        f.flush()
        return subprocess.run([executable, "--check", f.name], capture_output=True).returncode in (0, 3)


PDF_NAMES = ["pdf_openaction_js", "pdf_names_js", "pdf_page_aa_js", "pdf_launch_action", "pdf_embedded_exe",
             "pdf_fileattachment_annot", "pdf_xfa_form", "pdf_widget_with_js", "pdf_uri_javascript", "pdf_gotor",
             "pdf_submitform", "pdf_richmedia", "pdf_metadata", "pdf_hidden_layer_and_text", "pdf_incremental_update",
             "pdf_inherited_mediabox", "pdf_jbig2_stream"]


@pytest.mark.parametrize("name", PDF_NAMES)
@pytest.mark.parametrize("mode", ["balanced", "paranoid"])
def test_output_is_clean_valid_and_independently_verified(run, name, mode):
    r = run(name, mode)
    assert r.ok, r.reason
    assert verify_pdf(r.data, paranoid=(mode == "paranoid")) == []
    qpdf_result = qpdf_ok(r.data)
    if qpdf_result is not None:
        assert qpdf_result
    pdf = pikepdf.open(io.BytesIO(r.data))
    assert "/Info" not in pdf.trailer
    assert set(pdf.Root.keys()) <= {"/Type", "/Pages"}


@pytest.mark.parametrize("name", PDF_NAMES)
def test_balanced_preserves_visible_text_and_fidelity(run, corpus, name):
    r = run(name)
    assert "Invoice total: $100.00" in pdftotext(r.data)
    assert r.report["fidelity_score"] >= 99


def test_threat_details_name_the_object_and_code(run):
    r = run("pdf_openaction_js")
    js = next(t for t in r.threats if t["type"] == "JavaScript")
    assert js["risk"] == "critical" and "evil.example" in js["details"][0]
    emb = next(t for t in run("pdf_embedded_exe").threats if t["type"] == "EmbeddedFile")
    assert any("malware.exe" in d for d in emb["details"])
    assert emb["count"] == 1          # one attached file is one finding, not two


def test_hidden_layer_and_invisible_text_removed_but_visible_kept(run):
    r = run("pdf_hidden_layer_and_text")
    text = pdftotext(r.data)
    assert "Invoice total" in text and "SECRET-LAYER-TEXT" not in text and "INVISIBLE-RUN" not in text
    assert b"SECRET-LAYER" not in r.data and b"INVISIBLE" not in r.data


def test_remove_hidden_can_be_switched_off(run):
    r = run("pdf_hidden_layer_and_text", remove_hidden=False)
    assert r.ok and "INVISIBLE-RUN" in pdftotext(r.data)


def test_incremental_update_history_discarded(run):
    r = run("pdf_incremental_update")
    assert r.data.count(b"%%EOF") == 1 and b"OLD-REVISION-SECRET" not in r.data


def test_inherited_mediabox_survives_rebuild(run):
    pdf = pikepdf.open(io.BytesIO(run("pdf_inherited_mediabox").data))
    assert [float(x) for x in pdf.pages[0].MediaBox] == [0, 0, 300, 300]


def test_filled_form_value_kept_but_interactivity_gone(run):
    r = run("pdf_widget_with_js")
    assert "FILLED-VALUE" in pdftotext(r.data)
    pdf = pikepdf.open(io.BytesIO(r.data))
    assert all(str(a.Subtype) != "/Widget" for a in pdf.pages[0].get("/Annots", []))


def _link_pdf(uri):
    from reportlab.pdfgen import canvas
    b = io.BytesIO()
    c = canvas.Canvas(b, pagesize=(200, 200))
    c.drawString(20, 100, "link page")
    c.linkURL(uri, (10, 90, 150, 120))
    c.save()
    return b.getvalue()


def test_safe_links_kept_unsafe_dropped_and_paranoid_drops_all():
    ok = sanitize(_link_pdf("https://example.com/a"), "l.pdf")
    assert ok.ok and b"example.com" in ok.data
    bad = sanitize(_link_pdf("file:///c:/windows/system32/calc.exe"), "l.pdf")
    assert bad.ok and b"calc.exe" not in bad.data and any(t["type"] == "DangerousURI" for t in bad.threats)
    off = sanitize(_link_pdf("https://example.com/a"), "l.pdf", "balanced", {"keep_links": False})
    assert b"example.com" not in off.data


def test_paranoid_is_image_only(run):
    r = run("pdf_hidden_layer_and_text", "paranoid")
    assert pdftotext(r.data).strip() == ""
    pdf = pikepdf.open(io.BytesIO(r.data))
    assert len(pdf.pages) == 1 and "/Annots" not in pdf.pages[0].obj and "/Font" not in pdf.pages[0].Resources
    assert r.report["fidelity_score"] >= 98


def test_metadata_only_mode_is_honest_about_leaving_active_content(run):
    r = run("pdf_metadata", "metadata_only")
    assert r.ok and b"CEO John Doe" not in r.data and b"XMPNAME" not in r.data
    js = run("pdf_openaction_js", "metadata_only")
    assert js.ok and b"evil.example" in js.data          # by design
    assert js.report["warnings"] and "active content" in js.report["warnings"][0]


def test_verifier_sees_direct_dictionaries_regression():
    """The verifier must find JS in a *direct* dict, not only in numbered objects."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    pdf.Root.OpenAction = Dictionary(S=Name.JavaScript, JS=String("app.alert(1)"))
    b = io.BytesIO()
    pdf.save(b)
    v = verify_pdf(b.getvalue())
    assert any("/OpenAction" in x for x in v) or any("/JS" in x for x in v)


def test_encrypted_pdf_handling():
    src = pikepdf.new()
    src.add_blank_page()
    b = io.BytesIO()
    src.save(b, encryption=pikepdf.Encryption(user="secret", owner="owner"))
    r = sanitize(b.getvalue(), "locked.pdf")
    assert r.status == "failed" and "password" in r.reason
    b2 = io.BytesIO()
    src.save(b2, encryption=pikepdf.Encryption(user="", owner="owner"))   # owner-restricted only
    r2 = sanitize(b2.getvalue(), "restricted.pdf")
    assert r2.ok and not pikepdf.open(io.BytesIO(r2.data)).is_encrypted


def test_page_and_object_bombs():
    pdf = pikepdf.new()
    for _ in range(5):
        pdf.add_blank_page()
    b = io.BytesIO()
    pdf.save(b)
    r = sanitize(b.getvalue(), "many.pdf", limits=Limits(max_pdf_pages=3))
    assert r.status == "blocked" and "pages" in r.reason
    r = sanitize(b.getvalue(), "many.pdf", limits=Limits(max_pdf_objects=3))
    assert r.status == "blocked"


def test_garbage_fails_closed(run):
    r = run("garbage_pdf")
    assert r.status == "failed" and r.data is None
