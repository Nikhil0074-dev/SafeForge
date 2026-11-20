import io
import json
import shutil

import pytest
from PIL import Image

from safeforge import convert
from safeforge.__main__ import main


def test_image_to_pdf_to_png_roundtrip():
    b = io.BytesIO()
    Image.new("RGB", (60, 40), (200, 30, 30)).save(b, "PNG")
    pdf = convert.image_to_pdf(b.getvalue())
    assert pdf.startswith(b"%PDF")
    png = convert.pdf_to_png(pdf, 0, 72)
    im = Image.open(io.BytesIO(png)).convert("RGB")
    assert im.getpixel((10, 10)) == pytest.approx((200, 30, 30), abs=3)


def test_text_extraction(corpus):
    from safeforge.engine import sanitize
    r = sanitize(corpus["pdf_metadata"].data, "a.pdf")
    assert b"Invoice total" in convert.to_text(r.data, "pdf")
    d = sanitize(corpus["docx_hidden_text_trackchanges_comments"].data, "a.docx")
    t = convert.to_text(d.data, "docx").decode()
    assert "INSERTED-KEPT" in t and "DELETED" not in t


def test_page_out_of_range_and_unknown_target(corpus):
    from safeforge.engine import sanitize
    from safeforge.errors import CDRError
    r = sanitize(corpus["pdf_metadata"].data, "a.pdf")
    with pytest.raises(CDRError):
        convert.pdf_to_png(r.data, 5)
    with pytest.raises(CDRError):
        convert.convert_sanitized(r.data, "pdf", "docx")


@pytest.mark.skipif(not shutil.which("soffice"), reason="LibreOffice missing")
def test_paranoid_office_is_image_only_pdf(corpus):
    from safeforge.engine import sanitize
    f = corpus["docx_hidden_text_trackchanges_comments"]
    r = sanitize(f.data, f.filename, "paranoid")
    assert r.ok and r.out_type == "pdf" and r.out_name.endswith(".pdf")
    import subprocess
    assert subprocess.run(["pdftotext", "-", "-"], input=r.data, capture_output=True).stdout.strip() == b""


@pytest.mark.skipif(not shutil.which("soffice"), reason="LibreOffice missing")
def test_docx_to_pdf_via_disarmed_copy(corpus):
    from safeforge.engine import sanitize
    r = sanitize(corpus["docm_macro"].data, "m.docm")
    pdf, mime, ext = convert.convert_sanitized(r.data, r.out_type, "pdf")
    assert pdf.startswith(b"%PDF") and ext == "pdf"
    assert b"Quarterly report" in convert.pdf_to_text(pdf)


def test_cli_sanitize_and_exit_codes(tmp_path, corpus, capsys):
    good, bad = tmp_path / "in.pdf", tmp_path / "evil.pdf"
    good.write_bytes(corpus["pdf_openaction_js"].data)
    bad.write_bytes(corpus["exe_renamed_pdf"].data)
    out = tmp_path / "out"
    assert main(["sanitize", str(good), "-o", str(out)]) == 0
    assert (out / "safe_in.pdf").read_bytes().startswith(b"%PDF")
    assert main(["sanitize", str(bad), "-o", str(out)]) == 2
    cap = capsys.readouterr().out
    assert "OK" in cap and "REJECTED" in cap
    assert main(["sanitize", str(good), "-o", str(out), "--json", "-m", "paranoid"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "paranoid"
