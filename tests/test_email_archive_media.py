import io
import shutil
import zipfile
from email import policy
from email.parser import BytesParser

import pytest

from safeforge.engine import sanitize
from safeforge.media_cdr import _probe


def test_eml_headers_html_and_attachments(run):
    r = run("eml_tracking_script_attachments")
    assert r.ok and r.out_name.endswith(".eml")
    msg = BytesParser(policy=policy.default).parsebytes(r.data)
    assert set(msg.keys()) >= {"From", "To", "Subject", "Date"}
    assert "Received" not in msg and "X-Mailer" not in msg and "X-Originating-IP" not in msg
    html = msg.get_body(("html",)).get_content().lower()
    assert "hello" in html and "<script" not in html and "<img" not in html and "href" not in html and "pay now" in html
    assert msg.get_body(("plain",)).get_content().startswith("Plain body")
    names = [p.get_filename() for p in msg.iter_attachments()]
    assert names == ["safe_invoice.pdf"]                       # exe dropped, pdf sanitised
    pdf = next(msg.iter_attachments()).get_payload(decode=True)
    assert b"evil.example" not in pdf and pdf.startswith(b"%PDF")
    types = {t["type"] for t in r.threats}
    assert {"TrackingPixel", "AttachmentBlocked", "Attachment:JavaScript"} <= types
    tp = next(t for t in r.threats if t["type"] == "TrackingPixel")
    assert tp["details"] == ["tracker.example"]


def test_eml_header_injection_neutralised():
    raw = b"From: a@b.c\r\nTo: d@e.f\r\nSubject: hi\r\nX-Evil: 1\r\nContent-Type: text/plain\r\n\r\nbody"
    r = sanitize(raw, "m.eml")
    assert r.ok and b"X-Evil" not in r.data


def test_nested_eml_attachment_recursed():
    from email.message import EmailMessage
    inner = EmailMessage()
    inner["From"], inner["To"], inner["Subject"] = "x@y.z", "q@w.e", "inner"
    inner.set_content("inner")
    inner.add_attachment(b"MZ" + b"\0" * 80, maintype="application", subtype="octet-stream", filename="a.exe")
    outer = EmailMessage()
    outer["From"], outer["To"], outer["Subject"] = "a@b.c", "d@e.f", "outer"
    outer.set_content("outer")
    outer.add_attachment(inner, filename="fwd.eml")   # real message/rfc822 part
    r = sanitize(outer.as_bytes(), "o.eml")
    assert r.ok
    msg = BytesParser(policy=policy.default).parsebytes(r.data)
    atts = list(msg.iter_attachments())
    assert len(atts) == 1 and atts[0].get_content_type() == "message/rfc822"
    inner_msg = atts[0].get_payload(0)
    assert inner_msg["Subject"] == "inner" and list(inner_msg.iter_attachments()) == []   # inner .exe dropped
    assert b"MZ" not in r.data


def test_eml_attachment_with_malformed_message_part_does_not_crash():
    """message/rfc822 with a base64 body is non-standard; it must be handled (recursively sanitised), never trusted."""
    from email.message import EmailMessage
    inner = EmailMessage()
    inner["From"], inner["To"], inner["Subject"] = "x@y.z", "q@w.e", "inner"
    inner.set_content("inner")
    outer = EmailMessage()
    outer["From"], outer["To"], outer["Subject"] = "a@b.c", "d@e.f", "outer"
    outer.set_content("outer")
    outer.add_attachment(inner.as_bytes(), maintype="message", subtype="rfc822", filename="fwd.eml")
    r = sanitize(outer.as_bytes(), "o.eml")
    assert r.status in ("completed", "failed") and (r.data is None or b"MZ" not in r.data)


def test_zip_members_sanitised_recursively(run):
    r = run("zip_mixed_content")
    assert r.ok
    z = zipfile.ZipFile(io.BytesIO(r.data))
    names = z.namelist()
    assert "docs/safe_invoice.pdf" in names and "readme.txt" not in names and "safe_readme.txt" in names
    assert not any(n.endswith(".exe") for n in names)
    assert b"evil.example" not in b"".join(z.read(n) for n in names)
    inner = zipfile.ZipFile(io.BytesIO(z.read("safe_nested.zip")))
    assert inner.namelist() == ["deep/safe_evil.pdf"] and b"evil.example" not in inner.read("deep/safe_evil.pdf")
    types = {t["type"] for t in r.threats}
    assert "ArchiveEntryBlocked" in types and "Member:JavaScript" in types


def test_zip_slip_names_dropped(run):
    r = run("zip_slip")
    z = zipfile.ZipFile(io.BytesIO(r.data))
    assert all(".." not in n and not n.startswith("/") for n in z.namelist())
    assert any(t["type"] == "PathTraversal" for t in r.threats)


def test_zip_bomb_and_nesting_depth(run):
    b = run("zip_bomb_ratio")
    assert b.status == "blocked" and "ratio" in b.reason and b.report["processing_time_ms"] < 3000
    n = run("zip_deep_nesting")
    assert n.ok and "Member:ArchiveEntryBlocked" in {t["type"] for t in n.threats}


def test_other_archives_blocked(run):
    assert run("rar_unsupported").status == "blocked"


def test_unsupported_and_blocked_policy(corpus):
    f = corpus["zip_mixed_content"]
    r = sanitize(f.data, f.filename, "balanced", {"block_types": ["zip"]})
    assert r.status == "blocked"


@pytest.mark.skipif(not shutil.which("ffmpeg"), reason="ffmpeg missing")
@pytest.mark.parametrize("name", ["mp4_gps_metadata", "mp3_id3_tags", "wav_list_tags"])
def test_media_metadata_removed_and_stream_untouched(run, corpus, name, tmp_path):
    r = run(name)
    assert r.ok
    for secret in (b"CEO-ARTIST", b"SECRET-TITLE", b"SECRET-COMMENT", b"19.0760"):
        assert secret not in r.data
    p = tmp_path / ("o." + r.out_type)
    p.write_bytes(r.data)
    tags = _probe(str(p))
    assert not {k for k in tags if k.split(":")[-1] not in ("major_brand", "minor_version", "compatible_brands", "handler_name", "vendor_id", "language")}
    if name == "mp4_gps_metadata":
        assert any(t["type"] == "GPS" and "19.0760" in t["details"][0] for t in r.threats)
