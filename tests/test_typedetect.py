import io
import zipfile

import pytest

from safeforge.typedetect import detect


@pytest.mark.parametrize("data,name,kind", [
    (b"%PDF-1.7\n...", "a.pdf", "pdf"),
    (b"\x89PNG\r\n\x1a\n" + b"0" * 20, "a.png", "png"),
    (b"\xff\xd8\xff\xe0" + b"0" * 20, "a.jpg", "jpeg"),
    (b"GIF89a" + b"0" * 20, "a.gif", "gif"),
    (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "a.webp", "webp"),
    (b"MZ\x90\x00" + b"0" * 20, "a.exe", "exe"),
    (b"\x7fELF" + b"0" * 20, "a", "elf"),
    (b"Rar!\x1a\x07\x00", "a.rar", "rar"),
    (b"hello world", "a.txt", "text"),
    (b"\x00\x01\x02\xfe\xfd", "a.bin", "unknown"),
])
def test_magic_bytes(data, name, kind):
    assert detect(data, name)["type"] == kind


def _zip(names):
    o = io.BytesIO()
    with zipfile.ZipFile(o, "w") as z:
        for n in names:
            z.writestr(n, b"x")
    return o.getvalue()


@pytest.mark.parametrize("names,kind", [
    (["word/document.xml", "[Content_Types].xml"], "docx"),
    (["word/document.xml", "word/vbaProject.bin"], "docm"),
    (["xl/workbook.xml"], "xlsx"), (["xl/workbook.xml", "xl/vbaProject.bin"], "xlsm"),
    (["ppt/presentation.xml"], "pptx"), (["a.txt"], "zip"),
])
def test_zip_family(names, kind):
    assert detect(_zip(names), "f")["type"] == kind


def test_spoofing_flagged():
    exe = detect(b"MZ" + b"0" * 50, "resume.pdf")
    assert exe["type"] == "exe" and exe["extension_mismatch"]
    assert not detect(b"%PDF-1.4", "ok.pdf")["extension_mismatch"]
    assert detect(_zip(["word/document.xml", "word/vbaProject.bin"]), "x.docx")["extension_mismatch"]  # macro doc named .docx


def test_svg_and_eml_and_ole():
    assert detect(b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>', "a.svg")["type"] == "svg"
    assert detect(b"From: a@b.c\r\nTo: d@e.f\r\n\r\nhi", "a.eml")["type"] == "eml"
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + "WordDocument".encode("utf-16-le") + b"\x00" * 50
    assert detect(ole, "a.doc")["type"] == "doc"
