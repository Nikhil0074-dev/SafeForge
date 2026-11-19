"""Module 1 - true type identification from content, never from the extension."""
import io
import re
import zipfile

MIME = {
    "pdf": "application/pdf", "png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif",
    "webp": "image/webp", "bmp": "image/bmp", "tiff": "image/tiff", "svg": "image/svg+xml",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "docm": "application/vnd.ms-word.document.macroEnabled.12",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "pptm": "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "doc": "application/msword", "xls": "application/vnd.ms-excel", "ppt": "application/vnd.ms-powerpoint",
    "ole": "application/x-ole-storage", "zip": "application/zip", "rar": "application/vnd.rar",
    "7z": "application/x-7z-compressed", "mp4": "video/mp4", "mp3": "audio/mpeg", "wav": "audio/wav",
    "eml": "message/rfc822", "text": "text/plain", "exe": "application/x-msdownload",
    "elf": "application/x-elf", "macho": "application/x-mach-binary", "unknown": "application/octet-stream",
}
EXTS = {
    "pdf": {"pdf"}, "png": {"png"}, "jpeg": {"jpg", "jpeg", "jpe", "jfif"}, "gif": {"gif"},
    "webp": {"webp"}, "bmp": {"bmp"}, "tiff": {"tif", "tiff"}, "svg": {"svg"},
    "docx": {"docx"}, "docm": {"docm"}, "xlsx": {"xlsx"}, "xlsm": {"xlsm"},
    "pptx": {"pptx"}, "pptm": {"pptm"}, "doc": {"doc"}, "xls": {"xls"}, "ppt": {"ppt"},
    "zip": {"zip"}, "rar": {"rar"}, "7z": {"7z"}, "mp4": {"mp4", "m4v", "mov", "m4a"},
    "mp3": {"mp3"}, "wav": {"wav"}, "eml": {"eml"},
    "text": {"txt", "csv", "tsv", "log", "md", "json", "text"},
}
OOXML = {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm"}
BLOCKED = {"exe", "elf", "macho", "ole", "rar", "7z", "unknown"}


def _zip_kind(data):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = {n.lower() for n in zf.namelist()}
    except Exception:
        return "zip"
    macro = any(n.endswith("vbaproject.bin") for n in names)
    ct = b""
    for n in zf.namelist():
        if n.lower() == "[content_types].xml" and zf.getinfo(n).file_size < 1 << 20:
            ct = zf.read(n).lower()
    macro = macro or b"macroenabled" in ct
    if "word/document.xml" in names:
        return "docm" if macro else "docx"
    if "xl/workbook.xml" in names:
        return "xlsm" if macro else "xlsx"
    if "ppt/presentation.xml" in names:
        return "pptm" if macro else "pptx"
    return "zip"


def _looks_text(head):
    if not head:
        return True
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
        return True
    except UnicodeDecodeError:
        try:  # tolerate a multi-byte char cut at the end of the sample
            head[:-3].decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False


EML_RE = re.compile(rb"\A\s*(?:from |return-path:|received:|mime-version:|date:|to:|from:|subject:|message-id:|x-[\w-]+:)", re.IGNORECASE)


def detect(data, filename=""):
    head = data[:4096]
    kind = "unknown"
    if head.startswith(b"%PDF-") or b"%PDF-" in data[:1024]:
        kind = "pdf"
    elif head.startswith(b"\x89PNG\r\n\x1a\n"):
        kind = "png"
    elif head.startswith(b"\xff\xd8\xff"):
        kind = "jpeg"
    elif head[:6] in (b"GIF87a", b"GIF89a"):
        kind = "gif"
    elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        kind = "webp"
    elif head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        kind = "wav"
    elif head[:2] == b"BM" and len(data) > 26 and not _looks_text(head[:64]):
        kind = "bmp"
    elif head[:4] in (b"II*\x00", b"MM\x00*"):
        kind = "tiff"
    elif head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        kind = _zip_kind(data)
    elif head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        kind = "ole"
        for label, key in (("doc", "WordDocument"), ("xls", "Workbook"), ("ppt", "PowerPoint Document")):
            if key.encode("utf-16-le") in data[:2_000_000]:
                kind = label
                break
    elif head.startswith(b"Rar!\x1a\x07"):
        kind = "rar"
    elif head.startswith(b"7z\xbc\xaf\x27\x1c"):
        kind = "7z"
    elif head[4:8] == b"ftyp":
        kind = "mp4"
    elif head.startswith(b"ID3") or (len(head) > 2 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0):
        kind = "mp3"
    elif head[:2] == b"MZ":
        kind = "exe"
    elif head[:4] == b"\x7fELF":
        kind = "elf"
    elif head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        kind = "macho"
    elif _looks_text(head):
        low = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
        if b"<svg" in head.lower() and (low.startswith((b"<?xml", b"<svg", b"<!doctype svg", b"<!--"))):
            kind = "svg"
        elif EML_RE.match(head):
            kind = "eml"
        else:
            kind = "text"

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    allowed = EXTS.get(kind)
    mismatch = bool(ext) and allowed is not None and ext not in allowed
    if kind in ("exe", "elf", "macho") and ext:
        mismatch = True
    return {
        "type": kind,
        "mime": MIME.get(kind, "application/octet-stream"),
        "claimed_ext": ext,
        "extension_mismatch": mismatch,
        "magic": data[:8].hex(),
    }
