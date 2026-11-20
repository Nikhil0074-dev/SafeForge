import io

from PIL import Image

from safeforge.engine import sanitize
from safeforge.image_cdr import _gps


def test_gps_and_camera_metadata_reported_and_removed(run, corpus):
    r = run("jpg_with_gps_exif")
    gps = next(t for t in r.threats if t["type"] == "GPS")
    assert gps["details"] == ["GPS: 19.0760,72.8777"] and gps["risk"] == "high"
    assert any("Canon" in d for t in r.threats if t["type"] == "Metadata" for d in t["details"])
    im = Image.open(io.BytesIO(r.data))
    assert len(im.getexif()) == 0 and b"Exif" not in r.data and r.out_type == "jpeg"
    assert r.report["fidelity_score"] >= 95


def test_trailing_payloads_dropped(run):
    for n in ("jpg_with_trailing_payload", "png_text_chunks_and_trailer"):
        r = run(n)
        assert b"TRAILING-PAYLOAD" not in r.data and b"MZ-APPENDED-EXE" not in r.data and b"<?php" not in r.data
        assert any(t["type"] == "TrailingData" for t in r.threats)


def test_png_text_chunks_removed(run):
    r = run("png_text_chunks_and_trailer")
    assert b"tEXt" not in r.data and b"Secret Author" not in r.data
    assert Image.open(io.BytesIO(r.data)).size == (64, 48)


def test_png_pixels_identical_lossless(corpus):
    f = corpus["png_text_chunks_and_trailer"]
    r = sanitize(f.data, f.filename)
    assert Image.open(io.BytesIO(f.data)).convert("RGB").tobytes() == Image.open(io.BytesIO(r.data)).convert("RGB").tobytes()


def test_animated_gif_frames_and_timing_preserved(run):
    im = Image.open(io.BytesIO(run("gif_animated_comment").data))
    assert im.n_frames == 3 and im.info.get("duration") == 80 and b"GIF-SECRET-COMMENT" not in run("gif_animated_comment").data


def test_format_conversions(run):
    assert run("bmp_plain").out_type == "png" and run("tiff_plain").out_type == "png"
    assert run("webp_with_exif").out_type == "webp" and b"Canon" not in run("webp_with_exif").data


def test_exif_orientation_applied_before_stripping():
    im = Image.new("RGB", (40, 20), (255, 0, 0))
    ex = Image.Exif()
    ex[0x0112] = 6   # rotate 90 CW
    b = io.BytesIO()
    im.save(b, "JPEG", exif=ex)
    r = sanitize(b.getvalue(), "o.jpg")
    assert Image.open(io.BytesIO(r.data)).size == (20, 40)


def test_pixel_bomb_blocked_before_decoding(run):
    r = run("png_pixel_bomb")
    assert r.status == "blocked" and "pixels" in r.reason and r.report["processing_time_ms"] < 2000


def _embed_lsb(msg):
    bits = "".join(f"{b:08b}" for b in msg)
    im = Image.new("RGB", (64, 64), (120, 130, 140))
    raw = bytearray(im.tobytes())
    for i, bit in enumerate(bits):
        raw[i] = (raw[i] & 0xFE) | int(bit)
    return Image.frombytes("RGB", im.size, bytes(raw)), len(bits)


def _extract(png, n):
    raw = Image.open(io.BytesIO(png)).convert("RGB").tobytes()
    return "".join(str(raw[i] & 1) for i in range(n))


def test_lsb_steganography_survives_balanced_but_not_paranoid():
    """Honest behaviour: lossless re-encode keeps LSBs. Only paranoid (scrub_lsb) destroys them."""
    msg = b"EXFIL-KEY-123456"
    im, n = _embed_lsb(msg)
    b = io.BytesIO()
    im.save(b, "PNG")
    original_bits = _extract(b.getvalue(), n)
    bal = sanitize(b.getvalue(), "s.png", "balanced")
    par = sanitize(b.getvalue(), "s.png", "paranoid")
    assert _extract(bal.data, n) == original_bits
    assert _extract(par.data, n) != original_bits
    diff = sum(a != c for a, c in zip(original_bits, _extract(par.data, n)))
    assert 20 < diff < n - 20                                  # ~50% of bits randomised
    assert par.report["fidelity_score"] >= 99                  # imperceptible


def test_gps_parser_handles_south_west():
    ex = Image.Exif()
    ex[0x8825] = {1: "S", 2: (33.0, 51.0, 54.0), 3: "W", 4: (151.0, 12.0, 36.0)}
    b = io.BytesIO()
    Image.new("RGB", (4, 4)).save(b, "JPEG", exif=ex)
    assert _gps(Image.open(io.BytesIO(b.getvalue())).getexif()) == "-33.8650,-151.2100"


def test_spoofed_extension_reported(run):
    r = run("jpg_wrong_extension_html")
    assert any(t["type"] == "TypeSpoofing" for t in r.threats)
    # a text file wearing a .jpg name is released as .txt, so the lie is not propagated
    assert r.out_type == "text" and r.out_name.endswith(".txt")


def test_corrupt_image_fails_closed():
    r = sanitize(b"\x89PNG\r\n\x1a\n" + b"junk" * 10, "x.png")
    assert r.status == "failed" and r.data is None
