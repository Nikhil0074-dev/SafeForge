import io
import zipfile

import pytest

from safeforge.errors import BombError, CDRError
from safeforge.limits import Limits, ReadBudget, check_pixels, check_xml, open_zip


def test_expat_blocks_entities_and_dtd_subset():
    with pytest.raises(BombError):
        check_xml(b'<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>')
    with pytest.raises(BombError):
        check_xml(b'<!DOCTYPE a [<!ENTITY % p SYSTEM "http://evil/x">%p;]><a/>')
    check_xml(b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg/>')  # plain DOCTYPE ok


def test_utf16_entity_bomb_not_hidden_by_encoding():
    xml = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>'.encode("utf-16")
    with pytest.raises(BombError):
        check_xml(xml)


def test_xml_depth_limit():
    deep = b"<a>" * 300 + b"</a>" * 300
    with pytest.raises(BombError):
        check_xml(deep, Limits(max_xml_depth=100))
    check_xml(b"<a><b><c/></b></a>")


def test_malformed_xml_is_cdr_error():
    with pytest.raises(CDRError):
        check_xml(b"<a><b></a>")


def _zip(payload, level=9):
    o = io.BytesIO()
    with zipfile.ZipFile(o, "w", zipfile.ZIP_DEFLATED, compresslevel=level) as z:
        z.writestr("z.bin", payload)
    return o.getvalue()


def test_zip_ratio_blocked_but_small_files_ok():
    with pytest.raises(BombError, match="ratio"):
        open_zip(_zip(b"\x00" * (20 << 20)))
    open_zip(_zip(b"\x00" * 5000))                    # tiny, very compressible: allowed
    open_zip(_zip(__import__("os").urandom(2 << 20)))  # large, incompressible: allowed


def test_zip_entry_count_and_total_limits():
    o = io.BytesIO()
    with zipfile.ZipFile(o, "w") as z:
        for i in range(30):
            z.writestr(f"f{i}", b"x")
    with pytest.raises(BombError, match="entries"):
        open_zip(o.getvalue(), Limits(max_zip_entries=10))
    with pytest.raises(BombError):
        open_zip(_zip(b"A" * (3 << 20)), Limits(max_zip_total=1 << 20, max_zip_ratio=10_000))


def test_invalid_zip_and_budget():
    with pytest.raises(CDRError):
        open_zip(b"PK\x03\x04garbage")
    b = ReadBudget(100)
    b.take(60)
    with pytest.raises(BombError):
        b.take(60)


def test_pixel_limit():
    check_pixels(1000, 1000)
    with pytest.raises(BombError):
        check_pixels(40000, 40000)
    with pytest.raises(BombError):
        check_pixels(5000, 5000, frames=10)
