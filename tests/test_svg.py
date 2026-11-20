import pytest
from make_corpus import SVG_PAYLOADS

from safeforge.engine import sanitize
from safeforge.svg_cdr import verify_svg


@pytest.mark.parametrize("name", list(SVG_PAYLOADS))
def test_payload_neutralised_and_output_idempotent(run, name):
    r = run(name)
    assert r.ok and verify_svg(r.data) == []
    _, threats, bad = SVG_PAYLOADS[name]
    for b in bad:
        assert b not in r.data
    assert {t["type"] for t in r.threats} >= set(threats)


def test_legitimate_svg_survives():
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">'
           b'<defs><linearGradient id="g"><stop offset="0" stop-color="red"/></linearGradient></defs>'
           b'<rect width="5" height="5" fill="url(#g)"/><use xlink:href="#g"/><text x="1" y="9">Hi</text>'
           b'<image href="data:image/png;base64,iVBORw0KGgo=" width="1" height="1"/></svg>')
    r = sanitize(svg, "ok.svg")
    assert r.ok and not r.threats
    for tag in (b"<rect", b"linearGradient", b"<text", b"<use", b"<image", b"url(#g)"):
        assert tag in r.data


def test_comments_and_pis_stripped_and_non_svg_rejected():
    r = sanitize(b'<?xml version="1.0"?><?xml-stylesheet href="http://e/x.css"?><svg xmlns="http://www.w3.org/2000/svg"><!-- c --><g/></svg>', "a.svg")
    assert r.ok and b"stylesheet" not in r.data and b"<!--" not in r.data
    wrong_ns = sanitize(b'<?xml version="1.0"?><svg xmlns="http://evil.example/ns"><g/></svg>', "a.svg")
    assert wrong_ns.status == "failed" and "not an SVG" in wrong_ns.reason


def test_bombs_blocked(run):
    assert run("svg_billion_laughs").status == "blocked" and run("svg_xxe").status == "blocked"
