import json

import pytest

from safeforge.chain import ChainLog, certificate_pdf, sign
from safeforge.engine import sanitize
from safeforge.policy import build_policy


def test_modes_are_presets():
    assert build_policy("paranoid").flatten and build_policy("paranoid").scrub_lsb
    m = build_policy("metadata_only")
    assert m.remove_metadata and not m.remove_active and not m.remove_hidden
    assert build_policy("balanced").remove_active and not build_policy("balanced").flatten


@pytest.mark.parametrize("mode,ov", [("nope", None), ("balanced", {"bogus": 1}), ("balanced", {"dpi": 5}),
                                     ("balanced", {"remove_active": "yes"}), ("balanced", {"max_depth": 99}), ("balanced", {"mode": "paranoid"})])
def test_invalid_policies_rejected(mode, ov):
    with pytest.raises(ValueError):
        build_policy(mode, ov)


def test_policy_override_changes_behaviour(corpus):
    f = corpus["jpg_with_gps_exif"]
    keep = sanitize(f.data, f.filename, "balanced", {"remove_metadata": False})
    assert keep.ok  # engine still re-encodes; metadata reporting continues
    flat = sanitize(corpus["docx_dde_fields"].data, "a.docx", "balanced", {"remove_active": False})
    assert b"DDEAUTO" in __import__("safeforge.office_cdr", fromlist=["x"]).load_package(flat.data)["word/document.xml"]


def test_chain_detects_tampering_and_deletion(tmp_path):
    c = ChainLog(str(tmp_path / "chain.jsonl"))
    for i in range(4):
        c.append(f"job{i}", "a" * 64, "b" * 64, "balanced", i)
    assert c.verify() == (True, 4, None)
    lines = (tmp_path / "chain.jsonl").read_text().splitlines()
    e = json.loads(lines[1])
    e["sanitized_sha256"] = "c" * 64
    tampered = lines[:1] + [json.dumps(e, sort_keys=True)] + lines[2:]
    (tmp_path / "chain.jsonl").write_text("\n".join(tampered) + "\n")
    ok, n, bad = c.verify()
    assert not ok and bad == 1
    (tmp_path / "chain.jsonl").write_text("\n".join(lines[:1] + lines[2:]) + "\n")    # deleted entry
    assert not c.verify()[0]


def test_chain_links_engine_reports(corpus, tmp_path):
    c = ChainLog(str(tmp_path / "c.jsonl"))
    f = corpus["pdf_metadata"]
    a, b = sanitize(f.data, f.filename, chain=c), sanitize(f.data, f.filename, chain=c)
    assert b.report["chain_of_custody"]["prev_hash"] == a.report["chain_of_custody"]["entry_hash"]
    assert c.verify()[0]


def test_certificate_is_valid_pdf_with_hashes_and_mac(corpus):
    import subprocess
    r = sanitize(corpus["pdf_openaction_js"].data, "inv.pdf")
    r.report["chain_of_custody"] = {"entry_hash": "e" * 64}
    pdf = certificate_pdf(r.report, b"k" * 32)
    txt = subprocess.run(["pdftotext", "-", "-"], input=pdf, capture_output=True).stdout.decode()
    assert r.report["original"]["sha256"][:60] in txt.replace("\n", "")
    assert sign(b"k" * 32, "e" * 64)[:40] in txt.replace("\n", "")
    assert "not a third-party" in txt.replace("\n", " ")


def test_hostile_strings_in_certificate_do_not_break_it(corpus):
    rep = {"job_id": "j", "mode": "balanced", "original": {"name": "<b>\u202e\u4e2d\u6587</b>.pdf", "sha256": "0" * 64, "true_type": "pdf"},
           "sanitized": {"name": "s.pdf", "sha256": "1" * 64}, "threats_removed": [{"type": "X", "risk": "high", "count": 1, "details": ["(((\\\\)))\n\x00"]}]}
    assert certificate_pdf(rep, b"k").startswith(b"%PDF")
