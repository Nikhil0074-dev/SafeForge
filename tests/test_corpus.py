"""Every fixture in the corpus must behave as declared (status, reported threats, secrets gone, content kept)."""
import make_corpus
import pytest
from run_corpus import check

FIXTURES = make_corpus.build_all()


@pytest.mark.parametrize("fx", FIXTURES, ids=[f.name for f in FIXTURES])
def test_fixture(fx):
    r, problems = check(fx)
    assert not problems, problems


def test_corpus_size_and_diversity():
    assert len(FIXTURES) >= 60
    assert {f.category for f in FIXTURES} >= {"pdf", "office", "image", "svg", "bomb", "spoof", "archive", "email"}


def test_every_completed_output_is_stable_under_resanitisation():
    """Sanitising a sanitised file must find nothing dangerous (idempotence)."""
    from safeforge.engine import sanitize
    DANGER = {"JavaScript", "Launch", "Macro", "XLMMacro", "ActiveX", "EmbeddedFile", "EmbeddedObject", "DDE/Field",
              "ActiveContent", "EventHandler", "ExternalLink", "ExternalReference", "TemplateInjection", "GPS",
              "TrailingData", "XFA", "DangerousURI", "DangerousLink", "FormulaInjection", "HiddenSheet", "TrackingPixel"}
    n = 0
    for f in FIXTURES:
        if f.category in ("bomb",) or f.status != "completed" or f.category in ("media", "archive", "email"):
            continue
        r = sanitize(f.data, f.filename)
        if not r.ok:
            continue
        r2 = sanitize(r.data, r.out_name)
        assert r2.ok, (f.name, r2.reason)
        assert not ({t["type"] for t in r2.threats} & DANGER), (f.name, r2.threats)
        n += 1
    assert n > 40
