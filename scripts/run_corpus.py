"""Run every corpus fixture through the engine and check expectations. Exit code 1 on any miss."""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "corpus")]
import make_corpus

from safeforge.engine import sanitize
from safeforge.office_cdr import load_package


def blob(data):
    """All searchable bytes of an output: raw plus (for ZIP-based) the inflated parts."""
    out = [data]
    try:
        out += list(load_package(data).values())
    except Exception:
        try:
            import io
            import zipfile
            z = zipfile.ZipFile(io.BytesIO(data))
            for n in z.namelist():
                out.append(z.read(n))
        except Exception:
            pass
    return b"\n".join(out)


def check(fx, quiet=False):
    r = sanitize(fx.data, fx.filename, fx.mode)
    problems = []
    if r.status != fx.status:
        problems.append(f"status {r.status!r} != expected {fx.status!r} ({r.reason[:120]})")
    types = {t["type"] for t in r.threats}
    for t in fx.threats:
        if t not in types:
            problems.append(f"threat '{t}' not reported (got {sorted(types)})")
    if r.ok:
        b = blob(r.data)
        for s in fx.must_not_contain:
            if s in b:
                problems.append(f"{s!r} survived in output")
        if fx.must_contain:
            from safeforge.fidelity import text_score  # noqa
            from safeforge.convert import to_text
            try:
                txt = to_text(r.data, r.out_type).decode("utf-8", "replace")
            except Exception:
                txt = b.decode("utf-8", "replace")
            for s in fx.must_contain:
                if s not in txt:
                    problems.append(f"business content {s!r} lost")
    return r, problems


if __name__ == "__main__":
    fixtures = make_corpus.build_all()
    bad = 0
    print(f"{'fixture':44}{'expected':10}{'actual':11}{'threats':>8}{'fidelity':>9}{'ms':>7}  result")
    for fx in fixtures:
        t = time.time()
        r, probs = check(fx)
        bad += bool(probs)
        fid = r.report.get("fidelity_score")
        print(f"{fx.name:44}{fx.status:10}{r.status:11}{sum(x['count'] for x in r.threats):>8}{('%.1f' % fid) if fid is not None else '-':>9}{int((time.time()-t)*1000):>7}  {'PASS' if not probs else 'FAIL'}")
        for p in probs:
            print("      -", p)
    print(f"\n{len(fixtures) - bad}/{len(fixtures)} fixtures behaved as expected")
    sys.exit(1 if bad else 0)
