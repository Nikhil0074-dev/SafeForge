"""Plain-text normaliser: strips NULs and bidirectional controls (Trojan Source)."""
import re

BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]")
CTRL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(data, log):
    s = data.decode("utf-8", errors="replace")
    n = len(BIDI.findall(s))
    if n:
        log.add("BidiControl", "medium", f"{n} bidirectional override character(s) (Trojan Source)", n)
    c = len(CTRL.findall(s))
    if c:
        log.add("ControlChars", "low", f"{c} control character(s)", c)
    s = CTRL.sub("", BIDI.sub("", s)).lstrip("\ufeff")
    return s.encode("utf-8")


def verify_text(data):
    s = data.decode("utf-8", errors="replace")
    return ["bidi/control characters survived"] if BIDI.search(s) or CTRL.search(s) else []
