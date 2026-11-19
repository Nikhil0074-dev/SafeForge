"""Chain of custody (hash-chained log) + signed PDF certificate."""
import hashlib
import hmac
import io
import json
import os
import threading
import time

GENESIS = "0" * 64


def sha256(b):
    return hashlib.sha256(b).hexdigest()


class ChainLog:
    """Append-only JSONL; each entry commits to the previous one, so edits/deletions are detectable."""

    def __init__(self, path):
        self.path, self._lock = path, threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def _last(self):
        if not os.path.exists(self.path):
            return GENESIS
        last = GENESIS
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)["entry_hash"]
        return last

    @staticmethod
    def _hash(entry):
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        return sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())

    def append(self, job_id, original_sha, sanitized_sha, mode, threats):
        with self._lock:
            e = {"ts": int(time.time()), "job_id": job_id, "original_sha256": original_sha,
                 "sanitized_sha256": sanitized_sha, "mode": mode, "threat_count": threats, "prev_hash": self._last()}
            e["entry_hash"] = self._hash(e)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(e, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return e

    def verify(self):
        """(ok, entries_checked, first_bad_index)"""
        prev, n = GENESIS, 0
        if not os.path.exists(self.path):
            return True, 0, None
        with open(self.path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if not line.strip():
                    continue
                e = json.loads(line)
                if e["prev_hash"] != prev or e["entry_hash"] != self._hash(e):
                    return False, n, i
                prev, n = e["entry_hash"], n + 1
        return True, n, None


def sign(key, entry_hash):
    return hmac.new(key, entry_hash.encode(), hashlib.sha256).hexdigest()


def _a(s, n=110):
    return str(s).encode("ascii", "replace").decode()[:n]


def certificate_pdf(report, signing_key):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    c.setTitle("SafeForge Sanitization Certificate")
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, h - 70, "SafeForge - Sanitization Certificate")
    c.setFont("Helvetica", 10)
    y = h - 100
    rows = [("Job ID", report["job_id"]), ("Mode", report["mode"]),
            ("Original file", f"{report['original']['name']} ({report['original']['true_type']})"),
            ("Sanitized file", report["sanitized"]["name"] if report.get("sanitized") else "-"),
            ("Threats neutralised", sum(t["count"] for t in report["threats_removed"])),
            ("Fidelity score", report.get("fidelity_score")), ("Verifier", report.get("verification", {}).get("result"))]
    for k, v in rows:
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, k)
        c.setFont("Helvetica", 10)
        c.drawString(170, y, _a(v))
        y -= 16
    y -= 8
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "SHA-256 chain")
    y -= 14
    c.setFont("Courier", 8)
    c.drawString(50, y, "original : " + report["original"]["sha256"])
    y -= 12
    c.drawString(50, y, "sanitized: " + (report["sanitized"]["sha256"] if report.get("sanitized") else "-"))
    y -= 24
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "Threats removed")
    y -= 14
    c.setFont("Helvetica", 9)
    for t in report["threats_removed"][:25]:
        c.drawString(55, y, _a(f"[{t['risk']}] {t['type']} x{t['count']}  {'; '.join(t['details'][:1])}", 105))
        y -= 12
        if y < 140:
            break
    y = 110
    c.setFont("Helvetica", 8)
    chain = report.get("chain_of_custody") or {}
    c.drawString(50, y, _a("Chain entry hash: " + chain.get("entry_hash", "-"), 120))
    c.drawString(50, y - 11, _a("Integrity MAC (HMAC-SHA256): " + sign(signing_key, chain.get("entry_hash", report["job_id"])), 120))
    c.drawString(50, y - 26, "Controls implemented are aligned with NIST SP 800-53 SI-10 (input validation). This is not a third-party")
    c.drawString(50, y - 37, "certification; the MAC proves integrity to the holder of the server key only.")
    c.showPage()
    c.save()
    return buf.getvalue()
