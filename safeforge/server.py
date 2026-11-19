"""REST API + web UI (Module 8).  POST /api/v1/sanitize, /convert, /batch; GET report/certificate/download/preview."""
import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
import threading
import time

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge

from . import __version__
from .chain import ChainLog, certificate_pdf
from .convert import convert_sanitized
from .engine import sanitize
from .errors import SafeForgeError

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
STATIC = os.path.join(os.path.dirname(__file__), "static")
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
       "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def create_app(config=None):
    cfg = {
        "DATA_DIR": os.environ.get("SAFEFORGE_DATA", os.path.join(tempfile.gettempdir(), "safeforge-data")),
        "API_KEYS": {k.strip() for k in os.environ.get("SAFEFORGE_API_KEYS", "").split(",") if k.strip()},
        "TTL_SECONDS": int(os.environ.get("SAFEFORGE_TTL", 24 * 3600)),
        "MAX_BYTES": int(os.environ.get("SAFEFORGE_MAX_BYTES", 50 * 1024 * 1024)),
        "SIGNING_KEY": os.environ.get("SAFEFORGE_SIGNING_KEY", "").encode() or os.urandom(32),
        "BATCH_MAX": 20,
    }
    cfg.update(config or {})
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = cfg["MAX_BYTES"] + 1024 * 1024
    jobs_dir = os.path.join(cfg["DATA_DIR"], "jobs")
    os.makedirs(jobs_dir, exist_ok=True)
    chain = ChainLog(os.path.join(cfg["DATA_DIR"], "chain.jsonl"))
    state = {"last_purge": 0.0}
    lock = threading.Lock()

    # ------------------------------------------------------------ helpers
    def purge():
        now = time.time()
        with lock:
            if now - state["last_purge"] < 30:
                return
            state["last_purge"] = now
        for d in os.listdir(jobs_dir):
            p = os.path.join(jobs_dir, d)
            if os.path.isdir(p) and now - os.path.getmtime(p) > cfg["TTL_SECONDS"]:
                shutil.rmtree(p, ignore_errors=True)

    app.safeforge = {"cfg": cfg, "chain": chain, "state": state, "purge": purge}

    def err(code, msg, status):
        return jsonify({"error": {"code": code, "message": msg}}), status

    def authed():
        if not cfg["API_KEYS"]:
            return True
        key = request.headers.get("X-API-Key", "")
        return any(hmac.compare_digest(key.encode(), k.encode()) for k in cfg["API_KEYS"])

    @app.before_request
    def gate():
        purge()
        if request.path.startswith("/api/") and request.path != "/api/v1/health" and not authed():
            return err("unauthorized", "missing or invalid X-API-Key", 401)

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Content-Security-Policy", CSP)
        return resp

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(e):
        return err("too_large", f"file exceeds {cfg['MAX_BYTES']} bytes", 413)

    def job_path(job_id, name=""):
        if not UUID_RE.match(job_id):
            return None
        return os.path.join(jobs_dir, job_id, name) if name else os.path.join(jobs_dir, job_id)

    def parse_request():
        f = request.files.get("file")
        if f is None:
            raise ValueError("multipart field 'file' is required")
        data = f.read()
        mode = request.form.get("mode", "balanced")
        pol = request.form.get("policy")
        overrides = None
        if pol:
            try:
                overrides = json.loads(pol)
            except json.JSONDecodeError:
                raise ValueError("'policy' must be a JSON object")
            if not isinstance(overrides, dict):
                raise ValueError("'policy' must be a JSON object")
        return f.filename or "file", data, mode, overrides

    def store(res, filename):
        """Persist a completed/failed job; returns job_id."""
        job_id = res.report["job_id"]
        d = job_path(job_id)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "report.json"), "w") as fh:
            json.dump(res.report, fh)
        if res.ok:
            with open(os.path.join(d, "output.bin"), "wb") as fh:
                fh.write(res.data)
            for k, v in res.previews.items():
                with open(os.path.join(d, k + ".png"), "wb") as fh:
                    fh.write(v)
        return job_id

    def public(res):
        r = dict(res.report)
        jid = r["job_id"]
        base = "/api/v1"
        if res.ok:
            r["sanitized"] = dict(r["sanitized"], download_url=f"{base}/download/{jid}")
            r["certificate_url"] = f"{base}/certificate/{jid}"
            r["previews"] = {k[:-4]: f"{base}/preview/{jid}/{k[:-4]}" for k in res.previews}
        r["report_url"] = f"{base}/report/{jid}"
        return r

    def run(filename, data, mode, overrides):
        res = sanitize(data, filename, mode, overrides, previews=True, chain=chain)
        store(res, filename)
        return res

    # ------------------------------------------------------------ routes
    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC, name)

    @app.get("/api/v1/health")
    def health():
        from .convert import soffice_available
        from .media_cdr import available
        return jsonify({"status": "ok", "version": __version__, "auth_required": bool(cfg["API_KEYS"]),
                        "capabilities": {"libreoffice": soffice_available(), "ffmpeg": available()}})

    @app.post("/api/v1/sanitize")
    def api_sanitize():
        try:
            filename, data, mode, overrides = parse_request()
            fmt = request.form.get("output_format", "original")
            if fmt not in ("original", "pdf", "png", "txt"):
                raise ValueError("output_format must be original, pdf, png or txt")
            res = run(filename, data, mode, overrides)
        except ValueError as e:
            return err("bad_request", str(e), 400)
        if not res.ok:
            return jsonify(public(res)), 422
        out = public(res)
        if fmt != "original":
            try:
                out = apply_conversion(res, fmt, out)
            except (SafeForgeError, ValueError) as e:
                return err("conversion_failed", str(e), 422)
        return jsonify(out), 200

    def apply_conversion(res, fmt, out):
        data, mime, ext = convert_sanitized(res.data, res.out_type, fmt)
        if fmt == "pdf" and res.out_type in ("docx", "xlsx", "pptx"):
            again = sanitize(data, "converted.pdf", "balanced")  # LibreOffice output is re-disarmed before release
            if not again.ok:
                raise SafeForgeError("converted PDF failed verification")
            data = again.data
        jid = res.report["job_id"]
        name = re.sub(r"\.[^.]+$", "", res.out_name) + "." + ext
        with open(job_path(jid, "output.bin"), "wb") as fh:
            fh.write(data)
        out["sanitized"] = dict(out["sanitized"], name=name, size=len(data), mime=mime, sha256=hashlib.sha256(data).hexdigest(),
                                converted_from=res.out_type, download_url=f"/api/v1/download/{jid}")
        with open(job_path(jid, "report.json"), "w") as fh:
            json.dump({k: v for k, v in out.items() if k not in ("previews", "report_url", "certificate_url")}, fh)
        return out

    @app.post("/api/v1/convert")
    def api_convert():
        try:
            filename, data, mode, overrides = parse_request()
            fmt = request.form.get("output_format", "pdf")
            if fmt not in ("pdf", "png", "txt"):
                raise ValueError("output_format must be pdf, png or txt")
            res = run(filename, data, mode, overrides)
        except ValueError as e:
            return err("bad_request", str(e), 400)
        if not res.ok:
            return jsonify(public(res)), 422
        try:
            out = apply_conversion(res, fmt, public(res))
        except (SafeForgeError, ValueError) as e:
            return err("conversion_failed", str(e), 422)
        with open(job_path(res.report["job_id"], "output.bin"), "rb") as fh:
            body = fh.read()
        return file_response(body, out["sanitized"]["mime"], out["sanitized"]["name"], res.report["job_id"])

    @app.post("/api/v1/batch")
    def api_batch():
        files = request.files.getlist("files")
        if not files:
            return err("bad_request", "multipart field 'files' (one or more) is required", 400)
        if len(files) > cfg["BATCH_MAX"]:
            return err("bad_request", f"at most {cfg['BATCH_MAX']} files per batch", 400)
        mode = request.form.get("mode", "balanced")
        try:
            overrides = json.loads(request.form["policy"]) if request.form.get("policy") else None
            results = []
            for f in files:
                res = run(f.filename or "file", f.read(), mode, overrides)
                p = public(res)
                results.append({k: p.get(k) for k in ("job_id", "status", "reason", "original", "sanitized", "threat_total",
                                                       "fidelity_score", "report_url", "certificate_url") if k in p})
        except (ValueError, TypeError) as e:
            return err("bad_request", str(e), 400)
        ok = sum(1 for r in results if r["status"] == "completed")
        return jsonify({"count": len(results), "completed": ok, "rejected": len(results) - ok, "results": results})

    def file_response(body, mime, name, jid):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
        resp = Response(body, mimetype=mime)
        resp.headers["Content-Disposition"] = f'attachment; filename="{safe}"'
        resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
        resp.headers["X-Job-Id"] = jid
        return resp

    def load_report(jid):
        p = job_path(jid, "report.json")
        if p is None or not os.path.exists(p):
            return None
        with open(p) as fh:
            return json.load(fh)

    @app.get("/api/v1/report/<jid>")
    def api_report(jid):
        r = load_report(jid)
        return jsonify(r) if r else err("not_found", "unknown or expired job", 404)

    @app.get("/api/v1/download/<jid>")
    def api_download(jid):
        r, p = load_report(jid), job_path(jid, "output.bin")
        if not r or r.get("status") != "completed" or not os.path.exists(p):
            return err("not_found", "unknown, expired or rejected job", 404)
        with open(p, "rb") as fh:
            return file_response(fh.read(), r["sanitized"]["mime"], r["sanitized"]["name"], jid)

    @app.get("/api/v1/certificate/<jid>")
    def api_cert(jid):
        r = load_report(jid)
        if not r or r.get("status") != "completed":
            return err("not_found", "unknown, expired or rejected job", 404)
        return file_response(certificate_pdf(r, cfg["SIGNING_KEY"]), "application/pdf", f"certificate_{jid}.pdf", jid)

    @app.get("/api/v1/preview/<jid>/<which>")
    def api_preview(jid, which):
        if which not in ("original", "sanitized", "diff"):
            return err("not_found", "unknown preview", 404)
        p = job_path(jid, f"{which}_png.png")
        if p is None or not os.path.exists(p):
            return err("not_found", "no preview for this job", 404)
        with open(p, "rb") as fh:
            return Response(fh.read(), mimetype="image/png")

    @app.get("/api/v1/chain/verify")
    def api_chain():
        ok, n, bad = chain.verify()
        return jsonify({"intact": ok, "entries": n, "first_bad_index": bad})

    return app
