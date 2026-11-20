import io
import json
import os
import time

import pytest

from safeforge.server import create_app


@pytest.fixture()
def client(tmp_path):
    return create_app({"DATA_DIR": str(tmp_path), "MAX_BYTES": 3 * 1024 * 1024}).test_client()


def post(c, f, mode="balanced", **extra):
    data = {"file": (io.BytesIO(f.data), f.filename), "mode": mode, **extra}
    return c.post("/api/v1/sanitize", data=data, content_type="multipart/form-data")


def test_sanitize_contract_matches_spec(client, corpus):
    r = post(client, corpus["pdf_embedded_exe"])
    j = r.get_json()
    assert r.status_code == 200 and j["status"] == "completed" and j["mode"] == "balanced"
    for k in ("job_id", "original", "sanitized", "fidelity_score", "processing_time_ms", "threats_removed", "report_url", "certificate_url"):
        assert k in j
    assert j["original"]["true_type"] == "pdf" and len(j["original"]["sha256"]) == 64
    assert j["sanitized"]["sha256"] != j["original"]["sha256"]
    assert any(t["type"] == "EmbeddedFile" for t in j["threats_removed"])
    dl = client.get(j["sanitized"]["download_url"])
    assert dl.status_code == 200 and dl.data.startswith(b"%PDF") and b"malware.exe" not in dl.data
    assert "attachment" in dl.headers["Content-Disposition"] and dl.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in dl.headers["Content-Security-Policy"]
    rep = client.get(j["report_url"]).get_json()
    assert rep["job_id"] == j["job_id"]
    cert = client.get(j["certificate_url"])
    assert cert.status_code == 200 and cert.data.startswith(b"%PDF")
    for which in ("original", "sanitized", "diff"):
        p = client.get(f"/api/v1/preview/{j['job_id']}/{which}")
        assert p.status_code == 200 and p.data.startswith(b"\x89PNG")


def test_rejections_return_422_with_reason(client, corpus):
    r = post(client, corpus["exe_renamed_pdf"])
    assert r.status_code == 422 and r.get_json()["status"] == "blocked"
    assert client.get(f"/api/v1/download/{r.get_json()['job_id']}").status_code == 404   # nothing to download
    r = post(client, corpus["png_pixel_bomb"])
    assert r.status_code == 422 and "bomb" in r.get_json()["reason"]


def test_bad_requests(client, corpus):
    assert client.post("/api/v1/sanitize", data={}, content_type="multipart/form-data").status_code == 400
    assert post(client, corpus["pdf_metadata"], mode="turbo").status_code == 400
    assert post(client, corpus["pdf_metadata"], policy="[1]").status_code == 400
    assert post(client, corpus["pdf_metadata"], policy="{nope").status_code == 400
    assert post(client, corpus["pdf_metadata"], policy='{"dpi": 1}').status_code == 400
    assert post(client, corpus["pdf_metadata"], output_format="exe").status_code == 400


def test_size_limit(client):
    big = io.BytesIO(b"A" * (4 * 1024 * 1024))
    r = client.post("/api/v1/sanitize", data={"file": (big, "x.txt")}, content_type="multipart/form-data")
    assert r.status_code == 413 and r.get_json()["error"]["code"] == "too_large"


def test_job_ids_are_validated_no_path_traversal(client):
    for bad in ("..", "../../etc/passwd", "not-a-uuid", "%2e%2e%2f"):
        assert client.get(f"/api/v1/report/{bad}").status_code == 404
        assert client.get(f"/api/v1/download/{bad}").status_code == 404
    assert client.get("/api/v1/report/00000000-0000-0000-0000-000000000000").status_code == 404


def test_api_key_enforced(tmp_path, corpus):
    c = create_app({"DATA_DIR": str(tmp_path), "API_KEYS": {"sk_live_abc"}}).test_client()
    f = corpus["pdf_metadata"]
    body = lambda: {"file": (io.BytesIO(f.data), "a.pdf")}
    assert c.get("/api/v1/health").get_json()["auth_required"] is True
    assert c.post("/api/v1/sanitize", data=body(), content_type="multipart/form-data").status_code == 401
    assert c.post("/api/v1/sanitize", data=body(), content_type="multipart/form-data", headers={"X-API-Key": "wrong"}).status_code == 401
    assert c.post("/api/v1/sanitize", data=body(), content_type="multipart/form-data", headers={"X-API-Key": "sk_live_abc"}).status_code == 200
    assert c.get("/").status_code == 200                                   # UI shell is public


def test_policy_via_api(client, corpus):
    j = post(client, corpus["pdf_hidden_layer_and_text"], policy=json.dumps({"remove_hidden": False})).get_json()
    assert j["policy"]["remove_hidden"] is False
    assert not any(t["type"] in ("HiddenText", "HiddenLayer") for t in j["threats_removed"])
    on = post(client, corpus["pdf_hidden_layer_and_text"]).get_json()
    assert {"HiddenText", "HiddenLayer"} <= {t["type"] for t in on["threats_removed"]}


def test_convert_endpoints(client, corpus):
    f = corpus["pdf_openaction_js"]
    r = client.post("/api/v1/convert", data={"file": (io.BytesIO(f.data), "a.pdf"), "output_format": "png"}, content_type="multipart/form-data")
    assert r.status_code == 200 and r.data.startswith(b"\x89PNG") and r.mimetype == "image/png" and r.headers["X-Job-Id"]
    r = client.post("/api/v1/convert", data={"file": (io.BytesIO(f.data), "a.pdf"), "output_format": "txt"}, content_type="multipart/form-data")
    assert r.status_code == 200 and b"Invoice total" in r.data
    j = post(client, corpus["jpg_with_gps_exif"], output_format="pdf").get_json()
    assert j["sanitized"]["converted_from"] == "jpeg" and j["sanitized"]["name"].endswith(".pdf")
    assert client.get(j["sanitized"]["download_url"]).data.startswith(b"%PDF")
    bad = client.post("/api/v1/convert", data={"file": (io.BytesIO(corpus["svg_script_tag"].data), "a.svg"), "output_format": "pdf"}, content_type="multipart/form-data")
    assert bad.status_code == 422


def test_batch(client, corpus):
    files = [(io.BytesIO(corpus[n].data), corpus[n].filename) for n in ("pdf_metadata", "exe_renamed_pdf", "svg_onload_attr")]
    r = client.post("/api/v1/batch", data={"files": files}, content_type="multipart/form-data").get_json()
    assert (r["count"], r["completed"], r["rejected"]) == (3, 2, 1)
    assert client.post("/api/v1/batch", data={}, content_type="multipart/form-data").status_code == 400


def test_chain_endpoint_and_ttl_purge(tmp_path, corpus):
    app = create_app({"DATA_DIR": str(tmp_path), "TTL_SECONDS": 60})
    c = app.test_client()
    j = post(c, corpus["pdf_metadata"]).get_json()
    assert c.get("/api/v1/chain/verify").get_json() == {"entries": 1, "first_bad_index": None, "intact": True}
    d = tmp_path / "jobs" / j["job_id"]
    assert d.exists()
    old = time.time() - 3600
    os.utime(d, (old, old))
    app.safeforge["state"]["last_purge"] = 0
    c.get("/api/v1/health")
    assert not d.exists() and c.get(j["report_url"]).status_code == 404


def test_ui_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in r.headers["Content-Security-Policy"].split("script-src")[1].split(";")[0]
