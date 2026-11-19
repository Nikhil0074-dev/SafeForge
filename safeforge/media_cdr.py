"""Video/audio metadata stripping with ffmpeg (stream copy - no re-encode, metadata only)."""
import json
import os
import shutil
import subprocess
import tempfile

from .errors import BlockedError, CDRError

EXT = {"mp4": ".mp4", "mp3": ".mp3", "wav": ".wav"}
BENIGN = {"major_brand", "minor_version", "compatible_brands", "handler_name", "vendor_id", "language"}
TIMEOUT = 120


def available():
    return bool(shutil.which("ffmpeg") and shutil.which("ffprobe"))


def _probe(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format", "-show_streams", path],
                       capture_output=True, timeout=TIMEOUT)
    if r.returncode != 0:
        raise CDRError("ffprobe could not parse media file")
    j = json.loads(r.stdout or b"{}")
    tags = dict(j.get("format", {}).get("tags", {}))
    for s in j.get("streams", []):
        tags.update({f"stream:{k}": v for k, v in s.get("tags", {}).items()})
    return tags


def strip_media(data, kind, opts, log):
    if not available():
        raise BlockedError("ffmpeg/ffprobe not installed; media files cannot be sanitized")
    with tempfile.TemporaryDirectory(prefix="sf_media_") as d:
        src, dst = os.path.join(d, "in" + EXT[kind]), os.path.join(d, "out" + EXT[kind])
        with open(src, "wb") as f:
            f.write(data)
        for k, v in _probe(src).items():
            kk = k.split(":")[-1]
            if kk in BENIGN:
                continue
            risk = "high" if "location" in kk.lower() or "gps" in kk.lower() else "low"
            log.add("GPS" if risk == "high" else "Metadata", risk, f"{kk}: {str(v)[:100]}")
        cmd = ["ffmpeg", "-nostdin", "-v", "error", "-y", "-i", src, "-map", "0:v?", "-map", "0:a?", "-dn", "-sn",
               "-map_metadata", "-1", "-map_metadata:s:v", "-1", "-map_metadata:s:a", "-1", "-map_chapters", "-1",
               "-c", "copy", "-fflags", "+bitexact", "-flags:v", "+bitexact", "-flags:a", "+bitexact"]
        if kind == "mp3":
            cmd += ["-write_id3v2", "0", "-write_id3v1", "0", "-write_xing", "0"]
        cmd.append(dst)
        r = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT, cwd=d, env={"PATH": os.environ.get("PATH", "")})
        if r.returncode != 0 or not os.path.exists(dst):
            raise CDRError("ffmpeg failed: " + r.stderr.decode("utf-8", "replace")[:200])
        with open(dst, "rb") as f:
            return f.read()


def verify_media(data, kind):
    if not available():
        return []
    with tempfile.TemporaryDirectory(prefix="sf_media_") as d:
        p = os.path.join(d, "v" + EXT[kind])
        with open(p, "wb") as f:
            f.write(data)
        try:
            tags = _probe(p)
        except Exception as e:
            return [f"output not parseable: {e}"]
    return [f"metadata tag survived: {k}" for k in tags if k.split(":")[-1] not in BENIGN]
