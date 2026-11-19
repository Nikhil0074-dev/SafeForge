"""Raster image scrubber (Module 2/4/5): decode -> fresh bitmap -> fresh encode."""
import io
import os

from PIL import ExifTags, Image, ImageOps, ImageSequence

from .errors import BombError, CDRError
from .limits import DEFAULT_LIMITS, check_pixels

Image.MAX_IMAGE_PIXELS = DEFAULT_LIMITS.max_pixels
OUT_KIND = {"jpeg": "jpeg", "png": "png", "gif": "gif", "webp": "webp", "bmp": "png", "tiff": "png"}
FORMAT = {"jpeg": "JPEG", "png": "PNG", "gif": "GIF", "webp": "WEBP"}
BENIGN_INFO = {"dpi", "transparency", "duration", "loop", "background", "version", "extension", "progressive",
               "progression", "jfif", "jfif_version", "jfif_unit", "jfif_density", "adobe", "adobe_transform",
               "gamma", "srgb", "aspect", "interlace", "optimize", "compression", "timestamp"}
SENSITIVE_TAGS = {"Make", "Model", "Software", "Artist", "Copyright", "DateTime", "DateTimeOriginal",
                  "HostComputer", "LensModel", "LensMake", "BodySerialNumber", "CameraOwnerName", "ImageDescription",
                  "XPAuthor", "XPComment", "UserComment"}


def _gps(exif):
    try:
        g = exif.get_ifd(0x8825)
    except Exception:
        return None
    if not g:
        return None

    def conv(v, ref):
        d, m, s = (float(x) for x in v)
        r = d + m / 60 + s / 3600
        return -r if ref in ("S", "W") else r
    try:
        lat = conv(g[2], g.get(1, "N"))
        lon = conv(g[4], g.get(3, "E"))
        return f"{lat:.4f},{lon:.4f}"
    except Exception:
        return "present (unparsed)"


def _trailing(data, kind):
    if kind == "png":
        i = data.rfind(b"IEND")
        return len(data) - (i + 8) if i >= 0 else 0
    if kind == "jpeg":
        i = data.rfind(b"\xff\xd9")
        return len(data) - (i + 2) if i >= 0 else 0
    if kind == "gif":
        i = data.rfind(b"\x3b")
        return len(data) - (i + 1) if i >= 0 else 0
    return 0


def report_metadata(im, data, kind, log):
    try:
        exif = im.getexif()
    except Exception:
        exif = {}
    gps = _gps(exif) if exif else None
    if gps:
        log.add("GPS", "high", f"GPS: {gps}")
    for tag, val in (exif.items() if exif else []):
        name = ExifTags.TAGS.get(tag, str(tag))
        if name in SENSITIVE_TAGS and not isinstance(val, bytes):
            log.add("Metadata", "medium" if name in ("Make", "Model", "Software", "Artist") else "low", f"{name}: {str(val)[:100]}")
    if exif and not log.has("Metadata") and not gps:
        log.add("Metadata", "low", "EXIF block")
    for k in im.info:
        if k == "icc_profile":
            log.add("Metadata", "low", "ICC colour profile")
        elif k in ("xmp", "XML:com.adobe.xmp"):
            log.add("Metadata", "low", "XMP packet")
        elif k == "comment":
            log.add("Metadata", "low", f"comment: {str(im.info[k])[:100]}")
        elif k not in BENIGN_INFO and k not in ("exif",) and isinstance(k, str):
            log.add("Metadata", "low", f"embedded field: {k}")
    for k, v in (getattr(im, "text", None) or {}).items():
        log.add("Metadata", "low", f"text chunk {k}: {str(v)[:80]}")
    extra = _trailing(data, kind)
    if extra > 0:
        log.add("TrailingData", "high", f"{extra} bytes appended after image end (polyglot / payload)")


def _randomise_lsb(raw):
    n = len(raw)
    keep = int.from_bytes(b"\xfe" * n, "big")
    bit = int.from_bytes(b"\x01" * n, "big")
    rnd = int.from_bytes(os.urandom(n), "big")
    return ((int.from_bytes(raw, "big") & keep) | (rnd & bit)).to_bytes(n, "big")


def _fresh(frame, opts, force_mode=None):
    if frame.mode in ("P", "PA"):
        frame = frame.convert("RGBA" if "transparency" in frame.info or frame.mode == "PA" else "RGB")
    elif frame.mode not in ("1", "L", "LA", "RGB", "RGBA", "CMYK", "I;16"):
        frame = frame.convert("RGBA" if "A" in frame.getbands() else "RGB")
    if force_mode and frame.mode != force_mode:
        frame = frame.convert(force_mode)
    raw = frame.tobytes()
    if opts.scrub_lsb and frame.mode in ("L", "LA", "RGB", "RGBA"):
        raw = _randomise_lsb(raw)
    return Image.frombytes(frame.mode, frame.size, raw)


def scrub_raster(data, kind, opts, log, limits=DEFAULT_LIMITS):
    try:
        im = Image.open(io.BytesIO(data))
        w, h = im.size
        frames = getattr(im, "n_frames", 1)
        if frames > limits.max_gif_frames:
            raise BombError(f"{frames} frames (limit {limits.max_gif_frames})")
        check_pixels(w, h, frames if kind == "gif" else 1, limits)
        report_metadata(im, data, kind, log)
        if frames > 1 and kind in ("tiff", "bmp", "webp"):
            log.add("Info", "info", f"multi-frame {kind}: only first frame kept")
        out_kind = OUT_KIND[kind]
        buf = io.BytesIO()
        if kind == "gif" and frames > 1:
            fr, dur = [], []
            for f in ImageSequence.Iterator(im):
                dur.append(f.info.get("duration", 100))
                fr.append(_fresh(f.convert("RGBA"), opts))
            fr[0].save(buf, "GIF", save_all=True, append_images=fr[1:], duration=dur, loop=im.info.get("loop", 0), disposal=2)
            return buf.getvalue(), out_kind
        im.load()
        im = ImageOps.exif_transpose(im)
        if out_kind == "jpeg":
            mode = "RGB" if im.mode not in ("L", "CMYK") else None
            fresh = _fresh(im, opts, mode)
            fresh.save(buf, "JPEG", quality=95, optimize=True)
        elif out_kind == "png":
            fresh = _fresh(im, opts)
            fresh.save(buf, "PNG", optimize=True)
        elif out_kind == "webp":
            fresh = _fresh(im, opts)
            fresh.save(buf, "WEBP", quality=95)
        else:  # gif single frame
            fresh = _fresh(im.convert("RGBA"), opts)
            fresh.save(buf, "GIF")
        return buf.getvalue(), out_kind
    except (BombError, CDRError):
        raise
    except Image.DecompressionBombError as e:
        raise BombError(str(e))
    except Exception as e:
        raise CDRError(f"cannot decode image: {e}")


def verify_raster(data, opts):
    v = []
    try:
        im = Image.open(io.BytesIO(data))
        im.load()
    except Exception as e:
        return [f"output not decodable: {e}"]
    if len(im.getexif()):
        v.append("EXIF survived")
    for k in im.info:
        if k not in BENIGN_INFO:
            v.append(f"metadata field {k} survived")
    if getattr(im, "text", None):
        v.append("text chunks survived")
    return v
