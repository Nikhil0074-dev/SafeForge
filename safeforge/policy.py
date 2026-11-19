"""Policy engine (Module 8). Modes are presets; JSON policies override individual switches."""
from dataclasses import asdict, dataclass, fields

MODES = ("paranoid", "balanced", "metadata_only")


@dataclass
class Policy:
    mode: str = "balanced"
    remove_active: bool = True     # JS, macros, OLE, ActiveX, external refs, DDE ...
    remove_metadata: bool = True   # author, GPS, EXIF, docProps ...
    remove_hidden: bool = True     # hidden layers/sheets/text, comments, tracked changes
    flatten: bool = False          # PDF -> image-only PDF (Office -> PDF -> image-only)
    scrub_lsb: bool = False        # randomise least-significant bits (anti-steganography)
    keep_links: bool = True        # keep http/https/mailto hyperlinks
    strip_email_links: bool = True # defang links in email bodies
    dpi: int = 150
    block_types: tuple = ()        # extra type names to refuse, e.g. ("zip",)
    max_depth: int = 3


def _preset(mode):
    if mode == "paranoid":
        return Policy(mode="paranoid", flatten=True, scrub_lsb=True, keep_links=False)
    if mode == "balanced":
        return Policy(mode="balanced")
    if mode == "metadata_only":
        return Policy(mode="metadata_only", remove_active=False, remove_hidden=False)
    raise ValueError(f"unknown mode '{mode}' (use {', '.join(MODES)})")


def build_policy(mode="balanced", overrides=None):
    p = _preset(mode)
    overrides = overrides or {}
    allowed = {f.name: f for f in fields(Policy)}
    for k, v in overrides.items():
        if k == "mode" or k not in allowed:
            raise ValueError(f"unknown policy key '{k}'")
        cur = getattr(p, k)
        if isinstance(cur, bool) and not isinstance(v, bool):
            raise ValueError(f"policy key '{k}' must be boolean")
        if k == "dpi":
            if not isinstance(v, int) or not 50 <= v <= 600:
                raise ValueError("dpi must be an integer 50-600")
        if k == "max_depth" and (not isinstance(v, int) or not 0 <= v <= 5):
            raise ValueError("max_depth must be 0-5")
        if k == "block_types":
            v = tuple(str(x) for x in v)
        setattr(p, k, v)
    return p


def to_dict(p):
    d = asdict(p)
    d["block_types"] = list(p.block_types)
    return d
