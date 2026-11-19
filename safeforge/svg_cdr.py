"""SVG allowlist sanitizer - SVG is the #1 XSS vector in image uploads."""
import re

from lxml import etree

from .errors import BombError, CDRError
from .limits import DEFAULT_LIMITS, check_xml

SVG_NS = "http://www.w3.org/2000/svg"
XLINK = "http://www.w3.org/1999/xlink"
ALLOWED = {"svg", "g", "defs", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "text", "tspan",
           "textPath", "title", "desc", "linearGradient", "radialGradient", "stop", "clipPath", "mask", "pattern",
           "symbol", "use", "image", "marker", "style", "filter", "feGaussianBlur", "feOffset", "feBlend",
           "feColorMatrix", "feMerge", "feMergeNode", "feFlood", "feComposite", "switch"}
BAD_CSS = re.compile(r"(javascript:|vbscript:|expression\s*\(|@import|behavior\s*:|-moz-binding|url\s*\(\s*(?![\s'\"]*#))", re.IGNORECASE)
DATA_IMG = re.compile(r"^data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=\s]*$", re.IGNORECASE)
MAX_ELEMENTS = 500_000


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _clean_attrs(el, name, log):
    for attr in list(el.attrib):
        ns = attr.rsplit("}", 1)[0][1:] if attr.startswith("{") else ""
        local = _local(attr)
        val = el.get(attr)
        reason = None
        if local.lower().startswith("on"):
            reason = ("EventHandler", f"{name}@{local}={val[:60]}")
        elif ns not in ("", XLINK, "http://www.w3.org/XML/1998/namespace"):
            reason = ("ForeignAttribute", local)
        elif local == "href":
            ok = val.startswith("#") or (name == "image" and DATA_IMG.match(val or ""))
            if not ok:
                reason = ("ExternalReference", f"{name} href={val[:80]}")
        elif re.search(r"javascript:|vbscript:", val, re.IGNORECASE):
            reason = ("ScriptURL", f"{name}@{local}")
        elif BAD_CSS.search(val) and (local == "style" or "url(" in val.lower()):
            reason = ("ExternalReference", f"{name}@{local}={val[:60]}")
        if reason:
            log.add(reason[0], "high", reason[1])
            del el.attrib[attr]
            if local == "href" and name in ("use", "image"):
                return False
    return True


def _walk(el, log, counter, limits):
    for child in list(el):
        counter[0] += 1
        if counter[0] > MAX_ELEMENTS:
            raise BombError("SVG has too many elements")
        if not isinstance(child.tag, str):
            el.remove(child)  # comments, processing instructions
            continue
        ns = child.tag[1:].split("}")[0] if child.tag.startswith("{") else ""
        name = _local(child.tag)
        if ns != SVG_NS or name not in ALLOWED:
            risk = "critical" if name.lower() in ("script", "foreignobject", "iframe", "embed", "object") else "high"
            log.add("ActiveContent", risk, f"<{name}> removed")
            el.remove(child)
            continue
        if not _clean_attrs(child, name, log):
            el.remove(child)
            continue
        if name == "style" and BAD_CSS.search(child.text or ""):
            log.add("ExternalReference", "high", "<style> with external/script content removed")
            el.remove(child)
            continue
        _walk(child, log, counter, limits)


def sanitize_svg(data, opts, log, limits=DEFAULT_LIMITS):
    check_xml(data, limits)
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False,
                             remove_comments=True, remove_pis=True)
    try:
        root = etree.fromstring(data, parser)
    except etree.XMLSyntaxError as e:
        raise CDRError(f"malformed SVG: {e}")
    if root.tag != "{%s}svg" % SVG_NS:
        raise CDRError("root element is not an SVG element")
    _clean_attrs(root, "svg", log)
    _walk(root, log, [0], limits)
    etree.cleanup_namespaces(root)
    return etree.tostring(root, xml_declaration=True, encoding="utf-8")


def verify_svg(data):
    from .threats import ThreatLog
    log = ThreatLog()
    try:
        sanitize_svg(data, None, log)
    except Exception as e:
        return [str(e)]
    return [f"{t['type']}: {t['details']}" for t in log.to_list()]
