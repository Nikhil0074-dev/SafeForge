"""EML sanitiser: allow-listed headers, tracking pixels / remote content / scripts removed,
every attachment is sanitised recursively through the engine."""
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from urllib.parse import urlparse

import lxml.html

KEEP_HEADERS = ("From", "To", "Cc", "Subject", "Date")
DROP_WITH_CONTENT = {"script", "style", "iframe", "object", "embed", "form", "input", "button", "select",
                     "textarea", "meta", "link", "base", "svg", "math", "applet", "noscript", "template",
                     "head", "title", "video", "audio", "source", "canvas"}
ALLOWED = {"html", "body", "p", "br", "div", "span", "b", "i", "u", "strong", "em", "a", "ul", "ol", "li",
           "table", "thead", "tbody", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote",
           "pre", "code", "hr", "small", "big", "center"}
ATTRS = {"a": {"href"}, "td": {"colspan", "rowspan"}, "th": {"colspan", "rowspan"}}


def _oneline(s):
    return re.sub(r"[\r\n\x00]+", " ", str(s))[:998]


def _safe_name(n):
    n = (n or "attachment").replace("\\", "/").split("/")[-1]
    n = re.sub(r"[\x00-\x1f\"<>|:*?]", "_", n).strip(". ") or "attachment"
    return n[:120]


def clean_html(html, opts, log):
    try:
        root = lxml.html.fromstring(html)
    except Exception:
        return ""
    for el in list(root.iter()):
        if not isinstance(el.tag, str):
            if el.getparent() is not None:
                el.drop_tree()
            continue
        if el.getparent() is None and el is root:
            continue
        tag = el.tag.lower()
        if el.getparent() is None:
            continue
        if tag in DROP_WITH_CONTENT:
            if tag not in ("head", "title", "style", "meta", "link"):
                log.add("ActiveContent", "high", f"<{tag}> removed")
            el.drop_tree()
        elif tag == "img":
            src = (el.get("src") or "").strip()
            w, h = el.get("width", ""), el.get("height", "")
            tiny = w in ("0", "1", "2") or h in ("0", "1", "2")
            if src.lower().startswith(("http:", "https:", "//")):
                host = urlparse(src if not src.startswith("//") else "http:" + src).netloc
                log.add("TrackingPixel" if tiny else "ExternalImage", "high" if tiny else "medium", host)
            alt = el.get("alt")
            if alt:
                span = lxml.html.fromstring("<span></span>")
                span.text = alt
                span.tail = el.tail
                el.getparent().replace(el, span)
            else:
                el.drop_tree()
        elif tag not in ALLOWED:
            el.drop_tag()
    for el in list(root.iter()):
        if not isinstance(el.tag, str):
            continue
        tag = el.tag.lower()
        for a in list(el.attrib):
            if a not in ATTRS.get(tag, ()):
                del el.attrib[a]
        if tag == "a":
            href = (el.get("href") or "").strip()
            if opts.strip_email_links or not href.lower().startswith(("http://", "https://", "mailto:")):
                if href:
                    log.add("ExternalLink", "medium", urlparse(href).netloc or href[:60])
                el.attrib.pop("href", None)
                if el.getparent() is not None:
                    el.drop_tag()
    return lxml.html.tostring(root, encoding="unicode")


def sanitize_eml(data, opts, log, sanitize_fn, depth):
    msg = BytesParser(policy=policy.default).parsebytes(data)
    out = EmailMessage()
    for h in KEEP_HEADERS:
        if msg[h] is not None:
            out[h] = _oneline(msg[h])
    dropped = [h for h in set(msg.keys()) if h not in KEEP_HEADERS]
    for h in dropped:
        if h.lower() in ("received", "x-originating-ip", "x-mailer", "user-agent", "return-path", "message-id", "reply-to", "x-ms-exchange-organization-authsource"):
            log.add("Metadata", "low", f"header {h} removed")
    plain, html = msg.get_body(("plain",)), msg.get_body(("html",))
    plain_s = plain.get_content() if plain is not None else None
    html_s = clean_html(html.get_content(), opts, log) if html is not None else None
    if plain_s is None and html_s:
        plain_s = lxml.html.fromstring(html_s).text_content()
    out.set_content(plain_s or "")
    if html_s:
        out.add_alternative(html_s, subtype="html")
    n_att = 0
    for part in msg.iter_attachments():
        name = _safe_name(part.get_filename())
        if part.get_content_type() == "message/rfc822":
            raw = part.get_payload()
            payload = raw[0].as_bytes() if isinstance(raw, list) else part.get_payload(decode=True)
            name = name if name.endswith(".eml") else name + ".eml"
        else:
            payload = part.get_payload(decode=True)
        if payload is None:
            log.add("AttachmentBlocked", "high", f"{name}: unreadable payload")
            continue
        r = sanitize_fn(payload, name, depth + 1)
        if r.status != "completed":
            log.add("AttachmentBlocked", "high", f"{name}: {r.reason}")
            continue
        for t in r.threats:
            if t["type"] == "Info":
                continue
            log.add(t["type"] if t["type"].startswith("Attachment:") else f"Attachment:{t['type']}", t["risk"], f"{name}: " + "; ".join(t["details"][:2]), t["count"])
        mt, _, st = r.mime.partition("/")
        if r.mime == "message/rfc822":   # nested mail: attach as a real message part, not opaque bytes
            out.add_attachment(BytesParser(policy=policy.default).parsebytes(r.data), filename=r.out_name)
        else:
            out.add_attachment(r.data, maintype=mt, subtype=st or "octet-stream", filename=r.out_name)
        n_att += 1
    if n_att:
        log.add("Info", "info", f"{n_att} attachment(s) sanitised")
    return out.as_bytes(policy=policy.SMTP)


def verify_eml(data):
    v = []
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as e:
        return [f"output not parseable: {e}"]
    for h in msg.keys():
        if h not in KEEP_HEADERS and h not in ("MIME-Version", "Content-Type", "Content-Transfer-Encoding"):
            v.append(f"header {h} survived")
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            body = part.get_content().lower()
            if re.search(r"<script|<iframe|<img|<object|<embed|\bon\w+\s*=|href\s*=|src\s*=", body):
                v.append("active/remote HTML content survived")
    return v
