"""Office (OOXML: docx/xlsx/pptx and macro-enabled variants) disarm & reconstruct.

The package is unzipped with bounded reads, dangerous parts and relationships are removed, XML
parts are rewritten, unreachable parts are garbage-collected and a fresh ZIP is written.
"""
import io
import posixpath
import re
import zipfile
from collections import defaultdict

from lxml import etree

from .errors import CDRError
from .limits import DEFAULT_LIMITS, ReadBudget, check_xml, open_zip, safe_read

NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
NS_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS_S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_P = "http://schemas.openxmlformats.org/presentationml/2006/main"
NS_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
W, S, P_ = "{%s}" % NS_W, "{%s}" % NS_S, "{%s}" % NS_P
RNS = "{%s}" % NS_R

# (regex on lower-case part name, policy flag, threat type, risk)
_RULES_RAW: list[tuple[str, str, str | None, str | None]] = [
    (r"(^|/)vbaproject\.bin$", "active", "Macro", "critical"),
    (r"(^|/)vbaprojectsignature\.bin$", "active", "Macro", "critical"),
    (r"(^|/)vbadata\.xml$", "active", "Macro", "critical"),
    (r"(^|/)activex/", "active", "ActiveX", "critical"),
    (r"(^|/)embeddings/", "active", "EmbeddedObject", "high"),
    (r"(^|/)externallinks/", "active", "ExternalLink", "high"),
    (r"(^|/)querytables/", "active", "QueryTable", "high"),
    (r"^xl/connections\.xml$", "active", "DataConnection", "high"),
    (r"^xl/macrosheets/", "active", "XLMMacro", "critical"),
    (r"^xl/dialogsheets/", "active", "XLMMacro", "critical"),
    (r"^word/glossary/", "active", "Glossary", "medium"),
    (r"\.(exe|dll|bat|cmd|ps1|vbs|js|jar|scr|com|msi|lnk|hta|wsf|sh)$", "active", "Executable", "critical"),
    (r"^xl/calcchain\.xml$", "always", None, None),
    (r"^docprops/", "metadata", "Metadata", "low"),
    (r"(^|/)printersettings/", "metadata", "Metadata", "low"),
    (r"^word/people\.xml$", "metadata", "Metadata", "low"),
    (r"^word/comments[^/]*\.xml$", "hidden", "Comment", "medium"),
    (r"^xl/comments[^/]*\.xml$", "hidden", "Comment", "medium"),
    (r"^xl/threadedcomments/", "hidden", "Comment", "medium"),
    (r"^xl/persons/", "metadata", "Metadata", "low"),
    (r"^ppt/comments/", "hidden", "Comment", "medium"),
    (r"^ppt/commentauthors\.xml$", "metadata", "Metadata", "low"),
    (r"^ppt/notesslides/", "hidden", "SpeakerNotes", "medium"),
    (r"^ppt/notesmasters/", "hidden", "SpeakerNotes", "medium"),
    (r"(^|/)customxml/", "hidden", "CustomXML", "medium"),
]
RULES = [(re.compile(a), b, c, d) for a, b, c, d in _RULES_RAW]

BAD_REL_TYPES = {"attachedtemplate", "oleobject", "externallink", "externallinkpath", "frame", "subdocument",
                 "vbaproject", "package", "control", "afchunk", "macrosheet", "dialogsheet", "externaldata"}
SAFE_LINK = ("http://", "https://", "mailto:")
DANGEROUS_FIELDS = {"DDE", "DDEAUTO", "INCLUDETEXT", "INCLUDEPICTURE", "LINK", "IMPORT", "INCLUDE", "MACROBUTTON", "DATABASE", "RD"}
DANGEROUS_FORMULA = re.compile(r"(WEBSERVICE|RTD|FILTERXML|EXEC|CALL|REGISTER|REGISTER\.ID)\s*\(|\w+\|['\"]?[^!]*['\"]?!", re.IGNORECASE)
MACRO_CT = {
    "application/vnd.ms-word.document.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "application/vnd.ms-word.template.macroEnabledTemplate.main+xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
}
OUT_KIND = {"docm": "docx", "xlsm": "xlsx", "pptm": "pptx"}
REV_ELEMS = {"rPrChange", "pPrChange", "sectPrChange", "tblPrChange", "tcPrChange", "trPrChange",
             "tblGridChange", "numberingChange", "tblPrExChange", "cellIns", "cellDel", "cellMerge",
             "moveFromRangeStart", "moveFromRangeEnd", "moveToRangeStart", "moveToRangeEnd"}


# ------------------------------------------------------------------ helpers
def _norm(name):
    n = name.replace("\\", "/")
    if n.startswith("/") or any(seg == ".." for seg in n.split("/")) or re.match(r"^[A-Za-z]:", n):
        return None
    while n.startswith("./"):
        n = n[2:]
    return n


def _parse(data, limits=DEFAULT_LIMITS):
    check_xml(data, limits)
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)
    try:
        return etree.fromstring(data, parser)
    except etree.XMLSyntaxError as e:
        raise CDRError(f"malformed XML: {e}")


def _ser(root):
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


def rels_path(part):
    if not part:
        return "_rels/.rels"
    d, b = posixpath.split(part)
    return posixpath.join(d, "_rels", b + ".rels")


def source_part(rp):
    d, b = posixpath.split(rp)
    name = b[:-5]
    return posixpath.join(posixpath.dirname(d), name) if name else ""


def resolve(src, target):
    if target.startswith("/"):
        return posixpath.normpath(target[1:])
    return posixpath.normpath(posixpath.join(posixpath.dirname(src), target))


def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _text_before(el, text):
    if not text:
        return
    prev = el.getprevious()
    if prev is not None:
        prev.tail = (prev.tail or "") + text
    else:
        p = el.getparent()
        p.text = (p.text or "") + text


def _remove(el):
    p = el.getparent()
    if p is None:
        return
    _text_before(el, el.tail)
    p.remove(el)


def _unwrap(el):
    p = el.getparent()
    if p is None:
        return
    _text_before(el, el.text)
    for ch in list(el):
        el.addprevious(ch)
    _text_before(el, el.tail)
    p.remove(el)


def _safe_link(t):
    return t.strip().lower().startswith(SAFE_LINK)


def field_is_dangerous(instr):
    s = instr.strip()
    if not s:
        return False
    cmd = s.split(None, 1)[0].upper()
    if cmd in DANGEROUS_FIELDS:
        return True
    if cmd == "HYPERLINK":
        m = re.search(r'"([^"]*)"', s)
        return bool(m) and not _safe_link(m.group(1))
    return False


def load_package(data, limits=DEFAULT_LIMITS, log=None):
    zf = open_zip(data, limits)
    budget = ReadBudget(limits.max_zip_total)
    parts, seen = {}, set()
    for info in zf.infolist():
        if info.filename.endswith("/"):
            continue
        n = _norm(info.filename)
        if n is None:
            if log is not None:
                log.add("PathTraversal", "high", info.filename[:100])
            continue
        if n.lower() in seen:
            raise CDRError(f"duplicate ZIP entry '{n[:60]}' (parser-differential trick)")
        seen.add(n.lower())
        parts[n] = safe_read(zf, info, budget, limits)
    if "[Content_Types].xml" not in parts:
        raise CDRError("not an OOXML package: [Content_Types].xml missing")
    return parts


def _enabled(opts, flag):
    return {"active": opts.remove_active, "metadata": opts.remove_metadata,
            "hidden": opts.remove_hidden, "always": opts.remove_active or opts.remove_hidden}[flag]


# ------------------------------------------------------------------ format specific
def _clean_word(root, opts, log, part):
    if opts.remove_active:
        stack = []
        for el in root.iter(W + "fldChar", W + "instrText", W + "fldSimple"):
            t = _local(el.tag)
            if t == "fldSimple":
                if field_is_dangerous(el.get(W + "instr", "")):
                    el.set(W + "instr", ' QUOTE "[field removed by SafeForge]" ')
                    log.add("DDE/Field", "critical", "field instruction neutralised")
                continue
            if t == "fldChar":
                kind = el.get(W + "fldCharType")
                if kind == "begin":
                    stack.append({"els": [], "open": True})
                elif kind in ("separate", "end") and stack:
                    top = stack[-1]
                    if top["open"]:
                        top["open"] = False
                        instr = "".join(e.text or "" for e in top["els"])
                        if field_is_dangerous(instr):
                            top["els"][0].text = ' QUOTE "[field removed by SafeForge]" '
                            for e in top["els"][1:]:
                                e.text = ""
                            log.add("DDE/Field", "critical", instr.strip()[:120])
                    if kind == "end":
                        stack.pop()
            elif stack and stack[-1]["open"]:
                stack[-1]["els"].append(el)
    if opts.remove_hidden:
        n = 0
        for el in list(root.iter(W + "commentRangeStart", W + "commentRangeEnd")):
            _remove(el)
        for el in list(root.iter(W + "commentReference")):
            r = el.getparent()
            _remove(r if r is not None and r.tag == W + "r" else el)
        for el in list(root.iter(W + "ins", W + "moveTo", W + "del", W + "moveFrom")):
            if el.getparent() is None:
                continue
            t, par = _local(el.tag), el.getparent()
            if par.tag in (W + "rPr", W + "trPr"):
                if t in ("del", "moveFrom") and par.tag == W + "trPr":
                    tr = par.getparent()
                    if tr is not None and tr.getparent() is not None:
                        _remove(tr)
                        n += 1
                        continue
                _remove(el)
            elif t in ("ins", "moveTo"):
                _unwrap(el)
                n += 1
            else:
                _remove(el)
                n += 1
        for el in list(root.iter(*[W + e for e in REV_ELEMS])):
            _remove(el)
            n += 1
        if n:
            log.add("TrackedChanges", "medium", f"{part}: revision history removed (insertions kept, deletions discarded)", n)
        v = 0
        for el in list(root.iter(W + "vanish")):
            if el.get(W + "val", "1").lower() in ("0", "false", "off"):
                continue
            rpr = el.getparent()
            run = rpr.getparent() if rpr is not None else None
            if run is not None and run.tag == W + "r" and run.getparent() is not None:
                _remove(run)
                v += 1
        if v:
            log.add("HiddenText", "medium", f"{v} hidden text run(s) (w:vanish)", v)
        for el in list(root.iter(W + "docVars")):
            _remove(el)
            log.add("HiddenData", "medium", "document variables removed")


def _col_idx(ref):
    m = re.match(r"([A-Z]+)", ref or "")
    n = 0
    for ch in m.group(1) if m else "":
        n = n * 26 + ord(ch) - 64
    return n


def _clean_sheet(root, opts, log, used_strings, state):
    if opts.remove_active:
        for f in list(root.iter(S + "f")):
            if f.text and DANGEROUS_FORMULA.search(f.text):
                log.add("FormulaInjection", "high", f.text[:120])
                _remove(f)
    if opts.remove_hidden:
        for row in list(root.iter(S + "row")):
            if row.get("hidden", "0").lower() in ("1", "true"):
                _remove(row)
                state["cells"] = True
                log.add("HiddenData", "medium", "hidden row(s) removed")
        hidden = set()
        for col in root.iter(S + "col"):
            if col.get("hidden", "0").lower() in ("1", "true"):
                hidden.update(range(int(col.get("min", 0)), int(col.get("max", 0)) + 1))
        if hidden:
            for c in list(root.iter(S + "c")):
                if _col_idx(c.get("r")) in hidden:
                    _remove(c)
            state["cells"] = True
            log.add("HiddenData", "medium", f"{len(hidden)} hidden column(s) cleared")
    for c in root.iter(S + "c"):
        if c.get("t") == "s":
            v = c.find(S + "v")
            if v is not None and (v.text or "").strip().isdigit():
                used_strings.add(int(v.text))


def _hidden_parts(parts, kind, opts, log):
    """Return (set of part names to drop, removed sheet indices) for hidden sheets / slides."""
    drop, removed_idx = set(), []
    if not opts.remove_hidden:
        return drop, removed_idx
    if kind in ("xlsx", "xlsm") and "xl/workbook.xml" in parts:
        wb = _parse(parts["xl/workbook.xml"])
        rels = {}
        rp = "xl/_rels/workbook.xml.rels"
        if rp in parts:
            for r in _parse(parts[rp]):
                rels[r.get("Id")] = r.get("Target")
        for i, sh in enumerate(wb.iter(S + "sheet")):
            if sh.get("state", "visible") in ("hidden", "veryHidden"):
                tgt = rels.get(sh.get(RNS + "id"))
                if tgt:
                    drop.add(resolve("xl/workbook.xml", tgt))
                removed_idx.append(i)
                log.add("HiddenSheet", "high", f"{sh.get('state')} sheet '{(sh.get('name') or '')[:60]}' removed")
    if kind in ("pptx", "pptm"):
        for p, d in parts.items():
            if re.match(r"^ppt/slides/slide\d+\.xml$", p):
                r = _parse(d)
                if r.get("show") == "0":
                    drop.add(p)
                    log.add("HiddenSlide", "medium", f"{p} removed")
    return drop, removed_idx


def _clean_workbook(root, removed_idx, opts, log):
    for el in list(root.iter(S + "externalReferences")):
        _remove(el)
    if removed_idx:
        dn = root.find(S + "definedNames")
        if dn is not None:
            for name in list(dn):
                loc = name.get("localSheetId")
                if loc is None:
                    continue
                loc = int(loc)
                if loc in removed_idx:
                    _remove(name)
                else:
                    name.set("localSheetId", str(loc - sum(1 for r in removed_idx if r < loc)))
        for bv in root.iter(S + "workbookView"):
            for a in ("activeTab", "firstSheet"):
                if a in bv.attrib:
                    bv.set(a, "0")


def _prune_shared_strings(root, used):
    for i, si in enumerate(root.findall(S + "si")):
        if i not in used:
            for ch in list(si):
                si.remove(ch)
            etree.SubElement(si, S + "t")


# ------------------------------------------------------------------ main entry
def disarm_office(data, kind, opts, log, limits=DEFAULT_LIMITS):
    parts = load_package(data, limits, log)
    dropped = set()
    for p in list(parts):
        if p.endswith(".rels") or p == "[Content_Types].xml":
            continue
        for rx, flag, typ, risk in RULES:
            if rx.search(p.lower()) and _enabled(opts, flag):
                dropped.add(p)
                if typ:
                    log.add(typ, risk, p)
                break
    hid, removed_idx = _hidden_parts(parts, kind, opts, log)
    dropped |= hid

    # --- relationships
    removed_rids = defaultdict(set)
    rel_trees = {}
    for rp in [p for p in parts if p.endswith(".rels")]:
        src = source_part(rp)
        if src and (src in dropped or src not in parts and src != ""):
            dropped.add(rp)
            continue
        root = _parse(parts[rp], limits)
        changed = False
        for rel in list(root):
            if not isinstance(rel.tag, str):
                continue
            typ = (rel.get("Type") or "").rsplit("/", 1)[-1].lower()
            tgt, mode = rel.get("Target") or "", rel.get("TargetMode", "Internal")
            reason = None
            if mode == "External":
                if opts.remove_active:
                    if typ == "hyperlink":
                        if not _safe_link(tgt):
                            reason = ("DangerousLink", "high", tgt)
                        elif not opts.keep_links:
                            reason = ("Hyperlink", "info", tgt)
                    elif typ == "attachedtemplate":
                        reason = ("TemplateInjection", "critical", tgt)
                    elif typ in ("image", "video", "audio", "media"):
                        reason = ("ExternalResource", "medium", tgt)
                    else:
                        reason = ("ExternalLink", "high", f"{typ}: {tgt}")
            else:
                res = resolve(src, tgt)
                if res in dropped or res not in parts:
                    reason = ("__silent__", "info", None)
                elif typ in BAD_REL_TYPES and opts.remove_active:
                    dropped.add(res)
                    reason = ("EmbeddedObject", "high", res)
            if reason:
                if reason[0] != "__silent__":
                    log.add(reason[0], reason[1], reason[2][:200] if reason[2] else None)
                removed_rids[src].add(rel.get("Id"))
                root.remove(rel)
                changed = True
        rel_trees[rp] = root
        if changed:
            if src and not any(isinstance(e.tag, str) for e in root):
                dropped.add(rp)          # nothing left in this relationship part
                continue
            parts[rp] = _ser(root)

    # --- XML parts
    used_strings, state = set(), {"cells": False}
    shared = None
    for p in sorted(parts):
        if p in dropped or not p.lower().endswith(".xml") or p == "[Content_Types].xml":
            continue
        root = _parse(parts[p], limits)
        before = parts[p]
        todo = []
        rids = removed_rids.get(p)
        if rids:
            for el in root.iter():
                if not isinstance(el.tag, str):
                    continue
                for a, v in el.attrib.items():
                    if a.startswith(RNS) and v in rids:
                        todo.append((el, a))
        for el, a in todo:
            if el.getparent() is None:
                continue
            t = _local(el.tag)
            if t == "hyperlink":
                _unwrap(el)
            elif t == "blip" or t == "imagedata":
                del el.attrib[a]
            else:
                _remove(el)
        if re.match(r"^word/(document|header\d*|footer\d*|footnotes|endnotes|settings)\.xml$", p):
            _clean_word(root, opts, log, p)
        elif re.match(r"^xl/worksheets/[^/]+\.xml$", p):
            _clean_sheet(root, opts, log, used_strings, state)
        elif p == "xl/workbook.xml":
            _clean_workbook(root, removed_idx, opts, log)
        elif p == "xl/sharedStrings.xml":
            shared = root
            continue
        new = _ser(root)
        if todo or new != before:
            parts[p] = new
    if shared is not None and state["cells"]:
        _prune_shared_strings(shared, used_strings)
        parts["xl/sharedStrings.xml"] = _ser(shared)

    # --- garbage collect unreachable parts
    if opts.remove_active or opts.remove_hidden:
        reach, queue = {"[Content_Types].xml"}, [""]
        while queue:
            src = queue.pop()
            rp = rels_path(src)
            if rp not in parts or rp in dropped:
                continue
            reach.add(rp)
            root = rel_trees.get(rp) if rp in rel_trees else _parse(parts[rp], limits)
            for rel in root:
                if not isinstance(rel.tag, str) or rel.get("TargetMode") == "External":
                    continue
                t = resolve(src, rel.get("Target") or "")
                if t in parts and t not in dropped and t not in reach:
                    reach.add(t)
                    queue.append(t)
        keep = reach
    else:
        keep = {p for p in parts if p not in dropped}
        keep = {p for p in keep if not p.endswith(".rels") or source_part(p) in keep or source_part(p) == ""}

    # --- content types
    ct = _parse(parts["[Content_Types].xml"], limits)
    for el in list(ct):
        if not isinstance(el.tag, str):
            continue
        if _local(el.tag) == "Override":
            if el.get("PartName", "").lstrip("/") not in keep:
                ct.remove(el)
            elif opts.remove_active and el.get("ContentType") in MACRO_CT:
                el.set("ContentType", MACRO_CT[el.get("ContentType")])
        elif _local(el.tag) == "Default" and opts.remove_active and "vbaProject" in (el.get("ContentType") or ""):
            ct.remove(el)
    parts["[Content_Types].xml"] = _ser(ct)

    out = io.BytesIO()
    order = ["[Content_Types].xml", "_rels/.rels"] + sorted(p for p in keep if p not in ("[Content_Types].xml", "_rels/.rels"))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in order:
            if p in keep and p in parts:
                zi = zipfile.ZipInfo(p, date_time=(1980, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = 0o600 << 16
                z.writestr(zi, parts[p])
    return out.getvalue(), (OUT_KIND.get(kind, kind) if opts.remove_active else kind)


# ------------------------------------------------------------------ verification
def verify_office(data, opts, limits=DEFAULT_LIMITS):
    v = []
    try:
        parts = load_package(data, limits)
    except Exception as e:
        return [f"output is not a valid OOXML package: {e}"]
    for p in parts:
        if p.endswith(".rels") or p == "[Content_Types].xml":
            continue
        for rx, flag, typ, _ in RULES:
            if rx.search(p.lower()) and flag != "always" and _enabled(opts, flag):
                v.append(f"part {p} survived ({typ})")
    for p, d in parts.items():
        if not p.lower().endswith((".xml", ".rels")):
            continue
        try:
            root = _parse(d, limits)
        except Exception as e:
            v.append(f"{p}: {e}")
            continue
        if p.endswith(".rels"):
            src = source_part(p)
            for rel in root:
                if not isinstance(rel.tag, str):
                    continue
                typ = (rel.get("Type") or "").rsplit("/", 1)[-1].lower()
                tgt = rel.get("Target") or ""
                if rel.get("TargetMode") == "External":
                    if opts.remove_active and (typ != "hyperlink" or not _safe_link(tgt)):
                        v.append(f"{p}: external relationship {typ}")
                else:
                    if resolve(src, tgt) not in parts:
                        v.append(f"{p}: dangling relationship to {tgt}")
                    if opts.remove_active and typ in BAD_REL_TYPES:
                        v.append(f"{p}: dangerous relationship {typ}")
        elif p == "[Content_Types].xml":
            if opts.remove_active and any("macroEnabled" in (e.get("ContentType") or "") for e in root if isinstance(e.tag, str)):
                v.append("macro-enabled content type survived")
        elif re.match(r"^word/[^/]+\.xml$", p):
            if opts.remove_active:
                for el in root.iter(W + "instrText"):
                    if field_is_dangerous(el.text or ""):
                        v.append(f"{p}: dangerous field")
                for el in root.iter(W + "fldSimple"):
                    if field_is_dangerous(el.get(W + "instr", "")):
                        v.append(f"{p}: dangerous fldSimple")
            if opts.remove_hidden and p != "word/styles.xml":
                if next(root.iter(W + "ins", W + "del", W + "moveFrom", W + "vanish"), None) is not None:
                    v.append(f"{p}: tracked change or hidden text survived")
        elif p == "xl/workbook.xml" and opts.remove_hidden:
            for sh in root.iter(S + "sheet"):
                if sh.get("state", "visible") != "visible":
                    v.append("hidden sheet survived")
        elif re.match(r"^ppt/slides/slide\d+\.xml$", p) and opts.remove_hidden and root.get("show") == "0":
            v.append("hidden slide survived")
    return v


# ------------------------------------------------------------------ text extraction (fidelity / convert)
def visible_text(data, kind, limits=DEFAULT_LIMITS):
    """Human-visible text of an OOXML file (hidden, deleted and commented text excluded)."""
    parts = load_package(data, limits)
    out = []
    if kind in ("docx", "docm"):
        for p in sorted(parts):
            if re.match(r"^word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$", p):
                root = _parse(parts[p], limits)
                for para in root.iter(W + "p"):
                    txt = []
                    for r in para.iter(W + "r"):
                        rpr = r.find(W + "rPr")
                        if rpr is not None:
                            van = rpr.find(W + "vanish")
                            if van is not None and van.get(W + "val", "1").lower() not in ("0", "false", "off"):
                                continue
                        if any(a.tag in (W + "del", W + "moveFrom") for a in r.iterancestors()):
                            continue
                        txt.extend(t.text or "" for t in r.iter(W + "t"))
                    if txt:
                        out.append("".join(txt))
    elif kind in ("xlsx", "xlsm"):
        ss = []
        if "xl/sharedStrings.xml" in parts:
            for si in _parse(parts["xl/sharedStrings.xml"], limits).findall(S + "si"):
                ss.append("".join(t.text or "" for t in si.iter(S + "t")))
        wb = _parse(parts["xl/workbook.xml"], limits)
        rels = {r.get("Id"): r.get("Target") for r in _parse(parts["xl/_rels/workbook.xml.rels"], limits)}
        for sh in wb.iter(S + "sheet"):
            tgt = rels.get(sh.get(RNS + "id"))
            if not tgt or sh.get("state", "visible") != "visible":
                continue
            path = resolve("xl/workbook.xml", tgt)
            if path not in parts:
                continue
            root = _parse(parts[path], limits)
            hcols = set()
            for col in root.iter(S + "col"):
                if col.get("hidden", "0").lower() in ("1", "true"):
                    hcols.update(range(int(col.get("min", 0)), int(col.get("max", 0)) + 1))
            for row in root.iter(S + "row"):
                if row.get("hidden", "0").lower() in ("1", "true"):
                    continue
                for c in row.iter(S + "c"):
                    if _col_idx(c.get("r")) in hcols:
                        continue
                    v = c.find(S + "v")
                    if c.get("t") == "s" and v is not None and (v.text or "").strip().isdigit() and int(v.text) < len(ss):
                        out.append(ss[int(v.text)])
                    elif c.get("t") == "inlineStr":
                        out.append("".join(t.text or "" for t in c.iter(S + "t")))
                    elif v is not None and v.text:
                        out.append(v.text)
    elif kind in ("pptx", "pptm"):
        for p in sorted(parts):
            if re.match(r"^ppt/slides/slide\d+\.xml$", p):
                root = _parse(parts[p], limits)
                if root.get("show") == "0":
                    continue
                out.extend((t.text or "") for t in root.iter("{%s}t" % NS_A))
    return "\n".join(x for x in out if x.strip())
