(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  // SECURITY: report fields (threat details, file names) are attacker-controlled -> only ever textContent.
  function el(tag, props = {}, kids = []) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    for (const c of [].concat(kids)) if (c != null) n.append(c);
    return n;
  }

  const chamber = $("#chamber"), fileInput = $("#file"), statusEl = $("#status");
  const state = { key: "", busy: false, last: null };

  async function health() {
    try {
      const h = await (await fetch("/api/v1/health")).json();
      if (h.auth_required) $("#keyrow").hidden = false;
    } catch (_) { /* offline server: ignore */ }
  }
  const headers = () => (state.key ? { "X-API-Key": state.key } : {});
  $("#apikey").addEventListener("input", (e) => { state.key = e.target.value.trim(); renderCurl(); });
  const mode = () => document.querySelector("input[name=mode]:checked").value;

  function setState(s) { chamber.dataset.state = s; }
  function say(t) { statusEl.textContent = t; }

  function renderCurl() {
    const f = (state.last && state.last.name) || "invoice.pdf";
    $("#curl").textContent =
      `curl -X POST ${location.origin}/api/v1/sanitize \\\n  -F file=@${f} -F mode=${mode()} \\\n  -H "X-API-Key: ${state.key ? "••••" : "$SAFEFORGE_KEY"}"`;
  }
  document.querySelectorAll("input[name=mode]").forEach((r) => r.addEventListener("change", renderCurl));

  // ---------- chamber interaction
  chamber.addEventListener("click", () => { if (!state.busy) fileInput.click(); });
  chamber.addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && !state.busy) { e.preventDefault(); fileInput.click(); } });
  ["dragenter", "dragover"].forEach((ev) => chamber.addEventListener(ev, (e) => { e.preventDefault(); chamber.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => chamber.addEventListener(ev, (e) => { e.preventDefault(); chamber.classList.remove("over"); }));
  chamber.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f && !state.busy) process(f); });
  fileInput.addEventListener("change", () => { const f = fileInput.files[0]; if (f && !state.busy) process(f); fileInput.value = ""; });

  const SLOTS = [[8, 16], [52, 24], [14, 40], [48, 48], [10, 64], [50, 70], [28, 30], [30, 56]];
  function addTag(text, risk, i) {
    const [x, y] = SLOTS[i % SLOTS.length];
    const cls = risk === "critical" || risk === "high" ? "" : risk === "medium" ? "m" : "l";
    $("#tags").append(el("span", { class: `tag ${cls}`, style: `left:${x}%;top:${y}%`, text }));
  }

  async function process(file) {
    state.busy = true;
    state.last = file;
    renderCurl();
    $("#tags").replaceChildren();
    $("#fname").textContent = file.name;
    $("#stamp").textContent = "";
    $("#dl").disabled = true;
    ["#chip-fid", "#chip-thr"].forEach((s) => { $(s).textContent = "…"; $(s).parentElement.className = "chip"; });
    setState("closing"); say("Sealing chamber…");
    await sleep(reduced ? 0 : 650);
    setState("scanning"); say("Scanning: parsing in isolation, nothing is trusted…");
    const t0 = performance.now();
    const fd = new FormData();
    fd.append("file", file);
    fd.append("mode", mode());
    let res, json;
    try {
      res = await fetch("/api/v1/sanitize", { method: "POST", headers: headers(), body: fd });
      json = await res.json();
    } catch (e) {
      setState("rejected"); $("#stamp").textContent = "Error"; say("Could not reach the server."); state.busy = false; return;
    }
    await sleep(reduced ? 0 : Math.max(0, 1700 - (performance.now() - t0)));
    if (res.status === 401 || (json.error && !json.threats_removed)) {
      setState("rejected"); $("#stamp").textContent = "Refused";
      say((json.error && json.error.message) || "Request refused.");
      renderError((json.error && json.error.message) || "Request refused.");
      state.busy = false; return;
    }
    const threats = json.threats_removed || [];
    threats.filter((t) => t.risk !== "info").slice(0, 8).forEach((t, i) => addTag(`${t.type.toUpperCase()} ×${t.count}`, t.risk, i));
    await sleep(reduced ? 0 : 350 + 220 * Math.min(threats.length, 6));
    if (res.ok) {
      setState("sterilizing"); say("Sterilizing: rebuilding from safe primitives…");
      await sleep(reduced ? 0 : 900);
      setState("done"); $("#stamp").textContent = "Sterilized";
      const n = json.threat_total || 0;
      say(`Done in ${json.processing_time_ms} ms. ${n} threat${n === 1 ? "" : "s"} neutralised; output independently verified.`);
      renderReport(json);
      renderCompare(json);
      const fid = json.fidelity_score;
      $("#chip-fid").textContent = fid == null ? "n/a" : fid.toFixed(1) + "%";
      $("#chip-fid").parentElement.className = "chip good";
      $("#chip-thr").textContent = String(n);
      $("#chip-thr").parentElement.className = "chip " + (n ? "bad" : "good");
      $("#dl").disabled = false;
      $("#dl").onclick = () => download(json.sanitized.download_url, json.sanitized.name);
    } else {
      setState("rejected"); $("#stamp").textContent = json.status === "blocked" ? "Rejected" : "Failed";
      say("File refused: " + json.reason);
      renderReport(json);
      $("#compare").replaceChildren(el("div", { class: "empty" }, [el("p", { class: "serif", text: "Nothing released." }), el("p", { text: "Rejected files produce no output. This is fail-closed by design." })]));
      $("#chip-fid").textContent = "—"; $("#chip-thr").textContent = "—";
    }
    state.busy = false;
  }

  async function download(url, name) {
    const r = await fetch(url, { headers: headers() });
    if (!r.ok) return say("Download failed (" + r.status + ").");
    const a = el("a", { href: URL.createObjectURL(await r.blob()), download: name });
    document.body.append(a); a.click(); a.remove();
  }

  // ---------- report
  function renderError(msg) {
    $("#report").replaceChildren(el("div", { class: "reason", text: msg }));
  }
  function renderReport(j) {
    const root = $("#report");
    const ok = j.status === "completed";
    const threats = j.threats_removed || [];
    const n = j.threat_total ?? threats.reduce((a, t) => a + t.count, 0);
    const name = (j.original && j.original.name) || "file";
    const sum = el("div", { class: "summary" + (ok ? "" : " bad") });
    if (ok) {
      sum.append(el("p", { class: "serif" }, [n ? el("em", { text: `${n} threat${n === 1 ? "" : "s"}` }) : el("em", { text: "Nothing hostile" }), ` neutralised in ${name}`]));
      sum.append(el("p", { class: "verify", text: "✓ Output re-parsed and re-scanned by an independent verifier: clean." }));
    } else {
      sum.append(el("p", { class: "serif" }, [el("em", { text: j.status === "blocked" ? "Rejected" : "Failed" }), ` — ${name}`]));
    }
    const kids = [sum];
    if (!ok) kids.push(el("div", { class: "reason", text: j.reason || "Unknown reason" }));
    if (threats.length) {
      const list = el("ul", { class: "threats" });
      threats.forEach((t) => {
        const det = el("ul", { class: "tdetail" }, (t.details || []).map((d) => el("li", { text: d })));
        list.append(el("li", {}, [el("details", {}, [
          el("summary", {}, [el("span", { class: `risk ${t.risk}`, text: t.risk }), el("span", { class: "ttype", text: t.type }), el("span", { class: "tcount", text: "×" + t.count })]),
          (t.details || []).length ? det : null])]));
      });
      kids.push(list);
    }
    (j.warnings || []).forEach((w) => kids.push(el("div", { class: "warn", text: "⚠ " + w })));
    const o = j.original || {}, s = j.sanitized;
    const facts = el("dl", { class: "facts" });
    const row = (k, v) => { if (v != null && v !== "") { facts.append(el("dt", { text: k }), el("dd", { text: String(v) })); } };
    row("true type", o.true_type); row("mode", j.mode); row("time", j.processing_time_ms != null ? j.processing_time_ms + " ms" : null);
    row("sha256 in", o.sha256); row("sha256 out", s && s.sha256);
    row("chain", j.chain_of_custody && j.chain_of_custody.entry_hash);
    kids.push(facts);
    if (ok) {
      kids.push(el("div", { class: "links" }, [
        el("button", { class: "link", onclick: () => download(j.certificate_url, "certificate.pdf") }, "Certificate (PDF)"),
        el("button", { class: "link", onclick: () => download(j.report_url, "report.json") }, "Report (JSON)")]));
    }
    root.replaceChildren(...kids);
  }

  // ---------- compare
  function renderCompare(j) {
    const root = $("#compare");
    const fid = j.fidelity_score;
    const ring = el("div", { class: "ringwrap" }, [
      el("div", { class: "ring", style: `--p:${fid == null ? 0 : fid}` }, el("div", { text: fid == null ? "n/a" : Math.round(fid) + "%" })),
      el("p", {}, [el("b", { text: "Fidelity" }), j.fidelity_method || ""])]);
    const pv = j.previews;
    if (!pv || !pv.original) {
      root.replaceChildren(ring, el("p", { class: "note", text: "No visual preview for this file type. Rendering untrusted Office documents needs a sandbox, so SafeForge compares extracted visible text instead." }));
      return;
    }
    const mk = (u) => { const i = el("img", { alt: "", draggable: "false" }); fetch(u, { headers: headers() }).then((r) => r.blob()).then((b) => { i.src = URL.createObjectURL(b); }); return i; };
    const before = mk(pv.original), after = mk(pv.sanitized), diff = mk(pv.diff);
    const afterWrap = el("div", { class: "after" }, after);
    const range = el("input", { type: "range", min: 0, max: 100, value: 50, "aria-label": "Before and after comparison position" });
    const slider = el("div", { class: "slider" }, [before, afterWrap, el("div", { class: "bar" }), el("span", { class: "lbl a", text: "original" }), el("span", { class: "lbl b", text: "sterilized" }), range]);
    range.addEventListener("input", () => slider.style.setProperty("--x", range.value + "%"));
    slider.style.setProperty("--x", "50%");
    const diffBtn = el("button", { "aria-pressed": "false", text: "Show differences" });
    let showing = false;
    diffBtn.addEventListener("click", () => {
      showing = !showing;
      diffBtn.setAttribute("aria-pressed", showing);
      afterWrap.replaceChildren(showing ? diff : after);
    });
    root.replaceChildren(ring, slider, el("div", { class: "toggle" }, diffBtn),
      el("p", { class: "note", text: "Drag to compare. Red pixels in the difference view mark content that changed." }));
  }

  health(); renderCurl();
})();
