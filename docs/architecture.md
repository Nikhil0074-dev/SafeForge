# Architecture

```
upload ─► size cap ─► detect (magic bytes) ─► block list / policy ─► bomb checks
            │                                                          │
            ▼                                                          ▼
       spoof flag                                 per-type CDR  (parse → keep safe primitives → rebuild)
                                                                       │
                              reject (no output) ◄── violations ◄── independent verifier (re-parse + re-scan output)
                                                                       │ clean
                                         hashes · fidelity · chain entry · report · certificate
```

* **Fail-closed everywhere.** Unparseable, blocked, bomb, verifier-reject or any unexpected exception ⇒ status
  `blocked`/`failed`, `data=None`, generic message (no internals leaked).
* **Two code paths per format, deliberately.** The disarmer deletes; the verifier is a separate walk that must find
  nothing. A bug in one is caught by the other (this found two real bugs during development; see `tests/`).
* **Bounded reading.** ZIP members are inflated incrementally against a cumulative budget (headers can lie).
  XML is pre-scanned with expat for entity declarations/DOCTYPE subsets/depth before lxml sees it (UTF-16 safe).
* **PDF:** `pikepdf.new()` + copy pages. Catalog-level threats (OpenAction, Names, AcroForm, Metadata…) never reach
  the output because the catalog is fresh. Page annotations are re-created from an allow-list. A graph walk (including
  *direct* dictionaries and unreachable objects) both reports and verifies.
* **OOXML:** parts → drop rules → relationship rewrite → dangling `r:id` repair (unwrap hyperlinks, remove elements) →
  format-specific XML cleanup → reachability GC from `_rels/.rels` → content-types fix → fresh ZIP with fixed timestamps.
* **Conversion** only ever consumes already-sanitised bytes; LibreOffice output is re-disarmed before release.
* **API** validates job IDs (UUID), serves downloads with `Content-Disposition: attachment`, `nosniff`,
  `CSP: sandbox`; UI has a strict CSP (`script-src 'self'`, no inline script) and renders all report text via `textContent`.

## Chain of custody
Append-only JSONL; each entry hashes `prev_hash` + body. `verify()` detects edits and deletions (tested). It is local
and tamper-evident, not tamper-proof (an attacker who can rewrite the whole file can rebuild the chain).
