# Honest scope: what is implemented, what is not

This project started from a very large specification. What follows is the real status.

## Implemented and tested
True-type detection · ZIP/XML/pixel/PDF bomb guards · PDF, OOXML, image, SVG, EML, ZIP, media and text sanitisers ·
independent output verifier · three modes + policy engine · forensic report, SHA-256 chain, signed certificate ·
pixel/text fidelity scoring with visual diff · conversion (any→PDF/PNG/TXT) · REST API (+batch, API keys, TTL purge) ·
CLI · web UI "Decontamination Chamber" · 267 automated tests, 68-fixture attack corpus.

## Not implemented (and why it matters)
| Spec item | Status |
|---|---|
| Wasm / browser-side "privacy mode", Electron app, Zero-Knowledge mode | **Not built.** Engine is server-side Python. Files reach the server. |
| gVisor/microVM orchestration, per-file ephemeral VMs | **Not built.** Dockerfile/compose hints only, untested. |
| NestJS/React/Rust/BullMQ/Redis/Postgres/Supabase/S3, watch folders, Lambda | **Not built.** Flask + files on disk. Batch = one HTTP call. |
| Encryption at rest | **Not built.** Jobs are deleted after the TTL (default 24 h) but stored in plaintext meanwhile. |
| Claude Vision fidelity check, LLM content validation | **Replaced** by deterministic pixel comparison (PDF/images) and visible-text retention (Office). |
| Printer tracking-dot removal, QR-code inspection, redaction-quality detection, PII/PHI auto-tagging | **Not built.** |
| ClamAV, YARA, federated threat intel, threat-emulation video, deep file inspector | **Not built.** The independent *structural* verifier replaces a second AV pass. |
| Blockchain notarisation | **Not built.** A local hash-chained log (tamper-evident, not distributed) is provided. |
| RAR / 7z / 3D / CAD / DWG | **Blocked** (RAR/7z) or unsupported. |
| JS/TS SDK | **Not built.** Use the REST API or CLI. |
| Streaming large files | **Not built.** Whole file in memory (limit 50 MB API / 100 MB engine). |
| "Parser depth limit 10" | Set to **100**: real DOCX/XLSX nest deeper than 10. |
| "40+ file types" | ~22 families (see README). |

## Known technical limits
* **Parser risk is not eliminated** (see README warning). Verification checks *structure*, not that a parser is bug-free.
* **Balanced PDF keeps JBIG2 image streams** (reported as `DecoderRisk`); use paranoid mode to eliminate decoder exposure.
* **Optional-content filtering** covers page content streams and `Do` of OC-tagged XObjects, not marked content nested
  inside Form XObjects. White-on-white text is **not** detected.
* **Office uses a deny-list + reachability GC**, not a full allow-list of every OOXML part type. The verifier fails the
  job if a known-dangerous part/relationship survives, but an *unknown future* vector would not be caught.
* **Legacy `.doc/.xls/.ppt` (OLE)** cannot be disarmed structurally; they are converted by LibreOffice **in-process on
  the original file**, then rasterised. Sandbox required.
* **Steganography:** a lossless re-encode does **not** remove LSB data (a test asserts this). Only paranoid mode's LSB
  randomisation does; JPEG DCT-domain steganography is only *likely* disrupted by re-quantisation.
* **Fidelity score** is a heuristic: a 1 px blur tolerance for anti-aliasing, "ink-pixel" matching. 100 % does not mean
  byte-identical. Office files get a text-retention score, not a visual one; UI shows no visual preview for them
  because rendering a hostile Office file needs a sandbox.
* `metadata_only` leaves active content by design.
* ZIP ratio rule only applies above 1 MiB (tiny files legitimately compress >100:1).
* The certificate's HMAC proves integrity only to holders of the server key; it is **not** a PKI signature or a
  third-party certification.
* Media sanitising removes container metadata with stream copy; it does not inspect codec payloads.
