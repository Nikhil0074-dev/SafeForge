# Control mapping (supporting evidence, **not a compliance claim**)

| Framework / control | How SafeForge supports it | Gap |
|---|---|---|
| NIST SP 800-53 **SI-10** Information Input Validation | Content-based type check, size/bomb limits, allow-listed rebuild, fail-closed rejection | Deployment must isolate parsers |
| NIST SP 800-53 **SI-3** Malicious Code Protection | Disarm-and-reconstruct neutralises active content without signatures | Not an AV engine |
| NSA/CISA CDR guidance (rebuild from known-good primitives; image-only for highest assurance) | Balanced rebuild; paranoid image-only mode | Parser exploits out of scope |
| NIST SP 800-53 **AU-10** Non-repudiation / **SI-7** Integrity | SHA-256 in/out, hash-chained log, HMAC certificate | Local key, no PKI |
| NIST SP 800-53 **SC-39** Process isolation | Hardened compose file | Untested; gVisor not wired |
| GDPR Art. 5(1)(c)/(e) minimisation, storage limitation | Strips author/GPS/camera/revision metadata; jobs purged after TTL | No encryption at rest; metadata removal ≠ anonymisation |
| HIPAA Safe Harbor (§164.514(b)) | Removes some embedded identifiers (author, comments, tracked changes, hidden sheets) | Does **not** inspect visible PHI in content; not a de-identification tool |

Nothing here is a certification. Controls must be assessed in your environment.
