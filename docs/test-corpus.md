# Test corpus

`corpus/make_corpus.py` generates **68 fixtures in memory** (also writable with `python corpus/make_corpus.py test-corpus`).
All payloads are inert placeholders (`app.alert(1)`, `MZ`+filler, fake `vbaProject.bin`): they carry the *structure* of
attacks, so detection and removal are real, but nothing can execute.

| Category | Count | Examples |
|---|---|---|
| pdf | 18 | OpenAction/Names/AA JS, Launch, embedded EXE, FileAttachment, XFA, widget JS, `javascript:` URI, GoToR, SubmitForm, RichMedia, metadata, hidden layer + invisible text, real incremental update, inherited MediaBox, JBIG2 |
| office | 13 | macro docm, DDE/DDEAUTO, template injection, hidden text + tracked changes + comments, ActiveX/OLE, dangerous hyperlinks, tracker image, hidden sheets/rows/cols, external links, formula injection, XLM/VBA xlsm, pptx notes/hidden slide/OLE, zip-slip, duplicate entries |
| svg | 10 | script, onload, foreignObject, `javascript:` href, SMIL, external image/use, CSS `@import`, `style=url()` |
| image | 7 | GPS EXIF, JPEG/PNG trailing payload, PNG text chunks, animated GIF comment, WebP EXIF, BMP, TIFF |
| bomb | 7 | Billion-Laughs (DOCX, SVG), XXE, 40000×40000 PNG, 150 MiB ZIP, deep nesting, duplicate entries |
| spoof / text / archive / email / media | 5 / 1 / 3 / 1 / 3 | EXE named `.pdf`, ELF named `.png`, docx named `.pdf`, Trojan-Source text, zip-slip, mixed ZIP, hostile EML, MP4 GPS, MP3 ID3, WAV tags |

Each fixture declares: expected status, threat types that **must** be reported, byte strings that **must not** survive
in the output (searched inside inflated ZIP parts too), and business text that **must** survive.
`python scripts/run_corpus.py` prints the table in `docs/corpus-results.txt` (68/68). The spec's target of 100 files was
not reached; 68 distinct vectors are covered rather than padding with near-duplicates.
