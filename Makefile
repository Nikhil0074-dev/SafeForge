.PHONY: install test serve samples screenshots corpus
install:      ; pip install -r requirements-dev.txt
test:         ; python -m pytest tests -q
serve:        ; python -m safeforge serve --port 8080
samples:      ; python scripts/make_samples.py
corpus:       ; python scripts/run_corpus.py
