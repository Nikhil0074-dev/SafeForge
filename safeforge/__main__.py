import argparse
import json
import os
import sys

from .engine import sanitize
from .policy import MODES


def main(argv=None):
    ap = argparse.ArgumentParser(prog="safeforge", description="Zero-trust file sanitizer (CDR)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sanitize", help="sanitize one or more files")
    s.add_argument("files", nargs="+")
    s.add_argument("-m", "--mode", choices=MODES, default="balanced")
    s.add_argument("-o", "--out", default="safe_out")
    s.add_argument("--policy", help="JSON file with policy overrides")
    s.add_argument("--json", action="store_true", help="print full JSON reports")
    v = sub.add_parser("serve", help="run the web UI + REST API")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8080)
    a = ap.parse_args(argv)

    if a.cmd == "serve":
        from .server import create_app
        create_app().run(host=a.host, port=a.port)
        return 0

    overrides = json.load(open(a.policy)) if a.policy else None
    os.makedirs(a.out, exist_ok=True)
    rc = 0
    for path in a.files:
        with open(path, "rb") as fh:
            r = sanitize(fh.read(), os.path.basename(path), a.mode, overrides)
        if a.json:
            print(json.dumps(r.report, indent=2))
        if r.ok:
            dest = os.path.join(a.out, r.out_name)
            with open(dest, "wb") as fh:
                fh.write(r.data)
            if not a.json:
                n = sum(t["count"] for t in r.threats)
                print(f"OK       {path} -> {dest}  ({n} threat(s), fidelity {r.report['fidelity_score']})")
        else:
            rc = 2
            if not a.json:
                print(f"REJECTED {path}: {r.reason}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
