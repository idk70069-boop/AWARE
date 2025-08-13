#!/usr/bin/env python3
"""
AWARE — A simple, open-source prototype malware detection utility.
Features:
- Hash-based detection (SHA-256) using a local signatures.json
- Optional YARA scanning if yara-python is installed and rules present
- Optional directory monitoring if watchdog is installed
- Quarantine of detected files
- JSON reports and rotating log
This is a learning prototype, not production security software.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import sys
import time
import datetime
from typing import List, Dict, Optional

APP_NAME = "AWARE"
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR
SIG_PATH = DATA_DIR / "signatures.json"
RULES_DIR = DATA_DIR / "rules"
QUARANTINE_DIR = DATA_DIR / "quarantine"
REPORTS_DIR = DATA_DIR / "reports"
LOG_PATH = DATA_DIR / "aware.log"

for p in [QUARANTINE_DIR, REPORTS_DIR]:
    p.mkdir(parents=True, exist_ok=True)

def log(msg: str):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")

def sha256_file(path: pathlib.Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            h.update(data)
    return h.hexdigest()

def load_signatures(sig_path: pathlib.Path) -> Dict:
    if not sig_path.exists():
        return {"signatures": [], "metadata": {"algorithm": "sha256"}}
    with open(sig_path, "r", encoding="utf-8") as f:
        return json.load(f)

def yara_available():
    try:
        import yara  # type: ignore
        return True
    except Exception:
        return False

def compile_yara_rules(rule_dir: pathlib.Path):
    import yara  # type: ignore
    rules = []
    if not rule_dir.exists():
        return None
    rule_files = [str(p) for p in rule_dir.rglob("*.yar")]
    if not rule_files:
        return None
    return yara.compile(filepaths={str(i): f for i, f in enumerate(rule_files)})

def scan_file(path: pathlib.Path, sigs: Dict, use_yara: bool = True) -> Dict:
    result = {
        "path": str(path),
        "exists": path.exists(),
        "size": path.stat().st_size if path.exists() else None,
        "detections": []
    }
    if not path.exists() or not path.is_file():
        return result

    # Hash-based
    algo = sigs.get("metadata", {}).get("algorithm", "sha256")
    if algo != "sha256":
        log(f"Unsupported signature algorithm: {algo}")
    else:
        file_hash = sha256_file(path)
        for entry in sigs.get("signatures", []):
            if entry.get("hash") == file_hash:
                result["detections"].append({
                    "engine": "hash",
                    "label": entry.get("label", "Unknown"),
                    "severity": entry.get("severity", "unknown"),
                    "details": {"hash": file_hash}
                })
                break

    # YARA-based (optional)
    if use_yara and yara_available():
        try:
            rules = compile_yara_rules(RULES_DIR)
            if rules:
                matches = rules.match(str(path))
                for m in matches:
                    result["detections"].append({
                        "engine": "yara",
                        "label": m.rule,
                        "severity": m.meta.get("severity", "unknown"),
                        "details": {"tags": list(m.tags), "meta": dict(m.meta)}
                    })
        except Exception as e:
            log(f"YARA error scanning {path}: {e}")

    result["malicious"] = len(result["detections"]) > 0
    return result

def quarantine(path: pathlib.Path) -> pathlib.Path:
    rel = pathlib.Path(time.strftime("%Y%m%d")) / os.path.basename(path)
    dest = QUARANTINE_DIR / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(path), str(dest))
    # Make read-only
    os.chmod(dest, 0o400)
    return dest

def write_report(results: List[Dict]) -> pathlib.Path:
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out = REPORTS_DIR / f"aware_report_{ts}.json"
    report = {
        "app": APP_NAME,
        "timestamp": ts,
        "summary": {
            "scanned": len(results),
            "malicious": sum(1 for r in results if r.get("malicious"))
        },
        "results": results
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return out

def iter_files(root: pathlib.Path):
    for p in root.rglob("*"):
        if p.is_file():
            yield p

def cmd_scan(args):
    paths = [pathlib.Path(p).resolve() for p in args.paths]
    sigs = load_signatures(SIG_PATH)
    results = []
    for p in paths:
        if p.is_dir():
            for f in iter_files(p):
                res = scan_file(f, sigs, use_yara=not args.no_yara)
                if res.get("malicious"):
                    log(f"DETECTED: {f}")
                    if args.quarantine:
                        try:
                            q = quarantine(f)
                            res["quarantined_to"] = str(q)
                            log(f"QUARANTINED: {f} -> {q}")
                        except Exception as e:
                            log(f"Quarantine failed for {f}: {e}")
                results.append(res)
        else:
            res = scan_file(p, sigs, use_yara=not args.no_yara)
            if res.get("malicious"):
                log(f"DETECTED: {p}")
                if args.quarantine:
                    try:
                        q = quarantine(p)
                        res["quarantined_to"] = str(q)
                        log(f"QUARANTINED: {p} -> {q}")
                    except Exception as e:
                        log(f"Quarantine failed for {p}: {e}")
            results.append(res)

    report_path = write_report(results)
    print(f"Scan complete. Report saved to: {report_path}")
    print(json.dumps({
        "scanned": len(results),
        "malicious": sum(1 for r in results if r.get("malicious"))
    }, indent=2))

def cmd_monitor(args):
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except Exception:
        print("watchdog not installed. Install with: pip install watchdog")
        sys.exit(1)

    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            path = pathlib.Path(event.src_path)
            sigs = load_signatures(SIG_PATH)
            res = scan_file(path, sigs, use_yara=not args.no_yara)
            if res.get("malicious"):
                log(f"REALTIME DETECTED: {path}")
                print(f"[ALERT] Malicious file detected: {path}")
                if args.quarantine:
                    try:
                        q = quarantine(path)
                        print(f"Quarantined to: {q}")
                        log(f"REALTIME QUARANTINE: {path} -> {q}")
                    except Exception as e:
                        log(f"Realtime quarantine failed for {path}: {e}")

    observer = Observer()
    for folder in args.folders:
        observer.schedule(Handler(), folder, recursive=True)
        print(f"Monitoring: {folder}")
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def cmd_addhash(args):
    p = pathlib.Path(args.file).resolve()
    if not p.exists() or not p.is_file():
        print("File not found or not a file.")
        return
    h = sha256_file(p)
    sigs = load_signatures(SIG_PATH)
    sigs.setdefault("signatures", []).append({
        "hash": h,
        "label": args.label or p.name,
        "severity": args.severity,
        "source": "local"
    })
    with open(SIG_PATH, "w", encoding="utf-8") as f:
        json.dump(sigs, f, indent=2)
    print(f"Added hash for {p}: {h}")

def main():
    parser = argparse.ArgumentParser(prog=APP_NAME, description="AWARE malware detection prototype")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="Scan files or directories")
    p_scan.add_argument("paths", nargs="+", help="Files or directories to scan")
    p_scan.add_argument("--quarantine", action="store_true", help="Move detected files to quarantine")
    p_scan.add_argument("--no-yara", action="store_true", help="Disable YARA scanning even if available")
    p_scan.set_defaults(func=cmd_scan)

    p_mon = sub.add_parser("monitor", help="Watch directories and scan new files in real-time")
    p_mon.add_argument("folders", nargs="+", help="Folders to watch")
    p_mon.add_argument("--quarantine", action="store_true", help="Move detected files to quarantine")
    p_mon.add_argument("--no-yara", action="store_true", help="Disable YARA scanning even if available")
    p_mon.set_defaults(func=cmd_monitor)

    p_add = sub.add_parser("add-hash", help="Add a file's hash to local signatures")
    p_add.add_argument("file", help="File to hash and add as malicious")
    p_add.add_argument("--label", help="Label for the entry")
    p_add.add_argument("--severity", default="medium", help="Severity level (low|medium|high)")
    p_add.set_defaults(func=cmd_addhash)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return 1
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())