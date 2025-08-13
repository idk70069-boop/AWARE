# AWARE — Malware Detection Prototype

**AWARE** is a simple, open-source prototype that demonstrates core ideas behind malware detection:
- Hash-based detection (SHA-256) via a local `signatures.json`
- Optional YARA scanning if `yara-python` is installed and rules are in `rules/`
- Optional real-time monitoring using `watchdog`
- Quarantine for detected files
- JSON reports + a simple log

> ⚠️ This is an educational prototype, **not** production-grade security software.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate  # Linux/macOS
# or: py -3 -m venv .venv && .venv\Scripts\activate  # Windows PowerShell

pip install -r requirements.txt

# Example: scan your Downloads folder (no YARA required)
python aware/aware.py scan ~/Downloads --quarantine

# Example: monitor a folder in real-time
python aware/aware.py monitor ~/Downloads --quarantine

# Add a custom malicious hash
python aware/aware.py add-hash path/to/suspect.bin --label MySample --severity high
```

## Signatures

`signatures.json` ships with the EICAR test file's SHA-256 so you can validate detections safely.
You can append your own hashes with `add-hash`. The format is intentionally simple.

## YARA (optional)

If you install `yara-python` and place `.yar` rules in `rules/`, AWARE will compile and use them automatically.
An example rule `rules/example_eicar.yar` is included.

## Quarantine

When `--quarantine` is used, detected files are moved into `quarantine/YYYYMMDD/` and set read-only.

## Reports

Each scan creates a timestamped JSON report in `reports/` with a summary and per-file results.

## License

MIT