# Phishing Email Analysis & SOC Investigation

A defensive cybersecurity project for analyzing phishing emails through a terminal CLI and a local web GUI.

## Current features
- `.eml` parsing
- Sender / Reply-To mismatch detection
- Suspicious URL heuristics
- Attachment inventory
- Urgency and credential-language indicators
- Risk score and severity
- MITRE ATT&CK mapping
- IOC extraction
- HTML reporting
- Offline-first analysis

## Interfaces

### CLI
```bash
python3 cli/phishing_analyzer.py samples/sample_phishing.eml
```

### GUI
```bash
python3 gui/app.py
```
Then open `http://127.0.0.1:5000`.

The GUI supports both `.eml` upload and raw-email paste.

> Use only on emails and samples you are authorized to analyze. This tool uses heuristic analysis and is not a definitive malware/phishing verdict.
