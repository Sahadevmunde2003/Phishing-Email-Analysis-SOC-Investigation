#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.analyzer import analyze_file


def main():
    parser = argparse.ArgumentParser(description="Offline phishing email analyzer")
    parser.add_argument("eml", help="Path to .eml file")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()
    path = Path(args.eml)
    if not path.exists():
        parser.error(f"File not found: {path}")
    result = analyze_file(path)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print("\n=== PHISHING EMAIL ANALYZER ===")
    print(f"Subject  : {result['subject']}")
    print(f"From     : {result['from']}")
    print(f"Reply-To : {result['reply_to']}")
    print(f"Risk     : {result['score']}/100")
    print(f"Severity : {result['severity']}\n")
    print("FINDINGS")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['title']} — {f['detail']}")
    if not result["findings"]:
        print("  No heuristic findings detected.")
    print("\nMITRE ATT&CK")
    for t in result["mitre_attack"]:
        print(f"  {t['id']} — {t['name']}")
    print("\nIOCs")
    for u in result["iocs"]["urls"]: print(f"  URL: {u}")
    for a in result["iocs"]["attachments"]: print(f"  Attachment: {a}")


if __name__ == "__main__":
    main()
