import json
from pathlib import Path
from html import escape

def save_json(result, output):
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(result, indent=2), encoding="utf-8")

def save_html(result, output):
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    finding_rows = "".join(f"<tr><td>{escape(f['severity'])}</td><td>{escape(f['title'])}</td><td>{escape(f['detail'])}</td></tr>" for f in result["findings"])
    mitre_rows = "".join(f"<li><b>{escape(t['id'])}</b> — {escape(t['name'])}</li>" for t in result["mitre_attack"])
    html_doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Phishing Analysis Report</title><style>body{{font-family:Arial,sans-serif;max-width:1000px;margin:40px auto;line-height:1.5}}.card{{padding:18px;border:1px solid #ddd;border-radius:10px;margin:14px 0}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #ddd;padding:9px;text-align:left}}code{{word-break:break-all}}</style></head><body><h1>Phishing Email Analysis Report</h1><div class="card"><b>Subject:</b> {escape(result['subject'])}<br><b>From:</b> {escape(result['from'])}<br><b>Reply-To:</b> {escape(result['reply_to'])}<br><b>Risk Score:</b> {result['score']}/100<br><b>Severity:</b> {escape(result['severity'])}</div><h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Evidence</th></tr>{finding_rows}</table><h2>IOCs</h2><div class="card"><b>URLs</b><ul>{''.join('<li><code>'+escape(x)+'</code></li>' for x in result['iocs']['urls'])}</ul><b>Domains</b><ul>{''.join('<li>'+escape(x)+'</li>' for x in result['iocs']['domains'])}</ul><b>Attachments</b><ul>{''.join('<li>'+escape(x)+'</li>' for x in result['iocs']['attachments'])}</ul></div><h2>MITRE ATT&CK</h2><ul>{mitre_rows}</ul><h2>Recommendations</h2><ol>{''.join('<li>'+escape(x)+'</li>' for x in result['recommendations'])}</ol></body></html>"""
    Path(output).write_text(html_doc, encoding="utf-8")
