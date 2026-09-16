import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
EMAIL_RE = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
URGENT_TERMS = ["urgent", "immediately", "verify your account", "suspended", "password expires", "confirm your identity", "payment failed", "security alert", "action required", "click now"]
CREDENTIAL_TERMS = ["password", "login", "sign in", "verify", "username", "credential", "otp", "mfa"]
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img", ".lnk", ".jar", ".msi"}


def header_domain(value):
    match = EMAIL_RE.search(value or "")
    return match.group(0).split("@", 1)[1].lower() if match else ""


def extract_body(msg):
    parts = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
            if isinstance(content, str):
                parts.append(content)
        except Exception:
            pass
    return "\n".join(parts)


def analyze_file(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    body = extract_body(msg)
    subject = str(msg.get("Subject", ""))
    sender = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    auth = str(msg.get("Authentication-Results", ""))
    urls = sorted(set(u.rstrip(".,);]}>\"'") for u in URL_RE.findall(body)))
    attachments = [p.get_filename() or "unnamed" for p in msg.walk() if p.get_content_disposition() == "attachment"]
    findings, score = [], 0

    sd, rd = header_domain(sender), header_domain(reply_to)
    if sd and rd and sd != rd:
        score += 20
        findings.append({"severity": "HIGH", "title": "From / Reply-To domain mismatch", "detail": f"From domain is {sd}, while Reply-To uses {rd}."})

    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname and re.fullmatch(r"\d+(?:\.\d+){3}", parsed.hostname):
            score += 25
            findings.append({"severity": "HIGH", "title": "URL uses an IP address", "detail": url})
        if "@" in parsed.netloc:
            score += 15
            findings.append({"severity": "HIGH", "title": "URL contains userinfo obfuscation", "detail": url})
        if len(url) > 120:
            score += 5
            findings.append({"severity": "LOW", "title": "Unusually long URL", "detail": url})

    lower = (subject + "\n" + body).lower()
    urgent = sorted({x for x in URGENT_TERMS if x in lower})
    creds = sorted({x for x in CREDENTIAL_TERMS if x in lower})
    if urgent:
        score += min(15, len(urgent) * 4)
        findings.append({"severity": "MEDIUM", "title": "Urgency / pressure language detected", "detail": ", ".join(urgent)})
    if creds and urls:
        score += min(15, len(creds) * 3)
        findings.append({"severity": "HIGH", "title": "Credential-related language with links", "detail": ", ".join(creds)})

    risky = [a for a in attachments if any(a.lower().endswith(x) for x in RISKY_EXTENSIONS)]
    if risky:
        score += min(30, len(risky) * 15)
        findings.append({"severity": "HIGH", "title": "Potentially risky attachment type", "detail": ", ".join(risky)})

    if any(x in auth.lower() for x in ("spf=fail", "dkim=fail", "dmarc=fail")):
        score += 10
        findings.append({"severity": "MEDIUM", "title": "Email authentication failure reported", "detail": auth})

    score = min(score, 100)
    severity = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    techniques = []
    if urls: techniques.append({"id": "T1566.002", "name": "Phishing: Spearphishing Link"})
    if attachments: techniques.append({"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"})
    if creds: techniques.append({"id": "T1056.002", "name": "Input Capture: GUI Input Capture"})

    return {
        "file": str(path), "subject": subject, "from": sender, "reply_to": reply_to,
        "authentication_results": auth, "urls": urls, "attachments": attachments,
        "score": score, "severity": severity, "findings": findings, "mitre_attack": techniques,
        "iocs": {"emails": sorted(set(EMAIL_RE.findall(sender + " " + reply_to + " " + body))), "urls": urls, "attachments": attachments},
        "recommendations": ["Validate the sender using an independent trusted channel.", "Do not follow links or open suspicious attachments.", "Block confirmed malicious domains/URLs in appropriate security controls.", "If credentials were submitted, reset them and review sign-in activity.", "Preserve the original email and headers for incident response evidence."]
    }
