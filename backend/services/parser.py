import email
from email.policy import default
import re
import hashlib
import urllib.parse
import os

# --- PII MASKING ---
def mask_pii(text: str) -> str:
    if not text:
        return text
    # Mask Email Addresses
    email_pattern = re.compile(r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    def email_repl(match):
        user = match.group(1)
        domain = match.group(2)
        if len(user) > 2:
            masked_user = user[0] + "*" * (len(user) - 2) + user[-1]
        else:
            masked_user = "***"
        return f"{masked_user}@{domain}"
    
    text = email_pattern.sub(email_repl, text)
    
    # Mask Phone Numbers (Basic 10 digit patterns)
    phone_pattern = re.compile(r'\b(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b')
    text = phone_pattern.sub("[REDACTED_PHONE]", text)
    
    return text

# --- IOC CLASSIFICATION ---
def classify_ioc_url(url: str, domain: str) -> dict:
    url_lower = url.lower()
    
    # 1. Known Benign Resources
    benign_domains = ["cdn.openai.com", "fonts.googleapis.com", "cdnjs.cloudflare.com", "unpkg.com"]
    if domain in benign_domains or url_lower.endswith(('.woff2', '.ttf', '.css', '.png', '.jpg')):
        return {"classification": "BENIGN", "confidence": "HIGH", "reason": "Trusted CDN or static resource"}
        
    # 2. Suspicious Indicators
    suspicious_keywords = ["login", "verify", "secure", "update", "account", "billing"]
    if any(k in url_lower for k in suspicious_keywords):
        return {"classification": "SUSPICIOUS", "confidence": "MEDIUM", "reason": "Contains credential-harvesting keywords in URL"}
        
    # 3. URL Shorteners
    shorteners = ["bit.ly", "t.co", "tinyurl.com", "is.gd"]
    if domain in shorteners:
        return {"classification": "SUSPICIOUS", "confidence": "MEDIUM", "reason": "URL shortener obscures destination"}

    return {"classification": "UNKNOWN", "confidence": "LOW", "reason": "No explicit threat intelligence available"}

def extract_urls(text: str) -> list:
    url_pattern = re.compile(r'(https?://[^\s<>"\'{}|\\^`]+)')
    return list(dict.fromkeys(url_pattern.findall(text)))

def get_domain_from_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(':')[0]
    except:
        return ""

def parse_eml(raw_content: bytes) -> dict:
    # Evidence Preservation: Hash
    sha256_hash = hashlib.sha256(raw_content).hexdigest()

    # Parse the email from bytes
    msg = email.message_from_bytes(raw_content, policy=default)
    
    headers = {
        "subject": msg.get("Subject", "Not present"),
        "from": msg.get("From", "Not present"),
        "to": msg.get("To", "Not present"),
        "cc": msg.get("Cc", "Not present"),
        "date": msg.get("Date", "Not present"),
        "message_id": msg.get("Message-ID", "Not present"),
        "return_path": msg.get("Return-Path", "Not present"),
        "reply_to": msg.get("Reply-To", "Not present"),
        "authentication_results": msg.get("Authentication-Results", "Not present"),
        "dkim_signature": msg.get("DKIM-Signature", "Not present"),
        "x_mailer": msg.get("X-Mailer", "Not present"),
        "user_agent": msg.get("User-Agent", "Not present"),
        "x_originating_ip": msg.get("X-Originating-IP", "Not present")
    }
    
    # Extract 'Received' headers chronologically
    received_headers = msg.get_all("Received", [])
    routing_chain = received_headers[::-1]
    
    ip_pattern = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]|(\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b)')
    extracted_ips = []
    chronological_hops = []

    for i, hop in enumerate(routing_chain):
        hop_clean = hop.replace('\r', '').replace('\n', ' ')
        ips = [match[0] or match[1] for match in ip_pattern.findall(hop_clean)]
        if ips:
            extracted_ips.extend(ips)
        chronological_hops.append({
            "hop": i + 1,
            "raw": hop_clean,
            "extracted_ips": ips
        })
            
    extracted_ips = list(dict.fromkeys(extracted_ips))

    body = ""
    html_body = ""
    attachments = []
    
    for part in msg.walk():
        ctype = part.get_content_type()
        cdispo = str(part.get('Content-Disposition'))

        # Extract body
        if ctype == 'text/plain' and 'attachment' not in cdispo:
            body += part.get_content() or ""
        elif ctype == 'text/html' and 'attachment' not in cdispo:
            html_body += part.get_content() or ""
            
        # Extract attachments (Do not execute)
        if part.get_filename():
            file_data = part.get_payload(decode=True)
            if file_data:
                att_hash = hashlib.sha256(file_data).hexdigest()
                attachments.append({
                    "filename": part.get_filename(),
                    "mime_type": ctype,
                    "size_bytes": len(file_data),
                    "sha256": att_hash
                })

    if not body and html_body:
        body = re.sub(r'<[^>]+>', ' ', html_body)

    # IOC Extraction & Classification
    urls = extract_urls(body + " " + html_body)
    ioc_urls = []
    for u in urls:
        domain = get_domain_from_url(u)
        classification = classify_ioc_url(u, domain)
        ioc_urls.append({
            "value": u,
            "type": "URL",
            "domain": domain,
            **classification
        })
        
    domains = list(dict.fromkeys([u["domain"] for u in ioc_urls if u["domain"]]))

    # Perform PII Masking
    masked_body = mask_pii(body)

    return {
        "evidence": {
            "sha256": sha256_hash,
            "size_bytes": len(raw_content)
        },
        "metadata": headers,
        "routing": {
            "chronological_hops": chronological_hops,
            "extracted_ips": extracted_ips
        },
        "iocs": {
            "urls": ioc_urls,
            "domains": domains,
            "attachments": attachments
        },
        "body_preview": masked_body[:1000] + "..." if len(masked_body) > 1000 else masked_body,
        "pii_masking_applied": True
    }


