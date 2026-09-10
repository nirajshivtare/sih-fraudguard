import email
from email.policy import default
import re
import hashlib
import urllib.parse

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
        "subject": msg.get("Subject", "Unavailable"),
        "from": msg.get("From", "Unavailable"),
        "to": msg.get("To", "Unavailable"),
        "cc": msg.get("Cc", "Unavailable"),
        "date": msg.get("Date", "Unavailable"),
        "message_id": msg.get("Message-ID", "Unavailable"),
        "return_path": msg.get("Return-Path", "Unavailable"),
        "reply_to": msg.get("Reply-To", "Unavailable"),
        "authentication_results": msg.get("Authentication-Results", "Unavailable"),
        "dkim_signature": msg.get("DKIM-Signature", "Unavailable")
    }
    
    # Extract 'Received' headers chronologically (last added is first in the list usually, so we reverse it)
    received_headers = msg.get_all("Received", [])
    routing_chain = received_headers[::-1] # chronological order (oldest to newest hop)
    
    ip_pattern = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]|(\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b)')
    extracted_ips = []
    chronological_hops = []

    for i, hop in enumerate(routing_chain):
        # Flatten multiline headers
        hop_clean = hop.replace('\r', '').replace('\n', ' ')
        ips = [match[0] or match[1] for match in ip_pattern.findall(hop_clean)]
        if ips:
            extracted_ips.extend(ips)
        chronological_hops.append({
            "hop": i + 1,
            "raw": hop_clean,
            "extracted_ips": ips
        })
            
    # Remove duplicates but preserve order
    extracted_ips = list(dict.fromkeys(extracted_ips))

    body = ""
    html_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain':
                body += part.get_content() or ""
            elif ctype == 'text/html':
                html_body += part.get_content() or ""
    else:
        ctype = msg.get_content_type()
        if ctype == 'text/plain':
            body = msg.get_content() or ""
        elif ctype == 'text/html':
            html_body = msg.get_content() or ""
            
    # Fallback if plain text is empty but HTML exists
    if not body and html_body:
        # Strip simple HTML tags for text analysis
        body = re.sub(r'<[^>]+>', ' ', html_body)

    urls = extract_urls(body + " " + html_body)
    domains = list(dict.fromkeys([get_domain_from_url(u) for u in urls if get_domain_from_url(u)]))

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
            "urls": urls,
            "domains": domains
        },
        "body_preview": body[:1000] + "..." if len(body) > 1000 else body
    }

