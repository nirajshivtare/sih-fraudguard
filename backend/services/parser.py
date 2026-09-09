import email
from email.policy import default
import re

def parse_eml(raw_content: bytes) -> dict:
    """
    Parses a raw .eml file byte string and extracts key headers and routing information.
    """
    # Parse the email from bytes
    msg = email.message_from_bytes(raw_content, policy=default)
    
    # Extract basic headers
    headers = {
        "subject": msg.get("Subject", "No Subject"),
        "from": msg.get("From", "Unknown Sender"),
        "to": msg.get("To", "Unknown Recipient"),
        "date": msg.get("Date", "Unknown Date"),
        "message_id": msg.get("Message-ID", ""),
        "return_path": msg.get("Return-Path", ""),
        "authentication_results": msg.get("Authentication-Results", ""),
    }
    
    # Extract 'Received' headers (shows the IP hops/routing path)
    received_headers = msg.get_all("Received", [])
    
    # Extract IP addresses from the Received headers using regex
    ip_pattern = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
    extracted_ips = []
    
    for hop in received_headers:
        ips = ip_pattern.findall(hop)
        if ips:
            extracted_ips.extend(ips)
            
    # Remove duplicates but preserve order (last IP is usually the originator)
    extracted_ips = list(dict.fromkeys(extracted_ips))

    # Extract body text (for ML processing later)
    body = ""
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
    else:
        if msg.get_content_type() == 'text/plain':
            body = msg.get_content()
            
    return {
        "metadata": headers,
        "routing_hops": received_headers,
        "extracted_ips": extracted_ips,
        "body_preview": body[:500] + "..." if len(body) > 500 else body
    }
