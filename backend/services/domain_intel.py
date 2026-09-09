import whois
import re

def get_domain_from_email(email_address: str) -> str:
    """Extracts the domain from an email address string."""
    match = re.search(r'@([\w.-]+)', email_address)
    return match.group(1) if match else None

def analyze_domain(email_from: str) -> dict:
    """
    Performs a WHOIS lookup on the sender's domain to extract registration intelligence.
    Useful for identifying newly registered domains (common in phishing).
    """
    domain = get_domain_from_email(email_from)
    if not domain:
        return {"status": "error", "message": "Could not extract domain"}
        
    try:
        w = whois.whois(domain)
        
        # WHOIS data can be messy, some fields might be lists
        registrar = w.registrar if isinstance(w.registrar, str) else w.registrar[0] if w.registrar else "Unknown"
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        creation_str = creation_date.strftime("%Y-%m-%d") if creation_date else "Unknown"
        
        # Simple heuristic: If domain is very new (e.g. 2026), flag it
        is_suspicious = False
        if creation_date and hasattr(creation_date, 'year'):
            if creation_date.year >= 2024: # Just an example heuristic
                is_suspicious = True
                
        return {
            "status": "success",
            "domain": domain,
            "registrar": registrar,
            "creation_date": creation_str,
            "is_suspicious": is_suspicious,
            "country": w.country
        }
    except Exception as e:
        return {"status": "error", "domain": domain, "message": str(e)}
