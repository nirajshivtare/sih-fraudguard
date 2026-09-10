import whois
import re

def get_domain_from_email(email_address: str) -> str:
    match = re.search(r'@([\w.-]+)', str(email_address))
    return match.group(1) if match else None

def analyze_domain(email_from: str) -> dict:
    domain = get_domain_from_email(email_from)
    if not domain:
        return {"status": "error", "message": "DATA UNAVAILABLE"}
        
    try:
        w = whois.whois(domain)
        
        registrar = w.registrar if isinstance(w.registrar, str) else w.registrar[0] if w.registrar else "DATA UNAVAILABLE"
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        creation_str = creation_date.strftime("%Y-%m-%d") if hasattr(creation_date, 'strftime') else "DATA UNAVAILABLE"
        
        is_suspicious = False
        if creation_date and hasattr(creation_date, 'year'):
            if creation_date.year >= 2025: # Recent
                is_suspicious = True
                
        return {
            "status": "success",
            "domain": domain,
            "registrar": registrar,
            "creation_date": creation_str,
            "is_suspicious": is_suspicious,
            "country": w.country or "DATA UNAVAILABLE"
        }
    except Exception as e:
        return {"status": "error", "domain": domain, "message": "DATA UNAVAILABLE"}
