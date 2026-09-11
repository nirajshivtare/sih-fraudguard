import re
import urllib.parse
import tldextract

def get_base_domain(email_address: str) -> str:
    match = re.search(r'@([\w.-]+)', str(email_address))
    return match.group(1).lower() if match else ""

def get_organizational_domain(domain: str) -> str:
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def validate_email_auth(auth_header: str, from_header: str, return_path: str) -> dict:
    if not auth_header or auth_header == "Not present":
        return {
            "spf": "UNAVAILABLE",
            "dkim": "UNAVAILABLE",
            "dmarc": "UNAVAILABLE",
            "alignment": "UNKNOWN",
            "is_forged": False
        }

    spf_status = "NONE"
    dkim_status = "NONE"
    dmarc_status = "NONE"
    
    auth_lower = auth_header.lower()

    spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', auth_lower)
    dkim_match = re.search(r'dkim=(pass|fail|none|error)', auth_lower)
    dmarc_match = re.search(r'dmarc=(pass|fail|none|error)', auth_lower)

    if spf_match: spf_status = spf_match.group(1).upper()
    if dkim_match: dkim_status = dkim_match.group(1).upper()
    if dmarc_match: dmarc_status = dmarc_match.group(1).upper()
    
    # Domain Alignment Analysis
    from_domain = get_base_domain(from_header)
    return_path_domain = get_base_domain(return_path)
    
    alignment = "UNKNOWN"
    if from_domain and return_path_domain:
        from_org = get_organizational_domain(from_domain)
        return_org = get_organizational_domain(return_path_domain)
        
        if from_domain == return_path_domain:
            alignment = f"EXACT MATCH ({from_domain})"
        elif from_org == return_org:
            alignment = f"ORGANIZATIONAL ALIGNMENT ({from_org})"
        else:
            alignment = f"MISALIGNMENT (From: {from_domain} != Return: {return_path_domain})"

    # Forgery is only highly probable on hard fails
    is_forged = False
    if spf_status == "FAIL" or dkim_status == "FAIL" or dmarc_status == "FAIL":
        is_forged = True
        
    return {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "alignment": alignment,
        "is_forged": is_forged
    }

