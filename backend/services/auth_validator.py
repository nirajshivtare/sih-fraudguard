import re

def validate_email_auth(auth_header: str) -> dict:
    """
    Parses the Authentication-Results header to determine SPF, DKIM, and DMARC status.
    This fulfills the requirement: 'Validation of whether the email was sent through authorized infrastructure'
    """
    if not auth_header:
        # If the header doesn't exist, it's highly suspicious (most modern servers add it)
        return {
            "spf": "missing",
            "dkim": "missing",
            "dmarc": "missing",
            "is_forged": True
        }

    # Initialize statuses
    spf_status = "none"
    dkim_status = "none"
    dmarc_status = "none"
    
    auth_lower = auth_header.lower()

    # Regex to find statuses in the standard format (e.g., spf=pass, dkim=fail)
    spf_match = re.search(r'spf=(\w+)', auth_lower)
    dkim_match = re.search(r'dkim=(\w+)', auth_lower)
    dmarc_match = re.search(r'dmarc=(\w+)', auth_lower)

    if spf_match: spf_status = spf_match.group(1)
    if dkim_match: dkim_status = dkim_match.group(1)
    if dmarc_match: dmarc_status = dmarc_match.group(1)
    
    # Determine overall forgery status
    # If any of these failed or softfailed, it's likely forged or spoofed
    is_forged = False
    if "fail" in spf_status or "fail" in dkim_status or "fail" in dmarc_status:
        is_forged = True
        
    return {
        "spf": spf_status.upper(),
        "dkim": dkim_status.upper(),
        "dmarc": dmarc_status.upper(),
        "is_forged": is_forged
    }
