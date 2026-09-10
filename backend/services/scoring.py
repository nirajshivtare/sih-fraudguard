def calculate_scores(auth_data, nlp_data, geo_data, domain_data, iocs):
    # --- FRAUD RISK SCORE ---
    # Weightings: NLP (40%), Auth/Alignment (30%), Domain (15%), IOCs (15%)
    
    fraud_score = 0
    fraud_evidence = []
    trust_evidence = []

    # 1. NLP Assessment
    nlp_prob = nlp_data.get("nlp_fraud_probability", 0)
    fraud_score += (nlp_prob * 0.40)
    
    if nlp_data.get("signals"):
        for sig in nlp_data["signals"]:
            fraud_evidence.append(f"⚠ {sig['description']}")
    else:
        trust_evidence.append("✓ No explicit social engineering language detected")

    # 2. Authentication Assessment
    if auth_data.get("is_forged"):
        fraud_score += 30
        fraud_evidence.append("⚠ SPF/DKIM/DMARC hard failure detected (Spoofing risk)")
    elif auth_data.get("spf") == "PASS" and auth_data.get("dkim") == "PASS":
        trust_evidence.append("✓ SPF and DKIM passed")
    else:
        trust_evidence.append("ℹ Authentication missing or incomplete, not strictly malicious")
        fraud_score += 10 # Slight bump for missing auth

    if auth_data.get("alignment") == "GOOD ALIGNMENT":
        trust_evidence.append("✓ Sender domain aligns with return path")
    elif auth_data.get("alignment") == "MISALIGNMENT":
        fraud_score += 15
        fraud_evidence.append("⚠ Sender domain does not align with return path (Impersonation risk)")

    # 3. Domain Intelligence
    if domain_data.get("is_suspicious"):
        fraud_score += 15
        fraud_evidence.append("⚠ Domain registered recently or lacks reputation")
    elif domain_data.get("status") == "success":
        trust_evidence.append("✓ Sender domain appears established")

    # 4. IOCs
    if len(iocs.get("urls", [])) > 3:
        fraud_score += 5
        fraud_evidence.append("⚠ Email contains multiple external URLs")

    # Cap score at 100
    fraud_score = min(round(fraud_score), 100)

    if fraud_score > 75:
        fraud_level = "CRITICAL"
    elif fraud_score > 50:
        fraud_level = "HIGH"
    elif fraud_score > 20:
        fraud_level = "MEDIUM"
    else:
        fraud_level = "LOW"


    # --- ORIGIN CONFIDENCE SCORE ---
    # Asks: "How confidently can we identify the infrastructure?"
    # Weightings: Public IPs (50%), Consistent Routing (30%), Non-Anonymized (20%)
    
    origin_score = 100
    origin_evidence = []

    public_hops = [hop for hop in geo_data if hop.get("status") == "success"]
    
    if not public_hops:
        origin_score = 0
        origin_evidence.append("⚠ No public routing IPs extracted from headers")
    else:
        origin_evidence.append(f"✓ {len(public_hops)} public routing IP(s) successfully traced")
        
        # Check for VPN / Anonymizers
        is_anonymized = False
        for hop in public_hops:
            isp = (hop.get("isp") or "").lower()
            if "vpn" in isp or "proxy" in isp or "tor" in isp or "cloud" in isp:
                is_anonymized = True
                
        if is_anonymized:
            origin_score -= 40
            origin_evidence.append("⚠ Infrastructure belongs to Cloud/VPN/Proxy (Origin identity obscured)")
        else:
            origin_evidence.append("✓ Direct/Residential ISP detected (Higher attribution confidence)")

    if origin_score > 80:
        origin_level = "HIGH"
    elif origin_score > 50:
        origin_level = "MEDIUM"
    else:
        origin_level = "LOW"


    return {
        "fraud_risk": {
            "score": fraud_score,
            "level": fraud_level,
            "evidence_risk": fraud_evidence,
            "evidence_trust": trust_evidence
        },
        "origin_confidence": {
            "score": origin_score,
            "level": origin_level,
            "evidence": origin_evidence
        }
    }
