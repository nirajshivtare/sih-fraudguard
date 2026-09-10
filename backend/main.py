from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from services.parser import parse_eml
from services.geolocation import trace_ip_route
from services.nlp_engine import analyze_text
from services.domain_intel import analyze_domain
from services.auth_validator import validate_email_auth
from services.scoring import calculate_scores
import db

app = FastAPI(
    title="FraudGuard AI - Forensic Pipeline",
    description="SIH26106 Compliant Evidence-Driven Email Forensic Platform",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/v1/analyze-email")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")
    
    # Generate Case ID
    case_id = db.generate_case_id()
    
    try:
        content = await file.read()
        
        # 1. Parse Email Headers, extract IOCs, hash evidence
        parsed_data = parse_eml(content)
        
        # 2. Trace IP Geolocation (Probable Infrastructure)
        geo_data = trace_ip_route(parsed_data["routing"]["extracted_ips"])
        
        # 3. AI NLP Threat Detection
        ai_analysis = analyze_text(parsed_data["body_preview"])
        
        # 4. Domain Intelligence
        domain_intel = analyze_domain(parsed_data["metadata"]["from"])
        
        # 5. Email Authentication Validation & Alignment
        auth_status = validate_email_auth(
            parsed_data["metadata"]["authentication_results"],
            parsed_data["metadata"]["from"],
            parsed_data["metadata"]["return_path"]
        )
        
        # 6. Scoring Models
        scores = calculate_scores(auth_status, ai_analysis, geo_data, domain_intel, parsed_data["iocs"])
        
        # 7. Preserve Evidence in Database
        db.save_case(
            case_id=case_id,
            sha256_hash=parsed_data["evidence"]["sha256"],
            filename=file.filename,
            fraud_score=scores["fraud_risk"]["score"],
            fraud_level=scores["fraud_risk"]["level"],
            origin_score=scores["origin_confidence"]["score"],
            origin_level=scores["origin_confidence"]["level"]
        )
        
        return {
            "status": "success",
            "case_id": case_id,
            "filename": file.filename,
            "evidence": parsed_data["evidence"],
            "metadata": parsed_data["metadata"],
            "iocs": parsed_data["iocs"],
            "authentication": auth_status,
            "domain_intelligence": domain_intel,
            "ai_analysis": ai_analysis,
            "origin_traceability": geo_data,
            "scoring": scores,
            "raw_body_preview": parsed_data["body_preview"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


