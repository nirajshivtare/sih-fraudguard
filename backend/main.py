from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from services.parser import parse_eml
from services.geolocation import trace_ip_route
from services.nlp_engine import analyze_text
from services.domain_intel import analyze_domain
from services.auth_validator import validate_email_auth

app = FastAPI(
    title="FraudGuard AI - Backend API",
    description="API for parsing and analyzing email threats.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Welcome to the FraudGuard AI API"}

@app.post("/api/v1/analyze-email")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")
    
    try:
        content = await file.read()
        
        # 1. Parse Email Headers and Extract IPs
        parsed_data = parse_eml(content)
        
        # 2. Trace IP Geolocation
        ips_to_trace = parsed_data.get("extracted_ips", [])
        geo_data = trace_ip_route(ips_to_trace)
        
        # 3. AI Text Analysis
        body_text = parsed_data.get("body_preview", "")
        ai_analysis = analyze_text(body_text)
        
        # 4. Domain Intelligence (WHOIS)
        domain_intel = analyze_domain(parsed_data["metadata"]["from"])
        
        # 5. Email Authentication Validation (SPF/DKIM/DMARC)
        auth_status = validate_email_auth(parsed_data["metadata"]["authentication_results"])
        
        # Combine everything into a single structured forensic report
        return {
            "status": "success",
            "filename": file.filename,
            "metadata": parsed_data["metadata"],
            "authentication": auth_status,
            "domain_intelligence": domain_intel,
            "ai_analysis": ai_analysis,
            "origin_traceability": geo_data,
            "raw_body_preview": body_text
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

