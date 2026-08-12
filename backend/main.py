# backend/main.py
from fastapi import FastAPI
from api_models import ScanRequest, ScanResponse
from modules.threat_intel.lookup import analyze_url
from risk_engine import calculate_final_risk

# IMPORT THE LOGGER
from logger import log_scan_result

app = FastAPI(title="Phishing Detection API")

@app.get("/")
def read_root():
    return {"status": "Server is active"}

@app.post("/scan", response_model=ScanResponse)
def scan_url(payload: ScanRequest):
    # 1. Gather all module scores
    m1_dummy_score = 0.0
    m2_dummy_score = 0.0
    m3_dummy_score = 0.0
    
    threat_result = analyze_url(payload.url)
    m4_actual_score = threat_result["threat_score"]
    
    # 2. Run the Aggregation Engine
    decision = calculate_final_risk(
        m1_score=m1_dummy_score, 
        m2_score=m2_dummy_score, 
        m3_score=m3_dummy_score, 
        m4_score=m4_actual_score
    )
    
    reasons = threat_result["indicators"]
    if not reasons and decision["action"] == "SAFE":
        reasons.append("No threats detected")
        
    # 3. PRIVACY-SAFE LOGGING
    # We log the data silently in the background before returning the response
    log_scan_result(
        url=payload.url,
        final_score=decision["score"],
        result=decision["action"],
        m1=m1_dummy_score,
        m2=m2_dummy_score,
        m3=m3_dummy_score,
        m4=m4_actual_score
    )

    # 4. Return the response
    return ScanResponse(
        risk_level=decision["risk_level"],
        score=decision["score"],
        action=decision["action"],
        reasons=reasons
    )