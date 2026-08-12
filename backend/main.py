# backend/main.py
from fastapi import FastAPI
from api_models import ScanRequest, ScanResponse

# IMPORT MEMBER 4
from modules.threat_intel.lookup import analyze_url
# IMPORT MEMBER 1
from modules.url_engine.analyzer import URLEngine

from risk_engine import calculate_final_risk
from logger import log_scan_result

app = FastAPI(title="Phishing Detection API")

# Instantiate the URL Engine once when the server boots
url_engine = URLEngine()

@app.get("/")
def read_root():
    return {"status": "Server is active"}

@app.post("/scan", response_model=ScanResponse)
def scan_url(payload: ScanRequest):
    print(f"--- New Scan Request for {payload.url} ---")
    
    # 1. Run Member 1 (URL Engine)
    url_result = url_engine.extract_features(payload.url)
    m1_actual_score = url_result["url_score"]
    
    # 2. Run Member 4 (Threat Intel)
    threat_result = analyze_url(payload.url)
    m4_actual_score = threat_result["threat_score"]
    
    # 3. Mock remaining engines
    m2_dummy_score = 0.0
    m3_dummy_score = 0.0
    
    # 4. Run Risk Aggregation Engine
    decision = calculate_final_risk(
        m1_score=m1_actual_score, 
        m2_score=m2_dummy_score, 
        m3_score=m3_dummy_score, 
        m4_score=m4_actual_score
    )
    
    # 5. Combine the indicators from all active modules
    reasons = threat_result["indicators"] + url_result["indicators"]
    if not reasons and decision["action"] == "SAFE":
        reasons.append("No threats detected")
        
    # 6. Privacy-Safe Logging
    log_scan_result(
        url=payload.url,
        final_score=decision["score"],
        result=decision["action"],
        m1=m1_actual_score,
        m2=m2_dummy_score,
        m3=m3_dummy_score,
        m4=m4_actual_score
    )

    return ScanResponse(
        risk_level=decision["risk_level"],
        score=decision["score"],
        action=decision["action"],
        reasons=reasons
    )