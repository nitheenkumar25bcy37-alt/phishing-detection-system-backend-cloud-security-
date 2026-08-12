# backend/main.py
from fastapi import FastAPI
from api_models import ScanRequest, ScanResponse

# IMPORT ALL 4 ENGINES
from modules.url_engine.analyzer import URLEngine
from modules.webpage_engine.scorer import DOMScorer
from modules.threat_intel.lookup import analyze_url
from modules.ml_engine.predictor import MLPredictor

from risk_engine import calculate_final_risk
from logger import log_scan_result

app = FastAPI(title="Phishing Detection API")

# Instantiate all engines once on startup to ensure high speed
url_engine = URLEngine()
dom_scorer = DOMScorer()
ml_predictor = MLPredictor()

@app.get("/")
def read_root():
    return {"status": "Server is active"}

@app.post("/scan", response_model=ScanResponse)
def scan_url(payload: ScanRequest):
    print(f"--- New Scan Request for {payload.url} ---")
    
    # 1. Run Member 1 (URL Engine)
    url_result = url_engine.extract_features(payload.url)
    m1_score = url_result["url_score"]
    
    # 2. Run Member 2 (Webpage DOM Engine)
    dom_result = dom_scorer.evaluate_features(
        form_count=payload.page_features.form_count,
        password_fields=payload.page_features.password_fields,
        hidden_iframes=payload.page_features.hidden_iframes,
        has_external_action=payload.page_features.has_external_action
    )
    m2_score = dom_result["webpage_score"]
    
    # 3. Run Member 4 (Threat Intel)
    threat_result = analyze_url(payload.url)
    m4_score = threat_result["threat_score"]
    
    # 4. Prepare features and Run Member 3 (AI/ML Engine)
    # We translate indicators and booleans into the 1s and 0s the AI expects
    url_len = len(payload.url)
    has_ip = 1 if "ip_address_used" in url_result["indicators"] else 0
    suspicious_tld = 1 if any("suspicious_tld" in ind for ind in url_result["indicators"]) else 0
    external_act = 1 if payload.page_features.has_external_action else 0
    
    ml_result = ml_predictor.predict(
        url_length=url_len,
        has_ip=has_ip,
        suspicious_tld=suspicious_tld,
        password_fields=payload.page_features.password_fields,
        hidden_iframes=payload.page_features.hidden_iframes,
        external_action=external_act
    )
    m3_score = ml_result["ml_score"]
    
    # 5. Run Risk Aggregation Engine (All weights now active!)
    decision = calculate_final_risk(
        m1_score=m1_score, 
        m2_score=m2_score, 
        m3_score=m3_score, 
        m4_score=m4_score
    )
    
    # 6. Combine all indicators from all 4 modules
    reasons = url_result["indicators"] + dom_result["indicators"] + threat_result["indicators"] + ml_result["indicators"]
    
    # Deduplicate reasons to keep the UI clean
    reasons = list(set(reasons))
    
    if not reasons and decision["action"] == "SAFE":
        reasons.append("No threats detected")
        
    # 7. Privacy-Safe Logging
    log_scan_result(
        url=payload.url,
        final_score=decision["score"],
        result=decision["action"],
        m1=m1_score,
        m2=m2_score,
        m3=m3_score,
        m4=m4_score
    )

    return ScanResponse(
        risk_level=decision["risk_level"],
        action=decision["action"],
        score=decision["score"],
        reasons=reasons
    )