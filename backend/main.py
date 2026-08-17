from fastapi import FastAPI
from api_models import ScanRequest, ScanResponse
import tldextract

from modules.url_engine.analyzer import URLEngine
from modules.webpage_engine.scorer import DOMScorer
from modules.threat_intel.lookup import analyze_url
from modules.ml_engine.predictor import MLPredictor
from risk_engine import calculate_final_risk

app = FastAPI(title="Phishing Detection API")

url_engine = URLEngine()
dom_scorer = DOMScorer()
ml_predictor = MLPredictor()

# THE ENTERPRISE WHITELIST
SAFE_DOMAINS = [
    "chatgpt.com", "google.com", "youtube.com", "github.com", 
    "linkedin.com", "microsoft.com", "apple.com"
]

@app.post("/scan", response_model=ScanResponse)
def scan_url(payload: ScanRequest):
    # 1. Check the Whitelist First
    extracted = tldextract.extract(payload.url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    
    if domain in SAFE_DOMAINS:
        return ScanResponse(
            risk_level="LOW",
            action="SAFE",
            score=0.0,
            reasons=["Domain bypassed AI (Verified Enterprise Whitelist)"]
        )

    # 2. If not on the whitelist, proceed with standard AI analysis
    url_result = url_engine.extract_features(payload.url)
    m1_score = url_result["url_score"]
    
    dom_result = dom_scorer.evaluate_features(
        payload.page_features.form_count,
        payload.page_features.password_fields,
        payload.page_features.hidden_iframes,
        payload.page_features.has_external_action
    )
    m2_score = dom_result["webpage_score"]
    
    threat_result = analyze_url(payload.url)
    m4_score = threat_result["threat_score"]
    
    url_len = len(payload.url)
    has_ip = 1 if "ip_address_used" in url_result["indicators"] else 0
    suspicious_tld = 1 if any("suspicious_tld" in ind for ind in url_result["indicators"]) else 0
    external_act = 1 if payload.page_features.has_external_action else 0
    
    ml_result = ml_predictor.predict(
        url_len, has_ip, suspicious_tld, 
        payload.page_features.password_fields, 
        payload.page_features.hidden_iframes, 
        external_act
    )
    m3_score = ml_result["ml_score"]
    
    decision = calculate_final_risk(m1_score, m2_score, m3_score, m4_score)
    reasons = list(set(url_result["indicators"] + dom_result["indicators"] + threat_result["indicators"] + ml_result["indicators"]))

    return ScanResponse(
        risk_level=decision["risk_level"],
        action=decision["action"],
        score=decision["score"],
        reasons=reasons
    )