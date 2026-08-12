# backend/risk_engine.py

def calculate_final_risk(m1_score: float, m2_score: float, m3_score: float, m4_score: float) -> dict:
    """
    Calculates the final weighted risk score and determines the action.
    """
    # Apply the exact mathematical weights from the blueprint
    final_score = (m1_score * 0.2) + (m2_score * 0.2) + (m3_score * 0.4) + (m4_score * 0.2)
    
    # Ensure the score does not exceed 1.0 due to floating-point math
    final_score = min(final_score, 1.0)
    
    # Apply the deterministic thresholds
    if final_score >= 0.80:
        action = "BLOCK"
        risk_level = "HIGH"
    elif final_score >= 0.50:
        action = "WARN"
        risk_level = "MEDIUM"
    else:
        action = "SAFE"
        risk_level = "LOW"
        
    return {
        "score": round(final_score, 2),
        "action": action,
        "risk_level": risk_level
    }