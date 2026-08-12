# backend/modules/webpage_engine/scorer.py

class DOMScorer:
    def __init__(self):
        # We keep this class modular so we can add more complex DOM rules later
        pass

    def evaluate_features(self, form_count: int, password_fields: int, hidden_iframes: int, has_external_action: bool) -> dict:
        """
        Evaluates the risk of a webpage based on its HTML element counts.
        """
        score = 0.0
        indicators = []
        
        # Rule 1: Password fields submitting to external domains (Classic Phishing Behavior)
        if password_fields > 0 and has_external_action:
            score += 0.8
            indicators.append("password_form_external_action")
        elif password_fields > 0:
            # Password fields on their own are only mildly suspicious, but worth tracking
            score += 0.2
            indicators.append("password_field_present")
            
        # Rule 2: Hidden iframes (Often used for stealthy redirects, cryptomining, or malware)
        if hidden_iframes > 0:
            # We assign a heavy penalty for hidden iframes
            score += 0.6
            indicators.append(f"hidden_iframes_detected_({hidden_iframes})")
            
        # Cap the final score to ensure it never exceeds 1.0
        score = min(score, 1.0)
        
        # Determine strict risk threshold labels
        risk = "LOW"
        if score >= 0.7:
            risk = "HIGH"
        elif score >= 0.4:
            risk = "MEDIUM"
            
        return {
            "webpage_score": round(score, 2),
            "risk": risk,
            "indicators": indicators
        }

if __name__ == "__main__":
    scorer = DOMScorer()
    
    # Test 1: Legitimate blog (No passwords, maybe a search form)
    print("Test 1 (Safe Blog):", scorer.evaluate_features(form_count=1, password_fields=0, hidden_iframes=0, has_external_action=False))
    
    # Test 2: Basic Login Page (Password field, but posts locally)
    print("Test 2 (Normal Login):", scorer.evaluate_features(form_count=1, password_fields=1, hidden_iframes=0, has_external_action=False))
    
    # Test 3: Phishing Page (Password field submitting credentials to a remote server)
    print("Test 3 (Phishing POST):", scorer.evaluate_features(form_count=1, password_fields=1, hidden_iframes=0, has_external_action=True))
    
    # Test 4: Compromised Site (Hidden invisible iframes injected by attacker)
    print("Test 4 (Hidden Iframe):", scorer.evaluate_features(form_count=0, password_fields=0, hidden_iframes=2, has_external_action=False))