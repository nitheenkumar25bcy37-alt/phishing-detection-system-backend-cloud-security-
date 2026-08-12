# backend/modules/ml_engine/predictor.py
import os
import joblib
import pandas as pd

class MLPredictor:
    def __init__(self):
        # Load the saved model into memory once when the class is initialized
        current_dir = os.path.dirname(__file__)
        model_path = os.path.join(current_dir, "rf_model.pkl")
        
        try:
            self.model = joblib.load(model_path)
        except FileNotFoundError:
            print(f"Error: Model not found at {model_path}. Please run trainer.py first.")
            self.model = None

    def predict(self, url_length: int, has_ip: int, suspicious_tld: int, 
                password_fields: int, hidden_iframes: int, external_action: int) -> dict:
        """
        Takes live features and returns a phishing probability score (0.0 to 1.0).
        """
        if self.model is None:
            return {"ml_score": 0.0, "risk": "LOW", "indicators": ["ml_model_missing"]}

        # 1. Format the live data exactly how the model expects it
        features = pd.DataFrame([[
            url_length, 
            has_ip, 
            suspicious_tld, 
            password_fields, 
            hidden_iframes, 
            external_action
        ]], columns=[
            'url_length', 'has_ip', 'suspicious_tld', 
            'password_fields', 'hidden_iframes', 'external_action'
        ])

        # 2. Ask the model for the probability of class '1' (Phishing)
        # predict_proba returns a nested array: [[prob_safe, prob_phishing]]
        phishing_probability = self.model.predict_proba(features)[0][1]
        
        score = round(phishing_probability, 2)
        
        # 3. Assign risk levels based on AI confidence
        risk = "LOW"
        indicators = []
        
        if score >= 0.7:
            risk = "HIGH"
            indicators.append(f"ai_high_confidence_({score})")
        elif score >= 0.4:
            risk = "MEDIUM"
            indicators.append(f"ai_medium_confidence_({score})")

        return {
            "ml_score": score,
            "risk": risk,
            "indicators": indicators
        }

if __name__ == "__main__":
    predictor = MLPredictor()
    
    # Test 1: Safe features (Short URL, no IP, no passwords, no hidden iframes)
    print("Test 1 (Safe):", predictor.predict(url_length=30, has_ip=0, suspicious_tld=0, password_fields=0, hidden_iframes=0, external_action=0))
    
    # Test 2: Phishing features (Long URL, IP used, passwords requested, external action)
    print("Test 2 (Phishing):", predictor.predict(url_length=120, has_ip=1, suspicious_tld=0, password_fields=1, hidden_iframes=2, external_action=1))