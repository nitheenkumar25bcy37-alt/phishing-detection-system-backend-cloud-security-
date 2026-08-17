import os
import joblib
import pandas as pd
import shap
import numpy as np

class MLPredictor:
    def __init__(self):
        current_dir = os.path.dirname(__file__)
        model_path = os.path.join(current_dir, "xgb_model.pkl") 
        try:
            self.model = joblib.load(model_path)
            # Initialize the SHAP explainer on the trained model
            self.explainer = shap.TreeExplainer(self.model)
        except Exception as e:
            print(f"Model load error: {e}")
            self.model = None
            self.explainer = None

    def predict(self, url_length, has_ip, suspicious_tld, password_fields, hidden_iframes, external_action):
        if self.model is None or self.explainer is None: 
            return {"ml_score": 0.0, "risk": "LOW", "indicators": []}

        # Create the feature dataframe
        features_dict = {
            'url_length': [url_length], 
            'has_ip': [has_ip], 
            'suspicious_tld': [suspicious_tld], 
            'password_fields': [password_fields], 
            'hidden_iframes': [hidden_iframes], 
            'external_action': [external_action]
        }
        features = pd.DataFrame(features_dict)

        # Get the standard probability score
        prob = self.model.predict_proba(features)[0][1]
        score = round(prob, 2)
        
        # --- SHAP Explainability Engine ---
        indicators = []
        try:
            # Calculate SHAP values for this specific website
            shap_values = self.explainer.shap_values(features)
            
            # Identify the top 2 features that contributed most to the 'Phishing' score
            feature_names = list(features_dict.keys())
            # For XGBoost binary classification, shap_values is usually a 2D array
            contributions = shap_values[0] if isinstance(shap_values, list) else shap_values[0]
            
            # Pair feature names with their mathematical SHAP contribution
            feature_contributions = list(zip(feature_names, contributions))
            
            # Sort by the highest positive contribution to the phishing classification
            feature_contributions.sort(key=lambda x: x[1], reverse=True)
            
            # Add the top 2 reasons to our indicators if they actually contributed to danger
            for feat, impact in feature_contributions[:2]:
                if impact > 0: # Only report it if it increased the danger score
                    indicators.append(f"AI_Flagged_{feat.upper()}_(Impact: +{impact:.2f})")
                    
        except Exception as e:
            print(f"SHAP Error: {e}")

        # --- Risk Thresholds ---
        risk = "LOW"
        if score >= 0.7:
            risk = "HIGH"
            indicators.append(f"AI_High_Confidence_({score:.2f})")
        elif score >= 0.4:
            risk = "MEDIUM"
            indicators.append(f"AI_Medium_Confidence_({score:.2f})")

        return {"ml_score": score, "risk": risk, "indicators": indicators}