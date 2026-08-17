import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
import joblib
import os

def train_advanced_model():
    current_dir = os.path.dirname(__file__)
    
    # We will use your Kaggle dataset here. 
    # Ensure your Kaggle CSV is named 'kaggle_dataset.csv' and placed in this folder.
    csv_path = os.path.join(current_dir, "dataset.csv") 
    model_path = os.path.join(current_dir, "xgb_model.pkl")
    
    print("Loading dataset...")
    df = pd.read_csv(csv_path)
    
    # Separate features (X) and target label (y)
    X = df.drop('is_phishing', axis=1)
    y = df['is_phishing']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training XGBoost Classifier...")
    # XGBoost handles complex, non-linear patterns much better than Random Forest
    model = xgb.XGBClassifier(
        n_estimators=200, 
        learning_rate=0.1, 
        max_depth=5, 
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss'
    )
    
    model.fit(X_train, y_train)
    
    # Save the new, highly accurate model
    joblib.dump(model, model_path)
    print(f"Enterprise XGBoost Model successfully saved to {model_path}!")

if __name__ == "__main__":
    train_advanced_model()