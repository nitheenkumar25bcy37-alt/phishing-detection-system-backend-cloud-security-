# backend/modules/ml_engine/trainer.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

def train_model():
    print("--- Starting ML Model Training ---")
    
    # 1. Set up file paths
    current_dir = os.path.dirname(__file__)
    csv_path = os.path.join(current_dir, "dataset.csv")
    model_path = os.path.join(current_dir, "rf_model.pkl")
    
    # 2. Load the dataset
    print(f"Loading data from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # 3. Separate Features (X) and Labels (y)
    # Drop the 'is_phishing' column to get our features
    X = df.drop('is_phishing', axis=1)
    # The 'is_phishing' column is our target label
    y = df['is_phishing']
    
    # 4. Split data into Training and Testing sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 5. Initialize and Train the Random Forest
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # 6. Test the model's accuracy
    accuracy = model.score(X_test, y_test)
    print(f"Model Accuracy on Test Data: {accuracy * 100:.2f}%")
    
    # 7. Save the trained model to disk
    joblib.dump(model, model_path)
    print(f"Model successfully saved to {model_path}")

if __name__ == "__main__":
    train_model()