import os
import joblib
import json
import csv
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "ml", "data", "policy_paragraphs.csv")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "ml", "artifacts")

def train_model():
    if not os.path.exists(DATA_PATH):
        print(f"Data file not found at {DATA_PATH}")
        return

    print("Loading data...")
    X = []
    y = []
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("text"):
                X.append(row.get("text"))
                y.append(row.get("label"))
    
    if len(X) < 10:
        print("Not enough data to train. Add more to CSV.")
        return

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training model...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), stop_words="english", min_df=2, max_features=30000)),
        ('clf', LogisticRegression(max_iter=1000, class_weight="balanced"))
    ])

    pipeline.fit(X_train, y_train)
    
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    
    model_path = os.path.join(ARTIFACTS_DIR, "policy_clf.joblib")
    joblib.dump(pipeline, model_path)
    print(f"Model saved to {model_path}")

    labels = sorted(pipeline.classes_)
    labels_path = os.path.join(ARTIFACTS_DIR, "labels.json")
    with open(labels_path, "w") as f:
        json.dump(labels, f)
    
    print(f"Labels saved to {labels_path}")
    
    print("\n--- Model Evaluation ---")
    y_pred = pipeline.predict(X_test)
    print(classification_report(y_test, y_pred, zero_division=0))

if __name__ == "__main__":
    train_model()
