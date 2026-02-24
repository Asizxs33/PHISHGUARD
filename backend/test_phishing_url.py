import sys
import os
import json

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.heuristic_analyzer import analyze_url_heuristic
from ml.features import extract_url_features, get_url_feature_names
from ml.classifier import PhishingClassifier

url = "https://app.netlify.com/teams/ravshanbekovasror7/overview"

h_score, h_verdict, h_details = analyze_url_heuristic(url)

print("--- Heuristic Analysis ---")
print("Score:", h_score)
print("Verdict:", h_verdict)
print("Details:", json.dumps(h_details, indent=2))

print("\n--- ML Analysis ---")
features = extract_url_features(url)
print("Features:", json.dumps(features, indent=2))

clf = PhishingClassifier()
if clf.load('url_model'):
    import numpy as np
    feature_names = get_url_feature_names()
    feature_vector = np.array([features[f] for f in feature_names])
    ml_score, ml_verdict, ml_details = clf.predict(feature_vector)
    print("ML Score:", ml_score)
    print("ML Verdict:", ml_verdict)
    print("ML Details:", json.dumps(ml_details, indent=2))
else:
    print("URL model not found.")
