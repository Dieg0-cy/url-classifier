import sys
import joblib
from pandas.io import feather_format 
from detectors.feature_extractor import extract_domain
import pandas as pd
from sklearn.preprocessing import LabelEncoder

url = sys.argv[1] if len(sys.argv) > 1 else input("Enter the URL: ")

# Load the pre-trained model
model = joblib.load('detectors/url_model.pkl')
features_list = joblib.load('detectors/features.pkl')

features = extract_domain(url)
X = pd.DataFrame([features])[features_list]
if 'suffix' in X.columns:
    le = LabelEncoder()
    X['suffix'] = le.fit_transform(X['suffix'])

prediction = model.predict(X)[0]
proba = model.predict_proba(X)[0][prediction]

type = ['benign', 'defacement', 'phishing', 'malware'][prediction]
print (f"\nURL: {url}\nPrediction: {type} (Confidence: {proba:.2f})")


