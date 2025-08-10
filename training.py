import os
import pandas as pd
from detectors.feature_extractor import extract_domain
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from sklearn.metrics import classification_report
import joblib

print("Current working directory:", os.getcwd())
file_path = "data/malicious_phish.csv"
if not os.path.exists(file_path):
    raise FileNotFoundError(f"Data file not found at {file_path}. Please ensure the data is available before running the training script.")

# Load data
data = pd.read_csv(file_path)
data['type'] = data['type'].map({'benign': 0, 'defacement':1, 'phishing':2, 'malware':3})

print(f"Total rows in loaded data: {len(data)}")
features = []
for url in data['url']: 
    try: 
        features.append(extract_domain(url))
    except Exception as e:
        print(f"Error for URL:{url} -> {e}")
print (f"Total features extracted: {len(features)}")
x = pd.DataFrame(features)
y = data['type']

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=42)

print("x_train shape:", x_train.shape)
print("y_train shape:", y_train.shape)
print("x_train columns:", x_train.columns)
print("First few rows of x_train:\n", x_train.head())
print("First few values of y_train:\n", y_train.head())

model = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')

param_grid = {
    'n_estimators': [50, 100],
    'max_depth': [3, 6, 10],
    'learning_rate': [0.01, 0.1, 0.3],
    'subsample': [0.6, 0.8, 1.0],
    'colsample_bytree': [0.6, 0.8, 1.0],
    'reg_alpha': [0, 0.5, 1.0],
    'reg_lambda': [1.0, 2.0],
    'scale_pos_weight': [1, 2, 5]
}

grid = RandomizedSearchCV(model, param_grid, n_iter = 10, cv=3, scoring='f1_macro', n_jobs=-1)
grid.fit(x_train, y_train)

y_pred = grid.predict(x_test)
print(classification_report(y_test, y_pred))

print("Training set performance:")
print(classification_report(y_train, grid.predict(x_train)))

print("Test set performance:")
print(classification_report(y_test, grid.predict(x_test)))

joblib.dump(grid, 'detectors/url_model.pkl')

joblib.dump(x.columns.tolist(), 'detectors/features.pkl')

importances = grid.best_estimator_.feature_importances_
for name, importance in zip(x.columns, importances):
    print(f"{name}: {importance:.4f}")


























