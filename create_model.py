import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import sys
import requests

print("--- Starting Final Model Creation ---")

# Step 1: Download the standard Phishing Dataset from the UCI Machine Learning Repository
print("Step 1: Downloading standard dataset...")
try:
    url = 'https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff'
    response = requests.get(url)
    response.raise_for_status()
    data_lines = response.text.splitlines()
    data_start_index = [i for i, line in enumerate(data_lines) if line.strip().lower() == '@data'][0] + 1
    csv_data = [line.split(',') for line in data_lines[data_start_index:] if line]
    column_names = [
        'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
        'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
        'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler',
        'InfoEmail', 'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust',
        'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection',
        'AgeofDomain', 'DNSRecording', 'WebsiteTraffic', 'PageRank',
        'GoogleIndex', 'LinksPointingToPage', 'StatsReport', 'Result'
    ]
    df = pd.DataFrame(csv_data, columns=column_names)
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df.fillna(0, inplace=True)
    df = df.astype(int)
    print("✅ Dataset downloaded and processed successfully.")
except Exception as e:
    print(f"❌ CRITICAL ERROR: Could not process the dataset. Error: {e}")
    sys.exit()

# Step 2: Prepare the Data
print("Step 2: Preparing data...")
# THE FIX IS HERE: We use .values to get a raw NumPy array without feature names.
X = df.drop('Result', axis=1).values
y = df['Result'].values
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("✅ Data prepared. The labels are: 1 (Legitimate) and -1 (Phishing).")

# Step 3: Train and Test the AI Model
print("Step 3: 🤖 Training the AI model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
print("✅ Model training complete.")
accuracy = accuracy_score(y_test, model.predict(X_test))
print(f"🔬 Model Accuracy on test data: {accuracy*100:.2f}%")

# Step 4: Save the New Model
joblib.dump(model, 'phishing_model.pkl')
print("\n-------------------------------------------")
print("✅ SUCCESS! ✨ A new, warning-free 'phishing_model.pkl' has been created.")
print("-------------------------------------------")