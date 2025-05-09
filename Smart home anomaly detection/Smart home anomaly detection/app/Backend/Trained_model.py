import pandas as pd
import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Set base directory dynamically
base_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(base_dir, 'UNSW-NB15_1.csv')

def convert_hex_to_int(value):
    try:
        if isinstance(value, str) and value.startswith('0x'):
            return int(value, 16)  # Convert hex to integer
        return value
    except:
        return np.nan

try:
    # Load the dataset
    df = pd.read_csv(csv_path, header=None, encoding='utf-8', low_memory=False)
    print(f'✅ Data loaded successfully from: {csv_path}')

    # Manually assign column names
    columns = [
        'src_ip', 'sport', 'dst_ip', 'dport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 
        'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 
        'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 
        'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat', 
        'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 
        'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ ltm', 'ct_src_dport_ltm', 
        'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
    ]
    df.columns = columns

    # Fix column names by stripping whitespaces
    df.columns = [col.strip() for col in df.columns]
    print("✅ Column names after stripping whitespace:")
    print(df.columns)

    # Data Cleaning
    df.replace('-', np.nan, inplace=True)

    # Handle missing values specifically for 'attack_cat'
    if df['attack_cat'].isnull().sum() > 0:
        print("❗ Warning: 'attack_cat' column contains missing values. Filling with 'Unknown'.")
        df['attack_cat'] = df['attack_cat'].fillna('Unknown')

    # Drop columns with more than 80% missing values (less aggressive)
    threshold = len(df) * 0.2
    df = df.dropna(thresh=threshold, axis=1)

    # Drop rows with too many missing values (more than 50%)
    row_threshold = int(len(df.columns) * 0.5)
    df = df.dropna(thresh=row_threshold, axis=0)

    # Check if the cleaned DataFrame is empty
    if df.empty:
        print("❌ Error: The cleaned dataset is empty after data retention.")
        exit()

    print(f"✅ Data shape after retaining as much data as possible: {df.shape}")

    # Apply hex conversion where necessary
    for col in df.columns:
        df[col] = df[col].apply(convert_hex_to_int)
        try:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            print(f"✅ Converted column to numeric: {col}")
        except Exception as e:
            print(f"❌ Error converting column {col} to numeric: {str(e)}")

    # Encode the 'attack_cat' column
    le = LabelEncoder()
    df['attack_cat'] = le.fit_transform(df['attack_cat'].astype(str))
    print("✅ 'attack_cat' encoded successfully.")

    # Convert the label column to binary: 0 for normal, 1 for attack
    df['label'] = df['label'].apply(lambda x: 1 if x == 1 else 0)

    # Dynamically drop only the columns that exist in the DataFrame
    drop_cols = ['label', 'attack_cat', 'src_ip', 'dst_ip', 'proto', 'state', 'service']
    existing_cols = [col for col in drop_cols if col in df.columns]
    try:
        X = df.drop(existing_cols, axis=1)
        y = df['label']
        print("✅ Features and labels extracted successfully.")
    except KeyError as e:
        print(f"❌ Error: Column not found - {str(e)}")
        exit()

    # Check if any data is left after cleaning
    if X.empty or y.empty:
        print("❌ Error: No valid data left after preprocessing.")
        exit()

    # Train-test split with a smaller test size to avoid empty training set
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.05, random_state=42)
    print(f"✅ Train set size: {len(X_train)}, Test set size: {len(X_test)}")

    # Train the Isolation Forest model
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X_train)
    print("✅ Model trained successfully.")

    # Save the trained model
    model_path = os.path.join(base_dir, 'models', 'Isolation_forest_model.pkl')
    joblib.dump(model, model_path)
    print(f'✅ Model saved successfully to: {model_path}')

    # Save feature names
    feature_path = os.path.join(base_dir, 'models', 'features.pkl')
    joblib.dump(X_train.columns.tolist(), feature_path)
    print(f'✅ Features saved successfully to: {feature_path}')

except Exception as e:
    print(f'❌ Error: {str(e)}')
