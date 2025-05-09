import os
import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Initialize the FastAPI application
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)

# Get the base directory and model path
base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, 'models', 'Isolation_forest_model.pkl')
feature_path = os.path.join(base_dir, 'models', 'features.pkl')

# Load the trained model and feature names
try:
    model = joblib.load(model_path)
    model_features = joblib.load(feature_path)
    print(f'✅ Model and features loaded successfully from: {model_path} and {feature_path}')
except Exception as e:
    print(f'❌ Error loading model or features: {str(e)}')

# Pydantic model for user-friendly input
class UserInput(BaseModel):
    ip_address: str
    service_type: str
    data_sent_kb: float
    duration_sec: float
    protocol: str
    activity_type: str

@app.get("/")
async def root():
    return {"message": "Welcome to the Smart Home Anomaly Detection API"}

@app.post("/predict")
async def predict(data: UserInput):
    try:
        # Map service types and protocols to numeric values
        service_map = {'http': 1, 'ftp': 2, 'ssh': 3}
        protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
        activity_map = {'normal': 0, 'anomalous': 1}

        # Prepare the input dictionary
        input_data = {
            "sport": 80,  # Default HTTP port
            "dport": 443,  # Default HTTPS port
            "proto": protocol_map.get(data.protocol, 6),  # Default to TCP
            "state": 1,  # Default state as 1 (normal)
            "dur": data.duration_sec,
            "sbytes": int(data.data_sent_kb * 1024)  # Convert KB to bytes
        }

        # Convert to DataFrame
        input_df = pd.DataFrame([input_data])

        # Add missing columns with default values (0)
        for col in model_features:
            if col not in input_df.columns:
                input_df[col] = 0

        # Reorder columns to match model training
        input_df = input_df[model_features]

        # Predict the result
        prediction = model.predict(input_df)
        result = "Anomaly" if prediction[0] == 1 else "Normal"
        return {"prediction": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")
