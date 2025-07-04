from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import json
import os

from connection.connection import get_uploaded_files_collection
# 1
from controllers.display_total_assets import display_total_assets 
# 2

#3
from controllers.show_vulnerable_asset_percentage import show_vulnerable_asset_percentage
# 4
from controllers.show_vulnerability_severity_counts import show_vulnerability_severity_counts
# 5
from controllers.display_assets_and_vulnerabilities import display_assets_and_vulnerabilities
# 6
from controllers.display_last_scanned_date import display_last_scanned_date
# 7
from controllers.display_vulnerability_pie_chart import display_vulnerability_pie_chart
# 8
from controllers.display_vulnerability_trend import display_vulnerability_trend
# 9
from controllers.display_cvss_scores_and_risk import display_cvss_scores_and_risk
# 10
from controllers.list_recent_vulnerable_assets import list_recent_vulnerable_assets
# 11
from controllers.show_assets_not_scanned_recently import show_assets_not_scanned_recently
# 12
from controllers.display_assets_by_lab import display_assets_by_lab
# 13
from controllers.display_my_lab_assets_and_vulnerabilities import display_my_lab_assets_and_vulnerabilities
# 14
from controllers.show_vulnerability_remediation_progress import show_vulnerability_remediation_progress
# 15
from controllers.display_os_vs_application_vulnerabilities import display_os_vs_application_vulnerabilities
# 16
from controllers.display_vulnerability_history import display_vulnerability_history
# 17
from controllers.send_patch_update_notifications import send_patch_update_notifications
# 18
from controllers.display_highest_risk_assets import display_highest_risk_assets
# 19
from controllers.display_time_to_patch_critical_vulnerabilities import display_time_to_patch_critical_vulnerabilities








# You can add other controllers as needed

# FastAPI setup
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB setup
MONGO_URL = "mongodb+srv://harshdaftari2:harsh03032004@cluster0.exftgxj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = AsyncIOMotorClient(MONGO_URL)
database = client.user_input_file_db
collection = database.users

# Globals
model = None
tokenizer = None
id2label = {}
OOS_THRESHOLD = 0.5

# === Load Model on Startup ===
@app.on_event("startup")
async def load_model():
    global model, tokenizer, id2label

    model_path = os.path.abspath("./results/final_model")

    if not os.path.exists(model_path):
        print(f"Model path {model_path} not found.")
        if os.path.exists("./results"):
            checkpoints = [d for d in os.listdir("./results") if d.startswith("checkpoint-")]
            if checkpoints:
                latest_checkpoint = max(checkpoints, key=lambda x: int(x.split("-")[1]))
                model_path = os.path.abspath(f"./results/{latest_checkpoint}")
                print(f"Using latest checkpoint at: {model_path}")
            else:
                raise RuntimeError("No model checkpoint found.")
        else:
            raise RuntimeError("No results directory found.")

    # Load model/tokenizer
    model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)

    # Load id2label mapping
    with open(os.path.join(model_path, "config.json"), "r") as f:
        config = json.load(f)
        id2label = {int(k): v for k, v in config.get("id2label", {}).items()}

    print("✅ Model and tokenizer loaded.")
    print(f"📚 Classes: {id2label}")

# === Intent Prediction Function ===
def predict_intent(prompt: str):
    inputs = tokenizer(prompt, truncation=True, padding=True, max_length=128, return_tensors="pt")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)

    logits = outputs.logits
    probabilities = torch.nn.functional.softmax(logits, dim=1)
    pred_idx = logits.argmax(-1).item()
    confidence = probabilities[0][pred_idx].item()

    if confidence < OOS_THRESHOLD:
        return "OOS", confidence * 100
    else:
        return id2label[pred_idx], confidence * 100

# === Routes ===
@app.get("/")
async def root():
    return {"message": "Model API is running and ready!"}

@app.post("/predict-intent")
async def predict_route(request: Request):
    data = await request.json()
    prompt = data.get("prompt", "")

    if not prompt:
        return {"error": "Prompt is required."}

    intent, confidence = predict_intent(prompt)
    print(f"Predicted intent: {intent}, Confidence: {confidence}")
    return {"prompt": prompt, "predicted_intent": intent, "confidence": round(confidence, 2)}

@app.post("/analyze")
async def analyze_prompt(request: Request):
    data = await request.json()
    prompt = data.get("prompt", "")
    print("prompt is", prompt)
    if not prompt:
        return {"error": "Prompt is required."}

    intent_name, confidence = predict_intent(prompt)
    print("intent_name is", intent_name)
    # Load records
    records_collection = await get_uploaded_files_collection()
    cursor = records_collection.find({})
    records = await cursor.to_list(length=None)

    if not records:
        return {"message": "No records found in MongoDB."}

    # Route to the correct controller
    if intent_name == "display_total_assets":
        return await display_total_assets(records)
    elif intent_name == "display_vulnerability_pie_chart":
        return await display_vulnerability_pie_chart(records)
    elif intent_name == "show_vulnerability_severity_counts":
        return await show_vulnerability_severity_counts(records)
    elif intent_name == "display_assets_and_vulnerabilities":
        return await display_assets_and_vulnerabilities(records)
    elif intent_name == "display_last_scanned_date":
        return await display_last_scanned_date(records)
    elif intent_name == "display_vulnerability_trend":
        return await display_vulnerability_trend(records)
    elif intent_name == "display_cvss_scores_and_risk":
        return await display_cvss_scores_and_risk(records)
    elif intent_name == "list_recent_vulnerable_assets":
        return await list_recent_vulnerable_assets(records)
    elif intent_name == "show_assets_not_scanned_recently":
        return await show_assets_not_scanned_recently(records)
    elif intent_name == "display_assets_by_lab":
        return await display_assets_by_lab(records)
    elif intent_name == "show_vulnerability_remediation_progress":
        return await show_vulnerability_remediation_progress(records)
    elif intent_name == "display_os_vs_application_vulnerabilities":
        return await display_os_vs_application_vulnerabilities(records)
    elif intent_name == "display_vulnerability_history":
        return await display_vulnerability_history(records)
    elif intent_name == "send_patch_update_notifications":
        return await send_patch_update_notifications(records)
    elif intent_name == "display_highest_risk_assets":
        return await display_highest_risk_assets(records)
    elif intent_name == "display_time_to_patch_critical_vulnerabilities":
        return await display_time_to_patch_critical_vulnerabilities(records)
    elif intent_name == "display_my_lab_assets_and_vulnerabilities":
        return await display_my_lab_assets_and_vulnerabilities(records)
    elif intent_name == "show_vulnerable_asset_percentage":
        return await show_vulnerable_asset_percentage(records)

    return {"message": f"Intent '{intent_name}' not implemented yet."}
