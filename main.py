from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import json
import os

from connection.connection import get_uploaded_files_collection
from controllers.display_total_assets import display_total_assets 
from controllers.display_vulnerability_pie_chart import display_vulnerability_pie_chart
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
    return {"prompt": prompt, "predicted_intent": intent, "confidence": round(confidence, 2)}

@app.post("/analyze")
async def analyze_prompt(request: Request):
    data = await request.json()
    prompt = data.get("prompt", "")

    if not prompt:
        return {"error": "Prompt is required."}

    intent_name, confidence = predict_intent(prompt)

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


    return {"message": f"Intent '{intent_name}' not implemented yet."}
