import os
import torch
import json
from transformers import AutoModelForSequenceClassification, AutoTokenizer

def load_model_and_tokenizer():
    model_path = os.path.abspath("saved_model")
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)

    with open(os.path.join(model_path, "config.json"), "r") as f:
        config = json.load(f)
        id2label = {int(k): v for k, v in config["id2label"].items()}

    return model, tokenizer, id2label

def predict_intent(text, model, tokenizer, id2label):
    inputs = tokenizer(text, truncation=True, padding=True, max_length=128, return_tensors="pt")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)

    logits = outputs.logits
    pred_idx = logits.argmax(-1).item()
    probabilities = torch.nn.functional.softmax(logits, dim=1)
    confidence = probabilities[0][pred_idx].item() * 100

    return id2label[pred_idx], confidence
