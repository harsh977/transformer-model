import os
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import json

# === Check and Load Model ===
model_path = os.path.abspath("./results/final_model")
if not os.path.exists(model_path):
    print(f"Error: Model directory '{model_path}' does not exist!")
    if os.path.exists("./results"):
        print("The 'results' directory exists, but 'final_model' subdirectory is missing.")
        print("Contents of results directory:", os.listdir("./results"))

        checkpoints = [d for d in os.listdir("./results") if d.startswith("checkpoint-")]
        if checkpoints:
            latest_checkpoint = max(checkpoints, key=lambda x: int(x.split("-")[1]))
            print(f"Found checkpoint directory: {latest_checkpoint}")
            model_path = os.path.abspath(f"./results/{latest_checkpoint}")
            print(f"Using latest checkpoint: {model_path}")
    else:
        print("The 'results' directory does not exist.")
        exit(1)

try:
    print(f"Loading model from: {model_path}")
    model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
    
    with open(os.path.join(model_path, "config.json"), "r") as f:
        config = json.load(f)
        id2label = {int(k): v for k, v in config.get("id2label", {}).items()}
    
    print("Model loaded successfully!")
    print(f"Number of intent classes: {len(id2label)}")

except Exception as e:
    print(f"Error loading model: {str(e)}")
    exit(1)

# === Prediction Function with OOS Threshold ===
OOS_THRESHOLD = 0.5  # 50%

def predict_intent(text):
    inputs = tokenizer(text, truncation=True, padding=True, max_length=128, return_tensors="pt")
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

# === Test Examples ===
test_prompts = [
    "Show me a pie chart of vulnerabilities",                   # In-scope
    "List assets not scanned in the last month",                # In-scope
    "Display the trend of vulnerabilities over time",           # In-scope
    "Can I get this data emailed to me?",                       # OOS
    "How do I export the dashboard as a PDF?",                  # OOS
]

print("\nPredictions using existing model with OOS detection:")
for prompt in test_prompts:
    intent, confidence = predict_intent(prompt)
    print(f"Prompt: '{prompt}'")
    print(f"Predicted intent: '{intent}' (Confidence: {confidence:.2f}%)\n")

# === Interactive Mode ===
def interactive_mode():
    print("\n" + "="*50)
    print("Vulnerability Dashboard Intent Classifier with OOS")
    print("="*50)
    print("Enter prompts to classify (type 'exit' to quit):")

    while True:
        user_input = input("\nPrompt: ")
        if user_input.lower() in ['exit', 'quit', 'q']:
            break

        intent, confidence = predict_intent(user_input)
        print(f"Predicted intent: {intent} (Confidence: {confidence:.2f}%)")

# Run if main
if __name__ == "__main__":
    interactive_mode()
