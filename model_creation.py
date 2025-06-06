from datasets import Dataset, ClassLabel
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding
)
import numpy as np
from sklearn.metrics import accuracy_score
import torch
import pandas as pd
from sklearn.model_selection import train_test_split

# Load dataset
df = pd.read_csv('vulnerability_dashboard_structured_intents.csv')
x = df['text']
y = df['intent']

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.15, stratify=y, random_state=42)

# Encode labels
unique_labels = sorted(list(set(y_train)))
label2id = {label: idx for idx, label in enumerate(unique_labels)}
id2label = {idx: label for label, idx in label2id.items()}

# Prepare dataset
train_ds = Dataset.from_dict({
    "text": X_train.tolist(),
    "label": [label2id[label] for label in y_train]
}).cast_column("label", ClassLabel(names=unique_labels))

test_ds = Dataset.from_dict({
    "text": X_test.tolist(),
    "label": [label2id[label] for label in y_test]
}).cast_column("label", ClassLabel(names=unique_labels))

# Tokenization
model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)

def preprocess(examples):
    return tokenizer(examples['text'], truncation=True, padding=True, max_length=512)

train_ds = train_ds.map(preprocess, batched=True, remove_columns=["text"])
test_ds = test_ds.map(preprocess, batched=True, remove_columns=["text"])

# Model
model = AutoModelForSequenceClassification.from_pretrained(
    model_name,
    num_labels=len(unique_labels),
    id2label=id2label,
    label2id=label2id
)

# Data collator
data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

# TrainingArguments (compatible with 4.52.2)
training_args = TrainingArguments(
    output_dir="./results",
    learning_rate=2e-5,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    num_train_epochs=4,
    weight_decay=0.01,
    logging_dir='./logs',
    logging_steps=50,
    fp16=torch.cuda.is_available(),
    do_eval=True,        # Enables evaluation
    do_train=True,       # Enables training
    eval_steps=100       # Evaluate every 100 steps
)

# Metrics
def compute_metrics(eval_pred):
    predictions, labels = eval_pred
    preds = np.argmax(predictions, axis=1)
    return {"accuracy": accuracy_score(labels, preds)}

# Trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_ds,
    eval_dataset=test_ds,
    data_collator=data_collator,
    compute_metrics=compute_metrics,
)

# Train
trainer.train()

# Evaluate
metrics = trainer.evaluate()
print("Evaluation metrics:", metrics)

trainer.save_model("./saved_model")
tokenizer.save_pretrained("./saved_model")