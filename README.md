# Vulnerability Dashboard Intent Classifier

This project trains a transformer-based intent classification model for a vulnerability dashboard using Hugging Face Transformers and the `datasets` library.

## Features

- Fine-tunes a DistilBERT model for intent classification on vulnerability dashboard prompts.
- Supports evaluation and saving of the trained model and tokenizer.
- Includes utilities for data preprocessing, tokenization, and metric computation.

## Project Structure

- `model_creation.py`: Main script for training and evaluating the intent classifier.
- `requirements.txt`: Python dependencies.
- `app.py`, `main.py`: API and application logic.
- `controllers/`, `connection/`: Supporting modules for data handling and API endpoints.
- `results/`: Directory for model checkpoints and outputs.

## Getting Started

### 1. Install Dependencies

```sh
pip install -r requirements.txt
```

### 2. Prepare Data

Ensure you have a CSV file named `vulnerability_dashboard_structured_intents.csv` in the project root with at least the following columns:
- `text`: The prompt or input text.
- `intent`: The corresponding intent label.

### 3. Train the Model

Run the training script:

```sh
python model_creation.py
```

This will train the model and save it to the `./saved_model` directory.

### 4. Evaluate

After training, evaluation metrics will be printed to the console.

### 5. Using the Model

The trained model and tokenizer are saved in `./saved_model` and can be loaded for inference or API deployment.

## Configuration

- Model: `distilbert-base-uncased`
- Training epochs: 4
- Batch size: 16
- Learning rate: 2e-5

You can adjust these parameters in [`model_creation.py`](model_creation.py).

## License

This project is for educational and research