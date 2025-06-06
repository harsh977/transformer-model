from huggingface_hub import HfApi

api = HfApi(token=os.getenv("HF_TOKEN"))
api.upload_folder(
    folder_path="/results",
    repo_id="harsh9774/intent-classification",
    repo_type="model",
)
