# app.py

import os
import yaml
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
import logging
from mr_processor import MRProcessor

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_config(config_file: str):
    """
    Load configuration from a YAML file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        dict: Loaded configuration as a dictionary.
    """
    with open(config_file, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

config = load_config("config.yaml")
mr_processor = MRProcessor(config)

@app.post("/gitlab-webhook")
async def gitlab_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Handle incoming GitLab webhook requests.

    Args:
        request (Request): The incoming request object.
        background_tasks (BackgroundTasks): FastAPI's background tasks object.

    Returns:
        JSONResponse: A response indicating the webhook was received and processing has started.
    """
    headers = dict(request.headers)
    body = await request.json()
    
    background_tasks.add_task(mr_processor.process_mr, body, headers)
    
    return JSONResponse(content={"message": "Webhook received, processing started"}, status_code=200)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)