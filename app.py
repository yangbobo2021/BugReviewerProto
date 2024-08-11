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
    Handle incoming GitLab webhook requests for Merge Requests.

    Args:
        request (Request): The incoming request object.
        background_tasks (BackgroundTasks): FastAPI's background tasks object.

    Returns:
        JSONResponse: A response indicating the webhook was received and processing has started.
    """
    headers = dict(request.headers)
    body = await request.json()
    
    background_tasks.add_task(mr_processor.process_merge_request, body, headers, "gitlab")
    
    return JSONResponse(content={"message": "GitLab webhook received, processing started"}, status_code=200)

@app.post("/github-webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Handle incoming GitHub webhook requests for Pull Requests.

    Args:
        request (Request): The incoming request object.
        background_tasks (BackgroundTasks): FastAPI's background tasks object.

    Returns:
        JSONResponse: A response indicating the webhook was received and processing has started.
    """
    headers = dict(request.headers)
    body = await request.json()
    
    background_tasks.add_task(mr_processor.process_merge_request, body, headers, "github")
    
    return JSONResponse(content={"message": "GitHub webhook received, processing started"}, status_code=200)

@app.get("/ping")
async def health_check():
    """
    Simple health check endpoint.

    Returns:
        dict: A dictionary indicating the service is running.
    """
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)