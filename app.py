# app.py

import os
import yaml
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
import logging
from mr_processor import MRProcessor
from comment_processor import CommentProcessor

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
comment_processor = CommentProcessor(config)

@app.post("/gitlab-webhook")
async def gitlab_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Handle incoming GitLab webhook requests for Merge Requests and Comments.

    Args:
        request (Request): The incoming request object.
        background_tasks (BackgroundTasks): FastAPI's background tasks object.

    Returns:
        JSONResponse: A response indicating the webhook was received and processing has started.
    """
    headers = dict(request.headers)
    body = await request.json()
    
    event_type = headers.get('x-gitlab-event')

    logger.info(f"Received GitLab webhook event: {event_type}")
    logger.debug(f"GitLab webhook headers: {headers}")
    logger.debug(f"GitLab webhook body: {body}")
    
    if event_type == 'Note Hook':
        # This is a comment event
        background_tasks.add_task(comment_processor.handle_comment_event, body, headers, "gitlab")
        return JSONResponse(content={"message": "GitLab comment webhook received, processing started"}, status_code=200)
    elif event_type == 'Merge Request Hook':
        # This is a merge request event
        background_tasks.add_task(mr_processor.process_merge_request, body, headers, "gitlab")
        return JSONResponse(content={"message": "GitLab MR webhook received, processing started"}, status_code=200)
    else:
        logger.warning(f"Unsupported GitLab event type: {event_type}")
        return JSONResponse(content={"message": "Unsupported GitLab event type"}, status_code=400)

@app.post("/github-webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Handle incoming GitHub webhook requests for Pull Requests and Comments.

    Args:
        request (Request): The incoming request object.
        background_tasks (BackgroundTasks): FastAPI's background tasks object.

    Returns:
        JSONResponse: A response indicating the webhook was received and processing has started.
    """
    headers = dict(request.headers)
    body = await request.json()
    
    event_type = headers.get('X-GitHub-Event')
    
    logger.info(f"Received GitHub webhook event: {event_type}")
    logger.debug(f"GitHub webhook headers: {headers}")
    logger.debug(f"GitHub webhook body: {body}")
    
    if event_type in ['issue_comment', 'pull_request_review_comment']:
        # This is a comment event
        background_tasks.add_task(comment_processor.handle_comment_event, body, headers, "github")
        return JSONResponse(content={"message": "GitHub comment webhook received, processing started"}, status_code=200)
    elif event_type == 'pull_request':
        # This is a pull request event
        background_tasks.add_task(mr_processor.process_merge_request, body, headers, "github")
        return JSONResponse(content={"message": "GitHub PR webhook received, processing started"}, status_code=200)
    else:
        logger.warning(f"Unsupported GitHub event type: {event_type}")
        return JSONResponse(content={"message": "Unsupported GitHub event type"}, status_code=400)

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