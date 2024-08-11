# app.py

import os
import yaml
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
import logging
from mr_processor import MRProcessor
from comments import CommentManager

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
    Handle incoming GitLab webhook requests for Merge Requests and Comments.

    Args:
        request (Request): The incoming request object.
        background_tasks (BackgroundTasks): FastAPI's background tasks object.

    Returns:
        JSONResponse: A response indicating the webhook was received and processing has started.
    """
    headers = dict(request.headers)
    body = await request.json()
    
    event_type = headers.get('X-Gitlab-Event')
    
    if event_type == 'Note Hook':
        # 这是一个评论事件
        await handle_comment_event(body, headers, "gitlab")
        return JSONResponse(content={"message": "GitLab comment webhook received and processed"}, status_code=200)
    elif event_type == 'Merge Request Hook':
        # 这是一个合并请求事件
        background_tasks.add_task(mr_processor.process_merge_request, body, headers, "gitlab")
        return JSONResponse(content={"message": "GitLab MR webhook received, processing started"}, status_code=200)
    else:
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
    
    if event_type == 'issue_comment' or event_type == 'pull_request_review_comment':
        # 这是一个评论事件
        await handle_comment_event(body, headers, "github")
        return JSONResponse(content={"message": "GitHub comment webhook received and processed"}, status_code=200)
    elif event_type == 'pull_request':
        # 这是一个拉取请求事件
        background_tasks.add_task(mr_processor.process_merge_request, body, headers, "github")
        return JSONResponse(content={"message": "GitHub PR webhook received, processing started"}, status_code=200)
    else:
        return JSONResponse(content={"message": "Unsupported GitHub event type"}, status_code=400)

async def handle_comment_event(body, headers, platform):
    """
    Handle comment events for both GitLab and GitHub.

    Args:
        body (dict): The webhook payload.
        headers (dict): The request headers.
        platform (str): Either "gitlab" or "github".
    """
    if platform == "gitlab":
        api_url = body['project']['web_url'].rsplit('/', 2)[0]
        token = headers.get('X-Gitlab-Token')
        comment_id = body['object_attributes']['id']
        parent_id = body['object_attributes']['noteable_id']
        content = body['object_attributes']['note']
    else:  # github
        api_url = f"https://api.github.com"
        token = headers.get('X-Hub-Signature')
        comment_id = body['comment']['id']
        parent_id = body['issue']['number'] if 'issue' in body else body['pull_request']['number']
        content = body['comment']['body']

    # 为每个请求创建一个新的 CommentManager 实例
    comment_manager = CommentManager(platform=platform, api_url=api_url, token=token)

    # 检查是否是回复评论
    if comment_manager.get_parent_comment(str(comment_id)):
        reply_content = "yes"
        new_comment = comment_manager.reply_to_comment(str(parent_id), reply_content)
        logger.info(f"Replied to comment {comment_id} with content: {reply_content}")

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