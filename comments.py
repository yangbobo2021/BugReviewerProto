# comments.py

import logging
from typing import List, Dict, Optional
from datetime import datetime
import aiohttp
from aiohttp import ClientSession

logger = logging.getLogger(__name__)

class Comment:
    def __init__(self, id: str, content: str, author: str, created_at: datetime, parent_id: Optional[str] = None):
        self.id = id
        self.content = content
        self.author = author
        self.created_at = created_at
        self.parent_id = parent_id
        self.replies: List[Comment] = []
        self.resolved = False
        self.resolved_by = None
        self.resolved_at = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "content": self.content,
            "author": self.author,
            "created_at": self.created_at.isoformat(),
            "parent_id": self.parent_id,
            "replies": [reply.to_dict() for reply in self.replies],
            "resolved": self.resolved,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None
        }

class CommentManager:
    def __init__(self, platform: Optional[str] = None, api_url: Optional[str] = None, token: Optional[str] = None):
        self.platform = platform
        self.api_url = api_url
        if self.api_url and not self.api_url.endswith('/api/v4'):
            self.api_url = f"{self.api_url.rstrip('/')}/api/v4"
        self.token = token
        self.session: Optional[ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        if not self.session:
            self.session = aiohttp.ClientSession()

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        logger.info(f"Making {method} request to {url}")
        logger.debug(f"Request data: {data}")

        try:
            async with self.session.request(method, url, headers=headers, json=data) as response:
                response.raise_for_status()
                return await response.json()
        except aiohttp.ClientError as e:
            logger.error(f"Request failed: {e.status}, message='{str(e)}', url='{url}'")
            raise

    async def fetch_comments(self, project_id: str, mr_iid: str) -> List[Comment]:
        if self.platform == "gitlab":
            endpoint = f"projects/{project_id}/merge_requests/{mr_iid}/discussions"
        else:  # github
            endpoint = f"repos/{project_id}/pulls/{mr_iid}/comments"
        
        discussions_data = await self._make_request("GET", endpoint)
        return self._process_comments(discussions_data)

    def _process_comments(self, discussions_data: List[Dict]) -> List[Comment]:
        comments = []
        for discussion in discussions_data:
            notes = discussion.get('notes', [])
            for i, note_data in enumerate(notes):
                author = note_data.get("author", {}).get("username") or note_data.get("username")
                comment = Comment(
                    id=str(note_data["id"]),
                    content=note_data["body"],
                    author=author,
                    created_at=datetime.fromisoformat(note_data["created_at"].replace("Z", "+00:00")),
                    parent_id=str(notes[0]["id"]) if i > 0 else None
                )
                comments.append(comment)

                # If this is not the first note in the discussion, it's a reply
                if i > 0:
                    parent = next((c for c in comments if c.id == str(notes[0]["id"])), None)
                    if parent:
                        parent.replies.append(comment)

        return comments

    async def reply_to_comment(self, project_id: str, mr_id: str, discussion_id: Optional[str], comment_id: str, content: str) -> Comment:
        try:
            if self.platform == "gitlab":
                endpoint = f"projects/{project_id}/merge_requests/{mr_id}/discussions/{discussion_id}/notes"
                data = {"body": content, "in_reply_to_id": comment_id}
            else:  # github
                endpoint = f"repos/{project_id}/pulls/{mr_id}/comments"
                data = {"body": content, "in_reply_to": comment_id}
            
            response = await self._make_request("POST", endpoint, data)
            
            new_comment = Comment(
                id=str(response["id"]),
                content=response["body"],
                author=response["author"]["username"] if "author" in response else response["user"]["login"],
                created_at=datetime.fromisoformat(response["created_at"].replace("Z", "+00:00")),
                parent_id=comment_id
            )
            return new_comment
        except Exception as e:
            logger.error(f"Failed to reply to comment: {str(e)}")
            raise

    async def add_root_comment(self, project_id: str, mr_id: str, content: str) -> Comment:
        if self.platform == "gitlab":
            endpoint = f"projects/{project_id}/merge_requests/{mr_id}/notes"
        else:  # github
            endpoint = f"repos/{project_id}/pulls/{mr_id}/comments"
        
        data = {"body": content}
        response = await self._make_request("POST", endpoint, data)
        
        new_comment = Comment(
            id=str(response["id"]),
            content=response["body"],
            author=response["user"]["username"] if "user" in response else response["author"]["username"],
            created_at=datetime.fromisoformat(response["created_at"].replace("Z", "+00:00"))
        )
        return new_comment

    async def resolve_thread(self, project_id: str, mr_id: str, comment_id: str, resolver: str):
        comment = await self.fetch_comment(project_id, mr_id, comment_id)
        if comment:
            comment.resolved = True
            comment.resolved_by = resolver
            comment.resolved_at = datetime.now()
            
            if self.platform == "gitlab":
                endpoint = f"projects/{project_id}/merge_requests/{mr_id}/discussions/{comment.parent_id or comment_id}/notes/{comment_id}/resolve"
            else:  # github
                # GitHub doesn't have a direct "resolve" API, you might need to add a custom label or update the comment
                endpoint = f"repos/{project_id}/pulls/{mr_id}/comments/{comment_id}"
            
            await self._make_request("PUT", endpoint, {"resolved": True})

    async def fetch_comment(self, project_id: str, mr_id: str, comment_id: str) -> Optional[Comment]:
        if self.platform == "gitlab":
            endpoint = f"projects/{project_id}/merge_requests/{mr_id}/notes/{comment_id}"
        else:  # github
            endpoint = f"repos/{project_id}/pulls/{mr_id}/comments/{comment_id}"
        
        response = await self._make_request("GET", endpoint)
        
        return Comment(
            id=str(response["id"]),
            content=response["body"],
            author=response["user"]["username"] if "user" in response else response["author"]["username"],
            created_at=datetime.fromisoformat(response["created_at"].replace("Z", "+00:00")),
            parent_id=response.get("in_reply_to_id")
        )