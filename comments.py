import requests
from typing import List, Dict, Optional
from datetime import datetime

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
    def __init__(self, platform: str, api_url: str, token: str):
        self.platform = platform
        self.api_url = api_url
        self.token = token
        self.comments: Dict[str, Comment] = {}
        self.trigger_comment: Optional[Comment] = None

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"{self.api_url}/{endpoint}"
        response = requests.request(method, url, headers=headers, json=data)
        response.raise_for_status()
        return response.json()

    def fetch_comments(self, mr_id: str):
        if self.platform == "gitlab":
            endpoint = f"projects/{mr_id}/merge_requests/{mr_id}/notes"
        else:  # github
            endpoint = f"repos/{mr_id}/pulls/{mr_id}/comments"
        
        comments_data = self._make_request("GET", endpoint)
        self._process_comments(comments_data)

    def _process_comments(self, comments_data: List[Dict]):
        for comment_data in comments_data:
            comment = Comment(
                id=comment_data["id"],
                content=comment_data["body"],
                author=comment_data["user"]["username"],
                created_at=datetime.fromisoformat(comment_data["created_at"]),
                parent_id=comment_data.get("in_reply_to_id")
            )
            self.comments[comment.id] = comment

        # Build reply structure
        for comment in self.comments.values():
            if comment.parent_id:
                parent = self.comments.get(comment.parent_id)
                if parent:
                    parent.replies.append(comment)

    def get_root_comments(self) -> List[Comment]:
        return [comment for comment in self.comments.values() if not comment.parent_id]

    def get_parent_comment(self, comment_id: str) -> Optional[Comment]:
        comment = self.comments.get(comment_id)
        if comment and comment.parent_id:
            return self.comments.get(comment.parent_id)
        return None

    def get_reply_comments(self, comment_id: str) -> List[Comment]:
        comment = self.comments.get(comment_id)
        return comment.replies if comment else []

    def reply_to_comment(self, parent_id: str, content: str) -> Comment:
        if self.platform == "gitlab":
            endpoint = f"projects/{parent_id}/merge_requests/{parent_id}/notes"
        else:  # github
            endpoint = f"repos/{parent_id}/pulls/{parent_id}/comments"
        
        data = {"body": content, "in_reply_to": parent_id}
        response = self._make_request("POST", endpoint, data)
        
        new_comment = Comment(
            id=response["id"],
            content=response["body"],
            author=response["user"]["username"],
            created_at=datetime.fromisoformat(response["created_at"]),
            parent_id=parent_id
        )
        self.comments[new_comment.id] = new_comment
        parent = self.comments.get(parent_id)
        if parent:
            parent.replies.append(new_comment)
        return new_comment

    def add_root_comment(self, mr_id: str, content: str) -> Comment:
        if self.platform == "gitlab":
            endpoint = f"projects/{mr_id}/merge_requests/{mr_id}/notes"
        else:  # github
            endpoint = f"repos/{mr_id}/pulls/{mr_id}/comments"
        
        data = {"body": content}
        response = self._make_request("POST", endpoint, data)
        
        new_comment = Comment(
            id=response["id"],
            content=response["body"],
            author=response["user"]["username"],
            created_at=datetime.fromisoformat(response["created_at"])
        )
        self.comments[new_comment.id] = new_comment
        return new_comment

    def resolve_thread(self, comment_id: str, resolver: str):
        comment = self.comments.get(comment_id)
        if comment:
            comment.resolved = True
            comment.resolved_by = resolver
            comment.resolved_at = datetime.now()
            
            if self.platform == "gitlab":
                endpoint = f"projects/{comment_id}/merge_requests/{comment_id}/notes/{comment_id}/resolve"
            else:  # github
                # GitHub doesn't have a direct "resolve" API, you might need to add a custom label or update the comment
                endpoint = f"repos/{comment_id}/pulls/{comment_id}/comments/{comment_id}"
            
            self._make_request("PUT", endpoint, {"resolved": True})

    def set_trigger_comment(self, comment_id: str):
        self.trigger_comment = self.comments.get(comment_id)

    def get_trigger_comment(self) -> Optional[Comment]:
        return self.trigger_comment