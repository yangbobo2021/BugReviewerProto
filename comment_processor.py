# comment_processor.py

import logging
from typing import Dict, Any
from mr_processor import MRProcessor
from comments import CommentManager
from llm_service import analyze_comment_context

logger = logging.getLogger(__name__)

class CommentProcessor(MRProcessor):
    def __init__(self, config):
        super().__init__(config)
        self.comment_manager = CommentManager(platform=None, api_url=None, token=None)

    async def handle_comment_event(self, body: Dict[str, Any], headers: Dict[str, str], platform: str):
        """
        Handle the comment event, including checking if a reply is needed,
        generating a smart reply, and sending the reply.
        """
        logger.info(f"Handling {platform} comment event")

        if platform == "gitlab":
            gitlab_url = body['project']['web_url'].rsplit('/', 2)[0]
            gitlab_token = headers['x-gitlab-token']
            
            self.comment_manager = CommentManager(platform, gitlab_url, gitlab_token)
            
        elif platform == "github":
            github_token = headers.get('x-github-token')
            
            self.comment_manager = CommentManager("github", "https://api.github.com", github_token)
        
        if self.should_reply(body, headers, platform):
            try:
                comment_context = await self.get_comment_context(body, headers, platform)
                reply = await self.generate_smart_reply(comment_context)
                await self.send_reply(reply, body, headers, platform)
                logger.info("Comment processed and reply sent successfully")
            except Exception as e:
                logger.error(f"Error processing comment: {str(e)}")
        else:
            logger.info("No reply needed for this comment")

    def should_reply(self, body: Dict[str, Any], headers: Dict[str, str], platform: str) -> bool:
        """
        Determine if the bot should reply to this comment.
        """
        bot_name = headers.get('bot-name', '').lower()
        if not bot_name:
            logger.warning("Bot name not found in headers")
            return False

        if platform == "gitlab":
            comment_content = body.get('object_attributes', {}).get('note', '').lower()
        elif platform == "github":
            comment_content = body.get('comment', {}).get('body', '').lower()
        else:
            logger.warning(f"Unsupported platform: {platform}")
            return False

        return f"@{bot_name}" in comment_content

    async def get_comment_context(self, body: Dict[str, Any], headers: Dict[str, str], platform: str) -> Dict[str, Any]:
        """
        Retrieve the context for the comment, including MR/PR details and comments in the current thread.
        """
        if platform == "gitlab":
            project_id = body['project']['id']
            mr_iid = body['merge_request']['iid']
            gitlab_url = body['project']['web_url'].rsplit('/', 2)[0]
            gitlab_token = headers['x-gitlab-token']
            
            gl = self.get_gitlab_client(gitlab_url, gitlab_token)
            project, mr = self.get_mr_details(gl, project_id, mr_iid)
            changed_files = self.get_changed_files_gitlab(project, mr)
            
            # Fetch comments in the current thread
            current_discussion_id = body['object_attributes'].get('discussion_id')
            if current_discussion_id:
                discussion = mr.discussions.get(current_discussion_id)
                comments = discussion.attributes['notes']
            else:
                comments = [body['object_attributes']]  # If it's a single comment, not part of a thread
            
        elif platform == "github":
            repo_name = body['repository']['full_name']
            pr_number = body['issue']['number']
            github_token = headers.get('x-github-token')
            
            gh = self.get_github_client(github_token)
            repo, pr = self.get_pr_details(gh, repo_name, pr_number)
            changed_files = self.get_changed_files_github(pr)
            
            # Fetch comments in the current thread
            current_comment_id = body['comment']['id']
            comments = []
            for comment in pr.get_issue_comments():
                if comment.in_reply_to_id == current_comment_id or comment.id == current_comment_id:
                    comments.append(comment)
        
        return {
            "platform": platform,
            "changed_files": changed_files,
            "comments": comments,
            "current_comment": body.get('object_attributes', {}).get('note') if platform == "gitlab" else body.get('comment', {}).get('body')
        }

    async def generate_smart_reply(self, comment_context: Dict[str, Any]) -> str:
        """
        Generate a smart reply based on the comment context using LLM.
        """
        try:
            reply = await analyze_comment_context(comment_context)
            return reply
        except Exception as e:
            logger.error(f"Error generating smart reply: {str(e)}")
            return "I apologize, but I encountered an error while processing your request. Could you please try again later?"

    async def send_reply(self, reply: str, body: Dict[str, Any], headers: Dict[str, str], platform: str):
        """
        Send the generated reply to the appropriate platform.
        """
        if platform == "gitlab":
            project_id = body['project']['id']
            mr_iid = body['merge_request']['iid']
            comment_id = body['object_attributes']['id']
            discussion_id = body['object_attributes'].get('discussion_id')
            
            gitlab_url = body['project']['web_url'].rsplit('/', 2)[0]
            gitlab_token = headers['x-gitlab-token']
            
            self.comment_manager = CommentManager("gitlab", gitlab_url, gitlab_token)
            
            await self.comment_manager.reply_to_comment(project_id, mr_iid, discussion_id, comment_id, reply)
            
        elif platform == "github":
            repo_name = body['repository']['full_name']
            pr_number = body['issue']['number']
            comment_id = body['comment']['id']
            
            github_token = headers.get('x-github-token')
            
            self.comment_manager = CommentManager("github", "https://api.github.com", github_token)
            
            await self.comment_manager.reply_to_comment(repo_name, pr_number, None, comment_id, reply)

        logger.info(f"Reply sent successfully on {platform}")
