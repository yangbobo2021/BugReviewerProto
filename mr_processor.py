# mr_processor.py

import logging
import base64
import os
from typing import Dict, Any
import gitlab
from llm_service import analyze_code_security

# 设置日志级别
log_level = logging.DEBUG if os.environ.get('DEBUG', 'false').lower() == 'true' else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MRProcessor:
    def __init__(self, config):
        self.config = config
        logger.debug("MRProcessor initialized with config: %s", config)

    @staticmethod
    def get_gitlab_client(url, token):
        logger.debug("Creating GitLab client for URL: %s", url)
        try:
            return gitlab.Gitlab(url, private_token=token)
        except Exception as e:
            logger.error("Failed to create GitLab client: %s", str(e))
            raise

    @staticmethod
    def get_mr_details(gl, project_id, mr_iid):
        logger.debug("Fetching MR details for project %s, MR IID %s", project_id, mr_iid)
        try:
            project = gl.projects.get(project_id)
            mr = project.mergerequests.get(mr_iid)
            return project, mr
        except gitlab.exceptions.GitlabGetError as e:
            logger.error("Failed to get MR details: %s", str(e))
            raise

    @staticmethod
    def get_changed_files(project, mr):
        logger.debug("Fetching changed files for MR %s", mr.iid)
        try:
            changes = mr.changes()
            return [
                {
                    'old_path': change['old_path'],
                    'new_path': change['new_path'],
                    'diff': change['diff'],
                    'new_content': MRProcessor.get_file_content(project, mr.source_branch, change['new_path']) if not change.get('deleted_file') else None
                }
                for change in changes['changes']
            ]
        except Exception as e:
            logger.error("Failed to get changed files: %s", str(e))
            logger.debug("Full error details:", exc_info=True)
            return []

    @staticmethod
    def get_file_content(project, branch, file_path):
        logger.debug("Fetching content for file: %s", file_path)
        try:
            file_content = project.files.get(file_path=file_path, ref=branch)
            content = base64.b64decode(file_content.content).decode('utf-8')
            logger.debug("Successfully retrieved content for file: %s (length: %d characters)", file_path, len(content))
            return content
        except (gitlab.exceptions.GitlabError, UnicodeDecodeError) as e:
            logger.error("Error retrieving file content for %s: %s", file_path, str(e))
            return None

    @staticmethod
    def add_comment_to_mr(mr, comment):
        logger.debug("Adding comment to MR %s", mr.iid)
        try:
            mr.notes.create({'body': comment})
        except Exception as e:
            logger.error("Failed to add comment to MR: %s", str(e))
            raise

    async def process_mr(self, body: Dict[str, Any], headers: Dict[str, str], add_comments=True):
        logger.debug("Processing MR with action: %s", body.get("object_attributes", {}).get("action"))
        try:
            mr_action = body.get("object_attributes", {}).get("action")
            
            if self.need_security_analysis(mr_action, body):
                gitlab_url = body["project"]["web_url"].rsplit('/', 1)[0]
                gitlab_token = headers["x-gitlab-token"]
                project_id = body["project"]["id"]
                mr_iid = body["object_attributes"]["iid"]

                gl = self.get_gitlab_client(gitlab_url, gitlab_token)
                mr = self.get_mr_details(gl, project_id, mr_iid)
                changed_files = self.get_changed_files(mr)

                for file in changed_files:
                    await self.analyze_and_comment(mr, file, add_comments)

                logger.info("MR %s event processed successfully", mr_action)
            else:
                logger.info("MR %s event doesn't require security analysis", mr_action)
        except Exception as e:
            logger.error("Error processing MR: %s", str(e))
            raise

    @staticmethod
    def need_security_analysis(mr_action, body):
        logger.debug("Checking if security analysis is needed for action: %s", mr_action)
        if mr_action == "open":
            return True
        elif mr_action == "update":
            oldrev = body.get("object_attributes", {}).get("oldrev")
            return oldrev is not None
        return False

    @staticmethod
    async def analyze_and_comment(mr, file, add_comments=False):
        logger.debug("Analyzing file: %s", file['new_path'] or file['old_path'])
        try:
            if file['new_content'] is None:
                security_analysis = await analyze_code_security(file['diff'])
            else:
                security_analysis = await analyze_code_security(file['diff'], file['new_content'])

            if security_analysis is None:
                logger.error("Security analysis failed for file: %s", file['new_path'] or file['old_path'])
                return

            comment = MRProcessor.format_security_comment(file, security_analysis)
            if add_comments:
                MRProcessor.add_comment_to_mr(mr, comment)
            else:
                print(comment)
        except Exception as e:
            logger.error("Failed to analyze and comment on file %s: %s", file['new_path'] or file['old_path'], str(e))
            logger.debug("Full error details:", exc_info=True)

    @staticmethod
    def format_security_comment(file, security_analysis):
        logger.debug("Formatting security comment for file: %s", file['new_path'] or file['old_path'])
        comment = f"Security Analysis Results for {file['new_path'] or file['old_path']}:\n\n"
        if not security_analysis or 'risks' not in security_analysis:
            comment += "No security risks identified.\n"
        else:
            for risk in security_analysis['risks']:
                comment += f"Risk: {risk.get('description', 'N/A')}\n"
                comment += f"Location: {risk.get('location', 'N/A')}\n"
                comment += f"Suggestion: {risk.get('suggestion', 'N/A')}\n\n"
        return comment

    @staticmethod
    async def analyze_mr_cli(gitlab_url, token, project_id, mr_iid):
        logger.debug("Analyzing MR from CLI for project %s, MR IID %s", project_id, mr_iid)
        try:
            gl = MRProcessor.get_gitlab_client(gitlab_url, token)
            project, mr = MRProcessor.get_mr_details(gl, project_id, mr_iid)
            changed_files = MRProcessor.get_changed_files(project, mr)

            for file in changed_files:
                await MRProcessor.analyze_and_comment(mr, file, add_comments=False)
        except gitlab.exceptions.GitlabAuthenticationError:
            logger.error("Authentication failed. Please check your GitLab token.")
            raise
        except Exception as e:
            logger.error("An unexpected error occurred: %s", str(e))
            logger.debug("Full error details:", exc_info=True)
            raise