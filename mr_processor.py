# mr_processor.py

import logging
import base64
import os
from typing import Dict, Any, List
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
                    'new_file': change.get('new_file', False),
                    'deleted_file': change.get('deleted_file', False),
                    'new_content': MRProcessor.get_file_content(project, mr, change['new_path']) if not change.get('deleted_file') else None
                }
                for change in changes['changes'][:10+1]
            ]
        except Exception as e:
            logger.error("Failed to get changed files: %s", str(e))
            logger.debug("Full error details:", exc_info=True)
            return []

    @staticmethod
    def get_file_content(project, mr, file_path):
        logger.debug(f"Fetching content for file: {file_path} from MR: {mr.iid}")
        try:
            # 获取 MR 的最新提交 SHA
            commits = list(mr.commits())
            if not commits:
                logger.error(f"No commits found for MR: {mr.iid}")
                return None
            latest_commit_sha = commits[-1].id

            # 从最新提交中获取文件内容
            file_content = project.files.get(file_path=file_path, ref=latest_commit_sha)
            if file_content is None:
                logger.error(f"File not found in commit {latest_commit_sha}: {file_path}")
                return None

            content = base64.b64decode(file_content.content).decode('utf-8')
            logger.debug(f"Successfully retrieved content for file: {file_path} (length: {len(content)} characters)")
            return content
        except gitlab.exceptions.GitlabGetError as e:
            if e.response_code == 404:
                logger.error(f"File not found: {file_path} in commit {latest_commit_sha}")
            else:
                logger.error(f"GitLab API error when retrieving file {file_path}: {str(e)}")
        except UnicodeDecodeError as e:
            logger.error(f"Error decoding content for file {file_path}: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error retrieving file content for {file_path}: {str(e)}")
            logger.debug("Full error details:", exc_info=True)
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
                project, mr = self.get_mr_details(gl, project_id, mr_iid)
                changed_files = self.get_changed_files(project, mr)

                if len(changed_files) <= 10:
                    all_file_contents = self.prepare_file_contents(changed_files)
                else:
                    all_file_contents = ""
                security_analysis = await self.analyze_all_files(changed_files, all_file_contents)

                self.log_analysis_results(changed_files, security_analysis)

                if add_comments:
                    self.add_comments_to_mr(mr, security_analysis)

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
    def prepare_file_contents(changed_files: List[Dict]) -> str:
        all_contents = ""
        for file in changed_files:
            all_contents += f"File: {file['new_path'] or file['old_path']}\n"
            all_contents += f"Diff:\n{file['diff']}\n"
            if not file.get('deleted_file') and file['new_content']:
                all_contents += f"Full updated content:\n{file['new_content']}\n"
            all_contents += "---\n"
        return all_contents

    @staticmethod
    async def analyze_all_files(changed_files: List[Dict], all_file_contents: str) -> Dict:
        if len(changed_files) > 10:
            logger.warning(f"MR involves more than 10 files ({len(changed_files)} files). Skipping analysis.")
            return {"risks": []}

        # 估算 TOKEN 数量（这里使用一个简单的估算方法，实际上可能需要更精确的计算）
        estimated_tokens = len(all_file_contents.split())
        
        if estimated_tokens > 64000:  # 使用 64000 作为阈值，留有一些余量
            logger.warning(f"Content exceeds 64K tokens (estimated {estimated_tokens} tokens). Skipping LLM analysis.")
            return {"risks": []}  # 返回空的风险列表
        
        return await analyze_code_security(all_file_contents)

    @staticmethod
    def log_analysis_results(changed_files: List[Dict], security_analysis: Dict):
        file_count = len(changed_files)
        logger.info(f"Analyzed changes in {file_count} files:")
        for file in changed_files:
            status = "modified"
            if file.get('new_file'):
                status = "added"
            elif file.get('deleted_file'):
                status = "deleted"
            logger.info(f"- {file['new_path'] or file['old_path']} ({status})")

        if not security_analysis or 'risks' not in security_analysis:
            logger.info("No security risks identified.")
        else:
            risk_count = len(security_analysis['risks'])
            logger.info(f"Found {risk_count} potential security risks:")
            for risk in security_analysis['risks']:
                logger.info(f"- {risk.get('description', 'N/A')} ({risk.get('standard_id', 'N/A')})")

    @staticmethod
    def add_comments_to_mr(mr, security_analysis: Dict):
        if not security_analysis or 'risks' not in security_analysis:
            comment = "No security risks identified."
        else:
            comment = "Security Analysis Results:\n\n"
            for risk in security_analysis['risks']:
                comment += f"Risk: {risk.get('description', 'N/A')}\n"
                comment += f"Location: {risk.get('location', 'N/A')}\n"
                comment += f"Suggestion: {risk.get('suggestion', 'N/A')}\n"
                comment += f"Standard ID: {risk.get('standard_id', 'N/A')}\n\n"
        
        MRProcessor.add_comment_to_mr(mr, comment)

    @staticmethod
    async def analyze_mr_cli(gitlab_url, token, project_id, mr_iid):
        logger.debug("Analyzing MR from CLI for project %s, MR IID %s", project_id, mr_iid)
        try:
            gl = MRProcessor.get_gitlab_client(gitlab_url, token)
            project, mr = MRProcessor.get_mr_details(gl, project_id, mr_iid)
            changed_files = MRProcessor.get_changed_files(project, mr)

            if len(changed_files) <= 10:
                all_file_contents = MRProcessor.prepare_file_contents(changed_files)
            else:
                all_file_contents = ""
            security_analysis = await MRProcessor.analyze_all_files(changed_files, all_file_contents)

            MRProcessor.log_analysis_results(changed_files, security_analysis)
            
            logger.info("Security Analysis Results:")
            if not security_analysis or 'risks' not in security_analysis:
                logger.info("No security risks identified.")
            else:
                for risk in security_analysis['risks']:
                    logger.info(f"Risk: {risk.get('description', 'N/A')}")
                    logger.info(f"Location: {risk.get('location', 'N/A')}")
                    logger.info(f"evidence: {risk.get('evidence', 'N/A')}")
                    logger.info(f"Suggestion: {risk.get('suggestion', 'N/A')}")
                    logger.info(f"Standard ID: {risk.get('standard_id', 'N/A')}")
            return security_analysis

        except gitlab.exceptions.GitlabAuthenticationError:
            logger.error("Authentication failed. Please check your GitLab token.")
            raise
        except Exception as e:
            logger.error("An unexpected error occurred: %s", str(e))
            logger.debug("Full error details:", exc_info=True)
            raise