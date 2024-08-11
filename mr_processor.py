# mr_processor.py

import logging
import base64
import os
from typing import Dict, Any, List
import gitlab
import github
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
    def get_github_client(token):
        logger.debug("Creating GitHub client")
        try:
            return github.Github(token)
        except Exception as e:
            logger.error("Failed to create GitHub client: %s", str(e))
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
    def get_pr_details(gh, repo_full_name, pr_number):
        logger.debug("Fetching PR details for repo %s, PR number %s", repo_full_name, pr_number)
        try:
            repo = gh.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            return repo, pr
        except github.GithubException as e:
            logger.error("Failed to get PR details: %s", str(e))
            raise

    @staticmethod
    def get_changed_files_gitlab(project, mr):
        logger.debug("Fetching changed files for GitLab MR %s", mr.iid)
        try:
            changes = mr.changes()
            return [
                {
                    'old_path': change['old_path'],
                    'new_path': change['new_path'],
                    'diff': change['diff'],
                    'new_file': change.get('new_file', False),
                    'deleted_file': change.get('deleted_file', False),
                    'new_content': MRProcessor.get_file_content_gitlab(project, mr, change['new_path']) if not change.get('deleted_file') else None
                }
                for change in changes['changes'][:10+1]
            ]
        except Exception as e:
            logger.error("Failed to get changed files for GitLab: %s", str(e))
            logger.debug("Full error details:", exc_info=True)
            return []

    @staticmethod
    def get_changed_files_github(pr):
        logger.debug("Fetching changed files for GitHub PR %s", pr.number)
        try:
            return [
                {
                    'old_path': file.previous_filename or file.filename,
                    'new_path': file.filename,
                    'diff': file.patch,
                    'new_file': file.status == 'added',
                    'deleted_file': file.status == 'removed',
                    'new_content': MRProcessor.get_file_content_github(pr, file.filename) if file.status != 'removed' else None
                }
                for file in pr.get_files()[:10+1]
            ]
        except Exception as e:
            logger.error("Failed to get changed files for GitHub: %s", str(e))
            logger.debug("Full error details:", exc_info=True)
            return []

    @staticmethod
    def get_file_content_gitlab(project, mr, file_path):
        logger.debug(f"Fetching content for file: {file_path} from GitLab MR: {mr.iid}")
        try:
            commits = list(mr.commits())
            if not commits:
                logger.error(f"No commits found for MR: {mr.iid}")
                return None
            latest_commit_sha = commits[-1].id

            file_content = project.files.get(file_path=file_path, ref=latest_commit_sha)
            if file_content is None:
                logger.error(f"File not found in commit {latest_commit_sha}: {file_path}")
                return None

            content = base64.b64decode(file_content.content).decode('utf-8')
            logger.debug(f"Successfully retrieved content for file: {file_path} (length: {len(content)} characters)")
            return content
        except Exception as e:
            logger.error(f"Error retrieving file content for {file_path}: {str(e)}")
            logger.debug("Full error details:", exc_info=True)
        return None

    @staticmethod
    def get_file_content_github(pr, file_path):
        logger.debug(f"Fetching content for file: {file_path} from GitHub PR: {pr.number}")
        try:
            # 获取PR的头部分支
            head_sha = pr.head.sha
            
            # 从PR的基础仓库获取文件内容
            file_content = pr.base.repo.get_contents(file_path, ref=head_sha)
            
            if file_content is None:
                logger.error(f"File not found: {file_path}")
                return None

            content = file_content.decoded_content.decode('utf-8')
            logger.debug(f"Successfully retrieved content for file: {file_path} (length: {len(content)} characters)")
            return content
        except github.GithubException as e:
            if e.status == 404:
                logger.error(f"File not found: {file_path}")
            else:
                logger.error(f"Error retrieving file content for {file_path}: {str(e)}")
            logger.debug("Full error details:", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error retrieving file content for {file_path}: {str(e)}")
            logger.debug("Full error details:", exc_info=True)
        return None

    @staticmethod
    def add_comment_to_mr(mr, comment):
        logger.debug("Adding comment to GitLab MR %s", mr.iid)
        try:
            mr.notes.create({'body': comment})
        except Exception as e:
            logger.error("Failed to add comment to GitLab MR: %s", str(e))
            raise

    @staticmethod
    def add_comment_to_pr(pr, comment):
        logger.debug("Adding comment to GitHub PR %s", pr.number)
        try:
            pr.create_issue_comment(comment)
        except Exception as e:
            logger.error("Failed to add comment to GitHub PR: %s", str(e))
            raise

    async def process_merge_request(self, body: Dict[str, Any], headers: Dict[str, str], platform: str, add_comments=True):
        logger.debug("Processing %s with action: %s", "MR" if platform == "gitlab" else "PR", body.get("object_attributes", {}).get("action") or body.get("action"))
        try:
            if platform == "gitlab":
                await self.process_gitlab_mr(body, headers, add_comments)
            elif platform == "github":
                await self.process_github_pr(body, headers, add_comments)
            else:
                raise ValueError(f"Unsupported platform: {platform}")
        except Exception as e:
            logger.error("Error processing %s: %s", "MR" if platform == "gitlab" else "PR", str(e))
            raise

    async def process_gitlab_mr(self, body, headers, add_comments):
        mr_action = body.get("object_attributes", {}).get("action")
        
        if self.need_security_analysis(mr_action, body, "gitlab"):
            gitlab_url = body["project"]["web_url"].rsplit('/', 2)[0]
            gitlab_token = headers["x-gitlab-token"]
            project_id = body["project"]["id"]
            mr_iid = body["object_attributes"]["iid"]

            gl = self.get_gitlab_client(gitlab_url, gitlab_token)
            project, mr = self.get_mr_details(gl, project_id, mr_iid)
            changed_files = self.get_changed_files_gitlab(project, mr)

            security_analysis = await self.analyze_files(changed_files)

            self.log_analysis_results(changed_files, security_analysis)

            if add_comments:
                self.add_comments_to_mr(mr, security_analysis, "gitlab")

            logger.info("GitLab MR %s event processed successfully", mr_action)
        else:
            logger.info("GitLab MR %s event doesn't require security analysis", mr_action)

    async def process_github_pr(self, body, headers, add_comments):
        pr_action = body.get("action")
        
        if self.need_security_analysis(pr_action, body, "github"):
            github_token = headers.get("x-github-token")  # GitHub可能使用不同的header
            repo_name = body["repository"]["full_name"]
            pr_number = body["pull_request"]["number"]

            gh = self.get_github_client(github_token)
            repo, pr = self.get_pr_details(gh, repo_name, pr_number)
            changed_files = self.get_changed_files_github(pr)

            security_analysis = await self.analyze_files(changed_files)

            self.log_analysis_results(changed_files, security_analysis)

            if add_comments:
                self.add_comments_to_mr(pr, security_analysis, "github")

            logger.info("GitHub PR %s event processed successfully", pr_action)
        else:
            logger.info("GitHub PR %s event doesn't require security analysis", pr_action)

    @staticmethod
    def need_security_analysis(action, body, platform):
        logger.debug("Checking if security analysis is needed for %s action: %s", platform, action)
        if platform == "gitlab":
            if action == "open":
                return True
            elif action == "update":
                oldrev = body.get("object_attributes", {}).get("oldrev")
                return oldrev is not None
        elif platform == "github":
            return action in ["opened", "synchronize"]
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
    async def analyze_files(changed_files: List[Dict]) -> Dict:
        if len(changed_files) > 10:
            logger.warning(f"MR/PR involves more than 10 files ({len(changed_files)} files). Skipping analysis.")
            return {"risks": []}

        all_file_contents = MRProcessor.prepare_file_contents(changed_files)
        
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

        logger.info("Security Analysis Results:")
        if not security_analysis or 'risks' not in security_analysis:
            logger.info("No security risks identified.")
        else:
            risk_count = len(security_analysis['risks'])
            logger.info(f"Found {risk_count} potential security risks:")
            for risk in security_analysis['risks']:
                logger.info(f"Risk: {risk.get('description', 'N/A')}")
                logger.info(f"Location: {risk.get('location', 'N/A')}")
                logger.info(f"Evidence: {risk.get('evidence', 'N/A')}")
                logger.info(f"Suggestion: {risk.get('suggestion', 'N/A')}")
                logger.info(f"Standard ID: {risk.get('standard_id', 'N/A')}")
                logger.info("---")

    @staticmethod
    def add_comments_to_mr(item, security_analysis: Dict, platform: str):
        if not security_analysis or 'risks' not in security_analysis:
            comment = "No security risks identified."
            if platform == "gitlab":
                MRProcessor.add_comment_to_mr(item, comment)
            elif platform == "github":
                MRProcessor.add_comment_to_pr(item, comment)
        else:
            for risk in security_analysis['risks']:
                comment = f"# Security Risk: {risk.get('description', 'N/A')}\n\n"
                comment += f"**Location:** {risk.get('location', 'N/A')}\n\n"
                comment += f"**Evidence:**\n```\n{risk.get('evidence', 'N/A')}\n```\n\n"
                comment += f"**Suggestion:**\n```\n{risk.get('suggestion', 'N/A')}\n```\n\n"
                comment += f"**Standard ID:** {risk.get('standard_id', 'N/A')}\n"

                if platform == "gitlab":
                    MRProcessor.add_comment_to_mr(item, comment)
                elif platform == "github":
                    MRProcessor.add_comment_to_pr(item, comment)


    @staticmethod
    async def analyze_mr_cli(base_url, token, project_id, mr_iid, platform):
        logger.debug("Analyzing %s from CLI for project %s, %s IID %s", "MR" if platform == "gitlab" else "PR", project_id, "MR" if platform == "gitlab" else "PR", mr_iid)
        try:
            if platform == "gitlab":
                gl = MRProcessor.get_gitlab_client(base_url, token)
                project, mr = MRProcessor.get_mr_details(gl, project_id, mr_iid)
                changed_files = MRProcessor.get_changed_files_gitlab(project, mr)
            elif platform == "github":
                gh = MRProcessor.get_github_client(token)
                repo, pr = MRProcessor.get_pr_details(gh, project_id, mr_iid)
                changed_files = MRProcessor.get_changed_files_github(pr)
            else:
                raise ValueError(f"Unsupported platform: {platform}")

            security_analysis = await MRProcessor.analyze_files(changed_files)

            MRProcessor.log_analysis_results(changed_files, security_analysis)
            
            return security_analysis

        except Exception as e:
            logger.error("An unexpected error occurred: %s", str(e))
            logger.debug("Full error details:", exc_info=True)
            