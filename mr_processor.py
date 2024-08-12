# mr_processor.py

import logging
import base64
import os
import json
from typing import Dict, Any, List
import gitlab
import github
from llm_service import check_fixed_risks, compare_risks, identify_new_risks

# 设置日志级别
log_level = logging.DEBUG if os.environ.get('DEBUG', 'false').lower() == 'true' else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MRProcessor:
    def __init__(self, config):
        self.config = config
        self.risks_cache = {}
        self.db_file = 'db.json'
        self._load_risks_from_file()
        logger.debug("MRProcessor initialized with config: %s", config)

    def _load_risks_from_file(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                self.risks_cache = json.load(f)
        else:
            self.risks_cache = {}

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
            latest_commit_sha = commits[0].id

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

    async def add_comment_to_mr(self, mr, comment):
        try:
            discussion = mr.discussions.create({'body': comment})
            logger.info(f"Discussion created in GitLab MR. MR IID: {mr.iid}")
            return discussion
        except Exception as e:
            logger.error(f"Error adding comment to GitLab MR: {str(e)}")
            raise  # 重新抛出异常，而不是返回 None


    async def add_comment_to_pr(self, pr, comment):
        """
        在 GitHub 拉取请求中添加评论。

        :param pr: GitHub 拉取请求对象
        :param comment: 要添加的评论内容
        :return: 添加的评论对象
        """
        try:
            # 使用 GitHub API 添加评论
            new_comment = pr.create_issue_comment(comment)
            logger.info(f"Comment added to GitHub PR. PR Number: {pr.number}")
            return new_comment
        except Exception as e:
            logger.error(f"Error adding comment to GitHub PR: {str(e)}")
            raise  # 重新抛出异常，而不是返回 None

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

            await self.analyze_and_comment(changed_files, mr, "gitlab", add_comments)

            logger.info("GitLab MR %s event processed successfully", mr_action)
        else:
            logger.info("GitLab MR %s event doesn't require security analysis", mr_action)

    async def process_github_pr(self, body, headers, add_comments):
        pr_action = body.get("action")
        
        if self.need_security_analysis(pr_action, body, "github"):
            github_token = headers.get("x-github-token")
            repo_name = body["repository"]["full_name"]
            pr_number = body["pull_request"]["number"]

            gh = self.get_github_client(github_token)
            repo, pr = self.get_pr_details(gh, repo_name, pr_number)
            changed_files = self.get_changed_files_github(pr)

            await self.analyze_and_comment(changed_files, pr, "github", add_comments)

            logger.info("GitHub PR %s event processed successfully", pr_action)
        else:
            logger.info("GitHub PR %s event doesn't require security analysis", pr_action)

    async def analyze_and_comment(self, changed_files: List[Dict], mr_or_pr, platform: str, add_comments: bool):
        if len(changed_files) > 10:
            logger.warning(f"MR/PR involves more than 10 files ({len(changed_files)} files). Skipping analysis.")
            return

        all_file_contents = self.prepare_file_contents(changed_files)
        
        # 估算 TOKEN 数量（这里使用一个简单的估算方法，实际上可能需要更精确的计算）
        estimated_tokens = len(all_file_contents.split())
        
        if estimated_tokens > 64000:  # 使用 64000 作为阈值，留有一些余量
            logger.warning(f"Content exceeds 64K tokens (estimated {estimated_tokens} tokens). Skipping LLM analysis.")
            return

        # 获取之前的风险分析结果
        previous_risks = await self.get_previous_risks(mr_or_pr)

        # 步骤1：识别新的风险
        new_risks = await identify_new_risks(all_file_contents)

        # 步骤2：检查之前的风险是否被修复
        previous_unfixed_risks = [risk for risk in previous_risks if risk.get("status", "") != "fix"]
        fixed_risks = await check_fixed_risks(all_file_contents, previous_unfixed_risks)

        # 步骤3：比较新风险与之前的风险
        risk_comparison = await compare_risks(new_risks, previous_risks)

        # 处理比较结果
        unique_new_risks = []
        for risk in risk_comparison:
            risk["status"] = "open"
            risk['comment_id'] = ""
            risk['discussion_id'] = ""
            unique_new_risks.append(risk)
        
        for risk in fixed_risks:
            risk["status"] = "fix"

        self.log_analysis_results(changed_files, unique_new_risks, fixed_risks)

        if add_comments:
            await self.add_comments_to_mr(mr_or_pr, unique_new_risks, fixed_risks, platform)

        # 更新存储的风险
        await self.save_risks(mr_or_pr, unique_new_risks, fixed_risks)

    async def add_comments_to_mr(self, item, new_risks: List[Dict], fixed_risks: List[Dict], platform: str):
        for risk in new_risks:
            comment = self.format_risk_comment(risk, "New Risk Identified")
            comment_id, discussion_id = await self.add_comment(item, comment, platform)
            risk['comment_id'] = comment_id
            risk['discussion_id'] = discussion_id
            logger.info(f"Risk: {risk.get('description', 'N/A')}")
            logger.info(f"comment id: {comment_id} discussion id: {discussion_id}")

        for risk in fixed_risks:
            if 'comment_id' in risk and 'discussion_id' in risk:
                reply = f"The following risk has been resolved:\n\n{risk['description']}\n\nEvidence: {risk['fix_evidence']}"
                await self.add_reply(item, reply, risk['comment_id'], risk['discussion_id'], platform)


    async def add_reply(self, item, reply, comment_id, discussion_id, platform):
        if platform == "gitlab":
            await self.add_reply_to_mr(item, reply, comment_id, discussion_id)
        elif platform == "github":
            await self.add_reply_to_pr(item, reply, comment_id)

    async def add_reply_to_mr(self, mr, reply, comment_id, discussion_id):
        """
        在 GitLab 合并请求中回复特定的评论。
        
        :param mr: GitLab 合并请求对象
        :param reply: 回复内容
        :param comment_id: 要回复的评论 ID
        :param discussion_id: 讨论 ID
        """
        try:
            # 获取特定的讨论
            discussion = mr.discussions.get(discussion_id)
            
            # 在讨论中添加新的回复
            new_note = discussion.notes.create({
                'body': reply,
                'in_reply_to_id': comment_id
            })
            
            logger.info(f"Reply added to GitLab MR comment. MR IID: {mr.iid}, Discussion ID: {discussion_id}, Comment ID: {comment_id}")
            return new_note
        except Exception as e:
            logger.error(f"Error adding reply to GitLab MR comment: {str(e)}")
            raise

    async def add_reply_to_pr(self, pr, reply, comment_id):
        """
        在 GitHub 拉取请求中回复特定的评论。
        
        :param pr: GitHub 拉取请求对象
        :param reply: 回复内容
        :param comment_id: 要回复的评论 ID
        """
        try:
            # 获取原始评论
            original_comment = pr.get_issue_comment(comment_id)
            
            # 创建新的回复
            new_comment = pr.create_issue_comment(f"In reply to [{comment_id}](#{comment_id}):\n\n{reply}")
            
            logger.info(f"Reply added to GitHub PR comment. PR Number: {pr.number}, Original Comment ID: {comment_id}")
            return new_comment
        except Exception as e:
            logger.error(f"Error adding reply to GitHub PR comment: {str(e)}")
            raise

    async def get_previous_risks(self, mr_or_pr):
        # 为 GitLab 和 GitHub 创建唯一的键
        if hasattr(mr_or_pr, 'project_id'):  # GitLab
            key = f"gitlab:{mr_or_pr.project_id}:{mr_or_pr.iid}"
        else:  # GitHub
            key = f"github:{mr_or_pr.base.repo.full_name}:{mr_or_pr.number}"
        
        return self.risks_cache.get(key, [])

    async def save_risks(self, mr_or_pr, risks, fixed_risks):
        # 为 GitLab 和 GitHub 创建唯一的键
        if hasattr(mr_or_pr, 'project_id'):  # GitLab
            key = f"gitlab:{mr_or_pr.project_id}:{mr_or_pr.iid}"
        else:  # GitHub
            key = f"github:{mr_or_pr.base.repo.full_name}:{mr_or_pr.number}"
        
        existing_risks = self.risks_cache.get(key, [])
        for existing_risk in existing_risks:
            if existing_risk['status'] == 'open':
                for risk in fixed_risks:
                    if risk['description'] == existing_risk['description']:
                        existing_risk['status'] = risk['status']
                        break

        existing_risks += risks
        self.risks_cache[key] = existing_risks
    
        with open(self.db_file, 'w') as f:
            json.dump(self.risks_cache, f)

    def format_risk_comment(self, risk, title):
        comment = f"# {title}: {risk.get('description', 'N/A')}\n\n"
        comment += f"**Location:** {risk.get('location', 'N/A')}\n\n"
        comment += f"**Evidence:**\n```\n{risk.get('evidence', 'N/A')}\n```\n\n"
        comment += f"**Suggestion:**\n```\n{risk.get('suggestion', 'N/A')}\n```\n\n"
        comment += f"**Standard ID:** {risk.get('standard_id', 'N/A')}\n"
        return comment

    async def add_comment(self, item, comment, platform):
        try:
            if platform == "gitlab":
                discussion = await self.add_comment_to_mr(item, comment)
                return discussion.attributes['notes'][0]['id'], discussion.id
            elif platform == "github":
                response = await self.add_comment_to_pr(item, comment)
                return response.id, None  # GitHub doesn't have a direct equivalent to discussion_id
            else:
                raise ValueError(f"Unsupported platform: {platform}")
        except Exception as e:
            logger.error(f"Error adding comment on {platform}: {str(e)}")
            raise  # 重新抛出异常


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
        
        return await identify_new_risks(all_file_contents)

    @staticmethod
    def log_analysis_results(changed_files: List[Dict], new_risks: List[Dict], fixed_risks: List[Dict]):
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
        if not new_risks and not fixed_risks:
            logger.info("No new security risks identified and no existing risks fixed.")
        else:
            if new_risks:
                logger.info(f"Found {len(new_risks)} new potential security risks:")
                for risk in new_risks:
                    logger.info(f"New Risk: {risk.get('description', 'N/A')}")
                    logger.info(f"Location: {risk.get('location', 'N/A')}")
                    logger.info(f"Evidence: {risk.get('evidence', 'N/A')}")
                    logger.info(f"Suggestion: {risk.get('suggestion', 'N/A')}")
                    logger.info(f"Standard ID: {risk.get('standard_id', 'N/A')}")
                    logger.info(f"Standard Explanation: {risk.get('standard_explanation', 'N/A')}")
                    logger.info("---")

            if fixed_risks:
                logger.info(f"{len(fixed_risks)} existing risks have been fixed:")
                for risk in fixed_risks:
                    logger.info(f"Fixed Risk: {risk.get('description', 'N/A')}")
                    logger.info(f"Evidence of Fix: {risk.get('evidence', 'N/A')}")
                    logger.info("---")


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

            MRProcessor.log_analysis_results(changed_files, security_analysis, [])
            
            return security_analysis

        except Exception as e:
            logger.error("An unexpected error occurred: %s", str(e))
            logger.debug("Full error details:", exc_info=True)
            return {"risks": []}  # 返回一个空的风险列表，而不是 None

    @staticmethod
    def get_comment_context(body: Dict[str, Any], platform: str) -> Dict[str, Any]:
        """
        Retrieve the context for the comment, including MR/PR details and previous comments.
        This method is added to support comment processing functionality.
        """
        if platform == "gitlab":
            project_id = body['project']['id']
            mr_iid = body['merge_request']['iid']
            gitlab_url = body['project']['web_url'].rsplit('/', 2)[0]
            gitlab_token = body['project']['ci_config_path']  # 假设token存储在这个字段，实际使用时可能需要调整
            
            gl = MRProcessor.get_gitlab_client(gitlab_url, gitlab_token)
            project, mr = MRProcessor.get_mr_details(gl, project_id, mr_iid)
            changed_files = MRProcessor.get_changed_files_gitlab(project, mr)
            
            # Fetch previous comments
            comments = mr.notes.list()
            
        elif platform == "github":
            repo_name = body['repository']['full_name']
            pr_number = body['issue']['number']
            github_token = body['installation']['id']  # 假设token存储在这个字段，实际使用时可能需要调整
            
            gh = MRProcessor.get_github_client(github_token)
            repo, pr = MRProcessor.get_pr_details(gh, repo_name, pr_number)
            changed_files = MRProcessor.get_changed_files_github(pr)
            
            # Fetch previous comments
            comments = pr.get_issue_comments()
        else:
            raise ValueError(f"Unsupported platform: {platform}")
        
        return {
            "platform": platform,
            "changed_files": changed_files,
            "comments": comments,
            "current_comment": body.get('object_attributes', {}).get('note') if platform == "gitlab" else body.get('comment', {}).get('body')
        }

            