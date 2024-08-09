# cli.py

import asyncio
import argparse
import logging
from urllib.parse import urlparse, unquote
from mr_processor import MRProcessor

# 设置日志级别
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_mr_url(url):
    logger.debug("Parsing MR URL: %s", url)
    parsed_url = urlparse(url)
    gitlab_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    path_parts = parsed_url.path.strip('/').split('/')
    if len(path_parts) < 4 or path_parts[-2] != 'merge_requests':
        logger.error("Invalid GitLab MR URL: %s", url)
        raise ValueError("Invalid GitLab MR URL")
    
    # 修正：正确解析项目 ID，移除最后的 '-'
    project_id_parts = path_parts[:-2]
    if project_id_parts[-1] == '-':
        project_id_parts = project_id_parts[:-1]
    project_id = '/'.join(project_id_parts)
    project_id = unquote(project_id)  # URL 解码
    mr_iid = path_parts[-1]
    
    logger.debug("Parsed URL - GitLab URL: %s, Project ID: %s, MR IID: %s", gitlab_url, project_id, mr_iid)
    return gitlab_url, project_id, int(mr_iid)

async def main():
    parser = argparse.ArgumentParser(description="Analyze MR for security risks")
    parser.add_argument("--mr-url", required=True, help="GitLab Merge Request URL")
    parser.add_argument("--token", required=True, help="GitLab access token")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")

    try:
        gitlab_url, project_id, mr_iid = parse_mr_url(args.mr_url)
        await MRProcessor.analyze_mr_cli(gitlab_url, args.token, project_id, mr_iid)
    except ValueError as e:
        logger.error("Error: %s", str(e))
    except Exception as e:
        logger.error("An unexpected error occurred: %s", str(e))

if __name__ == "__main__":
    asyncio.run(main())