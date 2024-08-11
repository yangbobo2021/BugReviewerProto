# cli.py

import asyncio
import argparse
import logging
from urllib.parse import urlparse, unquote
from mr_processor import MRProcessor

# 设置日志级别
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_url(url):
    logger.debug("Parsing URL: %s", url)
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    path_parts = parsed_url.path.strip('/').split('/')
    if 'github.com' in parsed_url.netloc:
        if len(path_parts) < 4 or path_parts[-2] != 'pull':
            raise ValueError("Invalid GitHub PR URL")
        project_id = '/'.join(path_parts[:-2])
        pr_number = int(path_parts[-1])
        platform = "github"
    elif len(path_parts) < 4 or path_parts[-2] != 'merge_requests':
        raise ValueError("Invalid GitLab MR URL")
    else:
        project_id_parts = path_parts[:-2]
        if project_id_parts[-1] == '-':
            project_id_parts = project_id_parts[:-1]
        project_id = '/'.join(project_id_parts)
        pr_number = int(path_parts[-1])
        platform = "gitlab"
    
    project_id = unquote(project_id)
    
    logger.debug("Parsed URL - Base URL: %s, Project ID: %s, PR/MR Number: %s, Platform: %s", base_url, project_id, pr_number, platform)
    return base_url, project_id, pr_number, platform

async def main():
    parser = argparse.ArgumentParser(description="Analyze MR/PR for security risks")
    parser.add_argument("--url", required=True, help="GitLab MR or GitHub PR URL")
    parser.add_argument("--token", required=True, help="GitLab/GitHub access token")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")

    try:
        base_url, project_id, pr_number, platform = parse_url(args.url)
        logger.info(f"Analyzing {platform.upper()} {pr_number} for project {project_id}")
        
        result = await MRProcessor.analyze_mr_cli(base_url, args.token, project_id, pr_number, platform)
        
        if result and 'risks' in result:
            if len(result['risks']) == 0:
                logger.info("No security risks identified.")
            else:
                logger.info(f"Found {len(result['risks'])} potential security risks:")
                for risk in result['risks']:
                    logger.info(f"- Description: {risk.get('description', 'N/A')}")
                    logger.info(f"  Location: {risk.get('location', 'N/A')}")
                    logger.info(f"  Evidence: {risk.get('evidence', 'N/A')}")
                    logger.info(f"  Suggestion: {risk.get('suggestion', 'N/A')}")
                    logger.info(f"  Standard ID: {risk.get('standard_id', 'N/A')}")
                    logger.info("---")
        else:
            logger.warning("Unexpected result format. Unable to process security risks.")
        
    except ValueError as e:
        logger.error("Error: %s", str(e))
    except Exception as e:
        logger.error("An unexpected error occurred: %s", str(e))
        if args.debug:
            logger.exception("Detailed error information:")

if __name__ == "__main__":
    asyncio.run(main())