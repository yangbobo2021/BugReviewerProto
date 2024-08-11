# cli_test.py

import asyncio
import argparse
import logging
from gitlab import Gitlab
from github import Github
from mr_processor import MRProcessor
from cli import parse_url
import os
from datetime import datetime

def setup_logging(log_file):
    # 创建日志文件夹（如果不存在）
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # 配置根日志记录器
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # 移除所有现有的处理器
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # 创建文件处理器
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)

    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # 创建格式化器
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # 将处理器添加到根日志记录器
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

async def analyze_mr_pr(url, token):
    try:
        base_url, project_id, pr_number, platform = parse_url(url)
        result = await MRProcessor.analyze_mr_cli(base_url, token, project_id, pr_number, platform)
        
        if isinstance(result, dict) and 'risks' in result:
            if len(result['risks']) == 0:
                return True, "执行成功，没有发现问题"
            else:
                return True, "执行成功，发现问题"
        else:
            logging.warning(f"{platform.upper()} {pr_number}: 分析结果格式不符合预期，假定没有发现问题")
            return True, "执行成功，没有发现问题"
    except Exception as e:
        logging.error(f"分析{platform.upper()}时发生错误: {str(e)}")
        return False, str(e)

async def main(url, token, num_items):
    base_url, project_id, _, platform = parse_url(url)
    
    if platform == "gitlab":
        gl = Gitlab(base_url, private_token=token)
        project = gl.projects.get(project_id)
        items = project.mergerequests.list(state='merged', order_by='updated_at', sort='desc', per_page=num_items)
    else:  # GitHub
        gh = Github(token)
        repo = gh.get_repo(project_id)
        items = repo.get_pulls(state='closed', sort='updated', direction='desc')[:num_items]
    
    total_items = 0
    success_no_issue = 0
    success_with_issue = 0
    failed = 0
    
    for item in items:
        if total_items >= num_items:
            break
        
        total_items += 1
        if platform == "gitlab":
            current_url = item.web_url
            item_id = item.iid
        else:  # GitHub
            current_url = item.html_url
            item_id = item.number
        
        logging.info(f"正在分析 {platform.upper()} {item_id}: {current_url}")
        success, result = await analyze_mr_pr(current_url, token)
        
        if success:
            if "没有发现问题" in result:
                success_no_issue += 1
                logging.info(f"{platform.upper()} {item_id}: {result}")
            else:
                success_with_issue += 1
                logging.info(f"{platform.upper()} {item_id}: {result}")
        else:
            failed += 1
            logging.error(f"{platform.upper()} {item_id}: 执行失败，原因: {result}")
    
    logging.info(f"分析完成。总计分析 {total_items} 个{platform.upper()}:")
    logging.info(f"执行成功且没有发现问题: {success_no_issue}")
    logging.info(f"执行成功且发现问题: {success_with_issue}")
    logging.info(f"执行失败: {failed}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="批量分析GitLab MR或GitHub PR的安全风险")
    parser.add_argument("url", help="GitLab MR或GitHub PR URL，用于提取项目信息")
    parser.add_argument("token", help="GitLab或GitHub访问令牌")
    parser.add_argument("--num_items", type=int, default=100, help="要分析的MR/PR数量（默认为100）")
    parser.add_argument("--debug", action="store_true", help="启用调试模式")
    
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"logs/mr_pr_analysis_{timestamp}.log"

    logger = setup_logging(log_file)
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("调试模式已启用")

    logger.info(f"开始分析。URL: {args.url}, 分析数量: {args.num_items}")
    
    asyncio.run(main(args.url, args.token, args.num_items))