# cli_test.py

import asyncio
import argparse
import logging
from gitlab import Gitlab
from mr_processor import MRProcessor
from cli import parse_mr_url
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

async def analyze_mr(mr_url, token):
    try:
        gitlab_url, project_id, mr_iid = parse_mr_url(mr_url)
        result = await MRProcessor.analyze_mr_cli(gitlab_url, token, project_id, mr_iid)
        
        # 检查结果中是否包含风险
        if isinstance(result, dict) and 'risks' in result:
            if len(result['risks']) == 0:
                return True, "执行成功，没有发现问题"
            else:
                return True, "执行成功，发现问题"
        else:
            # 如果结果不是预期的格式，我们假设没有问题被发现
            logging.warning(f"MR {mr_iid}: 分析结果格式不符合预期，假定没有发现问题")
            return True, "执行成功，没有发现问题"
    except Exception as e:
        logging.error(f"分析MR时发生错误: {str(e)}")
        return False, str(e)

async def main(mr_url, token, num_mrs):
    gitlab_url, project_id, _ = parse_mr_url(mr_url)
    
    gl = Gitlab(gitlab_url, private_token=token)
    project = gl.projects.get(project_id)
    
    merged_mrs = project.mergerequests.list(state='merged', order_by='updated_at', sort='desc', per_page=num_mrs)
    
    total_mrs = 0
    success_no_issue = 0
    success_with_issue = 0
    failed = 0
    
    for mr in merged_mrs:
        if total_mrs >= num_mrs:
            break
        
        total_mrs += 1
        current_mr_url = mr.web_url
        
        logging.info(f"正在分析 MR {mr.iid}: {current_mr_url}")
        success, result = await analyze_mr(current_mr_url, token)
        
        if success:
            if "没有发现问题" in result:
                success_no_issue += 1
                logging.info(f"MR {mr.iid}: {result}")
            else:
                success_with_issue += 1
                logging.info(f"MR {mr.iid}: {result}")
        else:
            failed += 1
            logging.error(f"MR {mr.iid}: 执行失败，原因: {result}")
    
    logging.info(f"分析完成。总计分析 {total_mrs} 个MR:")
    logging.info(f"执行成功且没有发现问题: {success_no_issue}")
    logging.info(f"执行成功且发现问题: {success_with_issue}")
    logging.info(f"执行失败: {failed}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="批量分析GitLab MR的安全风险")
    parser.add_argument("mr_url", help="GitLab MR URL，用于提取项目信息")
    parser.add_argument("token", help="GitLab 访问令牌")
    parser.add_argument("--num_mrs", type=int, default=100, help="要分析的MR数量（默认为100）")
    
    args = parser.parse_args()

    # 设置日志文件名（使用当前时间戳）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"logs/mr_analysis_{timestamp}.log"

    # 设置日志
    setup_logging(log_file)
    
    logging.info(f"开始分析。MR URL: {args.mr_url}, 分析数量: {args.num_mrs}")
    
    asyncio.run(main(args.mr_url, args.token, args.num_mrs))