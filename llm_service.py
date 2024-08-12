# llm_service.py

import os
import json
import logging
import openai
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

CWE_TOP_25 = [
    "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78", "CWE-20", "CWE-125", "CWE-22", "CWE-352", "CWE-434",
    "CWE-862", "CWE-476", "CWE-287", "CWE-190", "CWE-502", "CWE-77", "CWE-119", "CWE-798", "CWE-918", "CWE-306",
    "CWE-362", "CWE-269", "CWE-94", "CWE-863", "CWE-276"
]

async def call_llm(messages):
    try:
        client = openai.AsyncOpenAI(
            api_key=os.environ["OPENAI_API_KEY"],
            base_url=os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
        )
        response = await client.chat.completions.create(
            model="claude-3-5-sonnet",
            messages=messages
        )
        print("->:", response.choices[0].message.content)
        return response.choices[0].message.content.strip()
    except KeyError as e:
        logger.error(f"Environment variable not set: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Exception in call_llm: {str(e)}")
        return None

def parse_json(response):
    if response is None:
        logger.error("Cannot parse None response")
        return None
    try:
        # 首先尝试查找 ```json 格式
        json_start = response.find("```json")
        if json_start != -1:
            json_end = response.find("}\n```", json_start + 7)
            if json_end != -1:
                json_str = response[json_start + 7:json_end+1].strip()
            else:
                json_str = response[json_start + 7:].strip()
        else:
            # 如果没有找到 ```json 格式，则尝试查找普通的 JSON 对象
            json_start = response.find("{")
            json_end = response.rfind("}")
            if json_start != -1 and json_end != -1:
                json_str = response[json_start:json_end + 1]
            else:
                logger.error("No valid JSON found in the response")
                return None

        return json.loads(json_str, strict=False)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Exception in parse_json: {str(e)}")
        return None

async def identify_new_risks(all_file_contents: str):
    """
    分析代码变更，识别新的风险问题。
    """
    prompt = f"""分析以下代码变更,并识别出由这个特定合并请求直接引入或加剧的最多2个最显著且有充分证据的风险:

{all_file_contents}

指示:
1. 仅检查差异中添加、修改或删除的代码。
2. 识别直接由这些变更导致的风险,例如:
   - 新的或修改的代码引入的安全漏洞
   - 变更导致的潜在错误或逻辑错误
   - 对现有功能的意外副作用
   - 修改创建的新边缘情况或错误场景
   - 与变更直接相关的性能风险
   - 由于变更导致的向后兼容性或API契约的破坏
3. 对于每个识别的风险(最多2个),请提供:
   a. 风险的简洁描述,明确链接到具体的变更
   b. 引入风险的确切文件和相关代码部分,不要使用行号。引用引入风险的具体代码。
   c. 详细解释这个变更如何创建或增加风险,包括:
      - 来自代码的强有力证据,包括引用的具体代码片段
      - 对这个风险潜在后果的解释
      - 这个风险如何与常见的安全漏洞或最佳实践相关
      - 来自代码库其余部分的任何相关上下文,这些上下文会导致这个风险
   d. 建议的修复或缓解策略
   e. 这个风险违反或涉及的最相关的安全标准或规则。这可以来自任何公认的安全标准(例如CWE, OWASP, CERT, SANS, ISO, NIST),行业最佳实践,或者如果没有适用的标准,可以是自定义规则。简要解释为什么这个标准或规则是相关的。

关键指南:
- 只报告在这个合并请求之前不存在的风险。
- 不要包括未更改部分代码中的预先存在的风险。
- 如果变更修改了现有的有风险代码,只有在显著增加风险或引入新风险时才报告。
- 专注于变更的直接影响,而不是假设的或不相关的风险。
- 优先考虑有最强有力证据和最高影响的风险。
- 即使发现更多,也最多包括2个风险。如果只能确定地识别出0个或1个风险,那也是可以接受的。

请将你的回答格式化为一个JSON对象,并用markdown代码块包装:
```json
{{
    "risks": [
        {{
            "description": "简洁的风险描述",
            "location": "文件名和相关代码部分(引用)",
            "evidence": "详细解释,包括来自代码的强有力证据,包括引用的代码片段,潜在后果,与安全最佳实践的关系,以及相关上下文",
            "suggestion": "建议的修复或缓解措施",
            "standard_id": "相关的安全标准或规则ID",
            "standard_explanation": "简要解释为什么这个标准或规则是相关的"
        }},
        ...
    ]
}}
```
如果没有识别出显著风险或者没有任何风险的强有力证据,请为"risks"返回一个空列表。"""

    messages = [{"role": "user", "content": prompt}]
    response = await call_llm(messages)
    parsed_response = parse_json(response)
    return parsed_response.get('risks', []) if parsed_response else []

async def check_fixed_risks(all_file_contents: str, previous_risks: List[Dict]):
    fixed_risks = []
    for risk in previous_risks:
        if risk['status'] == 'open':  # 只检查未修复的风险
            prompt = f"""分析以下代码变更，并评估以下特定风险是否已被修复：

代码变更：
{all_file_contents}

需要评估的风险：
{json.dumps(risk, indent=2)}

指示:
1. 仅检查差异中添加、修改或删除的代码。
2. 评估这个特定的风险是否已被修复。
3. 如果风险已被修复，请提供详细解释。

请将你的回答格式化为一个JSON对象,并用markdown代码块包装:
```json
{{
    "is_fixed": true/false,
    "evidence": "解释为什么这个风险被认为已修复或仍然存在"
}}
```
"""

            messages = [{"role": "user", "content": prompt}]
            response = await call_llm(messages)
            parsed_response = parse_json(response)
            
            if parsed_response and parsed_response.get('is_fixed'):
                risk['status'] = 'fixed'
                risk['fix_evidence'] = parsed_response['evidence']
                fixed_risks.append(risk)

    return fixed_risks

async def compare_risks(new_risks: List[Dict], previous_risks: List[Dict]):
    """
    比较每个新识别的风险与之前的所有风险，判断是否有重复。
    """
    risk_comparison = []
    for new_risk in new_risks:
        prompt = f"""比较以下新识别的风险与之前的所有风险，判断新风险是否与任何之前的风险相同或非常相似：

新识别的风险：
{json.dumps(new_risk, indent=2)}

之前识别的风险：
{json.dumps(previous_risks, indent=2)}

指示:
1. 判断这个新风险是否与任何之前的风险相同或非常相似。
2. 如果发现相同或非常相似的风险，请解释原因。

请将你的回答格式化为一个JSON对象,并用markdown代码块包装:
```json
{{
    "new_risk": "新风险的描述",
    "is_duplicate": true/false,
    "similar_to": "相似的旧风险描述（如果存在）",
    "explanation": "解释为什么这个风险被认为是相同或不同的"
}}
```
"""

        messages = [{"role": "user", "content": prompt}]
        response = await call_llm(messages)
        parsed_response = parse_json(response)
        
        if parsed_response and not parsed_response.get("is_duplicate", False):
            risk_comparison.append(new_risk)
        else:
            logger.info(f"判断为重复风险问题：{new_risk['description']}")

    return risk_comparison

async def analyze_comment_context(comment_context: Dict[str, Any]) -> str:
    """ 
    Analyze the comment context and generate a smart reply.

    Args:
    comment_context (Dict[str, Any]): The context of the comment, including changed files and previous comments.

    Returns:
        str: The generated smart reply.
    """
    platform = comment_context['platform']
    changed_files = comment_context['changed_files']
    comments = comment_context['comments']
    current_comment = comment_context['current_comment']

    # Prepare the context for the LLM
    context = f"Platform: {platform}\n\n"
    context += "Changed files:\n"
    for file in changed_files:
        context += f"File: {file['new_path'] or file['old_path']}\n"
        context += f"Diff:\n{file['diff']}\n"
        if not file.get('new_file') and not file.get('deleted_file') and file.get('new_content'):
            context += f"Full updated content:\n{file['new_content']}\n"
        context += "---\n"

    context += "Relevant comments in the thread:\n"
    for comment in comments:
        if platform == "gitlab":
            author = comment.get('author', {}).get('name') or comment.get('author', {}).get('username') or "Unknown"
            body = comment.get('body') or comment.get('note', '')
        elif platform == "github":
            author = comment.user.login if hasattr(comment, 'user') else "Unknown"
            body = comment.body if hasattr(comment, 'body') else ''
        else:
            author = "Unknown"
            body = str(comment)

        context += f"- {author}: {body}\n"

    context += f"\nCurrent comment: {current_comment}\n"

    prompt = f"""作为一个代码审查助手，你需要根据以下上下文生成一个智能回复：
{context}

请遵循以下指南：
1. 分析变更的代码和之前的评论。
2. 理解当前评论的内容和意图。
3. 提供一个有见地、有帮助的回复，可能包括：
    * 对代码变更的技术见解
    * 对之前评论的回应
    * 对当前评论提出的问题的解答
    * 如果适用，提供改进代码的建议
4. 保持专业和友好的语气。
5. 如果需要更多信息来做出准确的回应，可以礼貌地请求。

请直接给出回复内容，不需要任何额外的格式或前缀。"""
    messages = [{"role": "user", "content": prompt}]
    response = await call_llm(messages)
    return response