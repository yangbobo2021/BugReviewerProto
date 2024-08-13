# llm_service.py

import os
import json
import logging
import openai
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

KNOWLEDGE_BASE_DIR = "knowledge_bases"

CWE_TOP_25 = [
    "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78", "CWE-20", "CWE-125", "CWE-22", "CWE-352", "CWE-434",
    "CWE-862", "CWE-476", "CWE-287", "CWE-190", "CWE-502", "CWE-77", "CWE-119", "CWE-798", "CWE-918", "CWE-306",
    "CWE-362", "CWE-269", "CWE-94", "CWE-863", "CWE-276"
]

def get_knowledge_base_path(project_id):
    return os.path.join(KNOWLEDGE_BASE_DIR, f"{project_id}_knowledge_base.json")

def load_knowledge_base(project_id):
    path = get_knowledge_base_path(project_id)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {"rules": [], "exceptions": []}

def save_knowledge_base(project_id, knowledge_base):
    path = get_knowledge_base_path(project_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(knowledge_base, f, indent=2)


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

async def identify_new_risks(project_id: str, all_file_contents: str):
    """
    分析代码变更，识别新的风险问题。
    """
    knowledge_base = load_knowledge_base(project_id)
    
    prompt = f"""分析以下代码变更,并识别出由这个特定合并请求直接引入或加剧的最多2个最显著且有充分证据的风险:

{all_file_contents}

请考虑以下项目特定的知识库信息：
{json.dumps(knowledge_base, indent=2)}

指示:
1. 仔细阅读并应用知识库中的所有规则和例外情况。这些规则优先于通用的代码分析准则。
2. 仅检查差异中添加、修改或删除的代码。
3. 识别直接由这些变更导致的风险,例如:
   - 新的或修改的代码引入的安全漏洞
   - 变更导致的潜在错误或逻辑错误
   - 对现有功能的意外副作用
   - 修改创建的新边缘情况或错误场景
   - 与变更直接相关的性能风险
   - 由于变更导致的向后兼容性或API契约的破坏
4. 对于每个识别的风险(最多2个),请提供:
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
- 在识别风险时，请确保考虑知识库中的所有相关信息，包括任何特殊规则或例外情况。
- 识别风险时，如果传统规则与知识库中规则冲突，那么以知识库中规则为主。

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

async def check_fixed_risks(project_id: str, all_file_contents: str, previous_risks: List[Dict]):
    fixed_risks = []
    knowledge_base = load_knowledge_base(project_id)

    for risk in previous_risks:
        if risk['status'] == 'open':  # 只检查未修复的风险
            prompt = f"""分析以下代码变更，并评估以下特定风险是否已按照原始建议被修复：

当前代码变更：
{all_file_contents}

请特别注意并优先考虑以下项目特定的知识库信息：
{json.dumps(knowledge_base, indent=2)}

需要评估的风险：
{json.dumps(risk, indent=2)}

重要指示：
1. 严格聚焦于原始风险描述中提到的具体问题和建议的解决方案。
2. 检查代码是否已按照原始建议进行了修改。如果是，则应认为风险已修复。
3. 不要引入新的问题或考虑原始风险描述之外的潜在问题。
4. 如果代码修改基本符合建议的意图，即使实现细节可能略有不同，也应认为风险已修复。
5. 提供具体的代码证据来支持你的结论，引用相关的代码更改。
6. 知识库中的信息优先级高于一般的代码分析规则。

请将你的回答格式化为一个JSON对象,并用markdown代码块包装：
```json
{{
    "is_fixed": true/false,
    "evidence": "详细解释为什么这个特定风险被认为已修复或仍然存在，包括相关代码更改的引用，并说明修改是否符合原始建议"
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
    risk_duplicate = []

    # 为 previous_risks 中的每个风险添加带 ID 的新字段
    for i, risk in enumerate(previous_risks):
        risk['id_description'] = f"id-{i+1}: {risk['description']}"

    logger.info("==============>> previous_risks:")
    logger.info(json.dumps(previous_risks, indent=2))

    for new_risk in new_risks:
        prompt = f"""比较以下新识别的风险与之前的所有风险，判断新风险是否与任何之前的风险相同或非常相似：

新识别的风险：
{json.dumps(new_risk, indent=2)}

之前识别的风险：
{json.dumps(previous_risks, indent=2)}

指示:
1. 仅判断这个新风险是否与任何之前的风险触发的源码语句信息是完全一致的。
2. 关注风险的核心问题，但也关注问题的表述，确保工程师在两个表述上认为是同一个问题。
3. 如果发现相同的风险，请提供具体的相似之处。
4. 不要将泛化的原则或新引入的问题视为重复。
5. 如果发现相似的风险，请在 similar_to 字段中包含完整的 id_description。

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
            for risk in previous_risks:
                if risk["id_description"] == parsed_response.get("similar_to", ""):
                    risk_duplicate.append({
                        "old": risk,
                        "new": new_risk
                    })
            logger.info(f"判断为重复风险问题：{new_risk['description']}")

    return risk_comparison, risk_duplicate

async def analyze_comment_context(project_id: str, comment_context: Dict[str, Any]) -> str:
    """ 
    Analyze the comment context and generate a smart reply.

    Args:
    comment_context (Dict[str, Any]): The context of the comment, including changed files and previous comments.

    Returns:
        str: The generated smart reply.
    """
    knowledge_base = load_knowledge_base(project_id)

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

项目当前知识库：
    {json.dumps(knowledge_base, indent=2)}

请遵循以下指南：
1. 分析变更的代码和之前的评论。
2. 重点理解当前评论的内容和意图。
3. 提供一个有见地、有帮助的回复，可能包括：
    * 对当前评论提出的问题的解答
4. 保持专业和友好的语气。
5. 如果需要更多信息来做出准确的回应，可以礼貌地请求。

请直接给出回复内容，不需要任何额外的格式或前缀。"""
    messages = [{"role": "user", "content": prompt}]
    response = await call_llm(messages)
    return response

async def should_update_knowledge_base(project_id: str, comment_context: Dict[str, Any]) -> bool:
    knowledge_base = load_knowledge_base(project_id)
    
    prompt = f"""
    分析以下评论上下文，并判断是否需要更新项目的知识库：

    项目当前知识库：
    {json.dumps(knowledge_base, indent=2)}

    评论上下文：
    平台: {comment_context['platform']}
    变更文件:
    {json.dumps(comment_context['changed_files'], indent=2)}
    相关评论:
    {json.dumps(comment_context['comments'], indent=2)}
    当前评论: {comment_context['current_comment']}

    请判断：
    1. 这个评论及其上下文是否包含对现有知识的更正、补充或新的项目特定信息？
    2. 这些信息是否与识别代码风险相关，足以影响未来的风险分析？
    3. 这些信息是否足够重要，值得添加到知识库中？

    请返回一个JSON对象，格式如下：
    {{"should_update": true/false, "reason": "简要解释原因"}}
    """

    messages = [{"role": "user", "content": prompt}]
    response = await call_llm(messages)
    
    parsed_response = parse_json(response)
    if parsed_response and 'should_update' in parsed_response:
        should_update = parsed_response['should_update']
        reason = parsed_response.get('reason', 'No reason provided')
        logger.info(f"AI decision on updating knowledge base: {should_update}. Reason: {reason}")
        return should_update
    else:
        logger.warning(f"Unexpected response format from AI: {response}")
        return False

async def update_knowledge_base(project_id: str, comment_context: Dict[str, Any]):
    knowledge_base = load_knowledge_base(project_id)
    
    prompt = f"""
    根据以下评论上下文更新项目的知识库：

    当前知识库：
    {json.dumps(knowledge_base, indent=2)}

    评论上下文：
    平台: {comment_context['platform']}
    变更文件:
    {json.dumps(comment_context['changed_files'], indent=2)}
    相关评论:
    {json.dumps(comment_context['comments'], indent=2)}
    当前评论: {comment_context['current_comment']}

    请执行以下操作：
    1. 分析评论及其上下文，提取与代码风险分析相关的新信息或更正。
    2. 根据新信息，更新、删除或添加知识条目。
    3. 保持知识库简洁，只保留对识别风险问题有重要作用的知识，以及描述项目特点的信息。
    5. 返回更新后的知识库和一个描述知识库变化的自然语言摘要。

    请返回一个JSON对象，格式如下：
    {{
        "updated_knowledge_base": {{
            "knowledges": [
                "规则内容",
                ...
            ]
        }},
        "change_summary": "描述知识库变化的自然语言摘要，要反应具体的变更"
    }}
    """
    
    messages = [{"role": "user", "content": prompt}]
    response = await call_llm(messages)
    
    parsed_response = parse_json(response)
    if parsed_response and 'updated_knowledge_base' in parsed_response and 'change_summary' in parsed_response:
        updated_knowledge_base = parsed_response['updated_knowledge_base']
        change_summary = parsed_response['change_summary']
        save_knowledge_base(project_id, updated_knowledge_base)
        logger.info(f"Knowledge base updated for project {project_id}. Changes: {change_summary}")
        return change_summary
    else:
        logger.error(f"Failed to update knowledge base. Invalid response format: {response}")
        return "Failed to update knowledge base due to unexpected response format."

