# llm_service.py

import os
import json
import logging
import openai

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

async def analyze_code_security(all_file_contents: str):
    """
    Analyze code security by sending a diff and optionally full code to the LLM.

    Args:
        diff (str): The code diff to analyze.
        full_code (str, optional): The full updated file content.

    Returns:
        dict: Parsed JSON response containing security analysis results.
    """
    
    prompt = f"""Analyze the following code changes and identify up to 2 of the most significant and well-evidenced risks directly introduced or exacerbated by the modifications in this specific merge request:

{all_file_contents}

Instructions:
1. Examine only the added, modified, or deleted code in the diffs.
2. Identify risks that are a direct result of these changes, such as:
   - Security vulnerabilities introduced by the new or modified code
   - Potential bugs or logical errors caused by the changes
   - Unintended side effects on existing functionality
   - New edge cases or error scenarios created by the modifications
   - Performance risks directly tied to the changes
   - Breaks in backward compatibility or API contracts due to the changes
3. For each identified risk (maximum 2), provide:
   a. A concise description of the risk, clearly linking it to the specific change
   b. The exact file and relevant code section where the risk is introduced, without using line numbers. Quote the specific code that introduces the risk.
   c. A detailed explanation of how this change creates or increases the risk, including:
      - Strong evidence from the code, with specific code snippets quoted
      - An explanation of the potential consequences of this risk
      - How the risk relates to common security vulnerabilities or best practices
      - Any relevant context from the rest of the codebase that contributes to this risk
   d. A suggested fix or mitigation strategy
   e. The most relevant security standard or rule that this risk violates or relates to. This can be from any recognized security standard (e.g., CWE, OWASP, CERT, SANS, ISO, NIST), industry best practice, or a custom rule if no standard applies. Provide a brief explanation of why this standard or rule is relevant.

Critical Guidelines:
- Only report risks that did not exist before this merge request.
- Do NOT include pre-existing risks in unchanged parts of the code.
- If a change modifies existing risky code, only report if it significantly increases the risk or introduces new risks.
- Focus on the direct impact of the changes, not on hypothetical or unrelated risks.
- Prioritize risks with the strongest evidence and highest impact.
- Include no more than 2 risks, even if more are found. It's acceptable to report 0 or 1 risk if that's all that can be confidently identified.

Format your response as a JSON object wrapped in a markdown code block:
```json
{{
    "risks": [
        {{
            "description": "Concise risk description",
            "location": "File name and relevant code section (quoted)",
            "evidence": "Detailed explanation with strong evidence from the code, including quoted snippets, potential consequences, relation to security best practices, and relevant context",
            "suggestion": "Suggested fix or mitigation",
            "standard_id": "Relevant security standard or rule ID",
            "standard_explanation": "Brief explanation of why this standard or rule is relevant"
        }},
        ...
    ]
}}
```
If no significant risks are identified or if there isn't strong evidence for any risks, return an empty list for "risks"."""

    messages = [{"role": "user", "content": prompt}]
    response = await call_llm(messages)
    parsed_response = parse_json(response)
    if parsed_response is None:
        return {"risks": []}  # 返回一个空的风险列表而不是 None
    return parsed_response
