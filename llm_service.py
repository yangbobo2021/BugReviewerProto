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
            json_end = response.find("```", json_start + 7)
            if json_end != -1:
                json_str = response[json_start + 7:json_end].strip()
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
    
    prompt = f"""Analyze the following code changes for potential security and business risks, focusing ONLY on the changes introduced in this specific merge request:

{all_file_contents}

Instructions:
1. Examine the diffs carefully, paying attention ONLY to added or modified code.
2. Identify potential security risks introduced by these specific changes, considering:
   - CWE Top 25 Most Dangerous Software Weaknesses
   - OWASP Top 10 Web Application Security Risks
   - Specific business logic vulnerabilities
   - Data handling and privacy concerns
   - API usage and third-party integrations
   - Input validation and output encoding
   - Error handling and logging practices
   - Concurrency and resource management issues
   - Code quality and maintainability concerns
3. For each identified risk, provide:
   a. A brief description of the risk
   b. The specific file and line or section of code where the risk is introduced
   c. A suggested fix or mitigation strategy
   d. The relevant security standard identifier (e.g., CWE-79, OWASP A03:2021)

Important:
- Focus ONLY on new risks introduced by the changes in this merge request.
- Do NOT report on existing issues in unchanged code.
- If a function has been modified, only consider the new or changed parts of that function.

Format your response as a JSON object wrapped in a markdown code block, like this:
```json
{{
    "risks": [
        {{
            "description": "Risk description",
            "location": "File name and line number or code section",
            "suggestion": "Suggested fix or mitigation",
            "standard_id": "CWE-XXX or OWASP AXX:2021"
        }},
        ...
    ]
}}
```
If no new security or business risks are introduced by the changes in this merge request, return an empty list for "risks". """

    messages = [{"role": "user", "content": prompt}]
    response = await call_llm(messages)
    parsed_response = parse_json(response)
    if parsed_response is None:
        return {"risks": []}  # 返回一个空的风险列表而不是 None
    return parsed_response
