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
    prompt = f"""Analyze the following code changes for potential security risks, focusing on the changes introduced:

{all_file_contents}

CWE Top 25 list to check against: {', '.join(CWE_TOP_25)}

Instructions:
1. Examine the diffs and full file contents carefully, paying attention to added or modified code.
2. Identify potential security risks introduced by these changes, considering only the CWE Top 25 Most Dangerous Software Weaknesses list provided above.
3. Do not report issues that exist in the old code and were not affected by the changes.
4. For each identified risk, provide:
   a. A brief description of the risk
   b. The specific file and line or section of code where the risk is introduced
   c. A suggested fix or mitigation strategy
   d. The relevant CWE identifier from the provided list (e.g., CWE-79)

Format your response as a JSON object wrapped in a markdown code block, like this:
```json
{{
    "risks": [
        {{
            "description": "Risk description",
            "location": "File name and line number or code section",
            "suggestion": "Suggested fix or mitigation",
            "cwe_id": "CWE-XXX"
        }},
        ...
    ]
}}
```

If no new security risks from the CWE Top 25 list are introduced by the changes, return an empty list for "risks". """

    messages = [{"role": "user", "content": prompt}]
    response = await call_llm(messages)
    parsed_response = parse_json(response)
    if parsed_response is None:
        return {"risks": []}  # 返回一个空的风险列表而不是 None
    return parsed_response
