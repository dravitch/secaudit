# debug_deepseek.py
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    base_url="https://router.huggingface.co/v1",
    api_key=os.environ["HF_TOKEN"],
)

response = client.chat.completions.create(
    model="deepseek-ai/DeepSeek-V4-Pro:novita",
    temperature=0,
    max_tokens=256,
    messages=[{"role": "user", "content": "Say 'Hello' in JSON format: {\"msg\": \"...\"}"}],
    response_format={"type": "json_object"},
)

print("=== Full response object ===")
print(response)
print("=== finish_reason ===")
print(response.choices[0].finish_reason)
print("=== content ===")
print(repr(response.choices[0].message.content))
