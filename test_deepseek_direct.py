# test_deepseek_direct.py
import os, json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    base_url="https://api.deepseek.com/v1",
    api_key=os.environ["DEEPSEEK_API_KEY"],
)

# Simuler un finding complet (DMARC p=none)
finding = {
    "id": "test-dmarc-001",
    "title": "DMARC policy is p=none",
    "finding": "DMARC publié mais politique none",
    "evidence": ["v=DMARC1; p=none; aspf=r; adkim=r;"],
    "severity": "HIGH",
    "analyst_conclusion": "DMARC en observation sans effet",
    "critic_verdict": "PENDING",
    "confidence_score": 0.0,
    "flags": []
}

response = client.chat.completions.create(
    model="deepseek-chat",
    temperature=0,
    max_tokens=512,
    messages=[
        {
            "role": "system",
            "content": (
                "Tu es un critique de sécurité. Retourne UNIQUEMENT un objet JSON :\n"
                '{"findings": [{"id": "test-dmarc-001", "critic_verdict": "CONFIRMED", '
                '"critic_rationale": "...", "confidence_score": 0.XX, "flags": []}]}\n'
                "Pas de texte avant ou après."
            )
        },
        {"role": "user", "content": json.dumps(finding)}
    ]
)

content = response.choices[0].message.content
print("Réponse brute :", repr(content))
data = json.loads(content)
print("Verdicts :", data["findings"])
