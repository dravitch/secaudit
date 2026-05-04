#!/usr/bin/env python3
"""Vérifie que les deux API répondent avec le bon format."""

import json
import os
import sys
from openai import OpenAI
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

SAMPLE_FINDING = {
    "id": "test-001",
    "sprint": 2,
    "tool": "scanner-dns",
    "target": "telemo.gov.gn",
    "title": "DMARC policy is p=none",
    "finding": "DMARC publié mais politique 'none'",
    "evidence": ["v=DMARC1; p=none; aspf=r; adkim=r;"],
    "analyst_conclusion": "DMARC en observation sans effet",
    "severity": "HIGH",
    "critic_verdict": "PENDING",
    "confidence_score": 0.0,
    "flags": []
}

def test_analyst():
    """Anthropic AnalystAgent"""
    print("=== AnalystAgent (Anthropic) ===")
    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    response = client.messages.create(
        model=os.getenv("ANALYST_MODEL", "claude-sonnet-4-6"),
        max_tokens=1024,
        messages=[
            {"role": "system", "content": "Tu es un analyste de sécurité. Retourne UNIQUEMENT un objet JSON valide avec les champs 'analyst_conclusion' et 'cvss_score'."},
            {"role": "user", "content": json.dumps(SAMPLE_FINDING)}
        ]
    )
    content = response.content[0].text
    print(f"Réponse brute: {content[:200]}...")
    try:
        data = json.loads(content)
        print(f"✅ JSON valide: {list(data.keys())}")
    except json.JSONDecodeError as e:
        print(f"❌ JSON invalide: {e}")
        sys.exit(1)

def test_critic():
    """CriticAgent via HuggingFace Router -> DeepSeek"""
    print("=== CriticAgent (HF/DeepSeek) ===")
    client = OpenAI(
        base_url="https://router.huggingface.co/v1",
        api_key=os.environ["HF_TOKEN"],
    )
    response = client.chat.completions.create(
        model=os.getenv("CRITIC_MODEL", "deepseek-ai/DeepSeek-V4-Pro:novita"),
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "Tu es un critique de sécurité. Tu reçois un finding. Retourne UNIQUEMENT un objet JSON avec 'critic_verdict' (CONFIRMED/NUANCED/REJECTED), 'critic_rationale' (string), 'confidence_score' (float 0-1)."},
            {"role": "user", "content": json.dumps(SAMPLE_FINDING)}
        ]
    )
    content = response.choices[0].message.content
    print(f"Réponse brute: {content[:200]}...")
    try:
        data = json.loads(content)
        print(f"✅ JSON valide: {list(data.keys())}")
        print(f"   Verdict: {data.get('critic_verdict')}")
        print(f"   Confidence: {data.get('confidence_score')}")
    except json.JSONDecodeError as e:
        print(f"❌ JSON invalide: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_analyst()
    print()
    test_critic()
    print("\n✅ Les deux agents répondent correctement.")
