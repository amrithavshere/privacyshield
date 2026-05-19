import os
from abc import ABC, abstractmethod
from typing import Dict, Any
from .schema import ensure_valid_ai_output

class AIProvider(ABC):
    @abstractmethod
    def analyze_policy(self, text: str) -> Dict[str, Any]:
        """
        Analyze privacy policy text and return structured JSON matching SPEC.md.
        """
        pass


class MockAIProvider(AIProvider):
    def analyze_policy(self, text: str) -> Dict[str, Any]:
        """
        Deterministic keyword-based analysis. Always returns valid schema.
        """
        text_lower = text.lower() if text else ""

        # Default empty structure required by schema
        summary = {
            "data_collected": [],
            "purposes": [],
            "sharing": [],
            "retention": "unknown",  # Must be string
            "user_rights": [],
            "security_measures": []
        }
        flags = []
        categories = []

        # Rule 1: Advertising/Profiling
        if any(kw in text_lower for kw in ["advertising", "personalized ads", "profiling"]):
            flags.append({
                "flag": "profiling_ads",
                "severity": "medium",
                "evidence": "Mention of advertising or profiling."
            })
            categories.append({
                "category": "ads_profiling",
                "risk": "medium",
                "text": "Mentions of personalized ads."
            })

        # Rule 2: Third Party Sharing
        if "third party" in text_lower or "share" in text_lower:
            flags.append({
                "flag": "third_party_sharing",
                "severity": "medium",
                "evidence": "Mention of sharing data with third parties."
            })
            categories.append({
                "category": "sharing",
                "risk": "medium",
                "text": "Mentions of sharing data."
            })

        # Rule 3: Retention Unclear
        if "retain" in text_lower and "duration" not in text_lower:
            flags.append({
                "flag": "retention_unclear",
                "severity": "medium",
                "evidence": "Mentions retention without clear duration."
            })
            categories.append({
                "category": "retention",
                "risk": "medium",
                "text": "Data retention period is discussed."
            })

        # Rule 4: Children
        if "children" in text_lower or "minor" in text_lower:
            flags.append({
                "flag": "sensitive_data",
                "severity": "low",
                "evidence": "Mentions children or minors."
            })
            categories.append({
                "category": "children",
                "risk": "low",
                "text": "Children's privacy is addressed."
            })

        output = {
            "policy_summary": summary,
            "risk_flags": flags,
            "clause_categories": categories
        }

        # Ensure valid before returning
        return ensure_valid_ai_output(output)


class OpenAIProvider(AIProvider):
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable is missing.")

    def analyze_policy(self, text: str) -> Dict[str, Any]:
        """
        Use OpenAI SDK or requests to call API. 
        Only imports dynamic requirements locally so we don't break tests.
        """
        import requests
        import json
        
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        system_prompt = '''You are a privacy policy analyzer. Read the provided text and output STRICT JSON matching this schema:
{
  "policy_summary": {
    "data_collected": [string],
    "purposes": [string],
    "sharing": [string],
    "retention": "string duration or 'unknown'",
    "user_rights": [string],
    "security_measures": [string]
  },
  "risk_flags": [
    {
      "flag": "third_party_sharing|profiling_ads|retention_unclear|rights_unclear|weak_security_commitments|sensitive_data",
      "severity": "low|medium|high",
      "evidence": "string quote"
    }
  ],
  "clause_categories": [
    {
      "category": "collection|sharing|retention|rights|security|ads_profiling|children",
      "risk": "low|medium|high",
      "text": "string quote"
    }
  ]
}
Return standard JSON, do not wrap in markdown or backticks. If you cannot analyze, return the basic empty structure with retention="unknown".
'''
        
        payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text[:15000]} # Limit characters roughly
            ],
            "temperature": 0.0
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            
            # OpenAI sometimes wraps json in markdown backticks
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
                
            data = json.loads(content)
            return ensure_valid_ai_output(data)
        except Exception as e:
            # Fallback empty logic on failure if we want, or just raise
            raise RuntimeError(f"OpenAI fetch/parse failed: {e}")


def get_ai_provider() -> AIProvider:
    provider_name = os.environ.get("PRIVACYSHIELD_AI_PROVIDER", "mock").lower()
    has_key = bool(os.environ.get("OPENAI_API_KEY"))

    if provider_name == "openai" and has_key:
        return OpenAIProvider()
    return MockAIProvider()
