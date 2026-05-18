import json
import requests
import os
import pathlib
from datetime import datetime, timezone
from dotenv import load_dotenv
from eth_hash.auto import keccak

BASE = pathlib.Path("/home/james-warren/Projects/Vektasafe Projects/octio")
load_dotenv(BASE / ".env")

API_KEY = os.getenv("OPENROUTER_API_KEY").strip('"')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "google/gemma-3-27b-it"

def load_registry():
    with open(BASE / "registry.json") as f:
        data = json.load(f)
    return data["indicators"]

def hash_target(url_or_address):
    if url_or_address.startswith("http"):
        parts = url_or_address.split("/")
        domain = parts[2] if len(parts) > 2 else url_or_address
    else:
        domain = url_or_address
    return keccak(domain.encode()).hex()

def query_registry(target, registry):
    target_hash = hash_target(target)
    if target_hash in registry:
        ind = registry[target_hash]
        return {
            "flagged": True,
            "target_hash": target_hash,
            "severity": ind["severity"],
            "indicator_type": ind["indicator_type"],
            "reasoning": ind["reasoning"],
            "timestamp": ind["timestamp"]
        }
    return {
        "flagged": False,
        "target_hash": target_hash,
        "severity": None,
        "indicator_type": None,
        "reasoning": None,
        "timestamp": None
    }

def gemma_risk_assessment(target, query_result):
    if not query_result["flagged"]:
        prompt = f"""You are a DeFi security oracle. A protocol is about to interact with:
Target: {target}

This target is NOT in the threat registry. Based on the domain or address pattern alone, assess the risk.

Respond in JSON only:
{{
    "risk_level": "SAFE" or "SUSPICIOUS" or "UNKNOWN",
    "recommendation": "PROCEED" or "CAUTION" or "BLOCK",
    "reasoning": "one sentence"
}}"""
    else:
        prompt = f"""You are a DeFi security oracle. A protocol is about to interact with:
Target: {target}

This target IS in the threat registry:
- Severity: {query_result["severity"]}
- Type: {query_result["indicator_type"]}
- Reasoning: {query_result["reasoning"]}

Respond in JSON only:
{{
    "risk_level": "HIGH" or "CRITICAL",
    "recommendation": "BLOCK",
    "reasoning": "one sentence"
}}"""

    for attempt in range(3):
        try:
            response = requests.post(
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=30
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"].strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content.strip())
        except Exception as e:
            print(f"  Attempt {attempt+1} failed: {e}")
    return {"risk_level": "UNKNOWN", "recommendation": "CAUTION", "reasoning": "Analysis unavailable"}

def run_oracle(targets):
    registry = load_registry()
    print("\n=== OCTIO Oracle Interface ===")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"Registry size: {len(registry)} indicators\n")

    results = []
    for target in targets:
        print(f"Query: {target}")
        query_result = query_registry(target, registry)
        assessment = gemma_risk_assessment(target, query_result)

        result = {
            "target": target,
            "target_hash": query_result["target_hash"],
            "in_registry": query_result["flagged"],
            "registry_severity": query_result["severity"],
            "gemma_assessment": assessment,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        results.append(result)

        status = "FLAGGED" if query_result["flagged"] else "NOT IN REGISTRY"
        print(f"  Registry: {status}")
        print(f"  Risk Level: {assessment['risk_level']}")
        print(f"  Recommendation: {assessment['recommendation']}")
        print(f"  Reasoning: {assessment['reasoning']}\n")

    with open(BASE / "oracle_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"Oracle results saved to oracle_results.json")
    return results

if __name__ == "__main__":
    test_targets = [
        "http://www.dpdlocoqu.cyou/com",
        "https://uniswap.org",
        "http://metamask-security-alert.com/connect",
        "https://aave.com",
        "http://instagram.com.universal-api.org/"
    ]
    run_oracle(test_targets)
