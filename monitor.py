import requests
import os
import json
import pathlib
from datetime import datetime, timezone
from dotenv import load_dotenv
from eth_hash.auto import keccak

BASE = pathlib.Path("/home/james-warren/Projects/Vektasafe Projects/octio")
load_dotenv(BASE / ".env")

API_KEY = os.getenv("OPENROUTER_API_KEY").strip('"')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "google/gemma-3-27b-it"

def fetch_phishing_urls(limit=5):
    print("Fetching live phishing URLs from OpenPhish...")
    try:
        response = requests.get("https://openphish.com/feed.txt", timeout=10)
        response.raise_for_status()
        urls = response.text.strip().split("\n")[:limit]
        print(f"Fetched {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"OpenPhish unavailable: {e}")
        return [
            "http://secure-login.paypa1.com/verify",
            "http://amazon-account-suspended.xyz/login",
            "http://metamask-security-alert.com/connect",
            "http://binance-kyc-update.net/verify",
            "http://uniswap-airdrop-claim.io/wallet"
        ]

def analyse_with_gemma(url):
    prompt = f"""You are a threat intelligence analyst for a Web3 security system.

Analyse this URL and determine if it is a phishing or malicious URL targeting Web3, DeFi, or cryptocurrency users.

URL: {url}

Respond in JSON format only, no other text:
{{
    "is_threat": true or false,
    "threat_type": "PHISHING" or "MALWARE" or "SCAM" or "LEGITIMATE",
    "severity": "LOW" or "MEDIUM" or "HIGH" or "CRITICAL",
    "target": "which platform or service is being impersonated",
    "reasoning": "one sentence explanation"
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
            content = response.json()["choices"][0]["message"]["content"]
            content = content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content.strip())
        except Exception as e:
            print(f"  Attempt {attempt+1} failed: {e}")
    return None

def hash_target(url):
    domain = url.split("/")[2] if len(url.split("/")) > 2 else url
    return keccak(domain.encode()).hex()

def run_monitor():
    print("\n=== OCTIO Monitoring Layer ===")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"Model: {MODEL}\n")

    urls = fetch_phishing_urls(limit=5)
    indicators = []

    for url in urls:
        print(f"Analysing: {url}")
        analysis = analyse_with_gemma(url)
        if analysis is None:
            print(f"  Skipped -- all retry attempts failed\n")
            continue
        indicator = {
            "url": url,
            "target_hash": hash_target(url),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "gemma_analysis": analysis
        }
        indicators.append(indicator)
        print(f"  Threat: {analysis['is_threat']} | Type: {analysis['threat_type']} | Severity: {analysis['severity']}")
        print(f"  Target: {analysis['target']}")
        print(f"  Reason: {analysis['reasoning']}\n")

    with open(BASE / "indicators.json", "w") as f:
        json.dump(indicators, f, indent=2)

    print(f"Saved {len(indicators)} indicators to indicators.json")
    return indicators

if __name__ == "__main__":
    run_monitor()
