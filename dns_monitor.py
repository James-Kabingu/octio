import os
import json
import pathlib
import requests
import time
from dotenv import load_dotenv

BASE = pathlib.Path("/home/james-warren/Projects/Vektasafe Projects/octio")
load_dotenv(BASE / ".env")

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY").strip('"')
VT_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

def extract_domain(url):
    parts = url.split("/")
    return parts[2] if len(parts) > 2 else url

def query_virustotal(domain):
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(
            VT_URL.format(domain=domain),
            headers=headers,
            timeout=15
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            categories = data["data"]["attributes"].get("categories", {})
            reputation = data["data"]["attributes"].get("reputation", 0)
            return {
                "found": True,
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "harmless": stats["harmless"],
                "undetected": stats["undetected"],
                "reputation": reputation,
                "categories": list(categories.values())[:3],
                "vt_verdict": "MALICIOUS" if stats["malicious"] >= 3 else
                              "SUSPICIOUS" if stats["suspicious"] >= 2 or stats["malicious"] >= 1 else
                              "CLEAN"
            }
        elif response.status_code == 404:
            return {
                "found": False,
                "vt_verdict": "NOT_IN_VT",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "reputation": 0,
                "categories": []
            }
        else:
            return {"found": False, "vt_verdict": "ERROR", "error": str(response.status_code)}
    except Exception as e:
        return {"found": False, "vt_verdict": "ERROR", "error": str(e)}

def enrich_indicators():
    indicators_path = BASE / "indicators.json"
    if not indicators_path.exists():
        print("No indicators.json found. Run monitor.py first.")
        return []

    with open(indicators_path) as f:
        indicators = json.load(f)

    print("\n=== OCTIO DNS Monitor -- VirusTotal Enrichment ===")
    print(f"Enriching {len(indicators)} indicators...\n")

    enriched = []
    for i, indicator in enumerate(indicators):
        url = indicator["url"]
        domain = extract_domain(url)
        print(f"  Querying VT: {domain}")

        vt_result = query_virustotal(domain)
        indicator["virustotal"] = vt_result

        gemma_verdict = indicator.get("gemma_analysis", {}).get("is_threat", False)
        vt_verdict = vt_result["vt_verdict"]

        if gemma_verdict and vt_verdict == "MALICIOUS":
            indicator["confidence"] = "HIGH"
            indicator["confidence_reason"] = "Gemma 4 and VirusTotal both flag as malicious"
        elif gemma_verdict and vt_verdict == "NOT_IN_VT":
            indicator["confidence"] = "MEDIUM"
            indicator["confidence_reason"] = "Gemma 4 flags as malicious -- not yet in VirusTotal (OCTIO caught it first)"
        elif gemma_verdict and vt_verdict == "SUSPICIOUS":
            indicator["confidence"] = "MEDIUM"
            indicator["confidence_reason"] = "Gemma 4 flags as malicious -- VirusTotal marks suspicious"
        elif gemma_verdict and vt_verdict == "CLEAN":
            indicator["confidence"] = "LOW"
            indicator["confidence_reason"] = "Gemma 4 flags as malicious -- VirusTotal marks clean (possible false positive)"
        else:
            indicator["confidence"] = "LOW"
            indicator["confidence_reason"] = "No threat detected"

        print(f"    VT verdict: {vt_verdict} | Confidence: {indicator['confidence']}")
        if vt_result.get('malicious', 0) > 0:
            print(f"    Malicious votes: {vt_result['malicious']} | Suspicious: {vt_result['suspicious']}")
        print()

        enriched.append(indicator)

        if i < len(indicators) - 1:
            time.sleep(15)

    with open(indicators_path, "w") as f:
        json.dump(enriched, f, indent=2)

    print(f"Enriched {len(enriched)} indicators saved to indicators.json")

    high = sum(1 for i in enriched if i.get("confidence") == "HIGH")
    medium = sum(1 for i in enriched if i.get("confidence") == "MEDIUM")
    low = sum(1 for i in enriched if i.get("confidence") == "LOW")
    first = sum(1 for i in enriched if i.get("virustotal", {}).get("vt_verdict") == "NOT_IN_VT"
                and i.get("gemma_analysis", {}).get("is_threat"))

    print(f"\nConfidence breakdown:")
    print(f"  HIGH   (VT + Gemma agree): {high}")
    print(f"  MEDIUM (partial signal):   {medium}")
    print(f"  LOW    (weak signal):      {low}")
    print(f"  OCTIO caught first (not in VT): {first}")

    return enriched

if __name__ == "__main__":
    enrich_indicators()
