# backend/modules/url_engine/analyzer.py
import re
from urllib.parse import urlparse

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculates the minimum number of edits required to change s1 into s2.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
        
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class URLEngine:
    def __init__(self):
        self.suspicious_tlds = ['.xyz', '.top', '.tk', '.pw', '.cc', '.club', '.work']
        # The blueprint requires comparing against top targeted brands/banks
        self.target_brands = ['paypal', 'google', 'apple', 'microsoft', 'chase', 'bankofamerica', 'amazon']

    def extract_features(self, url: str) -> dict:
        score = 0.0
        indicators = []
        
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url.lower().strip())
            domain = parsed.hostname or ""
        except Exception:
            domain = ""
            
        # 1. URL Length
        if len(url) > 75:
            score += 0.2
            indicators.append("long_url")
            
        # 2. Suspicious TLDs
        if "." in domain:
            tld = "." + domain.split(".")[-1]
            if tld in self.suspicious_tlds:
                score += 0.4
                indicators.append(f"suspicious_tld_({tld})")
                
        # 3. IP Address Usage
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if ip_pattern.match(domain):
            score += 0.8
            indicators.append("ip_address_used")
            
        # 4. Typosquatting Detection (Levenshtein)
        if domain and not ip_pattern.match(domain):
            # Extract just the core name (e.g., 'paypa1' from 'paypa1.com')
            core_domain = domain.split(".")[0]
            
            for brand in self.target_brands:
                # We skip exact matches. If it's an exact match but the wrong TLD, Member 4 handles that.
                if core_domain == brand:
                    continue
                    
                dist = levenshtein_distance(core_domain, brand)
                
                # If it takes only 1 or 2 character changes to become a major brand, it's highly suspicious
                if dist == 1 or dist == 2:
                    score += 0.8
                    indicators.append(f"typosquatting_(looks_like_{brand})")
                    break # We only need to flag it once
            
        score = min(score, 1.0)
        
        risk = "LOW"
        if score >= 0.8:
            risk = "HIGH"
        elif score >= 0.5:
            risk = "MEDIUM"
            
        return {
            "url_score": round(score, 2),
            "risk": risk,
            "indicators": indicators
        }

if __name__ == "__main__":
    engine = URLEngine()
    
    # Test 1: Typosquatting (paypa1 instead of paypal - distance of 1)
    print("Test 1 (Typosquatting):", engine.extract_features("http://paypa1-update.com"))
    
    # Test 2: Typosquatting (g00gle instead of google - distance of 2)
    print("Test 2 (Typosquatting):", engine.extract_features("https://g00gle.xyz"))