# lookup.py
from .normalize import normalize_url
from .database import check_indicator_in_db
from .rules import check_brand_impersonation

def analyze_url(raw_url: str) -> dict:
    """
    The main Threat Intelligence Engine. 
    Combines database lookups with deterministic security rules.
    """
    norm_data = normalize_url(raw_url)
    clean_url = norm_data["clean_url"]
    domain = norm_data["domain"]
    root_domain = norm_data["root_domain"]
    
    # 1. Database/Blocklist Lookup
    is_url_blocked = check_indicator_in_db(clean_url)
    is_domain_blocked = check_indicator_in_db(domain)
    is_root_blocked = False
    if domain != root_domain:
        is_root_blocked = check_indicator_in_db(root_domain)

    # 2. Hard Security Rules (Brand Impersonation)
    is_impersonating = check_brand_impersonation(domain, root_domain)
    
    # 3. Determine Threat Score and Formatting
    indicators = []
    if is_url_blocked:
        indicators.append("known_phishing_url")
    if is_domain_blocked or is_root_blocked:
        indicators.append("known_phishing_domain")
    if is_impersonating:
        indicators.append("brand_impersonation")
        
    matched = len(indicators) > 0
    
    # Per blueprint: Blocklist matches or hard rules yield maximum threat score (1.0)
    threat_score = 1.0 if matched else 0.0
    
    return {
        "url_tested": raw_url,
        "threat_score": threat_score,
        "matched": matched,
        "indicators": indicators
    }

if __name__ == "__main__":
    # Test cases
    print("Test 1 (Safe):", analyze_url("https://paypal.com/login"))
    print("Test 2 (Impersonation):", analyze_url("http://paypal-security-update.xyz"))