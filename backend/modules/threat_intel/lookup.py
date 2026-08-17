import whois
import tldextract
from datetime import datetime

def analyze_url(url):
    indicators = []
    threat_score = 0.0
    
    # 1. Safely extract the root domain (e.g., getting 'paypal.com' from 'http://secure.login.paypal.com.xyz')
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    
    # Ignore local files or invalid URLs
    if not extracted.suffix or domain == ".":
        return {"threat_score": 0.0, "indicators": []}

    try:
        # 2. Perform the live WHOIS lookup
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        # WHOIS sometimes returns a list of dates if the domain was transferred; we grab the first one
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # 3. Calculate the exact age of the domain
            days_old = (datetime.now() - creation_date).days
            
            # 4. Apply risk heuristics
            if days_old < 30:
                threat_score += 0.85
                indicators.append(f"Recon_Alert:_Newly_Registered_Domain_({days_old}_days_old)")
            elif days_old < 90:
                threat_score += 0.40
                indicators.append(f"Recon_Alert:_Recent_Domain_({days_old}_days_old)")
        else:
            threat_score += 0.30
            indicators.append("Recon_Alert:_WHOIS_Creation_Date_Hidden")
            
    except Exception as e:
        # If the lookup fails or the registry blocks us, it's slightly suspicious
        threat_score += 0.0
        indicators.append("Recon_Alert:_WHOIS_Lookup_Failed")

    # Ensure the score never exceeds the maximum of 1.0
    threat_score = min(threat_score, 1.0)
    
    return {"threat_score": round(threat_score, 2), "indicators": indicators}