# normalize.py
from urllib.parse import urlparse

def normalize_url(raw_url: str) -> dict:
    """
    Safely normalizes an incoming URL to prevent evasion techniques.
    Returns a dictionary containing the cleaned URL, the full domain, and the root domain.
    """
    # 1. Force lowercase and remove accidental whitespace
    raw_url = raw_url.strip().lower()
    
    # 2. Add scheme if missing (urllib needs it to parse correctly)
    if not raw_url.startswith(('http://', 'https://')):
        raw_url = 'http://' + raw_url
        
    try:
        # 3. Parse the URL into components
        parsed = urlparse(raw_url)
        
        # 4. Handle Punycode/IDN to catch homograph attacks
        domain = parsed.hostname
        if domain:
            try:
                # Convert foreign characters to standard ASCII representation
                domain = domain.encode('idna').decode('ascii')
            except Exception:
                pass # Fallback to original if conversion fails
                
        # (Note: parsed.hostname automatically strips ports, satisfying our port removal requirement)
            
        # 5. Extract root domain (Naive MVP approach)
        # For this MVP, taking the last two parts of the domain works for .com, .org, etc.
        root_domain = domain
        if domain:
            parts = domain.split('.')
            if len(parts) > 2:
                root_domain = f"{parts[-2]}.{parts[-1]}"

        # 6. Reconstruct the clean URL (stripping fragments and query parameters)
        # We keep the path but remove the trailing slash.
        path = parsed.path.rstrip('/')
        clean_url = f"{parsed.scheme}://{domain}{path}"
        
        return {
            "clean_url": clean_url,
            "domain": domain,
            "root_domain": root_domain
        }
    except Exception:
        # If parsing completely fails due to heavy malformation, return a safe fallback
        return {
            "clean_url": raw_url,
            "domain": raw_url,
            "root_domain": raw_url
        }

if __name__ == "__main__":
    # Test our normalization
    test_urls = [
        "HTTP://PAYPAL.COM/",
        "https://badsite.com:443/login?session=123#top",
        "login.secure-update.xyz",
        "http://xn--pypal-4ve.com" # Punycode attack example
    ]
    for u in test_urls:
        print(f"Original: {u}\nNormalized: {normalize_url(u)}\n")