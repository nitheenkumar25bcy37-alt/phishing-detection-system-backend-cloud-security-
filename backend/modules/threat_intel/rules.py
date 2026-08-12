# rules.py

# A minimal dictionary of brands and their legitimate root domains for the MVP
PROTECTED_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "github": "github.com"
}

def check_brand_impersonation(domain: str, root_domain: str) -> bool:
    """
    Checks if a domain is trying to impersonate a protected brand.
    Returns True if impersonation is detected, False otherwise.
    """
    for brand, legit_root in PROTECTED_BRANDS.items():
        # Check if the brand name is anywhere in the domain string
        if brand in domain:
            # If it contains the brand, but it's NOT the legitimate root domain, flag it.
            if root_domain != legit_root:
                return True
    return False