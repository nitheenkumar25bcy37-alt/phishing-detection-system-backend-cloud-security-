# feed_updater.py
import urllib.request
import sqlite3
import os
from urllib.parse import urlparse

# Path to the database you created in Phase 3
DB_PATH = os.path.join(os.path.dirname(__file__), "threat_intel.db")

# The free community feed recommended for this MVP
FEED_URL = "https://openphish.com/feed.txt"

def update_blocklist():
    print(f"Fetching latest threat intelligence from {FEED_URL}...")
    
    try:
        # 1. Import Data securely
        # We add a User-Agent so the server doesn't block our automated request
        req = urllib.request.Request(FEED_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            # Read the data and split it line-by-line
            data = response.read().decode('utf-8').splitlines()
    except Exception as e:
        print(f"Failed to fetch feed: {e}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    added_count = 0
    
    for line in data:
        raw_url = line.strip()
        
        # 2. Validate: Skip empty lines or non-web URLs
        if not raw_url or not raw_url.startswith(("http://", "https://")):
            continue 
            
        try:
            # 3. Normalize Domain: Extract the domain and make it lowercase
            parsed = urlparse(raw_url)
            domain = parsed.netloc.lower()
            
            if not domain:
                continue
                
            # 4. Remove Duplicates: Use INSERT OR IGNORE
            # We insert the specific URL as a threat...
            cursor.execute('''
                INSERT OR IGNORE INTO blocklist (indicator, indicator_type, source)
                VALUES (?, ?, ?)
            ''', (raw_url, 'url', 'openphish'))
            
            # ...and we also insert the extracted domain as a threat
            cursor.execute('''
                INSERT OR IGNORE INTO blocklist (indicator, indicator_type, source)
                VALUES (?, ?, ?)
            ''', (domain, 'domain', 'openphish'))
            
            # Count if new rows were actually added
            if cursor.rowcount > 0:
                added_count += 1
                
        except Exception:
            # 5. Handle Malformed URLs: Silently skip them and keep processing
            continue

    conn.commit()
    conn.close()
    print(f"Update complete. Added new threat indicators to the database.")

if __name__ == "__main__":
    update_blocklist()