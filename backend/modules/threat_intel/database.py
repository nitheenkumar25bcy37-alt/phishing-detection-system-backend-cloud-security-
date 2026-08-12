# database.py
import sqlite3
import os

# Define the path to the database file in this folder
DB_PATH = os.path.join(os.path.dirname(__file__), "threat_intel.db")

def init_db():
    """
    Initializes the SQLite database and creates the blocklist table.
    We create an INDEX on the indicator column to make lookups extremely fast.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create the table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocklist (
            indicator TEXT UNIQUE NOT NULL,
            indicator_type TEXT NOT NULL,
            source TEXT NOT NULL
        )
    ''')
    
    # Create an index to ensure our database queries are lightning-fast
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_indicator ON blocklist(indicator)
    ''')
    
    conn.commit()
    conn.close()
    print("Threat Intelligence Database initialized successfully.")

# Run this block only if this script is executed directly
if __name__ == "__main__":
    init_db()
# Add this inside database.py

def check_indicator_in_db(indicator: str) -> bool:
    """
    Queries the database to see if the given indicator (URL or Domain) exists.
    Returns True if found, False otherwise.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # We use parameterized queries (?) to prevent SQL Injection attacks!
    cursor.execute('''
        SELECT 1 FROM blocklist WHERE indicator = ? LIMIT 1
    ''', (indicator,))
    
    result = cursor.fetchone()
    conn.close()
    
    # If result is not None, we found a match.
    return result is not None