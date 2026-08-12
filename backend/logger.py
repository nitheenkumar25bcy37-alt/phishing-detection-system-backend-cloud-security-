# backend/logger.py
import sqlite3
import os
from datetime import datetime
from urllib.parse import urlparse

# Path to the backend logs database
LOG_DB_PATH = os.path.join(os.path.dirname(__file__), "traffic_logs.db")

def init_log_db():
    """Creates the logging table if it doesn't exist."""
    conn = sqlite3.connect(LOG_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            final_risk_score REAL NOT NULL,
            result TEXT NOT NULL,
            m1_score REAL,
            m2_score REAL,
            m3_score REAL,
            m4_score REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def log_scan_result(url: str, final_score: float, result: str, m1: float, m2: float, m3: float, m4: float):
    """
    Safely extracts the domain to protect privacy, then logs the scores.
    """
    # PRIVACY ENFORCEMENT: Extract only the domain. Never log the raw URL.
    try:
        domain = urlparse(url).netloc
    except Exception:
        domain = "unknown_domain"

    conn = sqlite3.connect(LOG_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_logs (domain, final_risk_score, result, m1_score, m2_score, m3_score, m4_score)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (domain, final_score, result, m1, m2, m3, m4))
    conn.commit()
    conn.close()

# Initialize the database file when this module is first imported
init_log_db()