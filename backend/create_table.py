import sqlite3
import sys

try:
    conn = sqlite3.connect('phishguard.db')
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dangerous_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain VARCHAR(255) NOT NULL UNIQUE,
            source VARCHAR(50) DEFAULT 'user_check',
            risk_level VARCHAR(20),
            forensics_data TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    print("Table created successfully.")
except Exception as e:
    print("Error:", e)
