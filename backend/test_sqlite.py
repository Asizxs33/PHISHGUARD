import sqlite3
import sys

try:
    conn = sqlite3.connect('phishguard.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("Tables in db:", tables)
    conn.close()
except Exception as e:
    print("Error:", e)
