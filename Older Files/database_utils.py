import sqlite3
from datetime import datetime

def setup_database():
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            user_id BLOB,
            message BLOB,
            iv BLOB,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def store_message(user_id: bytes, message: bytes, iv: bytes):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (user_id, message, iv, timestamp) VALUES (?, ?, ?, ?)",
                   (user_id, message, iv, datetime.now()))
    conn.commit()
    conn.close()