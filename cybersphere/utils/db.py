import sqlite3
import os
import json

def get_db():
    os.makedirs("data", exist_ok=True)
    db_path = os.path.join("data", "cybersphere.db")
    conn = sqlite3.connect(db_path)
    create_tables(conn)
    return conn

def create_tables(conn):
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL)''')
    
    conn.commit()

def save_user(username, password_hash):
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                 (username, password_hash))
        conn.commit()
        return True
    except:
        return False

def get_user(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    result = c.fetchone()
    return result[0] if result else None