import sqlite3
import hashlib
import os

# vul 1: SQL Injection
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# vul 2: Hardcoded Password
SECRET_KEY = "admin123"
DB_PASSWORD = "root1234"

# vul 3: Weak Hashing (MD5)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# vul 4: Command Injection
def ping_host(host):
    os.system("ping -c 1 " + host)

# vul 5: No Input Validation
def create_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO users VALUES ('{username}', '{password}')")
    conn.commit()

print("App Running...")
