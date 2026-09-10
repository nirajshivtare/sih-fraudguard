import sqlite3
import os
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "fraudguard.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    # Cases table
    c.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            sha256_hash TEXT,
            filename TEXT,
            upload_timestamp TEXT,
            fraud_risk_score REAL,
            fraud_risk_level TEXT,
            origin_confidence_score REAL,
            origin_confidence_level TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_case(case_id, sha256_hash, filename, fraud_score, fraud_level, origin_score, origin_level):
    conn = get_db_connection()
    c = conn.cursor()
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    c.execute('''
        INSERT OR REPLACE INTO cases 
        (case_id, sha256_hash, filename, upload_timestamp, fraud_risk_score, fraud_risk_level, origin_confidence_score, origin_confidence_level)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (case_id, sha256_hash, filename, timestamp, fraud_score, fraud_level, origin_score, origin_level))
    conn.commit()
    conn.close()

def generate_case_id():
    # Simple ID generator: FG-YYYY-XXXXXX
    year = datetime.datetime.now().year
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM cases')
    count = c.fetchone()[0]
    conn.close()
    return f"FG-{year}-{(count + 1):06d}"

# Initialize DB on load
init_db()
