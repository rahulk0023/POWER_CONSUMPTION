#rahul
import sqlite3

DB_NAME = "power_data.db"
#kajal
def get_connection():
    return sqlite3.connect(DB_NAME)

def create_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            process_name TEXT,
            cpu REAL,
            memory REAL,
            power REAL,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

import sqlite3

def create_alert_table():
    conn = sqlite3.connect("power_data.db")
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        process_name TEXT,
        alert_type TEXT,
        alert_value REAL
    )
    """)

    conn.commit()
    conn.close()
create_alert_table()

