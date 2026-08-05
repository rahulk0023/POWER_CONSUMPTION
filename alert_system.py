#rahul
import sqlite3
import pandas as pd
from datetime import datetime

# Thresholds
CPU_THRESHOLD = 80.0
MEMORY_THRESHOLD = 70.0

# Connect DB
DB_PATH = r"C:\Users\ASUS\Downloads\SE2\power_data.db"

conn = sqlite3.connect(DB_PATH)



# Read latest process data
query = """
SELECT timestamp, process_name, cpu, memory
FROM process_metrics
ORDER BY timestamp DESC
LIMIT 50
"""

df = pd.read_sql_query(query, conn)

alerts = []

for _, row in df.iterrows():
    if row['cpu'] > CPU_THRESHOLD:
        alerts.append((
            row['timestamp'],
            row['process_name'],
            "High CPU Usage",
            row['cpu']
        ))

    if row['memory'] > MEMORY_THRESHOLD:
        alerts.append((
            row['timestamp'],
            row['process_name'],
            "High Memory Usage",
            row['memory']
        ))

# Insert alerts into DB
cur = conn.cursor()

for alert in alerts:
    cur.execute("""
    INSERT INTO alerts (timestamp, process_name, alert_type, alert_value)
    VALUES (?, ?, ?, ?)
    """, alert)

conn.commit()
conn.close()

print(f"{len(alerts)} alerts generated.")
