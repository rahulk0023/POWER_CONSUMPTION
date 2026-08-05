import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

# 1️⃣ Connect to correct database (absolute path)
conn = sqlite3.connect(r"C:\Users\ASUS\Downloads\SE2\power_data.db")

# 2️⃣ Correct query using REAL column names
query = """
SELECT timestamp, process_name, cpu, memory
FROM process_metrics
ORDER BY timestamp
"""

df = pd.read_sql_query(query, conn)
conn.close()

# 3️⃣ Convert timestamp to datetime
df['timestamp'] = pd.to_datetime(df['timestamp'])

# -------------------------------
# CPU USAGE TREND
# -------------------------------
plt.figure()
plt.plot(df['timestamp'], df['cpu'])
plt.title("CPU Usage Trend Over Time")
plt.xlabel("Time")
plt.ylabel("CPU Usage (%)")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# -------------------------------
# MEMORY USAGE TREND
# -------------------------------
plt.figure()
plt.plot(df['timestamp'], df['memory'])
plt.title("Memory Usage Trend Over Time")
plt.xlabel("Time")
plt.ylabel("Memory Usage (MB)")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# -------------------------------
# TOP 5 CPU CONSUMING PROCESSES
# -------------------------------
top_processes = (
    df.groupby('process_name')['cpu']
    .mean()
    .sort_values(ascending=False)
    .head(5)
)

plt.figure()
top_processes.plot(kind='bar')
plt.title("Top 5 CPU Consuming Processes")
plt.xlabel("Process Name")
plt.ylabel("Average CPU Usage (%)")
plt.xticks(rotation=30)
plt.tight_layout()
plt.show()

# -------------------------------
# RECENT ALERTS TABLE
# -------------------------------

conn = sqlite3.connect(r"C:\Users\ASUS\Downloads\SE2\power_data.db")

alerts_query = """
SELECT timestamp, process_name, alert_type, alert_value
FROM alerts
ORDER BY timestamp DESC
LIMIT 10
"""

alerts_df = pd.read_sql_query(alerts_query, conn)
conn.close()
# -------------------------------
# PRINT ALERTS (OPTION A)
# -------------------------------
if alerts_df.empty:
    print("\nNo alerts generated yet.")
else:
    print("\nRecent Alerts:\n")
    print(alerts_df)
