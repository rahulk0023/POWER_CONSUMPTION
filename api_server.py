from flask import Flask, jsonify
from flask_cors import CORS
from database import get_connection


app = Flask(__name__)
CORS(app)


@app.route("/metrics")
def metrics():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT process_name, cpu, memory, power, timestamp
        FROM process_metrics
        ORDER BY timestamp DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()
    conn.close()

    return jsonify([
        {
            "process": r[0],
            "cpu": r[1],
            "memory": r[2],
            "power": r[3],
            "timestamp": r[4]
        } for r in rows
    ])

if __name__ == "__main__":
    app.run(port=5000, debug=False)
   

