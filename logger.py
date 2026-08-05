# logger.py
import csv
from pathlib import Path
import time
# CRITICAL CHANGE 1: Import the single, correct estimate_power function 
from monitor import estimate_power 

BASELINE_PATH = Path("data/process_baseline.csv")
ANOMALY_LOG_PATH = Path("data/anomalies.log")
ALL_SAMPLES_LOG_PATH = Path("data/all_metrics.csv") 

BASELINE_PATH.parent.mkdir(exist_ok=True) 

#  NEW: All Sample Logging Function 
def log_all_samples(timestamp, snapshots, coeffs, interval):
    """Logs all process metrics (power, cpu, mem, io) for comprehensive history."""
    ALL_SAMPLES_LOG_PATH.parent.mkdir(exist_ok=True)
    is_new_file = not ALL_SAMPLES_LOG_PATH.exists()
    
    fieldnames = ['timestamp', 'pid', 'process_name', 'power_watts', 'cpu_percent', 'mem_mb', 'io_rate_mb_s']
    
    try:
        with open(ALL_SAMPLES_LOG_PATH, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if is_new_file:
                writer.writeheader()
            
            for pid, snap in snapshots.items():
                #  CRITICAL CHANGE 2: Use imported estimate_power 
                power_w, _ = estimate_power(snap, coeffs, interval) 
                
                writer.writerow({
                    'timestamp': timestamp,
                    'pid': pid,
                    'process_name': snap.name[:30],
                    'power_watts': f"{power_w:.2f}",
                    'cpu_percent': f"{snap.cpu_percent:.2f}",
                    'mem_mb': f"{snap.mem_mb:.2f}",
                    'io_rate_mb_s': f"{snap.io_rate_mb_s:.2f}"
                })
    except Exception as e:
        print(f"Error writing all samples log: {e}")

#  Utility to estimate power
#  Anomaly Logging Function 
def log_anomaly(timestamp, process_name, power_w, severity, details):
    ANOMALY_LOG_PATH.parent.mkdir(exist_ok=True)
    is_new_file = not ANOMALY_LOG_PATH.exists()
    detail_str = f"Z={details.get('z_score', 0.0):.2f} | Rel={details.get('rel_flag', False)} | Base={details.get('base', 0.0):.2f}"
    log_entry = {
        'timestamp': timestamp,
        'process_name': process_name[:30],
        'power_watts': f"{power_w:.2f}",
        'severity': severity,
        'details': detail_str
    }
    fieldnames = ['timestamp', 'process_name', 'power_watts', 'severity', 'details']
    try:
        with open(ANOMALY_LOG_PATH, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if is_new_file: writer.writeheader()
            writer.writerow(log_entry)
    except Exception as e:
        print(f"Error writing anomaly log: {e}")

# Baseline Persistence Functions
def load_baseline():
    res = {}
    if not BASELINE_PATH.exists(): return res
    with open(BASELINE_PATH, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row['process_name']
            res[name] = {
                'avg': float(row['avg_power']), 
                'samples': int(row['samples']),
                'M2': float(row.get('M2', 0.0))
            }
    return res

def save_baseline(baseline):
    with open(BASELINE_PATH, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['process_name','avg_power','samples','M2'])
        writer.writeheader()
        for name, data in baseline.items():
            writer.writerow({
                'process_name': name, 
                'avg_power': data['avg'], 
                'samples': data['samples'],
                'M2': data.get('M2', 0.0)
            })