# monitor.py
import psutil
from database import get_connection, create_table
from datetime import datetime
#deepak
class ProcessSnapshot:
    """A data structure to hold process metrics at a single point in time."""
    def __init__(self, name, pid, cpu_percent, mem_mb, io_rate_mb_s):
        self.name = name
        self.pid = pid
        self.cpu_percent = cpu_percent
        self.mem_mb = mem_mb
        self.io_rate_mb_s = io_rate_mb_s 

def sample_processes(prev_io_map, ignored_list, interval):
    """
    Samples all running processes, calculates I/O rate since the last sample, 
    and returns a dictionary of ProcessSnapshots and the updated cumulative I/O map.
    """
    snapshots = {}
    updated_io_map = {}
    ignored_list = set(ignored_list or [])
    
    for proc in psutil.process_iter(['name', 'pid', 'cpu_percent', 'memory_info', 'io_counters']):
        try:
            name = proc.info.get('name')
            pid = proc.info['pid']
            
            if name and name in ignored_list:
                continue
                
            io_counters = proc.io_counters()
            mem_mb = proc.memory_info().rss / (1024 * 1024)
            
            current_io_total = io_counters.read_bytes + io_counters.write_bytes
            
            # --- I/O RATE CALCULATION ---
            prev_io_total = prev_io_map.get(pid, 0)
            io_delta_bytes = max(0, current_io_total - prev_io_total)
            io_delta_mb = io_delta_bytes / (1024.0 * 1024.0)
            io_rate_mb_s = io_delta_mb / max(interval, 1e-6) 
            
            snapshots[pid] = ProcessSnapshot(
                name=name,
                pid=pid,
                cpu_percent=proc.info['cpu_percent'],
                mem_mb=mem_mb,
                io_rate_mb_s=io_rate_mb_s
            )
            
            updated_io_map[pid] = current_io_total
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
            
    return snapshots, updated_io_map

def estimate_power(snap, coeffs, interval):
    """
    Estimates process power consumption based on resource utilization.
    """
    cpu_w = coeffs.get('cpu_w_per_100pct', 45.0) * (snap.cpu_percent / 100.0)
    mem_gb = snap.mem_mb / 1024.0
    mem_w = coeffs.get('mem_w_per_gb', 2.0) * mem_gb
    io_w = coeffs.get('io_w_per_mb_s', 1.5) * snap.io_rate_mb_s
    
    estimated = max(0.0, cpu_w + mem_w + io_w)
    return estimated, {'cpu_w': cpu_w, 'mem_w': mem_w, 'io_w': io_w}

def get_system_stats(disk_path='/'):
    """Collects and returns key system-wide performance statistics."""
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    net = psutil.net_io_counters()

    try:
        disk = psutil.disk_usage(disk_path)
        disk_usage_pct = disk.percent
    except (FileNotFoundError, RuntimeError):
        print(f"Warning: Disk path '{disk_path}' could not be accessed. Defaulting usage to 0%.")
        disk_usage_pct = 0.0

    return {
        'cpu_percent': cpu,
        'mem_used_pct': mem.percent,
        'mem_total_gb': mem.total / (1024**3),
        'disk_usage_pct': disk_usage_pct,
        'net_sent_mb': net.bytes_sent / (1024**2),
        'net_recv_mb': net.bytes_recv / (1024**2),
    }

# =========================
# 🔵 DATABASE STORAGE PART
# =========================

def store_snapshot_to_db(snapshot, power_value):
    """
    Stores a single process snapshot and its estimated power into the database.
    """
    create_table()  # safe to call repeatedly

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO process_metrics
        (process_name, cpu, memory, power, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            snapshot.name,
            snapshot.cpu_percent,
            snapshot.mem_mb,
            power_value,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()
    conn.close()
   