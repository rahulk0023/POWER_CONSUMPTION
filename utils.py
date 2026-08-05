# utils.py
import time
import json
from pathlib import Path

def load_config(path="config.json"):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError("config.json not found")
    return json.loads(p.read_text())

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")
