# anomaly.py
import math
from collections import defaultdict

# --- HIGH SENSITIVITY CONSTANTS ---
MIN_STD_THRESHOLD = 0.0001
ABSOLUTE_POWER_THRESHOLD = 5.0
FAST_ALPHA = 0.1

class AnomalyDetector:
    def __init__(self, baseline=None, alpha=0.1, rel_threshold=0.5, z_threshold=3.0, min_samples=5):
        self.alpha = alpha
        self.rel_threshold = rel_threshold
        self.z_threshold = z_threshold
        self.min_samples = min_samples
        
        sanitized_baseline = {}
        
        CONTAMINATION_THRESHOLD = 50.0  
        
        if baseline:
            for name, data in baseline.items():
                if data.get('avg', 0.0) < CONTAMINATION_THRESHOLD:
                    sanitized_baseline[name] = data
                else:
                    print(f"[WARN] Baseline for {name} ignored (Contaminated: {data.get('avg'):.2f} W)")
        
        self.baseline = sanitized_baseline 
        
        self.stats = {}
        for name, data in self.baseline.items():
            self.stats[name] = {
                'n': data.get('samples', 1), 
                'mean': data.get('avg', 0.0), 
                'M2': data.get('M2', 0.0) 
            }

    def update_baseline(self, process_name, value):
        if process_name not in self.baseline:
            self.baseline[process_name] = {'avg': value, 'samples': 1, 'M2': 0.0}
            self.stats[process_name] = {'n': 1, 'mean': value, 'M2': 0.0}
            return

        prev_avg = self.baseline[process_name]['avg']
        new_avg = (1 - self.alpha) * prev_avg + self.alpha * value
        self.baseline[process_name]['avg'] = new_avg
        self.baseline[process_name]['samples'] += 1

        s = self.stats[process_name]
        s['n'] += 1
        delta = value - s['mean']
        s['mean'] += delta / s['n']
        s['M2'] += delta * (value - s['mean'])
        
        self.baseline[process_name]['M2'] = s['M2'] 

    def check_anomaly(self, process_name, value):
        
        # --- 1. NEW PROCESS / CONTAMINATED BASELINE CHECK ---
        if process_name not in self.baseline:
            if value >= ABSOLUTE_POWER_THRESHOLD:
                return True, {'reason': 'no_baseline_spike'} 
            return False, {'reason': 'no_baseline'}
            
        base = self.baseline[process_name]['avg']
        samples = self.baseline[process_name]['samples']
        
        if samples < self.min_samples:
            return False, {'reason':'insufficient_samples', 'samples': samples}

        # 2. Relative Rule 
        if base <= 0:
            rel_flag = value > self.rel_threshold
        else:
            rel_flag = value > base * (1 + self.rel_threshold)
            
        # 3. ABSOLUTE POWER CHECK (For high usage, independent of STD)
        absolute_flag = value > ABSOLUTE_POWER_THRESHOLD

        # 4. Z-score 
        s = self.stats.get(process_name)
        z_flag = False
        z_score = None
        
        if s and s['n'] > 1:
            variance = s['M2'] / (s['n'] - 1) if (s['n']-1) > 0 else 0.0
            std = variance**0.5
            
            stable_std = max(std, MIN_STD_THRESHOLD) 
            
            if stable_std > 1e-9:
                z_score = (value - s['mean']) / stable_std
                z_flag = abs(z_score) >= self.z_threshold

        # FINAL DECISION: Z-score OR Relative Rule OR Absolute Rule
        is_anom = rel_flag or z_flag or absolute_flag
        details = {'rel_flag': rel_flag, 'z_flag': z_flag, 'absolute_flag': absolute_flag, 
                   'z_score': z_score, 'base': base, 'samples': samples}
        return is_anom, details