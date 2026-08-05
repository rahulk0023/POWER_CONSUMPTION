# app.py
import sys
import os
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import psutil
import atexit 
import math


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import load_config
from anomaly import AnomalyDetector
import monitor 
import logger 

# --- NEW LIGHT MODE COLOR DEFINITIONS ---
BG_ROOT = "#F7F9FB"         
BG_PANEL = "#FFFFFF"        
FG_PRIMARY = "#1E1E1E"      
FG_SECONDARY = "#555555"    
FG_HEADING = "#0078D7"      
BTN_START = "#4CAF50"       
BTN_STOP = "#F44336"        
TABLE_HEADER_BG = "#E3F2FD" 
TABLE_ROW_HOVER = "#F1F8FF" 
BORDER_DIVIDER = "#DDDDDD"  
GRAPH_LINE_RT = "#0078D7"   
GRAPH_LINE_EMA = "#FF9800"  
GRAPH_FILL = "#FFCDD2"      
ALERT_HIGH_ROW = "#FDECEA"  
ALERT_HIGH_TEXT = "#F44336" 
ALERT_MEDIUM_BG = "#FFF59D" 
ALERT_OK_TEXT = "#4CAF50"   


#  Power Monitoring

class PowerMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Process-Level Power Consumption Analyzer")
        self.root.geometry("1200x850") 
        self.root.configure(bg=BG_ROOT) 

        self.is_running = False
        self.monitor_thread = None
        self.prev_io_map = {} 
        self.alert_triggered_time = 0
        
        self.total_estimated_power = 0.0
        self.max_power_seen = 0.0
        
        # --- History and Anomaly Counters ---
        self.history_data = {}  
        self.anomaly_counts = {'HIGH': 0, 'MEDIUM': 0}
        self.consecutive_high_anomaly_count = {} 
        self.SUSTAINED_THRESHOLD = 10

        try:
            self.config = load_config()
        except FileNotFoundError:
            messagebox.showerror("Error", "config.json not found. Application cannot start.")
            sys.exit(1)
            
        self.coeffs = self.config['estimation_coeffs']
        self.poll_interval = self.config['poll_interval_sec']
        self.disk_to_monitor = self.config.get('disk_to_monitor', '/')
        self.ignored_processes = self.config.get('ignored_processes', [])
        
        self.critical_system_names = {
            'wininit.exe', 'csrss.exe', 'smss.exe', 'winlogon.exe', 'lsass.exe', 
            'services.exe', 'System', 'ntoskrnl.exe', 'dwm.exe', 'init', 
            'systemd', 'kernel', 'kworker', 'Xorg', 'gnome-shell', 'sshd',
            'fontdrvhost.exe' 
        } #these are non killable 
        
        initial_baseline = logger.load_baseline()
        
        anomaly_cfg = self.config['anomaly']
        
        self.anomaly_detector = AnomalyDetector(
            baseline=initial_baseline,
            alpha=anomaly_cfg['ema_alpha'],
            rel_threshold=anomaly_cfg['relative_threshold_pct'],
            z_threshold=anomaly_cfg['zscore_threshold'],
            min_samples=anomaly_cfg['min_samples_for_baseline']
        )
        
        self.medium_z_threshold = 2.0 
        self.high_z_threshold = self.anomaly_detector.z_threshold 
        
        atexit.register(self.save_state_on_exit)

        self.time_data = []
        self.power_data = []
        self.baseline_power_data = []
        self.total_power_ema = 0.0
        self.ema_alpha_system = 0.02

        self.create_widgets()
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.on_double_click)
        self.anomaly_tree.bind("<Button-3>", self.show_context_menu)
        
        print(f"Monitoring initialized. Poll interval: {self.poll_interval}s. Baselines loaded: {len(initial_baseline)}")

    def save_state_on_exit(self):
        if self.anomaly_detector:
            baseline_data_to_save = {
                name: {**data, **self.anomaly_detector.stats.get(name, {})}
                for name, data in self.anomaly_detector.baseline.items()
            }
            logger.save_baseline(baseline_data_to_save)
            
    def __del__(self):
        try:
            self.stop_monitoring()
        except AttributeError:
            pass 
     #what not to kill       
    def is_system_critical(self, name):
        if name in self.critical_system_names: return True
        if name in self.ignored_processes: return True
        if name.lower() == 'python.exe' and os.path.basename(sys.argv[0]) in name: return True
        return False

    def start_monitoring(self):
        if not self.is_running:
            self.is_running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("Monitoring started.")

    def stop_monitoring(self):
        if self.is_running:
            self.is_running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.save_state_on_exit()
            print("Monitoring stopped and baseline saved.")
            
    def trigger_alert(self, process_name, power_w):
        if time.time() - self.alert_triggered_time > 120:
            self.alert_triggered_time = time.time()
            messagebox.showwarning(
                " HIGH ANOMALY DETECTED ",
                f"Process: {process_name} is showing unusually high power consumption.\n"
                f"Estimated Power: {power_w:.2f} W"
            )

    def handle_sustained_anomaly(self, pid, name, power_w):
        if time.time() - self.alert_triggered_time < 20:
            return
            
        is_critical = self.is_system_critical(name)

        self.alert_triggered_time = time.time()
        
        pid_str = str(pid)
        
        top = tk.Toplevel(self.root)
        top.title("SUSTAINED CRITICAL THREAT")
        top.configure(bg=BTN_STOP, padx=20, pady=20) 
        
        tk.Label(top, text="WARNING: PROCESS IS PERSISTENTLY HIGHLY ANOMALOUS", 
                 font=("Helvetica", 14, "bold"), bg=BTN_STOP, fg=BG_PANEL).pack(pady=(0, 10)) 
                 
        tk.Label(top, text=f"Process: {name} (PID: {pid_str})\nSustained Power: {power_w:.2f} W",
                 font=("Helvetica", 12), bg=BTN_STOP, fg=BG_PANEL).pack(pady=(0, 15)) 

        tk.Label(top, text=f"This process has triggered {self.SUSTAINED_THRESHOLD} consecutive HIGH anomalies. Please choose an action:",
                 font=("Helvetica", 10), bg=BTN_STOP, fg=BG_PANEL).pack(pady=(0, 20)) 

        button_frame = tk.Frame(top, bg=BTN_STOP) 
        button_frame.pack()
        
        def ignore_process_and_destroy():
            self.ignored_processes.append(name)
            self.consecutive_high_anomaly_count.pop(name, None) 
            messagebox.showinfo("Ignored", f"Process '{name}' added to ignored_processes list. Please update config.json manually for permanent change.")
            top.destroy()
            
        def kill_and_destroy():
            self.kill_process(pid_str, name) 
            self.consecutive_high_anomaly_count.pop(name, None) 
            top.destroy()
            
        kill_button_text = "TERMINATE PROCESS" if not is_critical else "CRITICAL (CANNOT KILL)"
        kill_button_color = BTN_STOP if not is_critical else FG_SECONDARY
        kill_button_state = tk.NORMAL if not is_critical else tk.DISABLED
        
        tk.Button(button_frame, text=kill_button_text, command=kill_and_destroy if not is_critical else None,
                  bg=kill_button_color, fg=BG_PANEL, font=("Helvetica", 11, "bold"), state=kill_button_state).grid(row=0, column=0, padx=10)
                 
        tk.Button(button_frame, text="IGNORE PROCESS (Temporary)", command=ignore_process_and_destroy,
                  bg=ALERT_MEDIUM_BG, fg=FG_PRIMARY, font=("Helvetica", 11, "bold")).grid(row=0, column=1, padx=10)


    def confirm_and_kill_anomaly(self, pid, name, power_w):
        if time.time() - self.alert_triggered_time < 20:
            return
            
        self.alert_triggered_time = time.time()
        
        pid_str = str(pid)
        
        top = tk.Toplevel(self.root)
        top.title("CRITICAL UNKNOWN ANOMALY")
        top.configure(bg=BTN_STOP, padx=20, pady=20) 
        
        tk.Label(top, text="DANGER: UNKNOWN PROCESS HIGH ANOMALY DETECTED", 
                 font=("Helvetica", 14, "bold"), bg=BTN_STOP, fg=BG_PANEL).pack(pady=(0, 10)) 
                 
        tk.Label(top, text=f"Process: {name} (PID: {pid_str})\nEstimated Power: {power_w:.2f} W",
                 font=("Helvetica", 12), bg=BTN_STOP, fg=BG_PANEL).pack(pady=(0, 15)) 

        tk.Label(top, text="This is a NEW process showing EXTREMELY HIGH resource usage. Do you want to terminate it?",
                 font=("Helvetica", 10), bg=BTN_STOP, fg=BG_PANEL).pack(pady=(0, 20)) 

        button_frame = tk.Frame(top, bg=BTN_STOP) 
        button_frame.pack()
        
        def kill_and_destroy():
            self.kill_process(pid_str, name)
            top.destroy()
            
        tk.Button(button_frame, text="TERMINATE PROCESS", command=kill_and_destroy,
                  bg=BTN_STOP, fg=BG_PANEL, font=("Helvetica", 11, "bold")).grid(row=0, column=0, padx=10)
                 
        tk.Button(button_frame, text="Ignore (Allow to Learn)", command=top.destroy,
                  bg=FG_SECONDARY, fg=BG_PANEL, font=("Helvetica", 11)).grid(row=0, column=1, padx=10)

    def create_widgets(self):
        title = tk.Label(
            self.root,
            text="Process-Level Power Consumption Monitor",
            font=("Helvetica", 20, "bold"),
            bg=BG_ROOT, 
            fg=FG_HEADING 
        )
        title.pack(pady=(10, 5))

        button_frame = tk.Frame(self.root, bg=BG_ROOT) 
        button_frame.pack(pady=5)

        self.start_btn = tk.Button(
            button_frame, text="Start Monitoring", font=("Helvetica", 12, "bold"),
            bg=BTN_START, fg=BG_PANEL, width=18, command=self.start_monitoring 
        )
        self.start_btn.grid(row=0, column=0, padx=10)

        self.stop_btn = tk.Button(
            button_frame, text="Stop Monitoring (Saves Baseline)", font=("Helvetica", 12, "bold"),
            bg=BTN_STOP, fg=BG_PANEL, width=25, command=self.stop_monitoring, state=tk.DISABLED 
        )
        self.stop_btn.grid(row=0, column=1, padx=10)

        # 1. System Statistics Dashboard
        self.stats_frame = tk.Frame(self.root, bg=BG_ROOT) 
        self.stats_frame.pack(pady=10, padx=20, fill="x")

        col_settings = [
            ("cpu_percent", FG_PRIMARY, "CPU Usage"),
            ("mem_used_pct", FG_PRIMARY, "Memory Used"),
            ("disk_usage_pct", FG_PRIMARY, "Disk Usage"),
            ("net_sent_mb", FG_PRIMARY, "Net Sent (MB)"),
            ("total_power", FG_HEADING, "Total Power (W)"), 
            ("high_alerts", BTN_STOP, "HIGH Alerts"), 
            ("medium_alerts", FG_SECONDARY, "MEDIUM Alerts"), 
        ]
        
        self.stats_labels = {}
        for i, (key, color, description) in enumerate(col_settings):
            
            label_value = tk.Label(self.stats_frame, text="---", font=("Helvetica", 10, "bold"), bg=BG_ROOT, fg=color) 
            label_value.grid(row=0, column=i * 2, padx=(20, 0), sticky="w")
            self.stats_labels[key] = label_value
            
            if key not in ["high_alerts", "medium_alerts"]:
                label_desc = tk.Label(self.stats_frame, text=description, font=("Helvetica", 10), bg=BG_ROOT, fg=FG_SECONDARY) 
                label_desc.grid(row=0, column=(i * 2) + 1, padx=(0, 20), sticky="w")


        # 2. Main Data Area 
        main_data_frame = tk.Frame(self.root, bg=BG_ROOT) 
        main_data_frame.pack(pady=10, padx=20, fill="x")

        main_data_frame.grid_columnconfigure(0, weight=3) 
        main_data_frame.grid_columnconfigure(1, weight=1) 
        main_data_frame.grid_rowconfigure(0, weight=1)

        # 2A. LEFT SIDE 
        left_side_frame = tk.Frame(main_data_frame, bg=BG_ROOT) 
        left_side_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_side_frame.grid_rowconfigure(3, weight=1)
        left_side_frame.grid_columnconfigure(0, weight=1)
        
        # Header: Unique Processes
        unique_label = tk.Label(left_side_frame, text="Unique Processes (Baseline)", font=("Helvetica", 10, "bold"), bg=BG_ROOT, fg=FG_PRIMARY) 
        unique_label.grid(row=0, column=0, padx=0, pady=(0, 2), sticky="w")
        
        # 2A.1. Unique Process List
        self.unique_process_list = tk.Listbox(left_side_frame, height=5, bg=BG_PANEL, fg=FG_PRIMARY, selectbackground=TABLE_ROW_HOVER, highlightthickness=0) 
        self.unique_process_list.grid(row=1, column=0, sticky="ew") 
        
        # Header: Real-time Process Table
        rt_label = tk.Label(left_side_frame, text="Real-time Processes", font=("Helvetica", 10, "bold"), bg=BG_ROOT, fg=FG_PRIMARY) 
        rt_label.grid(row=2, column=0, padx=0, pady=(5, 2), sticky="w")

        # 2A.2. Real-time Process Table
        style = ttk.Style()
        style.configure("Treeview", background=BG_PANEL, foreground=FG_PRIMARY, fieldbackground=BG_PANEL, rowheight=25) 
        style.map('Treeview', background=[('selected', TABLE_ROW_HOVER)]) 

        style.configure("Treeview.Heading", background=TABLE_HEADER_BG, foreground=FG_PRIMARY, font=('Helvetica', 10, 'bold')) 

        columns = ("PID", "Name", "CPU%", "Mem (MB)", "Power (W)", "Anomaly")
        self.tree = ttk.Treeview(left_side_frame, columns=columns, show="headings", height=12, style="Treeview") 
        
        self.tree.tag_configure('normal', background=BG_PANEL, foreground=FG_PRIMARY) 
        self.tree.tag_configure('medium', background=ALERT_MEDIUM_BG, foreground=FG_PRIMARY) 
        self.tree.tag_configure('high', background=ALERT_HIGH_ROW, foreground=FG_PRIMARY) 

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.CENTER)
            
        self.tree.column("Name", anchor=tk.W) 
        self.tree.column("PID", width=70)
        self.tree.grid(row=3, column=0, sticky="nsew")
        
        tree_scroll = ttk.Scrollbar(left_side_frame, orient="vertical", command=self.tree.yview)
        tree_scroll.grid(row=3, column=1, sticky='ns')
        self.tree.configure(yscrollcommand=tree_scroll.set)


        # 2B. RIGHT SIDE - High Anomaly Table
        anomaly_container = tk.Frame(main_data_frame, bg=BG_ROOT) 
        anomaly_container.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        anomaly_container.grid_rowconfigure(1, weight=1)
        anomaly_container.grid_columnconfigure(0, weight=1)
        
        anomaly_label = tk.Label(anomaly_container, text="CURRENT HIGH ANOMALIES", font=("Helvetica", 10, "bold"), bg=BG_ROOT, fg=BTN_STOP) 
        anomaly_label.grid(row=0, column=0, sticky="w", pady=(0, 2))
        
        anomaly_cols = ("PID", "Name", "Power (W)")
        self.anomaly_tree = ttk.Treeview(anomaly_container, columns=anomaly_cols, show="headings", height=20, style="Treeview")
        self.anomaly_tree.tag_configure('high', background=ALERT_HIGH_ROW, foreground=FG_PRIMARY) 

        for col in anomaly_cols:
            self.anomaly_tree.heading(col, text=col)
            self.anomaly_tree.column(col, anchor=tk.CENTER)
        
        self.anomaly_tree.column("Name", anchor=tk.W)
        self.anomaly_tree.column("PID", width=60)
        self.anomaly_tree.grid(row=1, column=0, sticky="nsew")
        
        anomaly_scroll = ttk.Scrollbar(anomaly_container, orient="vertical", command=self.anomaly_tree.yview)
        anomaly_scroll.grid(row=1, column=1, sticky='ns')
        self.anomaly_tree.configure(yscrollcommand=anomaly_scroll.set)


        # 3. Real-time Power Graph (Bottom)
        bottom_frame = tk.Frame(self.root, bg=BG_ROOT) 
        bottom_frame.pack(pady=10, padx=20, fill="both", expand=True)
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_rowconfigure(0, weight=1)

        self.fig, self.ax = plt.subplots(figsize=(1, 1))
        
        self.fig.patch.set_facecolor(BG_PANEL) 
        self.ax.set_facecolor(BG_PANEL) 
        self.ax.tick_params(colors=FG_SECONDARY) 
        self.ax.spines['bottom'].set_color(BORDER_DIVIDER) 
        self.ax.spines['left'].set_color(BORDER_DIVIDER) 
        self.ax.grid(True, color=BORDER_DIVIDER, linestyle=':', linewidth=0.5) 
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=bottom_frame)
        self.canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew")


    def show_context_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            item_id = self.anomaly_tree.identify_row(event.y)
            tree_target = self.anomaly_tree if item_id else None
        else:
            tree_target = self.tree

        if not item_id: return
        
        tree_target.selection_set(item_id)
        values = tree_target.item(item_id, 'values')
        if not values: return
            
        pid = values[0]
        name = values[1]
        
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(
            label=f"Kill Process: {name} (PID: {pid})", 
            command=lambda: self.kill_process(pid, name)
        )
        
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def kill_process(self, pid_str, name):
        if self.is_system_critical(name):
            messagebox.showerror(
                "CRITICAL SYSTEM PROCESS", 
                f"Cannot terminate core OS process '{name}' (PID {pid_str}). Termination is blocked for system stability."
            )
            print(f"WARNING: Attempted to kill critical system process: {name}")
            return
        
        try:
            pid = int(pid_str)
            process = psutil.Process(pid)
            process.terminate()
            messagebox.showinfo("Success", f"Process '{name}' (PID {pid}) terminated successfully.")
        except psutil.NoSuchProcess:
            messagebox.showerror("Error", f"Process '{name}' (PID {pid}) no longer exists.")
        except psutil.AccessDenied:
            messagebox.showerror("Access Denied", f"Access Denied: Cannot terminate process '{name}' (PID {pid}). Please run the application as Administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to kill process '{name}' (PID {pid}): {e}")

    def on_double_click(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            item_id = self.anomaly_tree.identify_row(event.y)
            tree_target = self.anomaly_tree if item_id else None
        else:
            tree_target = self.tree
            
        if not item_id: return
        
        values = tree_target.item(item_id, 'values')
        if not values: return
            
        process_name = values[1]
        self.show_process_history(process_name)

    def show_process_history(self, name):
        history = self.history_data.get(name, [])
        if len(history) < 2:
            messagebox.showinfo("History Unavailable", f"Insufficient data to graph history for {name}. Please wait for more samples.")
            return

        top = tk.Toplevel(self.root)
        top.title(f"Power History: {name}")
        top.geometry("600x350")
        top.configure(bg=BG_ROOT) 
        
        fig_hist, ax_hist = plt.subplots(figsize=(5, 3))
        ax_hist.plot(history, color=GRAPH_LINE_RT, linewidth=2) 
        ax_hist.set_title(f"Power Consumption: {name} (Last {len(history)} samples)", color=FG_PRIMARY)
        ax_hist.set_xlabel("Samples", color=FG_SECONDARY)
        ax_hist.set_ylabel("Power (W)", color=FG_SECONDARY)
        ax_hist.set_facecolor(BG_PANEL)
        ax_hist.tick_params(colors=FG_SECONDARY)
        ax_hist.spines['bottom'].set_color(BORDER_DIVIDER)
        ax_hist.spines['left'].set_color(BORDER_DIVIDER)
        ax_hist.grid(True, color=BORDER_DIVIDER, linestyle=':', linewidth=0.5)
        
        canvas = FigureCanvasTkAgg(fig_hist, master=top)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    # MONITORING LOOP (Includes diagnostics)
    def monitor_loop(self):
        while self.is_running:
            try:
                snapshots, updated_io_map = monitor.sample_processes(self.prev_io_map, self.ignored_processes, self.poll_interval)
                total_power = 0
                current_time_str = time.strftime("%Y-%m-%d %H:%M:%S")
                
                logger.log_all_samples(current_time_str, snapshots, self.coeffs, self.poll_interval)
                
                self.tree.delete(*self.tree.get_children())
                self.anomaly_tree.delete(*self.anomaly_tree.get_children())
                
                current_high_alerts = 0
                current_medium_alerts = 0
                sampled_process_names = set() 

                for pid, snap in snapshots.items():
                    sampled_process_names.add(snap.name)
                    power_w, _ = monitor.estimate_power(snap, self.coeffs, self.poll_interval)
                    total_power += power_w
                    
                    is_anomaly, details = self.anomaly_detector.check_anomaly(snap.name, power_w)
                    
                    # --- DIAGNOSTIC PRINTING START ---
                    if snap.name.lower() == 'python.exe' and snap.cpu_percent > 10.0:
                        detector_stats = self.anomaly_detector.stats.get(snap.name, {})
                        n = detector_stats.get('n', 0)
                        M2 = detector_stats.get('M2', 0.0)
                        std = math.sqrt(M2 / (n - 1)) if n > 1 else 0.0

                        print(f"\n[DIAGNOSTIC] Process: {snap.name} (PID: {pid})")
                        print(f"   Current Power (W): {power_w:.2f}")
                        print(f"   Baseline Avg (W): {detector_stats.get('mean', 0.0):.2f}")
                        print(f"   STD: {std:.4f}, Samples: {n}")
                        print(f"   Z-Score: {details.get('z_score', 'N/A'):.2f}, Z-Threshold: {self.high_z_threshold}")
                        print(f"   Relative Flag: {details.get('rel_flag', False)}")
                        print(f"   Absolute Flag: {details.get('absolute_flag', False)}")
                        print(f"   Anomaly Detected? {is_anomaly} (Reason: {details.get('reason', 'N/A')})")
                    # --- DIAGNOSTIC PRINTING END ---
                    
                    reason = details.get('reason', '')
                    
                    is_critical_anomaly = False

                    if reason == 'no_baseline_spike' and power_w > 0: # Checks for the forced absolute anomaly on a new process
                        if not self.is_system_critical(snap.name):
                            self.root.after(0, lambda p=pid, n=snap.name, w=power_w: self.confirm_and_kill_anomaly(p, n, w))
                            is_critical_anomaly = True
                        
                    if not is_critical_anomaly:
                        self.anomaly_detector.update_baseline(snap.name, power_w)

                    if snap.name not in self.history_data: self.history_data[snap.name] = []
                    history = self.history_data[snap.name]
                    history.append(power_w)
                    if len(history) > 30: history.pop(0)

                    anomaly_text = "OK" 
                    tag = 'normal'
                    severity = 'NORMAL'
                    
                    if is_anomaly:
                        z_score = abs(details.get('z_score')) if details.get('z_score') is not None else 0
                        samples = details.get('samples', 0)
                        
                        if reason == 'no_baseline' or reason == 'insufficient_samples':
                            anomaly_text = f"Learning"
                            tag = 'medium'
                            severity = 'LEARNING'
                            self.consecutive_high_anomaly_count[snap.name] = 0 
                            
                        elif z_score >= self.high_z_threshold:
                            anomaly_text = "ANOMALY"
                            tag = 'high'
                            severity = 'HIGH'
                            current_high_alerts += 1
                            
                            self.consecutive_high_anomaly_count[snap.name] = self.consecutive_high_anomaly_count.get(snap.name, 0) + 1
                            
                            if self.consecutive_high_anomaly_count[snap.name] >= self.SUSTAINED_THRESHOLD:
                                self.root.after(0, lambda p=pid, n=snap.name, w=power_w: self.handle_sustained_anomaly(p, n, w))
                                
                            self.anomaly_tree.insert("", tk.END, values=(
                                pid, snap.name[:20], f"{power_w:.2f}"
                            ), tags=('high',))

                            
                        elif z_score >= self.medium_z_threshold or details.get('rel_flag'):
                            anomaly_text = "MEDIUM"
                            tag = 'medium'
                            severity = 'MEDIUM'
                            current_medium_alerts += 1
                            self.consecutive_high_anomaly_count[snap.name] = 0 
                        
                        if severity in ('HIGH', 'MEDIUM', 'LEARNING'):
                            logger.log_anomaly(current_time_str, snap.name, power_w, severity, details)
                            
                        else:
                            self.consecutive_high_anomaly_count[snap.name] = 0


                    self.tree.insert(
                        "", tk.END, 
                        values=(pid, snap.name[:20], f"{snap.cpu_percent:.1f}", f"{snap.mem_mb:.1f}", f"{power_w:.2f}", anomaly_text),
                        tags=(tag,)
                    )

                for name in list(self.consecutive_high_anomaly_count.keys()):
                    if name not in sampled_process_names:
                         self.consecutive_high_anomaly_count.pop(name, None)

                self.prev_io_map = updated_io_map

                self.update_unique_process_list()

                if self.total_power_ema == 0.0:
                    self.total_power_ema = total_power
                else:
                    self.total_power_ema = (1 - self.ema_alpha_system) * self.total_power_ema + \
                                             self.ema_alpha_system * total_power

                system_stats = monitor.get_system_stats(self.disk_to_monitor) 
                
                self.total_estimated_power = total_power
                self.max_power_seen = max(self.max_power_seen, total_power)
                
                self.anomaly_counts['HIGH'] += current_high_alerts
                self.anomaly_counts['MEDIUM'] += current_medium_alerts

                self.stats_labels['cpu_percent'].config(text=f"{system_stats['cpu_percent']:.1f}%", fg=FG_PRIMARY) 
                self.stats_labels['mem_used_pct'].config(
                    text=f"{system_stats['mem_used_pct']:.1f}% ({system_stats['mem_total_gb']:.1f} GB Total)",
                    fg=FG_PRIMARY
                )
                self.stats_labels['disk_usage_pct'].config(text=f"{system_stats['disk_usage_pct']:.1f}%", fg=FG_PRIMARY)
                self.stats_labels['net_sent_mb'].config(text=f"{system_stats['net_sent_mb']:.1f}", fg=FG_PRIMARY)
                
                self.stats_labels['total_power'].config(text=f"{total_power:.2f} W (Max: {self.max_power_seen:.2f} W)", fg=FG_HEADING)
                
                self.stats_labels['high_alerts'].config(text=f"{self.anomaly_counts['HIGH']}", fg=BTN_STOP)
                self.stats_labels['medium_alerts'].config(text=f"{self.anomaly_counts['MEDIUM']}", fg=FG_SECONDARY)


                current_time = time.time()
                self.time_data.append(current_time)
                self.power_data.append(total_power)
                self.baseline_power_data.append(self.total_power_ema)
                
                if len(self.time_data) > 100:  
                    self.time_data.pop(0)
                    self.power_data.pop(0)
                    self.baseline_power_data.pop(0)

                self.ax.clear()

                start_time = self.time_data[0] if self.time_data else current_time
                relative_time = [t - start_time for t in self.time_data]
                
                self.ax.plot(relative_time, self.power_data, color=GRAPH_LINE_RT, linewidth=2, label="Real-time Power") 
                self.ax.plot(relative_time, self.baseline_power_data, color=GRAPH_LINE_EMA, linestyle='--', linewidth=1.5, label="EMA Baseline") 
                
                self.ax.fill_between(
                    relative_time, 
                    self.power_data, 
                    self.baseline_power_data, 
                    where=[(p > b) for p, b in zip(self.power_data, self.baseline_power_data)],
                    facecolor=GRAPH_FILL, 
                    alpha=0.6, 
                    label='Power Exceeds Baseline'
                )

                self.ax.set_facecolor(BG_PANEL) 
                self.ax.tick_params(colors=FG_SECONDARY)
                self.ax.spines['bottom'].set_color(BORDER_DIVIDER)
                self.ax.spines['left'].set_color(BORDER_DIVIDER)
                self.ax.grid(True, color=BORDER_DIVIDER, linestyle=':', linewidth=0.5)

                self.ax.legend(loc="upper left", framealpha=0.8, labelcolor=FG_PRIMARY)

                self.ax.set_title("Real-time Total Power Consumption vs. Baseline", color=FG_PRIMARY)
                self.ax.set_xlabel(f"Time (s) - Poll Interval: {self.poll_interval}s", color=FG_SECONDARY)
                self.ax.set_ylabel("Total Power (W)", color=FG_SECONDARY)
                
                self.canvas.draw()

                time.sleep(self.poll_interval)

            except Exception as e:
                print(f"Error in monitor loop: {e}", file=sys.stderr)
                time.sleep(self.poll_interval) 

    def update_unique_process_list(self):
        unique_names = sorted(self.anomaly_detector.baseline.keys())
        current_items = set(self.unique_process_list.get(0, tk.END))
        new_items_with_samples = [f"{name[:25]} ({self.anomaly_detector.baseline.get(name, {}).get('samples', 0)} samples)" for name in unique_names]
        if set(new_items_with_samples) == current_items:
            return

        self.unique_process_list.delete(0, tk.END)
        for item in new_items_with_samples:
            self.unique_process_list.insert(tk.END, item)


# Main Execution
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = PowerMonitorApp(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application crashed: {str(e)}")