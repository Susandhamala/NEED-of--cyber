import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
import os
import time
import threading

def run_keylogger_detector():
    detector_window = tk.Toplevel()
    detector_window.title("Keylogger Detector")
    detector_window.geometry("800x600")
    detector_window.configure(bg="#0f111a")
    
    KeyloggerDetector(detector_window)

class KeyloggerDetector:
    def __init__(self, parent):
        self.parent = parent
        self.monitoring = False
        self.setup_ui()
        self.suspicious_processes = [
            "keylogger", "logkeys", "keystroke", "keyboard", "inputlog",
            "spyware", "monitor", "capture", "record", "sniff",
            "softperfect", "revelation", "refog", "actualkeylogger",
            "winkey", "freekeylogger", "keylog", "passkey", "typekey"
        ]
        
    def setup_ui(self):
        main_frame = tk.Frame(self.parent, bg="#0f111a")
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(main_frame, text="🔍 Keylogger Detector", font=("Consolas", 16, "bold"),
                fg="#00fff7", bg="#0f111a").pack(pady=10)
        
        button_frame = tk.Frame(main_frame, bg="#0f111a")
        button_frame.pack(fill='x', pady=10)
        
        self.scan_btn = tk.Button(button_frame, text="Scan for Keyloggers", command=self.scan_keyloggers,
                                 bg="#141627", fg="#00fff7", font=("Consolas", 12))
        self.scan_btn.pack(side='left', padx=5)
        
        self.monitor_btn = tk.Button(button_frame, text="Start Real-time Monitoring", command=self.toggle_monitoring,
                                   bg="#141627", fg="#00fff7", font=("Consolas", 12))
        self.monitor_btn.pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Kill Suspicious Process", command=self.kill_process,
                 bg="#ff4444", fg="white", font=("Consolas", 12)).pack(side='left', padx=5)
        
        tk.Label(main_frame, text="Detected Processes:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(20,5))
        
        self.results_text = scrolledtext.ScrolledText(main_frame, height=20, bg="#1f2233", 
                                                     fg="#00fff7", font=("Consolas", 10))
        self.results_text.pack(fill='both', expand=True)
        
        self.detected_processes = []
        
    def scan_keyloggers(self):
        self.results_text.delete(1.0, tk.END)
        self.detected_processes = []
        
        self.results_text.insert(tk.END, "🔍 Scanning for potential keyloggers...\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        suspicious_found = False
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                name = proc.info['name'].lower()
                exe = proc.info['exe'] or ""
                cmdline = " ".join(proc.info['cmdline'] or []).lower()
                
                # Check for suspicious keywords
                for keyword in self.suspicious_processes:
                    if (keyword in name or 
                        keyword in exe.lower() or 
                        keyword in cmdline):
                        suspicious_found = True
                        process_info = {
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'exe': exe,
                            'reason': keyword
                        }
                        self.detected_processes.append(process_info)
                        
                        self.results_text.insert(tk.END, 
                            f"⚠️  SUSPICIOUS: {proc.info['name']} (PID: {proc.info['pid']})\n")
                        self.results_text.insert(tk.END, 
                            f"   Path: {exe}\n")
                        self.results_text.insert(tk.END, 
                            f"   Reason: Contains '{keyword}'\n\n")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        if not suspicious_found:
            self.results_text.insert(tk.END, "✅ No suspicious keylogger processes found.\n")
        else:
            self.results_text.insert(tk.END, f"\n🚨 Found {len(self.detected_processes)} suspicious processes!\n")
            self.results_text.insert(tk.END, "Consider investigating and terminating these processes.\n")
            
        self.parent.update()
        
    def toggle_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.monitor_btn.config(text="Stop Monitoring", bg="#ff4444")
            self.results_text.insert(tk.END, "🔄 Starting real-time process monitoring...\n")
            monitor_thread = threading.Thread(target=self.monitor_processes)
            monitor_thread.daemon = True
            monitor_thread.start()
        else:
            self.monitoring = False
            self.monitor_btn.config(text="Start Real-time Monitoring", bg="#141627")
            self.results_text.insert(tk.END, "⏹️ Stopped process monitoring.\n")
            
    def monitor_processes(self):
        known_processes = set()
        
        # Get initial processes
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                known_processes.add((proc.info['pid'], proc.info['name'].lower()))
            except:
                pass
                
        self.results_text.insert(tk.END, "📡 Monitoring for new suspicious processes...\n\n")
        
        while self.monitoring:
            try:
                current_processes = set()
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        proc_info = (proc.info['pid'], proc.info['name'].lower())
                        current_processes.add(proc_info)
                        
                        # Check if this is a new process
                        if proc_info not in known_processes:
                            name = proc.info['name'].lower()
                            for keyword in self.suspicious_processes:
                                if keyword in name:
                                    self.results_text.insert(tk.END, 
                                        f"🚨 NEW SUSPICIOUS PROCESS: {proc.info['name']} (PID: {proc.info['pid']})\n")
                                    self.parent.bell()
                                    break
                                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                        
                known_processes = current_processes
                time.sleep(2)
                
            except Exception as e:
                if self.monitoring:
                    self.results_text.insert(tk.END, f"Monitor error: {str(e)}\n")
                break
                
    def kill_process(self):
        if not self.detected_processes:
            messagebox.showwarning("Warning", "Please scan first to detect processes.", parent=self.parent)
            return
            
        # Show confirmation dialog with process list
        process_list = "\n".join([f"• {p['name']} (PID: {p['pid']})" for p in self.detected_processes])
        confirm = messagebox.askyesno("Confirm Kill", 
                                    f"Are you sure you want to terminate these processes?\n\n{process_list}",
                                    parent=self.parent)
        
        if confirm:
            killed_count = 0
            for proc_info in self.detected_processes:
                try:
                    process = psutil.Process(proc_info['pid'])
                    process.terminate()
                    process.wait(timeout=3)
                    killed_count += 1
                    self.results_text.insert(tk.END, f"💀 Killed: {proc_info['name']} (PID: {proc_info['pid']})\n")
                except psutil.NoSuchProcess:
                    self.results_text.insert(tk.END, f"⚠️  Already terminated: {proc_info['name']}\n")
                except psutil.AccessDenied:
                    self.results_text.insert(tk.END, f"❌ Access denied: {proc_info['name']} - Run as Administrator\n")
                except Exception as e:
                    self.results_text.insert(tk.END, f"❌ Error killing {proc_info['name']}: {str(e)}\n")
                    
            self.results_text.insert(tk.END, f"\n✅ Killed {killed_count} processes.\n\n")
            self.detected_processes = []  # Clear the list