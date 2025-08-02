import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import socket

def run_network_sniffer():
    sniffer_window = tk.Toplevel()
    sniffer_window.title("Network Sniffer")
    sniffer_window.geometry("900x700")
    sniffer_window.configure(bg="#0f111a")
    
    NetworkSniffer(sniffer_window)

class NetworkSniffer:
    def __init__(self, parent):
        self.parent = parent
        self.sniffing = False
        self.packet_count = 0
        self.setup_ui()
        
    def setup_ui(self):
        main_frame = tk.Frame(self.parent, bg="#0f111a")
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(main_frame, text="📡 Network Sniffer", font=("Consolas", 16, "bold"),
                fg="#00fff7", bg="#0f111a").pack(pady=10)
        
        # Controls
        control_frame = tk.Frame(main_frame, bg="#0f111a")
        control_frame.pack(fill='x', pady=10)
        
        self.start_btn = tk.Button(control_frame, text="Start Sniffing", command=self.toggle_sniffing,
                                  bg="#141627", fg="#00fff7", font=("Consolas", 12))
        self.start_btn.pack(side='left', padx=5)
        
        tk.Button(control_frame, text="Clear", command=self.clear_output,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Filter options
        filter_frame = tk.Frame(main_frame, bg="#0f111a")
        filter_frame.pack(fill='x', pady=5)
        
        tk.Label(filter_frame, text="Protocol Filter:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.protocol_var = tk.StringVar(value="All")
        protocols = ["All", "TCP", "UDP", "ICMP", "HTTP"]
        self.protocol_combo = ttk.Combobox(filter_frame, textvariable=self.protocol_var,
                                          values=protocols, state='readonly', width=10)
        self.protocol_combo.pack(side='left', padx=10)
        
        # Interface selection
        interface_frame = tk.Frame(main_frame, bg="#0f111a")
        interface_frame.pack(fill='x', pady=5)
        
        tk.Label(interface_frame, text="Interface:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.interface_var = tk.StringVar()
        interfaces = self.get_network_interfaces()
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var,
                                          values=interfaces, state='readonly', width=20)
        self.interface_combo.pack(side='left', padx=10)
        if interfaces:
            self.interface_var.set(interfaces[0])
        
        # Output area
        tk.Label(main_frame, text="Captured Packets:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(20,5))
        
        self.results_text = scrolledtext.ScrolledText(main_frame, height=25, bg="#1f2233", 
                                                     fg="#00fff7", font=("Consolas", 10))
        self.results_text.pack(fill='both', expand=True)
        
        # Stats
        self.stats_frame = tk.Frame(main_frame, bg="#0f111a")
        self.stats_frame.pack(fill='x', pady=5)
        
        self.stats_label = tk.Label(self.stats_frame, text="Packets: 0", font=("Consolas", 10),
                                   fg="#00ff9d", bg="#0f111a")
        self.stats_label.pack(side='left')
        
    def get_network_interfaces(self):
        try:
            # Get network interfaces
            from scapy.all import get_if_list
            interfaces = get_if_list()
            if interfaces:
                return interfaces
        except:
            pass
            
        # Fallback method
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return [f"Default ({local_ip})"]
        except:
            return ["Default"]
        
    def toggle_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_btn.config(text="Stop Sniffing", bg="#ff4444")
            self.results_text.insert(tk.END, "🔄 Starting packet capture...\n")
            self.packet_count = 0
            self.update_stats()
            
            sniff_thread = threading.Thread(target=self.start_sniffing)
            sniff_thread.daemon = True
            sniff_thread.start()
        else:
            self.sniffing = False
            self.start_btn.config(text="Start Sniffing", bg="#141627")
            self.results_text.insert(tk.END, "⏹️ Stopped packet capture.\n\n")
            
    def start_sniffing(self):
        try:
            interface = self.interface_var.get().split(' ')[0] if self.interface_var.get() else None
            
            # Start sniffing with callback
            sniff(prn=self.packet_callback, 
                  iface=interface if interface and interface != "Default" else None,
                  stop_filter=lambda x: not self.sniffing,
                  store=0)  # Don't store packets in memory
                  
        except PermissionError:
            self.results_text.insert(tk.END, "❌ Permission denied. Run as administrator/root.\n")
            self.sniffing = False
            self.start_btn.config(text="Start Sniffing", bg="#141627")
        except Exception as e:
            self.results_text.insert(tk.END, f"❌ Error starting sniffer: {str(e)}\n")
            self.sniffing = False
            self.start_btn.config(text="Start Sniffing", bg="#141627")
            
    def packet_callback(self, packet):
        if not self.sniffing:
            return
            
        self.packet_count += 1
        self.update_stats()
        
        # Filter packets
        protocol_filter = self.protocol_var.get()
        
        try:
            # Process IP packets
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Protocol filtering
                if protocol_filter != "All":
                    if protocol_filter == "TCP" and TCP not in packet:
                        return
                    elif protocol_filter == "UDP" and UDP not in packet:
                        return
                    elif protocol_filter == "ICMP" and ICMP not in packet:
                        return
                    elif protocol_filter == "HTTP" and (TCP not in packet or not self.is_http_packet(packet)):
                        return
                
                # Build packet info
                packet_info = f"[{time.strftime('%H:%M:%S')}] "
                packet_info += f"{src_ip} -> {dst_ip} "
                
                # Add protocol info
                if TCP in packet:
                    packet_info += f"(TCP {packet[TCP].sport} -> {packet[TCP].dport})"
                    if self.is_http_packet(packet):
                        packet_info += " [HTTP]"
                elif UDP in packet:
                    packet_info += f"(UDP {packet[UDP].sport} -> {packet[UDP].dport})"
                elif ICMP in packet:
                    packet_info += f"(ICMP Type {packet[ICMP].type})"
                else:
                    packet_info += f"(IP Proto {protocol})"
                    
                # Add payload info for HTTP
                if TCP in packet and self.is_http_packet(packet):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if payload:
                            lines = payload.split('\n')
                            if lines:
                                packet_info += f"\n   HTTP: {lines[0][:50]}..."
                    except:
                        pass
                        
                self.results_text.insert(tk.END, packet_info + "\n")
                
                # Auto-scroll but not too frequently
                if self.packet_count % 10 == 0:
                    self.results_text.see(tk.END)
                    self.parent.update()
                    
        except Exception as e:
            # Don't flood the UI with errors
            if self.packet_count % 100 == 0:
                self.results_text.insert(tk.END, f"Packet processing error: {str(e)}\n")
                
    def is_http_packet(self, packet):
        if TCP in packet and Raw in packet:
            try:
                payload = packet[Raw].load
                if b'HTTP' in payload[:10] or b'GET' in payload[:4] or b'POST' in payload[:5]:
                    return True
            except:
                pass
        return False
        
    def update_stats(self):
        self.stats_label.config(text=f"Packets: {self.packet_count}")
        
    def clear_output(self):
        self.results_text.delete(1.0, tk.END)
        self.packet_count = 0
        self.update_stats()