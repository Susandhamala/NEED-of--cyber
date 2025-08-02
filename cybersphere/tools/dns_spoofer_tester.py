import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import dns.resolver
import threading
import time

def run_dns_tester():
    tester_window = tk.Toplevel()
    tester_window.title("DNS Spoofing Tester")
    tester_window.geometry("800x600")
    tester_window.configure(bg="#0f111a")
    
    DNSTester(tester_window)

class DNSTester:
    def __init__(self, parent):
        self.parent = parent
        self.testing = False
        self.setup_ui()
        
    def setup_ui(self):
        main_frame = tk.Frame(self.parent, bg="#0f111a")
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(main_frame, text="🌐 DNS Spoofing Tester", font=("Consolas", 16, "bold"),
                fg="#00fff7", bg="#0f111a").pack(pady=10)
        
        input_frame = tk.Frame(main_frame, bg="#0f111a")
        input_frame.pack(fill='x', pady=10)
        
        tk.Label(input_frame, text="Domain to Test:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.domain_entry = tk.Entry(input_frame, width=30, bg="#1f2233", fg="#00fff7",
                                    font=("Consolas", 12), insertbackground="#00fff7")
        self.domain_entry.pack(side='left', padx=10)
        self.domain_entry.insert(0, "google.com")
        
        button_frame = tk.Frame(main_frame, bg="#0f111a")
        button_frame.pack(fill='x', pady=10)
        
        self.test_btn = tk.Button(button_frame, text="Test DNS Spoofing", command=self.test_dns,
                                 bg="#141627", fg="#00fff7", font=("Consolas", 12))
        self.test_btn.pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Check DNS Servers", command=self.check_dns_servers,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
        tk.Button(button_frame, text="Continuous Test", command=self.toggle_continuous_test,
                 bg="#141627", fg="#00ff9d", font=("Consolas", 12)).pack(side='left', padx=5)
        
        tk.Label(main_frame, text="DNS Resolution Results:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(20,5))
        
        self.results_text = scrolledtext.ScrolledText(main_frame, height=20, bg="#1f2233", 
                                                     fg="#00fff7", font=("Consolas", 10))
        self.results_text.pack(fill='both', expand=True)
        
    def test_dns(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name.", parent=self.parent)
            return
            
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"🔍 Testing DNS resolution for: {domain}\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        # Test with different DNS servers
        dns_servers = {
            "Google DNS": "8.8.8.8",
            "Cloudflare DNS": "1.1.1.1",
            "OpenDNS": "208.67.222.222",
            "Quad9": "9.9.9.9",
            "Level 3": "4.2.2.1"
        }
        
        results = {}
        
        for name, server in dns_servers.items():
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                resolver.timeout = 3
                resolver.lifetime = 3
                
                answers = resolver.resolve(domain, 'A')
                ips = [str(rdata) for rdata in answers]
                results[name] = ips
                
                self.results_text.insert(tk.END, f"✅ {name} ({server}):\n")
                for ip in ips:
                    self.results_text.insert(tk.END, f"   {ip}\n")
                self.results_text.insert(tk.END, "\n")
                
            except Exception as e:
                self.results_text.insert(tk.END, f"❌ {name} ({server}): Error - {str(e)}\n\n")
                
        # Check for inconsistencies (potential spoofing)
        all_ips = list(results.values())
        if len(all_ips) > 1:
            # Filter out empty results
            valid_results = [ips for ips in all_ips if ips]
            if len(valid_results) > 1:
                unique_results = set(tuple(ips) for ips in valid_results)
                if len(unique_results) > 1:
                    self.results_text.insert(tk.END, "⚠️  WARNING: Inconsistent DNS results detected!\n")
                    self.results_text.insert(tk.END, "This may indicate DNS spoofing or cache poisoning.\n\n")
                    self.parent.bell()
                else:
                    self.results_text.insert(tk.END, "✅ All DNS servers returned consistent results.\n\n")
            else:
                self.results_text.insert(tk.END, "ℹ️  Not enough valid results to compare.\n\n")
        else:
            self.results_text.insert(tk.END, "ℹ️  Only one DNS server responded.\n\n")
                
        self.results_text.see(tk.END)
        
    def check_dns_servers(self):
        self.results_text.insert(tk.END, "🔍 Current System DNS Servers:\n")
        self.results_text.insert(tk.END, "="*35 + "\n")
        
        try:
            # Get system DNS servers
            dns_servers = []
            try:
                # Try to get from system resolver
                resolver = dns.resolver.Resolver()
                dns_servers = resolver.nameservers
            except:
                # Fallback to manual detection
                pass
                
            if dns_servers:
                for i, server in enumerate(dns_servers):
                    self.results_text.insert(tk.END, f"🔹 DNS Server {i+1}: {server}\n")
                    # Test connectivity
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(2)
                        sock.connect((server, 53))
                        sock.close()
                        self.results_text.insert(tk.END, f"   ✅ Reachable\n")
                    except:
                        self.results_text.insert(tk.END, f"   ❌ Unreachable\n")
            else:
                self.results_text.insert(tk.END, "Could not detect DNS servers.\n")
                self.results_text.insert(tk.END, "Try: ipconfig /all (Windows) or cat /etc/resolv.conf (Linux)\n")
                
        except Exception as e:
            self.results_text.insert(tk.END, f"Error: {str(e)}\n")
            
        self.results_text.insert(tk.END, "\n💡 Security Recommendations:\n")
        self.results_text.insert(tk.END, "• Use trusted DNS servers like 1.1.1.1 or 8.8.8.8\n")
        self.results_text.insert(tk.END, "• Consider DNS over HTTPS (DoH) for better privacy\n")
        self.results_text.insert(tk.END, "• Regularly check for DNS spoofing\n")
        self.results_text.insert(tk.END, "• Monitor DNS queries for suspicious domains\n\n")
        self.results_text.see(tk.END)
        
    def toggle_continuous_test(self):
        if not self.testing:
            self.testing = True
            self.test_btn.config(text="Stop Continuous Test", bg="#ff4444")
            self.results_text.insert(tk.END, "🔄 Starting continuous DNS testing...\n")
            test_thread = threading.Thread(target=self.continuous_test)
            test_thread.daemon = True
            test_thread.start()
        else:
            self.testing = False
            self.test_btn.config(text="Test DNS Spoofing", bg="#141627")
            self.results_text.insert(tk.END, "⏹️ Stopped continuous testing.\n")
            
    def continuous_test(self):
        domain = self.domain_entry.get().strip() or "google.com"
        self.results_text.insert(tk.END, f"📡 Continuously testing {domain} every 10 seconds...\n\n")
        
        baseline_results = None
        
        while self.testing:
            try:
                self.results_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] Testing {domain}...\n")
                
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ["8.8.8.8"]  # Google DNS
                resolver.timeout = 3
                resolver.lifetime = 3
                
                answers = resolver.resolve(domain, 'A')
                current_ips = [str(rdata) for rdata in answers]
                
                if baseline_results is None:
                    baseline_results = current_ips
                    self.results_text.insert(tk.END, f"   Baseline: {', '.join(current_ips)}\n")
                elif set(current_ips) != set(baseline_results):
                    self.results_text.insert(tk.END, f"   ⚠️  CHANGED: {', '.join(current_ips)}\n")
                    self.results_text.insert(tk.END, f"   Previous: {', '.join(baseline_results)}\n")
                    self.parent.bell()
                else:
                    self.results_text.insert(tk.END, f"   ✅ Consistent: {', '.join(current_ips)}\n")
                    
                self.results_text.see(tk.END)
                self.parent.update()
                
                time.sleep(10)  # Wait 10 seconds
                
            except Exception as e:
                if self.testing:
                    self.results_text.insert(tk.END, f"   Error: {str(e)}\n")
                time.sleep(10)