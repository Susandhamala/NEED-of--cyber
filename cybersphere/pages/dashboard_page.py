import tkinter as tk
from tkinter import messagebox
from tools.keylogger_detector import run_keylogger_detector
from tools.arp_spoofer_detector import run_arp_detector
from tools.dns_spoofer_tester import run_dns_tester
from tools.security_websites import run_security_websites
from tools.network_sniffer import run_network_sniffer
from tools.password_generator import run_password_generator
from tools.secure_chat import run_secure_chat  # Added chat feature
from styles.styles import dashboard_style

class DashboardPage:
    def __init__(self, root, on_logout):
        self.root = root
        self.on_logout = on_logout

        self.frame = tk.Frame(root, bg=dashboard_style["bg_color"])
        self.frame.pack(fill="both", expand=True)

        tk.Label(self.frame, text="🛡️ CyberSphere - Cybersecurity Toolkit", font=dashboard_style["title_font"],
                 bg=dashboard_style["bg_color"], fg=dashboard_style["title_fg"]).pack(pady=15)

        # Create tool buttons in grid layout
        tools_frame = tk.Frame(self.frame, bg=dashboard_style["bg_color"])
        tools_frame.pack(fill="both", expand=True, padx=20, pady=10)

        tools = [
            ("⌨️ Keylogger Detector", run_keylogger_detector),
            ("🛡️ ARP Spoofer Detector", run_arp_detector),
            ("🌐 DNS Spoofing Tester", run_dns_tester),
            ("📚 Security Websites", run_security_websites),
            ("📡 Network Sniffer", run_network_sniffer),
            ("🔑 Password Generator", run_password_generator),
            ("💬 Secure Chat", run_secure_chat),  # Added chat feature
            ("🚪 Logout", self.logout)
        ]

        # Create buttons in a grid
        row, col = 0, 0
        for i, (text, cmd) in enumerate(tools):
            if text == "🚪 Logout":
                # Logout button at bottom
                logout_frame = tk.Frame(self.frame, bg=dashboard_style["bg_color"])
                logout_frame.pack(fill="x", pady=10)
                tk.Button(logout_frame, text=text, font=dashboard_style["button_font"],
                         bg="#ff4444", fg="white", width=20, pady=8, command=cmd).pack()
            else:
                btn = tk.Button(tools_frame, text=text, font=dashboard_style["button_font"],
                               bg=dashboard_style["button_bg"], fg=dashboard_style["button_fg"],
                               width=25, pady=12, command=cmd)
                btn.grid(row=row, column=col, padx=10, pady=8, sticky="nsew")
                
                col += 1
                if col > 1:  # 2 columns
                    col = 0
                    row += 1

        # Configure grid weights
        for i in range(5):
            tools_frame.grid_rowconfigure(i, weight=1)
        for i in range(2):
            tools_frame.grid_columnconfigure(i, weight=1)

    def logout(self):
        confirm = messagebox.askyesno("Logout", "Are you sure you want to logout?")
        if confirm:
            for widget in self.root.winfo_children():
                widget.destroy()
            self.on_logout(self.root)