import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import json
from styles.styles import login_style
from utils.db import get_user

USERS_FILE = "data/users.json"

class LoginPage:
    def __init__(self, root, on_success, on_show_register):
        self.root = root
        self.on_success = on_success
        self.on_show_register = on_show_register

        self.frame = tk.Frame(root, bg=login_style["bg_color"])
        self.frame.pack(fill="both", expand=True)

        tk.Label(self.frame, text="CyberSphere Login", font=login_style["title_font"],
                 fg=login_style["title_fg"], bg=login_style["bg_color"]).pack(pady=40)

        self.username_entry = self._create_entry("Username")
        self.password_entry = self._create_entry("Password", show="*")

        login_btn = tk.Button(self.frame, text="Login", command=self.verify,
                              font=login_style["button_font"], bg=login_style["button_bg"], 
                              fg=login_style["button_fg"])
        login_btn.pack(pady=15)

        register_btn = tk.Button(self.frame, text="Register New Account", command=self.show_register,
                               font=login_style["button_font"], bg=login_style["button_bg"], 
                               fg="#00ff9d")
        register_btn.pack(pady=10)

    def _create_entry(self, label, show=None):
        tk.Label(self.frame, text=label, bg=login_style["bg_color"], fg=login_style["label_fg"]).pack()
        entry = tk.Entry(self.frame, font=login_style["entry_font"], show=show, width=30,
                        bg="#1f2233", fg="#00fff7", insertbackground="#00fff7")
        entry.pack(pady=5)
        return entry

    def verify(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if self.authenticate(username, password):
            self.on_success(self.root)
        else:
            messagebox.showerror("Login Failed", "Incorrect username or password.")

    def authenticate(self, username, password):
        # Try database first
        stored_hash = get_user(username)
        if stored_hash:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            return stored_hash == hashed_password
        
        # Fallback to JSON file (for backward compatibility)
        users = self.load_users()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return users.get(username) == hashed_password

    def load_users(self):
        if not os.path.exists(USERS_FILE):
            return {}
        
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}

    def show_register(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        from pages.register_page import RegisterPage
        RegisterPage(self.root, self.on_show_register)