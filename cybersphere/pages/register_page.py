import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import json
from styles.styles import login_style
from utils.db import save_user

USERS_FILE = "data/users.json"

class RegisterPage:
    def __init__(self, root, on_back_to_login):
        self.root = root
        self.on_back_to_login = on_back_to_login
        
        os.makedirs("data", exist_ok=True)
        
        self.frame = tk.Frame(root, bg=login_style["bg_color"])
        self.frame.pack(fill="both", expand=True)

        tk.Label(self.frame, text="Register New Account", font=login_style["title_font"],
                 fg=login_style["title_fg"], bg=login_style["bg_color"]).pack(pady=30)

        self.username_entry = self._create_entry("Username")
        self.password_entry = self._create_entry("Password", show="*")
        self.confirm_password_entry = self._create_entry("Confirm Password", show="*")

        register_btn = tk.Button(self.frame, text="Register", command=self.register,
                               font=login_style["button_font"], bg=login_style["button_bg"], 
                               fg=login_style["button_fg"])
        register_btn.pack(pady=15)

        back_btn = tk.Button(self.frame, text="Back to Login", command=self.back_to_login,
                           font=login_style["button_font"], bg=login_style["button_bg"], 
                           fg=login_style["button_fg"])
        back_btn.pack(pady=5)

    def _create_entry(self, label, show=None):
        tk.Label(self.frame, text=label, bg=login_style["bg_color"], fg=login_style["label_fg"]).pack()
        entry = tk.Entry(self.frame, font=login_style["entry_font"], show=show, width=30,
                        bg="#1f2233", fg="#00fff7", insertbackground="#00fff7")
        entry.pack(pady=5)
        return entry

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not username or not password:
            messagebox.showerror("Registration Failed", "Username and password cannot be empty.")
            return

        if len(username) < 3:
            messagebox.showerror("Registration Failed", "Username must be at least 3 characters long.")
            return

        if len(password) < 6:
            messagebox.showerror("Registration Failed", "Password must be at least 6 characters long.")
            return

        if password != confirm_password:
            messagebox.showerror("Registration Failed", "Passwords do not match.")
            return

        # Check if user already exists
        if self.user_exists(username):
            messagebox.showerror("Registration Failed", "Username already exists.")
            return

        # Save new user
        if self.save_user(username, password):
            messagebox.showinfo("Registration Success", "Account created successfully! You can now login.")
            self.back_to_login()
        else:
            messagebox.showerror("Registration Failed", "Failed to create account. Please try again.")

    def user_exists(self, username):
        # Check in database
        from utils.db import get_user
        if get_user(username):
            return True
            
        # Check in JSON file (backward compatibility)
        users = self.load_users()
        return username in users

    def load_users(self):
        if not os.path.exists(USERS_FILE):
            return {}
        
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}

    def save_user(self, username, password):
        try:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            # Save to database (primary method)
            if save_user(username, hashed_password):
                return True
                
            # Fallback to JSON file
            users = self.load_users()
            users[username] = hashed_password
            
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f)
            return True
        except:
            return False

    def back_to_login(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.on_back_to_login(self.root)