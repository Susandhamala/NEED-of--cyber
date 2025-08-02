import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import string
import pyperclip
import hashlib
import time
import json
import os
from cryptography.fernet import Fernet

def run_password_generator():
    generator_window = tk.Toplevel()
    generator_window.title("Password Generator & Vault")
    generator_window.geometry("800x700")
    generator_window.configure(bg="#0f111a")
    
    PasswordGenerator(generator_window)

class PasswordGenerator:
    def __init__(self, parent):
        self.parent = parent
        self.vault_file = "data/password_vault.json"
        self.key_file = "data/vault_key.key"
        self.cipher = self.load_or_create_cipher()
        self.setup_ui()
        
    def load_or_create_cipher(self):
        try:
            os.makedirs("data", exist_ok=True)
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
            return Fernet(key)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize encryption: {str(e)}", parent=self.parent)
            return None
            
    def setup_ui(self):
        main_frame = tk.Frame(self.parent, bg="#0f111a")
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        tk.Label(main_frame, text="🔑 Secure Password Generator & Vault", font=("Consolas", 16, "bold"),
                fg="#00fff7", bg="#0f111a").pack(pady=10)
        
        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True, pady=10)
        
        # Generator Tab
        generator_frame = tk.Frame(notebook, bg="#0f111a")
        notebook.add(generator_frame, text="Password Generator")
        
        # Vault Tab
        vault_frame = tk.Frame(notebook, bg="#0f111a")
        notebook.add(vault_frame, text="Password Vault")
        
        self.setup_generator_tab(generator_frame)
        self.setup_vault_tab(vault_frame)
        
    def setup_generator_tab(self, parent):
        # Password length
        length_frame = tk.Frame(parent, bg="#0f111a")
        length_frame.pack(fill='x', pady=10)
        
        tk.Label(length_frame, text="Password Length:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.length_var = tk.IntVar(value=16)
        length_spinbox = tk.Spinbox(length_frame, from_=4, to=128, textvariable=self.length_var,
                                   width=5, bg="#1f2233", fg="#00fff7", font=("Consolas", 12))
        length_spinbox.pack(side='left', padx=10)
        
        # Character options
        options_frame = tk.Frame(parent, bg="#0f111a")
        options_frame.pack(fill='x', pady=10)
        
        tk.Label(options_frame, text="Character Types:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w')
        
        self.uppercase_var = tk.BooleanVar(value=True)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.numbers_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.exclude_similar_var = tk.BooleanVar(value=True)
        self.ambiguous_var = tk.BooleanVar(value=False)
        
        options = [
            ("Uppercase (A-Z)", self.uppercase_var),
            ("Lowercase (a-z)", self.lowercase_var),
            ("Numbers (0-9)", self.numbers_var),
            ("Symbols (!@#$...)", self.symbols_var),
            ("Exclude Similar (0,O,l,1)", self.exclude_similar_var),
            ("Avoid Ambiguous ({[]})", self.ambiguous_var)
        ]
        
        for text, var in options:
            tk.Checkbutton(options_frame, text=text, variable=var, 
                          bg="#0f111a", fg="#00fff7", selectcolor="#1f2233",
                          font=("Consolas", 10)).pack(anchor='w')
        
        # Generate button
        tk.Button(parent, text="Generate Password", command=self.generate_password,
                 bg="#141627", fg="#00fff7", font=("Consolas", 14), pady=10).pack(pady=20)
        
        # Password display
        tk.Label(parent, text="Generated Password:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(10,5))
        
        password_frame = tk.Frame(parent, bg="#0f111a")
        password_frame.pack(fill='x', pady=5)
        
        self.password_display = tk.Entry(password_frame, width=40, bg="#1f2233", fg="#00fff7",
                                        font=("Consolas", 12), insertbackground="#00fff7")
        self.password_display.pack(side='left', fill='x', expand=True, padx=(0, 5))
        
        tk.Button(password_frame, text="📋", command=self.copy_password,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12), width=3).pack(side='left', padx=2)
        
        # Action buttons
        button_frame = tk.Frame(parent, bg="#0f111a")
        button_frame.pack(fill='x', pady=10)
        
        tk.Button(button_frame, text="💾 Save to Vault", command=self.save_to_vault,
                 bg="#141627", fg="#00ff9d", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(button_frame, text="📋 Copy Password", command=self.copy_password,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Password strength
        tk.Label(parent, text="Password Strength:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(20,5))
        
        self.strength_label = tk.Label(parent, text="Not Generated", font=("Consolas", 12),
                                      fg="#aaaaaa", bg="#0f111a")
        self.strength_label.pack()
        
        # Entropy calculation
        self.entropy_label = tk.Label(parent, text="Entropy: 0 bits", font=("Consolas", 10),
                                     fg="#00ff9d", bg="#0f111a")
        self.entropy_label.pack()
        
        # Multiple passwords
        tk.Label(parent, text="Generate Multiple Passwords:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(20,5))
        
        multi_frame = tk.Frame(parent, bg="#0f111a")
        multi_frame.pack(fill='x')
        
        tk.Label(multi_frame, text="Count:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.count_var = tk.IntVar(value=5)
        count_spinbox = tk.Spinbox(multi_frame, from_=1, to=20, textvariable=self.count_var,
                                  width=5, bg="#1f2233", fg="#00fff7", font=("Consolas", 12))
        count_spinbox.pack(side='left', padx=10)
        
        tk.Button(multi_frame, text="Generate List", command=self.generate_password_list,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
        self.password_list = tk.Text(parent, height=6, bg="#1f2233", fg="#00fff7",
                                    font=("Consolas", 10))
        self.password_list.pack(fill='both', expand=True, pady=10)
        
    def setup_vault_tab(self, parent):
        # Vault controls
        control_frame = tk.Frame(parent, bg="#0f111a")
        control_frame.pack(fill='x', pady=10)
        
        tk.Button(control_frame, text="🔄 Refresh", command=self.load_vault,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(control_frame, text="➕ Add Manual Entry", command=self.add_manual_entry,
                 bg="#141627", fg="#00ff9d", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(control_frame, text="🗑️ Delete Selected", command=self.delete_selected,
                 bg="#ff4444", fg="white", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Vault treeview
        tk.Label(parent, text="Saved Passwords:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(10,5))
        
        columns = ('Service', 'Username', 'Password', 'Created')
        self.vault_tree = ttk.Treeview(parent, columns=columns, show='headings', height=15)
        
        self.vault_tree.heading('Service', text='Service')
        self.vault_tree.heading('Username', text='Username')
        self.vault_tree.heading('Password', text='Password')
        self.vault_tree.heading('Created', text='Created')
        
        self.vault_tree.column('Service', width=150)
        self.vault_tree.column('Username', width=150)
        self.vault_tree.column('Password', width=120)
        self.vault_tree.column('Created', width=120)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.vault_tree.yview)
        self.vault_tree.configure(yscroll=scrollbar.set)
        
        self.vault_tree.pack(side=tk.LEFT, fill='both', expand=True)
        scrollbar.pack(side=tk.RIGHT, fill='y')
        
        # Action buttons for vault
        vault_button_frame = tk.Frame(parent, bg="#0f111a")
        vault_button_frame.pack(fill='x', pady=10)
        
        tk.Button(vault_button_frame, text="📋 Copy Password", command=self.copy_vault_password,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(vault_button_frame, text="👁️ Show Password", command=self.show_vault_password,
                 bg="#141627", fg="#00ff9d", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(vault_button_frame, text="✏️ Edit Entry", command=self.edit_vault_entry,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Load vault data
        self.load_vault()
        
    def generate_password(self):
        try:
            length = self.length_var.get()
            if length < 4:
                messagebox.showerror("Error", "Password length must be at least 4 characters.", parent=self.parent)
                return
                
            # Build character set
            charset = ""
            if self.uppercase_var.get():
                charset += string.ascii_uppercase
            if self.lowercase_var.get():
                charset += string.ascii_lowercase
            if self.numbers_var.get():
                charset += string.digits
            if self.symbols_var.get():
                charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
                
            if self.exclude_similar_var.get():
                exclude_chars = "0O1lI"
                charset = ''.join(c for c in charset if c not in exclude_chars)
                
            if self.ambiguous_var.get():
                ambiguous = "{}[]()/\\'\"`~,;.<>"
                charset = ''.join(c for c in charset if c not in ambiguous)
                
            if not charset:
                messagebox.showerror("Error", "Please select at least one character type.", parent=self.parent)
                return
                
            # Generate password using cryptographically secure random
            password = ''.join(secrets.choice(charset) for _ in range(length))
            self.password_display.delete(0, tk.END)
            self.password_display.insert(0, password)
            
            # Calculate and display strength
            strength = self.calculate_strength(password)
            self.strength_label.config(text=strength[0], fg=strength[1])
            
            # Calculate entropy
            entropy = self.calculate_entropy(password, charset)
            self.entropy_label.config(text=f"Entropy: {entropy:.1f} bits")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}", parent=self.parent)
            
    def calculate_strength(self, password):
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        score = 0
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if has_upper:
            score += 1
        if has_lower:
            score += 1
        if has_digit:
            score += 1
        if has_symbol:
            score += 1
        if length >= 16:
            score += 1
        if length >= 20:
            score += 1
            
        if score <= 2:
            return ("Weak", "#ff4444")
        elif score <= 4:
            return ("Moderate", "#ffaa00")
        elif score <= 6:
            return ("Strong", "#44ff44")
        else:
            return ("Very Strong", "#00ff9d")
            
    def calculate_entropy(self, password, charset):
        import math
        charset_size = len(charset)
        if charset_size == 0:
            return 0
        return len(password) * math.log2(charset_size)
            
    def copy_password(self):
        password = self.password_display.get()
        if password:
            self.parent.clipboard_clear()
            self.parent.clipboard_append(password)
            self.parent.update()
            messagebox.showinfo("Copied", "Password copied to clipboard.", parent=self.parent)
        else:
            messagebox.showwarning("Warning", "Generate a password first.", parent=self.parent)
            
    def save_to_vault(self):
        password = self.password_display.get()
        if not password:
            messagebox.showwarning("Warning", "Generate a password first.", parent=self.parent)
            return
            
        # Create dialog to get service and username
        dialog = tk.Toplevel(self.parent)
        dialog.title("Save to Vault")
        dialog.geometry("400x200")
        dialog.configure(bg="#0f111a")
        dialog.grab_set()
        
        tk.Label(dialog, text="Service/Application:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(pady=5)
        service_entry = tk.Entry(dialog, bg="#1f2233", fg="#00fff7", font=("Consolas", 12))
        service_entry.pack(pady=5, padx=20, fill='x')
        
        tk.Label(dialog, text="Username/Email:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(pady=5)
        username_entry = tk.Entry(dialog, bg="#1f2233", fg="#00fff7", font=("Consolas", 12))
        username_entry.pack(pady=5, padx=20, fill='x')
        
        def save_entry():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            
            if not service or not username:
                messagebox.showerror("Error", "Service and username are required.", parent=dialog)
                return
                
            try:
                # Encrypt password
                encrypted_password = self.cipher.encrypt(password.encode()).decode()
                
                # Load existing vault
                vault_data = self.load_vault_data()
                
                # Add new entry
                entry_id = str(int(time.time() * 1000000))  # Unique ID
                vault_data[entry_id] = {
                    'service': service,
                    'username': username,
                    'password': encrypted_password,
                    'created': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # Save vault
                self.save_vault_data(vault_data)
                
                dialog.destroy()
                messagebox.showinfo("Success", "Password saved to vault.", parent=self.parent)
                self.load_vault()  # Refresh vault display
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save to vault: {str(e)}", parent=dialog)
                
        button_frame = tk.Frame(dialog, bg="#0f111a")
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Save", command=save_entry,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(button_frame, text="Cancel", command=dialog.destroy,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
    def generate_password_list(self):
        try:
            count = self.count_var.get()
            length = self.length_var.get()
            
            if length < 4:
                messagebox.showerror("Error", "Password length must be at least 4 characters.", parent=self.parent)
                return
                
            # Build character set
            charset = ""
            if self.uppercase_var.get():
                charset += string.ascii_uppercase
            if self.lowercase_var.get():
                charset += string.ascii_lowercase
            if self.numbers_var.get():
                charset += string.digits
            if self.symbols_var.get():
                charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
                
            if self.exclude_similar_var.get():
                exclude_chars = "0O1lI"
                charset = ''.join(c for c in charset if c not in exclude_chars)
                
            if self.ambiguous_var.get():
                ambiguous = "{}[]()/\\'\"`~,;.<>"
                charset = ''.join(c for c in charset if c not in ambiguous)
                
            if not charset:
                messagebox.showerror("Error", "Please select at least one character type.", parent=self.parent)
                return
                
            # Generate passwords
            self.password_list.delete(1.0, tk.END)
            for i in range(count):
                password = ''.join(secrets.choice(charset) for _ in range(length))
                self.password_list.insert(tk.END, f"{i+1}. {password}\n")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate passwords: {str(e)}", parent=self.parent)
            
    def load_vault_data(self):
        try:
            if os.path.exists(self.vault_file):
                with open(self.vault_file, 'r') as f:
                    return json.load(f)
            else:
                return {}
        except:
            return {}
            
    def save_vault_data(self, data):
        try:
            os.makedirs("data", exist_ok=True)
            with open(self.vault_file, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save vault: {str(e)}", parent=self.parent)
            return False
            
    def load_vault(self):
        # Clear existing items
        for item in self.vault_tree.get_children():
            self.vault_tree.delete(item)
            
        # Load vault data
        vault_data = self.load_vault_data()
        
        # Add items to treeview
        for entry_id, entry in vault_data.items():
            try:
                decrypted_password = self.cipher.decrypt(entry['password'].encode()).decode()
                masked_password = "*" * len(decrypted_password)
                self.vault_tree.insert('', tk.END, 
                                     values=(entry['service'], entry['username'], masked_password, entry['created']),
                                     tags=(entry_id, entry['password']))  # Store encrypted password in tags
            except:
                self.vault_tree.insert('', tk.END, 
                                     values=(entry['service'], entry['username'], "[DECRYPT ERROR]", entry['created']),
                                     tags=(entry_id, entry['password']))
                                     
    def copy_vault_password(self):
        selected = self.vault_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an entry to copy.", parent=self.parent)
            return
            
        item = self.vault_tree.item(selected[0])
        encrypted_password = item['tags'][1]  # Get encrypted password from tags
        
        try:
            decrypted_password = self.cipher.decrypt(encrypted_password.encode()).decode()
            self.parent.clipboard_clear()
            self.parent.clipboard_append(decrypted_password)
            self.parent.update()
            messagebox.showinfo("Copied", "Password copied to clipboard.", parent=self.parent)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}", parent=self.parent)
            
    def show_vault_password(self):
        selected = self.vault_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an entry to show.", parent=self.parent)
            return
            
        item = self.vault_tree.item(selected[0])
        encrypted_password = item['tags'][1]  # Get encrypted password from tags
        
        try:
            decrypted_password = self.cipher.decrypt(encrypted_password.encode()).decode()
            
            # Create dialog to show password
            dialog = tk.Toplevel(self.parent)
            dialog.title("Password")
            dialog.geometry("300x100")
            dialog.configure(bg="#0f111a")
            dialog.grab_set()
            
            tk.Label(dialog, text="Password:", font=("Consolas", 12),
                    fg="#00fff7", bg="#0f111a").pack(pady=5)
            password_entry = tk.Entry(dialog, bg="#1f2233", fg="#00fff7", font=("Consolas", 12))
            password_entry.pack(pady=5, padx=20, fill='x')
            password_entry.insert(0, decrypted_password)
            
            def copy_and_close():
                self.parent.clipboard_clear()
                self.parent.clipboard_append(decrypted_password)
                self.parent.update()
                dialog.destroy()
                messagebox.showinfo("Copied", "Password copied to clipboard.", parent=self.parent)
                
            button_frame = tk.Frame(dialog, bg="#0f111a")
            button_frame.pack(pady=10)
            
            tk.Button(button_frame, text="📋 Copy & Close", command=copy_and_close,
                     bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
            tk.Button(button_frame, text="Close", command=dialog.destroy,
                     bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}", parent=self.parent)
            
    def add_manual_entry(self):
        # Create dialog to add manual entry
        dialog = tk.Toplevel(self.parent)
        dialog.title("Add Manual Entry")
        dialog.geometry("400x250")
        dialog.configure(bg="#0f111a")
        dialog.grab_set()
        
        tk.Label(dialog, text="Service/Application:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(pady=5)
        service_entry = tk.Entry(dialog, bg="#1f2233", fg="#00fff7", font=("Consolas", 12))
        service_entry.pack(pady=5, padx=20, fill='x')
        
        tk.Label(dialog, text="Username/Email:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(pady=5)
        username_entry = tk.Entry(dialog, bg="#1f2233", fg="#00fff7", font=("Consolas", 12))
        username_entry.pack(pady=5, padx=20, fill='x')
        
        tk.Label(dialog, text="Password:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(pady=5)
        password_entry = tk.Entry(dialog, bg="#1f2233", fg="#00fff7", font=("Consolas", 12), show="*")
        password_entry.pack(pady=5, padx=20, fill='x')
        
        def save_manual_entry():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()
            
            if not service or not username or not password:
                messagebox.showerror("Error", "All fields are required.", parent=dialog)
                return
                
            try:
                # Encrypt password
                encrypted_password = self.cipher.encrypt(password.encode()).decode()
                
                # Load existing vault
                vault_data = self.load_vault_data()
                
                # Add new entry
                entry_id = str(int(time.time() * 1000000))  # Unique ID
                vault_data[entry_id] = {
                    'service': service,
                    'username': username,
                    'password': encrypted_password,
                    'created': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # Save vault
                self.save_vault_data(vault_data)
                
                dialog.destroy()
                messagebox.showinfo("Success", "Entry added to vault.", parent=self.parent)
                self.load_vault()  # Refresh vault display
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add entry: {str(e)}", parent=dialog)
                
        button_frame = tk.Frame(dialog, bg="#0f111a")
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Save", command=save_manual_entry,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(button_frame, text="Cancel", command=dialog.destroy,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
    def delete_selected(self):
        selected = self.vault_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an entry to delete.", parent=self.parent)
            return
            
        if not messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?", parent=self.parent):
            return
            
        item = self.vault_tree.item(selected[0])
        entry_id = item['tags'][0]  # Get entry ID from tags
        
        try:
            # Load existing vault
            vault_data = self.load_vault_data()
            
            # Remove entry
            if entry_id in vault_data:
                del vault_data[entry_id]
                
            # Save vault
            self.save_vault_data(vault_data)
            
            messagebox.showinfo("Success", "Entry deleted from vault.", parent=self.parent)
            self.load_vault()  # Refresh vault display
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete entry: {str(e)}", parent=self.parent)
            
    def edit_vault_entry(self):
        selected = self.vault_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an entry to edit.", parent=self.parent)
            return
            
        item = self.vault_tree.item(selected[0])
        entry_id = item['tags'][0]  # Get entry ID from tags
        encrypted_password = item['tags'][1]  # Get encrypted password from tags
        
        # Load vault data
        vault_data = self.load_vault_data()
        entry = vault_data.get(entry_id, {})
        
        if not entry:
            messagebox.showerror("Error", "Entry not found.", parent=self.parent)
            return
            
        # Create dialog to edit entry
        dialog = tk.Toplevel(self.parent)
        dialog.title("Edit Entry")
        dialog.geometry("400x250")
        dialog.configure(bg="#0f111a")
        dialog.grab_set()
        
        tk.Label(dialog, text="Service/Application:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(pady=5)
        service_entry = tk.Entry(dialog, bg="#1f2233", fg="#00fff7", font=("Consolas", 12))
        service_entry.pack(pady=5, padx=20, fill='x')
        service_entry.insert(0, entry.get('service', ''))
        
        tk.Label(dialog, text="Username/Email:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(pady=5)
        username_entry = tk.Entry(dialog, bg="#1f2233", fg="#00fff7", font=("Consolas", 12))
        username_entry.pack(pady=5, padx=20, fill='x')
        username_entry.insert(0, entry.get('username', ''))
        
        tk.Label(dialog, text="Password:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(pady=5)
        password_entry = tk.Entry(dialog, bg="#1f2233", fg="#00fff7", font=("Consolas", 12), show="*")
        password_entry.pack(pady=5, padx=20, fill='x')
        
        # Show current password masked
        try:
            decrypted_password = self.cipher.decrypt(encrypted_password.encode()).decode()
            password_entry.insert(0, decrypted_password)
        except:
            password_entry.insert(0, "[DECRYPT ERROR]")
            
        def update_entry():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()
            
            if not service or not username or not password:
                messagebox.showerror("Error", "All fields are required.", parent=dialog)
                return
                
            try:
                # Encrypt password
                encrypted_password_new = self.cipher.encrypt(password.encode()).decode()
                
                # Update entry
                vault_data[entry_id] = {
                    'service': service,
                    'username': username,
                    'password': encrypted_password_new,
                    'created': entry.get('created', time.strftime('%Y-%m-%d %H:%M:%S'))
                }
                
                # Save vault
                self.save_vault_data(vault_data)
                
                dialog.destroy()
                messagebox.showinfo("Success", "Entry updated.", parent=self.parent)
                self.load_vault()  # Refresh vault display
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update entry: {str(e)}", parent=dialog)
                
        button_frame = tk.Frame(dialog, bg="#0f111a")
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Update", command=update_entry,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(button_frame, text="Cancel", command=dialog.destroy,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)