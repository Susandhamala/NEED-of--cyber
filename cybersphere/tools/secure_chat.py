import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import time
import json
import hashlib
from cryptography.fernet import Fernet
import base64
import os

def run_secure_chat():
    chat_window = tk.Toplevel()
    chat_window.title("Secure Chat")
    chat_window.geometry("900x700")
    chat_window.configure(bg="#0f111a")
    
    SecureChat(chat_window)

class SecureChat:
    def __init__(self, parent):
        self.parent = parent
        self.server_socket = None
        self.client_socket = None
        self.chat_key = None
        self.cipher = None
        self.username = "User"  # This would come from login in real app
        self.connected = False
        self.listening = False
        self.setup_ui()
        
    def setup_ui(self):
        main_frame = tk.Frame(self.parent, bg="#0f111a")
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(main_frame, text="🔐 Secure Chat", font=("Consolas", 16, "bold"),
                fg="#00fff7", bg="#0f111a").pack(pady=10)
        
        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True, pady=10)
        
        # Server Tab
        server_frame = tk.Frame(notebook, bg="#0f111a")
        notebook.add(server_frame, text="Host Chat")
        
        # Client Tab
        client_frame = tk.Frame(notebook, bg="#0f111a")
        notebook.add(client_frame, text="Join Chat")
        
        # Chat Tab
        self.chat_frame = tk.Frame(notebook, bg="#0f111a")
        notebook.add(self.chat_frame, text="Chat Room")
        
        self.setup_server_tab(server_frame)
        self.setup_client_tab(client_frame)
        self.setup_chat_tab(self.chat_frame)
        
    def setup_server_tab(self, parent):
        # Server controls
        control_frame = tk.Frame(parent, bg="#0f111a")
        control_frame.pack(fill='x', pady=10)
        
        tk.Label(control_frame, text="Port:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.server_port = tk.Entry(control_frame, width=10, bg="#1f2233", fg="#00fff7",
                                   font=("Consolas", 12), insertbackground="#00fff7")
        self.server_port.pack(side='left', padx=10)
        self.server_port.insert(0, "12345")
        
        self.server_btn = tk.Button(control_frame, text="Start Server", command=self.toggle_server,
                                   bg="#141627", fg="#00fff7", font=("Consolas", 12))
        self.server_btn.pack(side='left', padx=5)
        
        # Encryption setup
        enc_frame = tk.Frame(parent, bg="#0f111a")
        enc_frame.pack(fill='x', pady=10)
        
        tk.Label(enc_frame, text="Chat Password:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.chat_password = tk.Entry(enc_frame, width=20, bg="#1f2233", fg="#00fff7",
                                     font=("Consolas", 12), show="*", insertbackground="#00fff7")
        self.chat_password.pack(side='left', padx=10)
        self.chat_password.insert(0, "securechat123")
        
        tk.Button(enc_frame, text="Generate Key", command=self.generate_chat_key,
                 bg="#141627", fg="#00ff9d", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Server info
        info_frame = tk.Frame(parent, bg="#0f111a")
        info_frame.pack(fill='x', pady=10)
        
        self.server_status = tk.Label(info_frame, text="Server: Stopped", font=("Consolas", 12),
                                     fg="#ff4444", bg="#0f111a")
        self.server_status.pack(side='left')
        
        # Connection info
        tk.Label(parent, text="Connection Info:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(20,5))
        
        self.server_info = scrolledtext.ScrolledText(parent, height=8, bg="#1f2233", 
                                                    fg="#00fff7", font=("Consolas", 10))
        self.server_info.pack(fill='both', expand=True)
        
    def setup_client_tab(self, parent):
        # Client controls
        control_frame = tk.Frame(parent, bg="#0f111a")
        control_frame.pack(fill='x', pady=10)
        
        tk.Label(control_frame, text="Server IP:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.client_ip = tk.Entry(control_frame, width=15, bg="#1f2233", fg="#00fff7",
                                 font=("Consolas", 12), insertbackground="#00fff7")
        self.client_ip.pack(side='left', padx=10)
        self.client_ip.insert(0, "127.0.0.1")
        
        tk.Label(control_frame, text="Port:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.client_port = tk.Entry(control_frame, width=10, bg="#1f2233", fg="#00fff7",
                                   font=("Consolas", 12), insertbackground="#00fff7")
        self.client_port.pack(side='left', padx=10)
        self.client_port.insert(0, "12345")
        
        self.client_btn = tk.Button(control_frame, text="Connect", command=self.toggle_client,
                                   bg="#141627", fg="#00fff7", font=("Consolas", 12))
        self.client_btn.pack(side='left', padx=5)
        
        # Encryption setup
        enc_frame = tk.Frame(parent, bg="#0f111a")
        enc_frame.pack(fill='x', pady=10)
        
        tk.Label(enc_frame, text="Chat Password:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.client_password = tk.Entry(enc_frame, width=20, bg="#1f2233", fg="#00fff7",
                                       font=("Consolas", 12), show="*", insertbackground="#00fff7")
        self.client_password.pack(side='left', padx=10)
        self.client_password.insert(0, "securechat123")
        
        # Client info
        info_frame = tk.Frame(parent, bg="#0f111a")
        info_frame.pack(fill='x', pady=10)
        
        self.client_status = tk.Label(info_frame, text="Client: Disconnected", font=("Consolas", 12),
                                     fg="#ff4444", bg="#0f111a")
        self.client_status.pack(side='left')
        
        # Connection info
        tk.Label(parent, text="Connection Status:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(20,5))
        
        self.client_info = scrolledtext.ScrolledText(parent, height=8, bg="#1f2233", 
                                                    fg="#00fff7", font=("Consolas", 10))
        self.client_info.pack(fill='both', expand=True)
        
    def setup_chat_tab(self, parent):
        # Chat display
        tk.Label(parent, text="Secure Chat Room", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(10,5))
        
        self.chat_display = scrolledtext.ScrolledText(parent, height=20, bg="#1f2233", 
                                                     fg="#00fff7", font=("Consolas", 10))
        self.chat_display.pack(fill='both', expand=True, pady=5)
        
        # Message input
        input_frame = tk.Frame(parent, bg="#0f111a")
        input_frame.pack(fill='x', pady=5)
        
        self.message_entry = tk.Entry(input_frame, bg="#1f2233", fg="#00fff7",
                                     font=("Consolas", 12), insertbackground="#00fff7")
        self.message_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', self.send_message)
        
        tk.Button(input_frame, text="Send", command=self.send_message,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left')
        
        # Chat controls
        control_frame = tk.Frame(parent, bg="#0f111a")
        control_frame.pack(fill='x', pady=5)
        
        tk.Button(control_frame, text="Clear Chat", command=self.clear_chat,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(control_frame, text="Save Chat", command=self.save_chat,
                 bg="#141627", fg="#00ff9d", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Status
        self.chat_status = tk.Label(parent, text="Not connected", font=("Consolas", 10),
                                   fg="#aaaaaa", bg="#0f111a")
        self.chat_status.pack()
        
        # Disable chat tab initially
        self.parent.children['!frame'].children['!notebook'].tab(2, state='disabled')
        
    def toggle_server(self):
        if not self.connected:
            self.start_server()
        else:
            self.stop_server()
            
    def start_server(self):
        try:
            port = int(self.server_port.get())
            password = self.chat_password.get()
            
            if not password:
                messagebox.showerror("Error", "Please enter a chat password.", parent=self.parent)
                return
                
            # Generate encryption key from password
            self.generate_cipher_from_password(password)
            
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)
            
            self.connected = True
            self.server_btn.config(text="Stop Server", bg="#ff4444")
            self.server_status.config(text=f"Server: Running on port {port}", fg="#44ff44")
            
            self.server_info.insert(tk.END, f"[+] Server started on port {port}\n")
            self.server_info.insert(tk.END, f"[+] Encryption key generated\n")
            self.server_info.insert(tk.END, f"[+] Waiting for connections...\n\n")
            
            # Enable chat tab
            self.parent.children['!frame'].children['!notebook'].tab(2, state='normal')
            self.chat_status.config(text=f"Server Mode - Port {port}")
            
            # Start listening thread
            self.listening = True
            listen_thread = threading.Thread(target=self.listen_for_clients)
            listen_thread.daemon = True
            listen_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}", parent=self.parent)
            
    def stop_server(self):
        try:
            self.listening = False
            self.connected = False
            
            if self.server_socket:
                self.server_socket.close()
                
            self.server_btn.config(text="Start Server", bg="#141627")
            self.server_status.config(text="Server: Stopped", fg="#ff4444")
            self.server_info.insert(tk.END, "[-] Server stopped\n\n")
            
            # Disable chat tab
            self.parent.children['!frame'].children['!notebook'].tab(2, state='disabled')
            self.chat_status.config(text="Not connected")
            
        except Exception as e:
            self.server_info.insert(tk.END, f"[-] Error stopping server: {str(e)}\n")
            
    def toggle_client(self):
        if not self.connected:
            self.connect_to_server()
        else:
            self.disconnect_from_server()
            
    def connect_to_server(self):
        try:
            host = self.client_ip.get().strip()
            port = int(self.client_port.get())
            password = self.client_password.get()
            
            if not host or not password:
                messagebox.showerror("Error", "Please enter server IP and password.", parent=self.parent)
                return
                
            # Generate encryption key from password
            self.generate_cipher_from_password(password)
            
            # Create client socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)
            self.client_socket.connect((host, port))
            
            self.connected = True
            self.client_btn.config(text="Disconnect", bg="#ff4444")
            self.client_status.config(text=f"Client: Connected to {host}:{port}", fg="#44ff44")
            
            self.client_info.insert(tk.END, f"[+] Connected to {host}:{port}\n")
            self.client_info.insert(tk.END, f"[+] Encryption initialized\n")
            self.client_info.insert(tk.END, f"[+] Ready to chat\n\n")
            
            # Enable chat tab
            self.parent.children['!frame'].children['!notebook'].tab(2, state='normal')
            self.chat_status.config(text=f"Connected to {host}:{port}")
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Send welcome message
            self.send_system_message("joined the chat")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}", parent=self.parent)
            
    def disconnect_from_server(self):
        try:
            if self.connected:
                self.send_system_message("left the chat")
                time.sleep(0.5)  # Give time to send message
                
            self.connected = False
            
            if self.client_socket:
                self.client_socket.close()
                
            self.client_btn.config(text="Connect", bg="#141627")
            self.client_status.config(text="Client: Disconnected", fg="#ff4444")
            self.client_info.insert(tk.END, "[-] Disconnected from server\n\n")
            
            # Disable chat tab
            self.parent.children['!frame'].children['!notebook'].tab(2, state='disabled')
            self.chat_status.config(text="Not connected")
            
        except Exception as e:
            self.client_info.insert(tk.END, f"[-] Error disconnecting: {str(e)}\n")
            
    def listen_for_clients(self):
        clients = []
        
        while self.listening and self.connected:
            try:
                self.server_socket.settimeout(1)
                client_socket, address = self.server_socket.accept()
                clients.append(client_socket)
                
                self.server_info.insert(tk.END, f"[+] New connection from {address[0]}:{address[1]}\n")
                self.server_info.see(tk.END)
                
                # Start client handler thread
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.listening:
                    self.server_info.insert(tk.END, f"[-] Server error: {str(e)}\n")
                    
    def handle_client(self, client_socket, address):
        try:
            while self.connected:
                try:
                    # Receive message
                    encrypted_message = client_socket.recv(1024)
                    if not encrypted_message:
                        break
                        
                    # Decrypt message
                    message = self.cipher.decrypt(encrypted_message).decode()
                    message_data = json.loads(message)
                    
                    # Display message
                    timestamp = time.strftime('%H:%M:%S')
                    display_message = f"[{timestamp}] {message_data['username']}: {message_data['message']}\n"
                    self.chat_display.insert(tk.END, display_message)
                    self.chat_display.see(tk.END)
                    
                    # Broadcast to other clients (in real implementation)
                    # This would send to all other connected clients
                    
                except Exception as e:
                    break
                    
        except Exception as e:
            self.server_info.insert(tk.END, f"[-] Client handler error: {str(e)}\n")
        finally:
            client_socket.close()
            
    def receive_messages(self):
        while self.connected:
            try:
                if self.client_socket:
                    encrypted_message = self.client_socket.recv(1024)
                    if not encrypted_message:
                        break
                        
                    # Decrypt message
                    message = self.cipher.decrypt(encrypted_message).decode()
                    message_data = json.loads(message)
                    
                    # Display message
                    timestamp = time.strftime('%H:%M:%S')
                    if message_data.get('type') == 'system':
                        display_message = f"[{timestamp}] *** {message_data['message']} ***\n"
                    else:
                        display_message = f"[{timestamp}] {message_data['username']}: {message_data['message']}\n"
                        
                    self.chat_display.insert(tk.END, display_message)
                    self.chat_display.see(tk.END)
                    
            except Exception as e:
                if self.connected:
                    self.client_info.insert(tk.END, f"[-] Receive error: {str(e)}\n")
                break
                
    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if not message or not self.connected:
            return
            
        try:
            # Create message data
            message_data = {
                'username': self.username,
                'message': message,
                'timestamp': time.time(),
                'type': 'message'
            }
            
            # Encrypt and send
            message_json = json.dumps(message_data)
            encrypted_message = self.cipher.encrypt(message_json.encode())
            
            if self.server_socket:  # Server mode
                # In real implementation, broadcast to all clients
                pass
            elif self.client_socket:  # Client mode
                self.client_socket.send(encrypted_message)
                
            # Display sent message
            timestamp = time.strftime('%H:%M:%S')
            display_message = f"[{timestamp}] You: {message}\n"
            self.chat_display.insert(tk.END, display_message)
            self.chat_display.see(tk.END)
            
            # Clear input
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}", parent=self.parent)
            
    def send_system_message(self, message):
        try:
            message_data = {
                'username': self.username,
                'message': message,
                'timestamp': time.time(),
                'type': 'system'
            }
            
            message_json = json.dumps(message_data)
            encrypted_message = self.cipher.encrypt(message_json.encode())
            
            if self.client_socket:
                self.client_socket.send(encrypted_message)
                
        except Exception as e:
            pass  # Silent fail for system messages
            
    def generate_chat_key(self):
        # Generate a random key for chat
        key = Fernet.generate_key()
        key_str = base64.urlsafe_b64encode(key).decode()
        self.chat_password.delete(0, tk.END)
        self.chat_password.insert(0, key_str[:16])  # Use first 16 chars for simplicity
        messagebox.showinfo("Key Generated", "Chat password generated. Share this with participants.", parent=self.parent)
        
    def generate_cipher_from_password(self, password):
        # Generate key from password
        key = hashlib.sha256(password.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key)
        self.cipher = Fernet(fernet_key)
        
    def clear_chat(self):
        self.chat_display.delete(1.0, tk.END)
        
    def save_chat(self):
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                parent=self.parent
            )
            
            if filename:
                chat_content = self.chat_display.get(1.0, tk.END)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(chat_content)
                messagebox.showinfo("Saved", "Chat log saved successfully.", parent=self.parent)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save chat: {str(e)}", parent=self.parent)