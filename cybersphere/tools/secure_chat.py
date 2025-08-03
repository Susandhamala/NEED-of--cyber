import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import time
import json
import hashlib
from cryptography.fernet import Fernet
import base64

def run_secure_chat():
    chat_window = tk.Toplevel()
    chat_window.title("Secure Chat")
    chat_window.geometry("800x600")
    chat_window.configure(bg="#0f111a")
    
    SecureChat(chat_window)

class SecureChat:
    def __init__(self, parent):
        self.parent = parent
        self.server_socket = None
        self.client_socket = None
        self.cipher = None
        self.username = "User"
        self.connected = False
        self.is_server = False
        self.clients = []
        self.setup_ui()
        
    def setup_ui(self):
        main_frame = tk.Frame(self.parent, bg="#0f111a")
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(main_frame, text="💬 Secure Chat", font=("Consolas", 16, "bold"),
                fg="#00fff7", bg="#0f111a").pack(pady=10)
        
        # Connection Frame
        conn_frame = tk.Frame(main_frame, bg="#0f111a")
        conn_frame.pack(fill='x', pady=10)
        
        # Server Section
        server_frame = tk.LabelFrame(conn_frame, text="Host Chat Room", bg="#0f111a", fg="#00fff7")
        server_frame.pack(side='left', fill='x', expand=True, padx=5)
        
        tk.Label(server_frame, text="Port:", bg="#0f111a", fg="#00fff7").pack(anchor='w')
        self.port_entry = tk.Entry(server_frame, width=10, bg="#1f2233", fg="#00fff7")
        self.port_entry.pack(pady=2)
        self.port_entry.insert(0, "12345")
        
        self.server_btn = tk.Button(server_frame, text="Start Server", command=self.toggle_server,
                                   bg="#141627", fg="#00fff7", font=("Consolas", 10))
        self.server_btn.pack(pady=5)
        
        # Client Section
        client_frame = tk.LabelFrame(conn_frame, text="Join Chat Room", bg="#0f111a", fg="#00fff7")
        client_frame.pack(side='left', fill='x', expand=True, padx=5)
        
        tk.Label(client_frame, text="IP:Port", bg="#0f111a", fg="#00fff7").pack(anchor='w')
        self.address_entry = tk.Entry(client_frame, width=15, bg="#1f2233", fg="#00fff7")
        self.address_entry.pack(pady=2)
        self.address_entry.insert(0, "127.0.0.1:12345")
        
        self.client_btn = tk.Button(client_frame, text="Connect", command=self.toggle_client,
                                   bg="#141627", fg="#00fff7", font=("Consolas", 10))
        self.client_btn.pack(pady=5)
        
        # Password for encryption
        pass_frame = tk.Frame(main_frame, bg="#0f111a")
        pass_frame.pack(fill='x', pady=5)
        
        tk.Label(pass_frame, text="Chat Password:", bg="#0f111a", fg="#00fff7").pack(side='left')
        self.password_entry = tk.Entry(pass_frame, width=20, bg="#1f2233", fg="#00fff7", show="*")
        self.password_entry.pack(side='left', padx=5)
        self.password_entry.insert(0, "securechat")
        
        # Status
        self.status_label = tk.Label(main_frame, text="Not connected", font=("Consolas", 10),
                                    fg="#aaaaaa", bg="#0f111a")
        self.status_label.pack(pady=5)
        
        # Chat Display
        self.chat_display = scrolledtext.ScrolledText(main_frame, height=15, bg="#1f2233", 
                                                     fg="#00fff7", font=("Consolas", 10))
        self.chat_display.pack(fill='both', expand=True, pady=5)
        
        # Message Input
        input_frame = tk.Frame(main_frame, bg="#0f111a")
        input_frame.pack(fill='x', pady=5)
        
        self.message_entry = tk.Entry(input_frame, bg="#1f2233", fg="#00fff7",
                                     font=("Consolas", 12), insertbackground="#00fff7")
        self.message_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', self.send_message)
        
        tk.Button(input_frame, text="Send", command=self.send_message,
                 bg="#141627", fg="#00fff7", font=("Consolas", 10)).pack(side='left')
        
        # Controls
        control_frame = tk.Frame(main_frame, bg="#0f111a")
        control_frame.pack(fill='x', pady=5)
        
        tk.Button(control_frame, text="Clear", command=self.clear_chat,
                 bg="#141627", fg="#00fff7", font=("Consolas", 10)).pack(side='left', padx=5)
        tk.Button(control_frame, text="Disconnect", command=self.disconnect,
                 bg="#ff4444", fg="white", font=("Consolas", 10)).pack(side='left', padx=5)
        
    def generate_cipher(self, password):
        key = hashlib.sha256(password.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key)
        self.cipher = Fernet(fernet_key)
        
    def toggle_server(self):
        if not self.connected:
            self.start_server()
        else:
            self.disconnect()
            
    def start_server(self):
        try:
            port = int(self.port_entry.get())
            password = self.password_entry.get()
            
            if not password:
                messagebox.showerror("Error", "Please enter a password.", parent=self.parent)
                return
                
            self.generate_cipher(password)
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)
            
            self.connected = True
            self.is_server = True
            self.server_btn.config(text="Stop Server", bg="#ff4444")
            self.status_label.config(text=f"Server running on port {port}", fg="#44ff44")
            
            self.chat_display.insert(tk.END, f"[+] Server started on port {port}\n")
            
            # Start listening thread
            listen_thread = threading.Thread(target=self.listen_for_clients)
            listen_thread.daemon = True
            listen_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}", parent=self.parent)
            
    def listen_for_clients(self):
        while self.connected and self.is_server:
            try:
                self.server_socket.settimeout(1)
                client_socket, address = self.server_socket.accept()
                
                self.chat_display.insert(tk.END, f"[+] {address[0]} joined the chat\n")
                self.chat_display.see(tk.END)
                
                # Start client handler
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                continue
            except:
                break
                
    def handle_client(self, client_socket):
        self.clients.append(client_socket)
        
        try:
            while self.connected:
                try:
                    encrypted_data = client_socket.recv(1024)
                    if not encrypted_data:
                        break
                        
                    # Decrypt message
                    message_json = self.cipher.decrypt(encrypted_data).decode()
                    message_data = json.loads(message_json)
                    
                    # Broadcast to all clients except sender
                    for client in self.clients:
                        if client != client_socket:
                            try:
                                client.send(encrypted_data)
                            except:
                                pass
                                
                    # Display message for server
                    timestamp = time.strftime('%H:%M:%S')
                    display_msg = f"[{timestamp}] {message_data['user']}: {message_data['msg']}\n"
                    self.chat_display.insert(tk.END, display_msg)
                    self.chat_display.see(tk.END)
                    
                except:
                    break
                    
        except:
            pass
        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            client_socket.close()
            
    def toggle_client(self):
        if not self.connected:
            self.connect_to_server()
        else:
            self.disconnect()
            
    def connect_to_server(self):
        try:
            address = self.address_entry.get().split(':')
            host, port = address[0], int(address[1])
            password = self.password_entry.get()
            
            if not password:
                messagebox.showerror("Error", "Please enter a password.", parent=self.parent)
                return
                
            self.generate_cipher(password)
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            
            self.connected = True
            self.client_btn.config(text="Disconnect", bg="#ff4444")
            self.status_label.config(text=f"Connected to {host}:{port}", fg="#44ff44")
            
            self.chat_display.insert(tk.END, f"[+] Connected to {host}:{port}\n")
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}", parent=self.parent)
            
    def receive_messages(self):
        while self.connected and self.client_socket:
            try:
                encrypted_data = self.client_socket.recv(1024)
                if not encrypted_data:
                    break
                    
                # Decrypt message
                message_json = self.cipher.decrypt(encrypted_data).decode()
                message_data = json.loads(message_json)
                
                # Display message
                timestamp = time.strftime('%H:%M:%S')
                display_msg = f"[{timestamp}] {message_data['user']}: {message_data['msg']}\n"
                self.chat_display.insert(tk.END, display_msg)
                self.chat_display.see(tk.END)
                
            except:
                break
                
        self.status_label.config(text="Disconnected", fg="#ff4444")
        
    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if not message or not self.connected:
            return
            
        try:
            # Create message
            message_data = {
                'user': self.username,
                'msg': message,
                'time': time.time()
            }
            
            message_json = json.dumps(message_data)
            encrypted_data = self.cipher.encrypt(message_json.encode())
            
            if self.is_server:
                # Broadcast to all clients
                for client in self.clients:
                    try:
                        client.send(encrypted_data)
                    except:
                        pass
                        
                # Display locally
                timestamp = time.strftime('%H:%M:%S')
                display_msg = f"[{timestamp}] {self.username}: {message}\n"
                self.chat_display.insert(tk.END, display_msg)
                self.chat_display.see(tk.END)
                
            elif self.client_socket:
                # Send to server
                self.client_socket.send(encrypted_data)
                
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send: {str(e)}", parent=self.parent)
            
    def disconnect(self):
        self.connected = False
        
        if self.is_server:
            if self.server_socket:
                self.server_socket.close()
            self.server_btn.config(text="Start Server", bg="#141627")
            self.is_server = False
        else:
            if self.client_socket:
                self.client_socket.close()
            self.client_btn.config(text="Connect", bg="#141627")
            
        self.status_label.config(text="Disconnected", fg="#ff4444")
        self.chat_display.insert(tk.END, "[-] Disconnected\n")
        
    def clear_chat(self):
        self.chat_display.delete(1.0, tk.END)