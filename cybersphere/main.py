import tkinter as tk
from pages.login_page import LoginPage
from pages.dashboard_page import DashboardPage
from pages.register_page import RegisterPage

def on_login_success(root):
    for widget in root.winfo_children():
        widget.destroy()
    DashboardPage(root, on_logout)

def on_logout(root):
    for widget in root.winfo_children():
        widget.destroy()
    show_login(root)

def show_login(root):
    LoginPage(root, on_login_success, show_register)

def show_register(root):
    for widget in root.winfo_children():
        widget.destroy()
    RegisterPage(root, show_login)

def main():
    root = tk.Tk()
    root.title("CyberSphere - Cybersecurity Toolkit")
    root.geometry("1000x700")
    root.resizable(False, False)

    show_login(root)

    root.mainloop()

if __name__ == "__main__":
    main()