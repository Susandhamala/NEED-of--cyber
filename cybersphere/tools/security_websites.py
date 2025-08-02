import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import webbrowser

def run_security_websites():
    websites_window = tk.Toplevel()
    websites_window.title("Security Websites Directory")
    websites_window.geometry("900x700")
    websites_window.configure(bg="#0f111a")
    
    SecurityWebsites(websites_window)

class SecurityWebsites:
    def __init__(self, parent):
        self.parent = parent
        self.setup_ui()
        self.load_websites()
        
    def setup_ui(self):
        main_frame = tk.Frame(self.parent, bg="#0f111a")
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(main_frame, text="📚 Cybersecurity Resources Directory", font=("Consolas", 16, "bold"),
                fg="#00fff7", bg="#0f111a").pack(pady=10)
        
        # Search frame
        search_frame = tk.Frame(main_frame, bg="#0f111a")
        search_frame.pack(fill='x', pady=10)
        
        tk.Label(search_frame, text="Search:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.search_entry = tk.Entry(search_frame, width=30, bg="#1f2233", fg="#00fff7",
                                    font=("Consolas", 12), insertbackground="#00fff7")
        self.search_entry.pack(side='left', padx=10)
        self.search_entry.bind('<KeyRelease>', self.search_websites)
        
        tk.Button(search_frame, text="Clear", command=self.clear_search,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Category filter
        category_frame = tk.Frame(main_frame, bg="#0f111a")
        category_frame.pack(fill='x', pady=5)
        
        tk.Label(category_frame, text="Category:", font=("Consolas", 12),
                fg="#00fff7", bg="#0f111a").pack(side='left')
        
        self.category_var = tk.StringVar(value="All")
        categories = ["All", "Learning", "Tools", "News", "Community", "Research"]
        self.category_combo = ttk.Combobox(category_frame, textvariable=self.category_var,
                                          values=categories, state='readonly', width=15)
        self.category_combo.pack(side='left', padx=10)
        self.category_combo.bind('<<ComboboxSelected>>', self.filter_by_category)
        
        # Websites list
        tk.Label(main_frame, text="Cybersecurity Resources:", font=("Consolas", 12, "bold"),
                fg="#00fff7", bg="#0f111a").pack(anchor='w', pady=(20,5))
        
        # Treeview for websites
        columns = ('Name', 'Category', 'Rating', 'Description')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=15)
        
        self.tree.heading('Name', text='Name')
        self.tree.heading('Category', text='Category')
        self.tree.heading('Rating', text='Rating')
        self.tree.heading('Description', text='Description')
        
        self.tree.column('Name', width=150)
        self.tree.column('Category', width=100)
        self.tree.column('Rating', width=80)
        self.tree.column('Description', width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill='both', expand=True)
        scrollbar.pack(side=tk.RIGHT, fill='y')
        
        # Button frame
        button_frame = tk.Frame(main_frame, bg="#0f111a")
        button_frame.pack(fill='x', pady=10)
        
        tk.Button(button_frame, text="Open Website", command=self.open_website,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        tk.Button(button_frame, text="Copy URL", command=self.copy_url,
                 bg="#141627", fg="#00fff7", font=("Consolas", 12)).pack(side='left', padx=5)
        
        # Configure tags for ratings
        self.tree.tag_configure('excellent', background='#44ff44')
        self.tree.tag_configure('good', background='#4488ff')
        self.tree.tag_configure('fair', background='#ffff44')
        self.tree.tag_configure('poor', background='#ff8844')
        
    def load_websites(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Cybersecurity websites database
        self.websites = [
            {
                'name': 'OWASP',
                'url': 'https://owasp.org',
                'category': 'Learning',
                'rating': '5/5',
                'description': 'Open Web Application Security Project - Top 10 security risks'
            },
            {
                'name': 'Kali Linux',
                'url': 'https://kali.org',
                'category': 'Tools',
                'rating': '5/5',
                'description': 'Advanced Penetration Testing Linux distribution'
            },
            {
                'name': 'SecurityTube',
                'url': 'https://securitytube.net',
                'category': 'Learning',
                'rating': '4/5',
                'description': 'Free cybersecurity training videos and courses'
            },
            {
                'name': 'Hack The Box',
                'url': 'https://hackthebox.eu',
                'category': 'Tools',
                'rating': '5/5',
                'description': 'Penetration testing labs and challenges'
            },
            {
                'name': 'TryHackMe',
                'url': 'https://tryhackme.com',
                'category': 'Learning',
                'rating': '5/5',
                'description': 'Cybersecurity learning platform with hands-on labs'
            },
            {
                'name': 'ThreatPost',
                'url': 'https://threatpost.com',
                'category': 'News',
                'rating': '4/5',
                'description': 'Latest cybersecurity news and threat intelligence'
            },
            {
                'name': 'Krebs on Security',
                'url': 'https://krebsonsecurity.com',
                'category': 'News',
                'rating': '5/5',
                'description': 'In-depth security journalism by Brian Krebs'
            },
            {
                'name': 'Reddit NetSec',
                'url': 'https://reddit.com/r/netsec',
                'category': 'Community',
                'rating': '4/5',
                'description': 'Active cybersecurity community discussions'
            },
            {
                'name': 'SANS Institute',
                'url': 'https://sans.org',
                'category': 'Learning',
                'rating': '5/5',
                'description': 'Leading cybersecurity training and certification'
            },
            {
                'name': 'NIST',
                'url': 'https://nist.gov/cybersecurity',
                'category': 'Research',
                'rating': '5/5',
                'description': 'National Institute of Standards and Technology cybersecurity guidelines'
            },
            {
                'name': 'MITRE ATT&CK',
                'url': 'https://attack.mitre.org',
                'category': 'Research',
                'rating': '5/5',
                'description': 'Comprehensive adversary tactics and techniques knowledge base'
            },
            {
                'name': 'VirusTotal',
                'url': 'https://virustotal.com',
                'category': 'Tools',
                'rating': '4/5',
                'description': 'Analyze suspicious files and URLs for malware'
            },
            {
                'name': 'Have I Been Pwned',
                'url': 'https://haveibeenpwned.com',
                'category': 'Tools',
                'rating': '5/5',
                'description': 'Check if your email or phone has been compromised'
            },
            {
                'name': 'Security Weekly',
                'url': 'https://securityweekly.com',
                'category': 'News',
                'rating': '4/5',
                'description': 'Cybersecurity podcast and news network'
            },
            {
                'name': 'Dark Reading',
                'url': 'https://darkreading.com',
                'category': 'News',
                'rating': '4/5',
                'description': 'Comprehensive cybersecurity news and analysis'
            }
        ]
        
        self.display_websites(self.websites)
        
    def display_websites(self, websites_list):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        for website in websites_list:
            rating_tag = self.get_rating_tag(website['rating'])
            self.tree.insert('', tk.END, 
                           values=(website['name'], website['category'], website['rating'], website['description']),
                           tags=(rating_tag, website['url']))
                           
    def get_rating_tag(self, rating):
        if '5' in rating:
            return 'excellent'
        elif '4' in rating:
            return 'good'
        elif '3' in rating:
            return 'fair'
        else:
            return 'poor'
            
    def search_websites(self, event=None):
        search_term = self.search_entry.get().lower()
        category = self.category_var.get()
        
        filtered_websites = self.websites
        
        # Filter by search term
        if search_term:
            filtered_websites = [
                w for w in filtered_websites 
                if search_term in w['name'].lower() or 
                   search_term in w['description'].lower() or
                   search_term in w['category'].lower()
            ]
            
        # Filter by category
        if category != "All":
            filtered_websites = [w for w in filtered_websites if w['category'] == category]
            
        self.display_websites(filtered_websites)
        
    def filter_by_category(self, event=None):
        self.search_websites()
        
    def clear_search(self):
        self.search_entry.delete(0, tk.END)
        self.category_var.set("All")
        self.display_websites(self.websites)
        
    def open_website(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a website to open.", parent=self.parent)
            return
            
        item = self.tree.item(selected[0])
        url = self.tree.item(selected[0])['tags'][1]  # tags[0] is rating, tags[1] is url
        
        try:
            webbrowser.open(url)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open website: {str(e)}", parent=self.parent)
            
    def copy_url(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a website to copy.", parent=self.parent)
            return
            
        item = self.tree.item(selected[0])
        url = self.tree.item(selected[0])['tags'][1]
        
        self.parent.clipboard_clear()
        self.parent.clipboard_append(url)
        self.parent.update()
        messagebox.showinfo("Copied", "URL copied to clipboard.", parent=self.parent)