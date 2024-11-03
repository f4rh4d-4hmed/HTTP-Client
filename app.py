import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import requests
import json
import time
import sv_ttk
from datetime import datetime
import base64

class HttpClient:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTP Client")
        self.root.geometry("1000x700")
        self.set_icon()
        self.setup_theme()
        self.create_variables()
        self.create_ui()
        self.setup_bindings()
        self.request_history = []

    def set_icon(self):
        try:
            self.root.iconbitmap('icon.ico')
        except Exception as e:
            print(f"Failed to set icon: {e}")
        
    def setup_theme(self):
        sv_ttk.set_theme("dark")
        self.style = ttk.Style()
        self.style.configure("Custom.TEntry", fieldbackground="#2A2A2A", foreground="white")
        self.style.configure("Custom.TButton", padding=5)
        
    def create_variables(self):
        self.request_method_var = tk.StringVar(value="GET")
        self.content_type_var = tk.StringVar(value="JSON")
        self.auth_type_var = tk.StringVar(value="No Auth")
        self.theme_var = tk.StringVar(value="dark")
        self.request_body_var = tk.StringVar(value="")
        
    def create_ui(self):
        toolbar_frame = ttk.Frame(self.root)
        toolbar_frame.grid(row=0, column=0, columnspan=4, sticky="ew", padx=5, pady=5)
        
        url_frame = ttk.Frame(toolbar_frame)
        url_frame.grid(row=0, column=0, sticky="ew")
        
        self.request_method_menu = ttk.Combobox(
            url_frame,
            textvariable=self.request_method_var,
            values=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
            state="readonly",
            width=8
        )
        self.request_method_menu.grid(row=0, column=0, padx=(0, 5))
        
        self.url_entry = ttk.Entry(url_frame, width=70, font=("Helvetica", 10))
        self.url_entry.insert(0, "https://api.example.com/")
        self.url_entry.grid(row=0, column=1, padx=5, sticky="ew")
        
        buttons_frame = ttk.Frame(toolbar_frame)
        buttons_frame.grid(row=0, column=1, padx=5)
    
        self.send_button = ttk.Button(buttons_frame, text="Send", command=self.send_request, style="Custom.TButton")
        self.send_button.grid(row=0, column=0, padx=2)
    
        self.save_button = ttk.Button(buttons_frame, text="Save", command=self.save_request, style="Custom.TButton")
        self.save_button.grid(row=0, column=1, padx=2)
    
        self.load_button = ttk.Button(buttons_frame, text="Load", command=self.load_request, style="Custom.TButton")
        self.load_button.grid(row=0, column=2, padx=2)
    
        self.reset_button = ttk.Button(buttons_frame, text="Reset", command=self.reset_fields, style="Custom.TButton")
        self.reset_button.grid(row=0, column=3, padx=2)
        
        theme_button = ttk.Button(buttons_frame, text="Toggle Theme", command=self.toggle_theme, style="Custom.TButton")
        theme_button.grid(row=0, column=3, padx=2)
        
        self.tab_control = ttk.Notebook(self.root)
        self.create_tabs()
        self.tab_control.grid(row=1, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)
        
        self.create_status_bar()
        
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        url_frame.grid_columnconfigure(1, weight=1)
        
    def create_tabs(self):
        self.request_tabs = ttk.Notebook(self.tab_control)
        self.content_tab = ttk.Frame(self.request_tabs)
        self.headers_tab = ttk.Frame(self.request_tabs)
        self.auth_tab = ttk.Frame(self.request_tabs)
        self.request_tabs.add(self.content_tab, text="Request Body")
        self.request_tabs.add(self.headers_tab, text="Headers")
        self.request_tabs.add(self.auth_tab, text="Authorization")
        
        self.response_tabs = ttk.Notebook(self.tab_control)
        self.response_content_tab = ttk.Frame(self.response_tabs)
        self.response_headers_tab = ttk.Frame(self.response_tabs)
        self.raw_tab = ttk.Frame(self.response_tabs)
        self.history_tab = ttk.Frame(self.response_tabs)
        self.response_tabs.add(self.response_content_tab, text="Response")
        self.response_tabs.add(self.response_headers_tab, text="Response Headers")
        self.response_tabs.add(self.raw_tab, text="Raw")
        self.response_tabs.add(self.history_tab, text="History")
        
        self.tab_control.add(self.request_tabs, text="Request")
        self.tab_control.add(self.response_tabs, text="Response")
        
        self.setup_request_body_tab()
        self.setup_headers_tab()
        self.setup_auth_tab()
        self.setup_response_tabs()
        self.setup_history_tab()
        
    def setup_request_body_tab(self):
        content_frame = ttk.Frame(self.content_tab)
        content_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        ttk.Label(content_frame, text="Content Type:").grid(row=0, column=0, padx=5)
        self.content_type_menu = ttk.Combobox(
            content_frame,
            textvariable=self.content_type_var,
            values=["JSON", "HTML", "XML", "Text", "Form Data"],
            state="readonly"
        )
        self.content_type_menu.grid(row=0, column=1, padx=5)
        
        self.request_body_text = self.create_scrolled_text(self.content_tab)
        self.request_body_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.content_tab.grid_rowconfigure(1, weight=1)
        self.content_tab.grid_columnconfigure(0, weight=1)
        
    def setup_headers_tab(self):
        self.headers_tree = ttk.Treeview(self.headers_tab, columns=("Header", "Value"), show="headings")
        self.headers_tree.heading("Header", text="Header")
        self.headers_tree.heading("Value", text="Value")
        self.headers_tree.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        btn_frame = ttk.Frame(self.headers_tab)
        btn_frame.grid(row=1, column=0, pady=5)
        ttk.Button(btn_frame, text="Add Header", command=self.add_header).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Remove Header", command=self.remove_header).grid(row=0, column=1, padx=5)
        
        self.headers_tab.grid_rowconfigure(0, weight=1)
        self.headers_tab.grid_columnconfigure(0, weight=1)
        
    def setup_auth_tab(self):
        auth_frame = ttk.Frame(self.auth_tab)
        auth_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        ttk.Label(auth_frame, text="Authorization Type:").grid(row=0, column=0, padx=5)
        self.auth_type_menu = ttk.Combobox(
            auth_frame,
            textvariable=self.auth_type_var,
            values=["No Auth", "Bearer Token", "Basic Auth", "API Key", "Custom"],
            state="readonly"
        )
        self.auth_type_menu.grid(row=0, column=1, padx=5)
        
        self.auth_input_frame = ttk.Frame(self.auth_tab)
        self.auth_input_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        
        self.bearer_token_frame = ttk.Frame(self.auth_input_frame)
        self.bearer_token_label = ttk.Label(self.bearer_token_frame, text="Token:")
        self.bearer_token_entry = ttk.Entry(self.bearer_token_frame, width=50)
        
        self.basic_auth_frame = ttk.Frame(self.auth_input_frame)
        self.username_label = ttk.Label(self.basic_auth_frame, text="Username:")
        self.username_entry = ttk.Entry(self.basic_auth_frame, width=30)
        self.password_label = ttk.Label(self.basic_auth_frame, text="Password:")
        self.password_entry = ttk.Entry(self.basic_auth_frame, width=30, show="*")
        
        self.api_key_frame = ttk.Frame(self.auth_input_frame)
        self.api_key_label = ttk.Label(self.api_key_frame, text="API Key:")
        self.api_key_entry = ttk.Entry(self.api_key_frame, width=40)
        self.api_key_name_label = ttk.Label(self.api_key_frame, text="Key Name:")
        self.api_key_name_entry = ttk.Entry(self.api_key_frame, width=20)
        
        self.custom_auth_frame = ttk.Frame(self.auth_input_frame)
        self.custom_auth_label = ttk.Label(self.custom_auth_frame, text="Custom Header:")
        self.custom_auth_entry = ttk.Entry(self.custom_auth_frame, width=50)
        
        self.auth_type_var.trace("w", self.update_auth_fields)
        
    def setup_response_tabs(self):
        self.response_text = self.create_scrolled_text(self.response_content_tab)
        self.response_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self.response_headers_text = self.create_scrolled_text(self.response_headers_tab)
        self.response_headers_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self.raw_text = self.create_scrolled_text(self.raw_tab)
        self.raw_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        for tab in [self.response_content_tab, self.response_headers_tab, self.raw_tab]:
            tab.grid_rowconfigure(0, weight=1)
            tab.grid_columnconfigure(0, weight=1)
            
    def setup_history_tab(self):
        self.history_tree = ttk.Treeview(
            self.history_tab,
            columns=("Time", "Method", "URL", "Status"),
            show="headings"
        )
        self.history_tree.heading("Time", text="Time")
        self.history_tree.heading("Method", text="Method")
        self.history_tree.heading("URL", text="URL")
        self.history_tree.heading("Status", text="Status")
        
        self.history_tree.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.history_tab.grid_rowconfigure(0, weight=1)
        self.history_tab.grid_columnconfigure(0, weight=1)
        
    def create_status_bar(self):
        status_frame = ttk.Frame(self.root)
        status_frame.grid(row=2, column=0, columnspan=4, sticky="ew", padx=5, pady=2)
        
        self.status_label = ttk.Label(status_frame, text="Ready")
        self.status_label.grid(row=0, column=0, sticky="w")
        
        self.size_label = ttk.Label(status_frame, text="Size: 0 bytes")
        self.size_label.grid(row=0, column=1, padx=20)
        
        self.time_label = ttk.Label(status_frame, text="Time: 0 ms")
        self.time_label.grid(row=0, column=2, padx=20)
        
    def create_scrolled_text(self, parent):
        text_widget = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            bg='#1C1C1C',
            fg='#FFFFFF',
            font=("Consolas", 10),
            insertbackground="white"
        )
        return text_widget
        
    def toggle_theme(self):
        current_theme = sv_ttk.get_theme()
        new_theme = "light" if current_theme == "dark" else "dark"
        sv_ttk.set_theme(new_theme)
        self.theme_var.set(new_theme)
        
    def update_auth_fields(self, *args):
        for frame in [self.bearer_token_frame, self.basic_auth_frame, 
                     self.api_key_frame, self.custom_auth_frame]:
            for widget in frame.winfo_children():
                widget.grid_forget()
            frame.grid_forget()
            
        auth_type = self.auth_type_var.get()
        
        if auth_type == "Bearer Token":
            self.bearer_token_frame.grid(row=0, column=0, sticky="ew", pady=5)
            self.bearer_token_label.grid(row=0, column=0, padx=5)
            self.bearer_token_entry.grid(row=0, column=1, padx=5)
            
        elif auth_type == "Basic Auth":
            self.basic_auth_frame.grid(row=0, column=0, sticky="ew", pady=5)
            self.username_label.grid(row=0, column=0, padx=5)
            self.username_entry.grid(row=0, column=1, padx=5)
            self.password_label.grid(row=0, column=2, padx=5)
            self.password_entry.grid(row=0, column=3, padx=5)
        elif auth_type == "API Key":
            self.api_key_frame.grid(row=0, column=0, sticky="ew", pady=5)
            self.api_key_name_label.grid(row=0, column=0, padx=5)
            self.api_key_name_entry.grid(row=0, column=1, padx=5)
            self.api_key_label.grid(row=0, column=2, padx=5)
            self.api_key_entry.grid(row=0, column=3, padx=5)
            
        elif auth_type == "Custom":
            self.custom_auth_frame.grid(row=0, column=0, sticky="ew", pady=5)
            self.custom_auth_label.grid(row=0, column=0, padx=5)
            self.custom_auth_entry.grid(row=0, column=1, padx=5)

    def setup_bindings(self):
        self.url_entry.bind("<FocusIn>", self.on_url_focus_in)
        self.url_entry.bind("<FocusOut>", self.on_url_focus_out)
        self.history_tree.bind("<Double-1>", self.load_history_item)
        
    def on_url_focus_in(self, event):
        if self.url_entry.get() == "https://api.example.com/":
            self.url_entry.delete(0, tk.END)
            
    def on_url_focus_out(self, event):
        if self.url_entry.get() == "":
            self.url_entry.insert(0, "https://api.example.com/")
            
    def add_header(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Header")
        dialog.geometry("300x150")
        
        ttk.Label(dialog, text="Header:").grid(row=0, column=0, padx=5, pady=5)
        header_entry = ttk.Entry(dialog, width=30)
        header_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Value:").grid(row=1, column=0, padx=5, pady=5)
        value_entry = ttk.Entry(dialog, width=30)
        value_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def save_header():
            header = header_entry.get()
            value = value_entry.get()
            if header and value:
                self.headers_tree.insert("", "end", values=(header, value))
            dialog.destroy()
            
        ttk.Button(dialog, text="Save", command=save_header).grid(row=2, column=0, columnspan=2, pady=10)
        
    def remove_header(self):
        selected_item = self.headers_tree.selection()
        if selected_item:
            self.headers_tree.delete(selected_item)
            
    def get_headers(self):
        headers = {}
        for item in self.headers_tree.get_children():
            header, value = self.headers_tree.item(item)['values']
            headers[header] = value
            
        auth_type = self.auth_type_var.get()
        if auth_type == "Bearer Token":
            token = self.bearer_token_entry.get()
            if token:
                headers['Authorization'] = f'Bearer {token}'
        elif auth_type == "Basic Auth":
            username = self.username_entry.get()
            password = self.password_entry.get()
            if username and password:
                auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers['Authorization'] = f'Basic {auth_string}'
        elif auth_type == "API Key":
            key_name = self.api_key_name_entry.get()
            api_key = self.api_key_entry.get()
            if key_name and api_key:
                headers[key_name] = api_key
        elif auth_type == "Custom":
            custom_auth = self.custom_auth_entry.get()
            if custom_auth:
                headers['Authorization'] = custom_auth
                
        content_type = self.content_type_var.get()
        if content_type == "JSON":
            headers['Content-Type'] = 'application/json'
        elif content_type == "HTML":
            headers['Content-Type'] = 'text/html'
        elif content_type == "XML":
            headers['Content-Type'] = 'application/xml'
        elif content_type == "Text":
            headers['Content-Type'] = 'text/plain'
        elif content_type == "Form Data":
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            
        return headers
        
    def send_request(self):
        self.status_label.config(text="Sending request...")
        url = self.url_entry.get()
        method = self.request_method_var.get()
        headers = self.get_headers()
        
        try:
            request_body = self.request_body_text.get("1.0", tk.END).strip()
            start_time = time.time()
            
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=request_body if request_body else None
            )
            
            end_time = time.time()
            elapsed_time = round((end_time - start_time) * 1000, 2)
            
            self.update_response_display(response, elapsed_time)
            self.add_to_history(response, elapsed_time)
            self.status_label.config(text=f"Request completed with status {response.status_code}")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_label.config(text="Request failed")
            
    def update_response_display(self, response, elapsed_time):
        self.response_text.delete("1.0", tk.END)
        content_type = response.headers.get('Content-Type', '')
        
        if 'application/json' in content_type:
            try:
                formatted_content = json.dumps(response.json(), indent=2)
                self.response_text.insert(tk.END, formatted_content)
            except:
                self.response_text.insert(tk.END, response.text)
        else:
            self.response_text.insert(tk.END, response.text)
            
        self.response_headers_text.delete("1.0", tk.END)
        headers_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
        self.response_headers_text.insert(tk.END, headers_text)
        
        self.raw_text.delete("1.0", tk.END)
        raw_text = f"{response.request.method} {response.request.url}\n\n"
        raw_text += "Request Headers:\n"
        raw_text += "\n".join([f"{k}: {v}" for k, v in response.request.headers.items()])
        raw_text += "\n\nResponse Status: {response.status_code}\n"
        raw_text += "\nResponse Headers:\n"
        raw_text += headers_text
        raw_text += "\n\nResponse Body:\n"
        raw_text += response.text
        self.raw_text.insert(tk.END, raw_text)
        
        self.size_label.config(text=f"Size: {len(response.content)} bytes")
        self.time_label.config(text=f"Time: {elapsed_time} ms")
        
    def add_to_history(self, response, elapsed_time):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.history_tree.insert(
            "",
            0,
            values=(
                timestamp,
                response.request.method,
                response.request.url,
                f"{response.status_code} ({elapsed_time}ms)"
            )
        )
        
        self.request_history.append({
            'timestamp': timestamp,
            'method': response.request.method,
            'url': response.request.url,
            'headers': dict(response.request.headers),
            'body': self.request_body_text.get("1.0", tk.END).strip(),
            'response': response.text,
            'status_code': response.status_code,
            'elapsed_time': elapsed_time
        })
        
    def load_history_item(self, event):
        selected_item = self.history_tree.selection()
        if not selected_item:
            return
            
        item_index = self.history_tree.index(selected_item)
        history_item = self.request_history[len(self.request_history) - 1 - item_index]
        
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, history_item['url'])
        self.request_method_var.set(history_item['method'])
        self.request_body_text.delete("1.0", tk.END)
        self.request_body_text.insert("1.0", history_item['body'])
        
    def save_request(self):
        try:
            request_data = {
                'url': self.url_entry.get(),
                'method': self.request_method_var.get(),
                'content_type': self.content_type_var.get(),
                'auth_type': self.auth_type_var.get(),
                'body': self.request_body_text.get("1.0", tk.END).strip(),
                'headers': {},
                'auth': {
                    'bearer_token': self.bearer_token_entry.get(),
                    'username': self.username_entry.get(),
                    'password': self.password_entry.get(),
                    'api_key': self.api_key_entry.get(),
                    'api_key_name': self.api_key_name_entry.get(),
                    'custom_auth': self.custom_auth_entry.get()
                }
            }

            for item in self.headers_tree.get_children():
                header, value = self.headers_tree.item(item)['values']
                request_data['headers'][header] = value

            file_path = filedialog.asksaveasfilename(
                defaultextension='.json',
                filetypes=[('JSON files', '*.json'), ('All files', '*.*')],
                initialfile='request.json',
                title='Save Request'
            )

            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(request_data, f, indent=2)
                self.status_label.config(text=f"Request saved to {file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save request: {str(e)}")

    def load_request(self):
        try:
            file_path = filedialog.askopenfilename(
                filetypes=[('JSON files', '*.json'), ('All files', '*.*')],
                title='Load Request'
            )

            if file_path:
                with open(file_path, 'r', encoding='utf-8') as f:
                    request_data = json.load(f)

                self.reset_fields()

                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, request_data.get('url', ''))
                self.request_method_var.set(request_data.get('method', 'GET'))
                self.content_type_var.set(request_data.get('content_type', 'JSON'))
                self.auth_type_var.set(request_data.get('auth_type', 'No Auth'))

                self.request_body_text.delete("1.0", tk.END)
                self.request_body_text.insert("1.0", request_data.get('body', ''))

                headers = request_data.get('headers', {})
                for header, value in headers.items():
                    self.headers_tree.insert("", "end", values=(header, value))

                auth_data = request_data.get('auth', {})
                self.bearer_token_entry.insert(0, auth_data.get('bearer_token', ''))
                self.username_entry.insert(0, auth_data.get('username', ''))
                self.password_entry.insert(0, auth_data.get('password', ''))
                self.api_key_entry.insert(0, auth_data.get('api_key', ''))
                self.api_key_name_entry.insert(0, auth_data.get('api_key_name', ''))
                self.custom_auth_entry.insert(0, auth_data.get('custom_auth', ''))

                self.status_label.config(text=f"Request loaded from {file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load request: {str(e)}")

        
    def reset_fields(self):
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, "https://api.example.com/")
        self.request_method_var.set("GET")
        self.content_type_var.set("JSON")
        self.auth_type_var.set("No Auth")
        self.request_body_text.delete("1.0", tk.END)
        self.response_text.delete("1.0", tk.END)
        self.response_headers_text.delete("1.0", tk.END)
        self.raw_text.delete("1.0", tk.END)
        self.size_label.config(text="Size: 0 bytes")
        self.time_label.config(text="Time: 0 ms")
        self.status_label.config(text="Ready")
        
        for item in self.headers_tree.get_children():
            self.headers_tree.delete(item)
            
        self.bearer_token_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.api_key_entry.delete(0, tk.END)
        self.api_key_name_entry.delete(0, tk.END)
        self.custom_auth_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = HttpClient(root)
    root.mainloop()
