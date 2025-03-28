# -*- coding: utf-8 -*-
import os
import winreg
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import json
import tkinter.ttk as ttk
import hashlib

class ProgramLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("Program Launcher with Registry Modifier")
        
        # Security settings
        self.max_attempts = 5
        self.attempts = 0
        
        # Set warm blue color scheme
        self.bg_color = "#E6F2FF"  # Very light blue
        self.button_color = "#99C2FF"  # Light blue
        self.highlight_color = "#66A3FF"  # Medium blue
        self.text_color = "#003366"  # Dark blue
        
        self.root.configure(bg=self.bg_color)
        
        # Load or initialize configuration
        self.config_file = "program_launcher_config.json"
        self.config = self.load_config()
        
        # Create GUI elements
        self.create_main_interface()
        self.create_settings_button()
    
    def hash_password(self, password):
        """Create a SHA-256 hash of the password"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def load_config(self):
        """Load configuration from file or create default if not exists"""
        default_config = {
            "password": "",
            "button1": {
                "name": "Button 1",
                "registry_key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "value_name": "EnableLUA",
                "value_data": "0",
                "program_path": r"C:\Windows\System32\notepad.exe"
            },
            "button2": {
                "name": "Button 2",
                "registry_key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
                "value_name": "EnableAutoTray",
                "value_data": "0",
                "program_path": r"C:\Windows\System32\calc.exe"
            },
            "button3": {
                "name": "Button 3",
                "registry_key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "value_name": "NoDriveTypeAutoRun",
                "value_data": "255",
                "program_path": r"C:\Windows\System32\mspaint.exe"
            },
            "colors": {
                "bg_color": "#E6F2FF",
                "button_color": "#99C2FF",
                "highlight_color": "#66A3FF",
                "text_color": "#003366"
            }
        }
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                loaded_config = json.load(f)
                # Ensure all required fields exist
                for btn in ["button1", "button2", "button3"]:
                    if btn not in loaded_config:
                        loaded_config[btn] = default_config[btn]
                    else:
                        # Add missing name field if it doesn't exist
                        if "name" not in loaded_config[btn]:
                            loaded_config[btn]["name"] = default_config[btn]["name"]
                # Add colors section if it doesn't exist
                if "colors" not in loaded_config:
                    loaded_config["colors"] = default_config["colors"]
                # Add password field if it doesn't exist
                if "password" not in loaded_config:
                    loaded_config["password"] = default_config["password"]
                return loaded_config
        except (FileNotFoundError, json.JSONDecodeError):
            return default_config
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=4)
    
    def create_main_interface(self):
        """Create the main interface with three buttons"""
        frame = tk.Frame(self.root, padx=20, pady=20, bg=self.bg_color)
        frame.pack()
        
        # Button 1
        btn1 = tk.Button(
            frame, 
            text=self.config["button1"].get("name", "Button 1"),
            width=20,
            command=lambda: self.modify_and_launch("button1"),
            bg=self.button_color,
            fg=self.text_color,
            activebackground=self.highlight_color,
            highlightbackground=self.highlight_color
        )
        btn1.grid(row=0, column=0, pady=5)
        
        # Button 2
        btn2 = tk.Button(
            frame, 
            text=self.config["button2"].get("name", "Button 2"),
            width=20,
            command=lambda: self.modify_and_launch("button2"),
            bg=self.button_color,
            fg=self.text_color,
            activebackground=self.highlight_color,
            highlightbackground=self.highlight_color
        )
        btn2.grid(row=1, column=0, pady=5)
        
        # Button 3
        btn3 = tk.Button(
            frame, 
            text=self.config["button3"].get("name", "Button 3"),
            width=20,
            command=lambda: self.modify_and_launch("button3"),
            bg=self.button_color,
            fg=self.text_color,
            activebackground=self.highlight_color,
            highlightbackground=self.highlight_color
        )
        btn3.grid(row=2, column=0, pady=5)
    
    def create_settings_button(self):
        """Create settings button at the bottom"""
        settings_btn = tk.Button(
            self.root, 
            text="Settings",
            command=self.open_settings,
            bg=self.button_color,
            fg=self.text_color,
            activebackground=self.highlight_color
        )
        settings_btn.pack(side=tk.BOTTOM, pady=10)
    
    def check_password(self):
        """Check if password is set and verify it"""
        if not self.config.get("password"):
            # No password set, ask to create one
            password = simpledialog.askstring("Set Password", 
                                            "No password set. Create a new password:",
                                            show='*')
            if password:
                self.config["password"] = self.hash_password(password)
                self.save_config()
                return True
            return False
        else:
            # Password exists, verify it
            if self.attempts >= self.max_attempts:
                messagebox.showerror("Locked", "Too many attempts. Settings locked.")
                return False
                
            password = simpledialog.askstring("Password Required", 
                                             "Enter password to access settings:",
                                             show='*')
            if password and self.hash_password(password) == self.config["password"]:
                self.attempts = 0
                return True
            else:
                self.attempts += 1
                remaining = self.max_attempts - self.attempts
                messagebox.showerror("Error", 
                                    f"Wrong password. {remaining} attempts remaining.")
                return False
    
    def change_password(self):
        """Change the current password"""
        if not self.check_password():
            return
        
        new_password = simpledialog.askstring("Change Password", 
                                             "Enter new password:",
                                             show='*')
        if new_password:
            confirm = simpledialog.askstring("Change Password", 
                                            "Confirm new password:",
                                            show='*')
            if new_password == confirm:
                self.config["password"] = self.hash_password(new_password)
                self.save_config()
                messagebox.showinfo("Success", "Password changed successfully")
            else:
                messagebox.showerror("Error", "Passwords do not match")
    
    def modify_registry(self, key_path, value_name, value_data, value_type=winreg.REG_SZ):
        """Modify a Windows registry value"""
        try:
            # Split the key path into hive and the rest
            hive, sub_key = key_path.split('\\', 1) if '\\' in key_path else (None, key_path)
            
            # Map hive names to winreg constants
            hives = {
                "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                "HKEY_USERS": winreg.HKEY_USERS,
                "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG
            }
            
            # Default to HKEY_CURRENT_USER if no hive specified
            if hive is None:
                hive = "HKEY_CURRENT_USER"
            else:
                hive = hive.upper()
            
            if hive not in hives:
                raise ValueError(f"Unknown registry hive: {hive}")
            
            # Open the key with write access
            with winreg.OpenKey(hives[hive], sub_key, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, value_name, 0, value_type, value_data)
            
            return True
        except Exception as e:
            messagebox.showerror("Registry Error", f"Failed to modify registry: {str(e)}")
            return False
    
    def launch_program(self, program_path):
        """Launch a program"""
        try:
            os.startfile(program_path)
            return True
        except Exception as e:
            messagebox.showerror("Program Launch Error", f"Failed to launch program: {str(e)}")
            return False
    
    def modify_and_launch(self, button_id):
        """Modify registry and then launch program for a specific button"""
        config = self.config[button_id]
        
        # Modify registry
        if self.modify_registry(
            config["registry_key"],
            config["value_name"],
            config["value_data"]
        ):
            # Launch program
            self.launch_program(config["program_path"])
    
    def open_settings(self):
        """Open settings window to configure buttons"""
        if not self.check_password():
            return
        
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Configuration Panel")
        settings_window.configure(bg=self.bg_color)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(settings_window)
        notebook.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Create tabs for each button
        for btn_id in ["button1", "button2", "button3"]:
            frame = tk.Frame(notebook, bg=self.bg_color)
            notebook.add(frame, text=btn_id.upper())
            self.create_settings_tab(frame, btn_id)
        
        # Color settings tab
        color_frame = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(color_frame, text="COLORS")
        self.create_color_settings_tab(color_frame)
        
        # Save button
        save_btn = tk.Button(
            settings_window,
            text="Save Configuration",
            command=lambda: [self.save_config(), settings_window.destroy(), self.update_ui()],
            bg=self.button_color,
            fg=self.text_color,
            activebackground=self.highlight_color
        )
        save_btn.pack(pady=10)
    
    def create_settings_tab(self, parent, button_id):
        """Create a settings tab for a specific button"""
        config = self.config[button_id]
        
        # Button Name
        tk.Label(parent, text="Button Name:", bg=self.bg_color, fg=self.text_color).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        name_entry = tk.Entry(parent, width=50)
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        name_entry.insert(0, config["name"])
        
        # Registry Key
        tk.Label(parent, text="Registry Key:", bg=self.bg_color, fg=self.text_color).grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        reg_key_entry = tk.Entry(parent, width=50)
        reg_key_entry.grid(row=1, column=1, padx=5, pady=5)
        reg_key_entry.insert(0, config["registry_key"])
        
        # Value Name
        tk.Label(parent, text="Value Name:", bg=self.bg_color, fg=self.text_color).grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        value_name_entry = tk.Entry(parent, width=50)
        value_name_entry.grid(row=2, column=1, padx=5, pady=5)
        value_name_entry.insert(0, config["value_name"])
        
        # Value Data
        tk.Label(parent, text="Value Data:", bg=self.bg_color, fg=self.text_color).grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        value_data_entry = tk.Entry(parent, width=50)
        value_data_entry.grid(row=3, column=1, padx=5, pady=5)
        value_data_entry.insert(0, config["value_data"])
        
        # Program Path
        tk.Label(parent, text="Program Path:", bg=self.bg_color, fg=self.text_color).grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        program_path_entry = tk.Entry(parent, width=50)
        program_path_entry.grid(row=4, column=1, padx=5, pady=5)
        program_path_entry.insert(0, config["program_path"])
        
        # Browse button for program path
        browse_btn = tk.Button(
            parent,
            text="Browse...",
            command=lambda: self.browse_for_program(program_path_entry),
            bg=self.button_color,
            fg=self.text_color,
            activebackground=self.highlight_color
        )
        browse_btn.grid(row=4, column=2, padx=5, pady=5)
        
        # Save button for this tab
        save_btn = tk.Button(
            parent,
            text="Save",
            command=lambda: self.save_button_config(
                button_id,
                name_entry.get(),
                reg_key_entry.get(),
                value_name_entry.get(),
                value_data_entry.get(),
                program_path_entry.get()
            ),
            bg=self.button_color,
            fg=self.text_color,
            activebackground=self.highlight_color
        )
        save_btn.grid(row=5, column=1, pady=10)
    
    def create_color_settings_tab(self, parent):
        """Create tab for color settings"""
        # Background Color
        tk.Label(parent, text="Background Color:", bg=self.bg_color, fg=self.text_color).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        bg_color_entry = tk.Entry(parent, width=10)
        bg_color_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        bg_color_entry.insert(0, self.config["colors"]["bg_color"])
        
        # Button Color
        tk.Label(parent, text="Button Color:", bg=self.bg_color, fg=self.text_color).grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        button_color_entry = tk.Entry(parent, width=10)
        button_color_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        button_color_entry.insert(0, self.config["colors"]["button_color"])
        
        # Highlight Color
        tk.Label(parent, text="Highlight Color:", bg=self.bg_color, fg=self.text_color).grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        highlight_color_entry = tk.Entry(parent, width=10)
        highlight_color_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        highlight_color_entry.insert(0, self.config["colors"]["highlight_color"])
        
        # Text Color
        tk.Label(parent, text="Text Color:", bg=self.bg_color, fg=self.text_color).grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        text_color_entry = tk.Entry(parent, width=10)
        text_color_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        text_color_entry.insert(0, self.config["colors"]["text_color"])
        
        # Password change button
        pass_btn = tk.Button(
            parent,
            text="Change Password",
            command=self.change_password,
            bg=self.button_color,
            fg=self.text_color,
            activebackground=self.highlight_color
        )
        pass_btn.grid(row=4, column=1, pady=10)
        
        # Save button for color settings
        save_btn = tk.Button(
            parent,
            text="Save Colors",
            command=lambda: self.save_color_config(
                bg_color_entry.get(),
                button_color_entry.get(),
                highlight_color_entry.get(),
                text_color_entry.get()
            ),
            bg=self.button_color,
            fg=self.text_color,
            activebackground=self.highlight_color
        )
        save_btn.grid(row=5, column=1, pady=10)
    
    def browse_for_program(self, entry_widget):
        """Open file dialog to browse for a program"""
        filepath = filedialog.askopenfilename(
            title="Select Program",
            filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")]
        )
        if filepath:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filepath)
    
    def save_button_config(self, button_id, name, reg_key, value_name, value_data, program_path):
        """Save configuration for a specific button"""
        self.config[button_id] = {
            "name": name,
            "registry_key": reg_key,
            "value_name": value_name,
            "value_data": value_data,
            "program_path": program_path
        }
        messagebox.showinfo("Success", f"Configuration for {button_id} saved!")
    
    def save_color_config(self, bg_color, button_color, highlight_color, text_color):
        """Save color configuration"""
        self.config["colors"] = {
            "bg_color": bg_color,
            "button_color": button_color,
            "highlight_color": highlight_color,
            "text_color": text_color
        }
        messagebox.showinfo("Success", "Color configuration saved!")
    
    def update_ui(self):
        """Update the UI with new colors and button names"""
        # Update colors
        self.bg_color = self.config["colors"]["bg_color"]
        self.button_color = self.config["colors"]["button_color"]
        self.highlight_color = self.config["colors"]["highlight_color"]
        self.text_color = self.config["colors"]["text_color"]
        
        # Recreate the interface
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.root.configure(bg=self.bg_color)
        self.create_main_interface()
        self.create_settings_button()

if __name__ == "__main__":
    root = tk.Tk()
    app = ProgramLauncher(root)
    root.mainloop()