#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import threading
import os
import platform
import shlex

class BlackIceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BlackIce Shellcode Loader Generator")
        self.root.geometry("1000x800")
        
        # Apply a dark theme (Manual colors for standard Tkinter widgets)
        self.root.tk_setPalette(background='#2b2b2b', foreground='#ffffff', 
                                activeBackground='#404040', activeForeground='#ffffff')
        
        # Style configuration for ttk widgets
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background="#2b2b2b", borderwidth=0)
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabelframe", background="#2b2b2b", foreground="white")
        style.configure("TLabelframe.Label", background="#2b2b2b", foreground="white")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Initialize variables
        self.blackice_path = tk.StringVar()
        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.format_var = tk.StringVar(value="exe")
        self.arch_var = tk.StringVar(value="amd64")
        self.exec_var = tk.StringVar(value="SuspendedProcess")
        self.proc_var = tk.StringVar(value="notepad.exe")
        
        # Booleans
        self.verbose_var = tk.BooleanVar()
        self.compress_var = tk.BooleanVar()
        self.calc_var = tk.BooleanVar()
        self.sandbox_var = tk.BooleanVar()
        self.hashing_var = tk.BooleanVar()
        self.amsi_var = tk.BooleanVar()

        # Build Tabs
        self.create_main_tab()
        self.create_execution_tab()
        self.create_evasion_tab()
        self.create_advanced_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.blackice_process = None
        self.find_blackice_binary()

    def find_blackice_binary(self):
        """Auto-locate the BlackIce binary based on OS."""
        name = "blackice.exe" if platform.system() == "Windows" else "blackice"
        possible = [f"./{name}", f"./build/{name}", f"/usr/local/bin/{name}"]
        for p in possible:
            if os.path.exists(p):
                self.blackice_path.set(os.path.abspath(p))
                self.status_var.set(f"Found binary: {p}")
                return
        self.status_var.set("Binary not found. Please set path in 'Advanced' tab.")

    def browse_input(self):
        path = filedialog.askopenfilename(title="Select Shellcode Binary (.bin)")
        if path: self.input_var.set(path)

    def browse_output(self):
        path = filedialog.asksaveasfilename(title="Save Loader As")
        if path: self.output_var.set(path)

    def create_main_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Main")
        
        # Files
        req = ttk.LabelFrame(tab, text="Required Parameters")
        req.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(req, text="Input:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(req, textvariable=self.input_var, width=50).grid(row=0, column=1)
        ttk.Button(req, text="Browse", command=self.browse_input).grid(row=0, column=2)
        
        ttk.Label(req, text="Output:").grid(row=1, column=0, padx=5, pady=5)
        ttk.Entry(req, textvariable=self.output_var, width=50).grid(row=1, column=1)
        ttk.Button(req, text="Browse", command=self.browse_output).grid(row=1, column=2)

        # Options
        opt = ttk.Frame(tab)
        opt.pack(fill="x", padx=10)
        ttk.Label(opt, text="Format:").pack(side=tk.LEFT, padx=5)
        ttk.Combobox(opt, textvariable=self.format_var, values=["exe", "dll"], width=10).pack(side=tk.LEFT)
        
        ttk.Label(opt, text="Arch:").pack(side=tk.LEFT, padx=20)
        ttk.Radiobutton(opt, text="x64", variable=self.arch_var, value="amd64").pack(side=tk.LEFT)
        ttk.Radiobutton(opt, text="x86", variable=self.arch_var, value="386").pack(side=tk.LEFT)

        # Output Console
        self.output_text = scrolledtext.ScrolledText(tab, height=15, bg="#1e1e1e", fg="#00ff00")
        self.output_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x")
        self.gen_btn = ttk.Button(btn_frame, text="GENERATE LOADER", command=self.start_generation)
        self.gen_btn.pack(side=tk.RIGHT, padx=10, pady=5)

    def create_execution_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Execution")
        
        ttk.Label(tab, text="Injection Technique:").pack(anchor="w", padx=10, pady=5)
        techniques = ["SuspendedProcess", "ProcessHollowing", "NtCreateThreadEx", "NtQueueApcThreadEx"]
        ttk.Combobox(tab, textvariable=self.exec_var, values=techniques).pack(fill="x", padx=10)
        
        ttk.Label(tab, text="Target Process:").pack(anchor="w", padx=10, pady=5)
        ttk.Entry(tab, textvariable=self.proc_var).pack(fill="x", padx=10)

    def create_evasion_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Evasion")
        
        ttk.Checkbutton(tab, text="Sandbox Evasion", variable=self.sandbox_var).pack(anchor="w", padx=20, pady=5)
        ttk.Checkbutton(tab, text="API Hashing", variable=self.hashing_var).pack(anchor="w", padx=20, pady=5)
        ttk.Checkbutton(tab, text="AMSI Bypass", variable=self.amsi_var).pack(anchor="w", padx=20, pady=5)

    def create_advanced_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Advanced")
        ttk.Label(tab, text="BlackIce Binary Path:").pack(anchor="w", padx=10, pady=5)
        ttk.Entry(tab, textvariable=self.blackice_path).pack(fill="x", padx=10)

    def log(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)

    def start_generation(self):
        # Build command list
        if not self.blackice_path.get():
            messagebox.showerror("Error", "BlackIce binary path is not set!")
            return
            
        cmd = [self.blackice_path.get(), "-f", self.format_var.get(), "-a", self.arch_var.get()]
        
        if self.calc_var.get():
            cmd.append("-calc")
        else:
            if not self.input_var.get():
                messagebox.showerror("Error", "Please select an input file or check 'Use calc'")
                return
            cmd.extend(["-i", self.input_var.get()])
            
        if self.output_var.get():
            cmd.extend(["-o", self.output_var.get()])
            
        # Add flags based on repository CLI args
        if self.sandbox_var.get(): cmd.append("-sandbox")
        if self.amsi_var.get(): cmd.append("-amsi")
        
        self.log(f"[*] Running: {' '.join(cmd)}")
        threading.Thread(target=self.run_process, args=(cmd,), daemon=True).start()

    def run_process(self, cmd):
        try:
            self.gen_btn.config(state=tk.DISABLED)
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                self.log(line.strip())
            process.wait()
            self.log("[+] Finished.")
        except Exception as e:
            self.log(f"[!] Error: {str(e)}")
        finally:
            self.gen_btn.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = BlackIceGUI(root)
    root.mainloop()
