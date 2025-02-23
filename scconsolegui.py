# GUI (Graphical User Interface) of scconsole.
# GUI version is to diffrent with CLI of scconsole!
# scconsolegui uses 9 exploits.

import tkinter as tk
from tkinter import ttk, filedialog
import subprocess
import threading
import os

if not 'SUDO_UID' in os.environ.keys():
    print("please try running SC-Console GUI with sudo.")
    exit()

class SCFrameworkGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SC Framework")
        self.root.geometry("800x600")
        
        # Create the menu bar
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        # Create the File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Exit", command=self.exit_application)
        self.file_menu.add_command(label="Save Logs As...", command=self.save_logs_as)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        
        # Create the Tools menu
        self.tools_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Tools", menu=self.tools_menu)
        
        # Create the Scan submenu
        self.scan_menu = tk.Menu(self.tools_menu, tearoff=0)
        self.scan_menu.add_command(label="sc-gui - Vulnerability Scan (URL)", command=lambda: self.run_exploit("sc-gui/vuln-curl-website.py"))
        self.scan_menu.add_command(label="sc-gui - SSH Version (URL)", command=lambda: self.run_exploit("sc-gui-version.py"))
        self.scan_menu.add_command(label="sc-gui - Vulnerability Find (URL)", command=lambda: self.run_exploit("sc-gui/vulnerability-find.py"))
        self.scan_menu.add_command(label="sc-gui - OS Detector (LHOST)", command=lambda: self.run_exploit("sc-gui/os_detector.py"))
        self.tools_menu.add_cascade(label="Scan", menu=self.scan_menu)
        
        # Create the Exploit submenu
        self.exploit_menu = tk.Menu(self.tools_menu, tearoff=0)
        self.exploit_menu.add_command(label="sc-gui - Reverse HTTP (URL)", command=lambda: self.run_exploit("sc-gui/reverse_http.py"))
        self.exploit_menu.add_command(label="sc-gui - Kernal xnu IP fragment privesc (LHOST)", command=lambda: self.run_exploit("sc-gui/kernal_xnu_ip_fragment_privesc.py"))
        self.exploit_menu.add_command(label="sc-gui - Kernal xnu IP fragment privesc 2 (LHOST)", command=lambda: self.run_exploit("sc-gui/kernal_xnu_ip_fragment_privesc_2.py"))
        self.tools_menu.add_cascade(label="Exploit", menu=self.exploit_menu)
        
        # Create the Web submenu
        self.web_menu = tk.Menu(self.tools_menu, tearoff=0)
        self.web_menu.add_command(label="sc-gui - Information Gather (URL)", command=lambda: self.run_exploit("sc-gui/information-gather.py"))
        self.web_menu.add_command(label="sc-gui - Extract Table DB Column (URL)", command=lambda: self.run_exploit("sc-gui/extract_table_db_column.py"))
        self.tools_menu.add_cascade(label="Web", menu=self.web_menu)
        
        # Create the text input for logs and inputs
        self.logs_input = tk.Text(self.root, height=10, width=80, bg="#D3D3D3")
        self.logs_input.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create the icon
        self.icon = tk.PhotoImage(file="images/SCframework-icon.png")
        self.root.iconphoto(False, self.icon)
        
    def run_exploit(self, exploit_path):
        def run_process():
            # Prompt the user for input
            user_input = input("\n(LHOST, URL)\nwe typed the requires on the exploits in 'Tools' bar!\nPlease enter first the required input: ")

            # Execute the selected exploit and capture the output
            output = subprocess.run(["python", f"exploits/{exploit_path}"], capture_output=True, text=True, input=user_input)

            # Display the user input and output in the logs input
            self.logs_input.insert(tk.END, f"User Input: {user_input}\n")
            self.logs_input.insert(tk.END, output.stdout)
            self.logs_input.insert(tk.END, output.stderr)

        # Run the process in a separate thread
        thread = threading.Thread(target=run_process)
        thread.start()

    def save_logs_as(self):
        # Open a file save dialog
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])

        # Save the logs to the selected file
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.logs_input.get("1.0", tk.END))

    def exit_application(self):
        self.root.destroy()

# Create the main window
root = tk.Tk()

# Create the SCFrameworkGUI instance
app = SCFrameworkGUI(root)

# Start the main event loop
root.mainloop()