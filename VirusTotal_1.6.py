import subprocess
import sys

# List of required packages
required_packages = [
    'requests',
    'scapy',
    'cryptography',
    'tk',
    'psutil',
]

# Install missing packages
for package in required_packages:
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

import requests
import scapy.all as scapy
import time
import json
import os
import socket
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk
from threading import Thread, Event, Lock
import psutil
import getpass

CONFIG_FILE = 'config.json'
KEY_FILE = 'secret.key'
IP_LOG_FILE = 'captured_ips.log'
PROCESSED_LOG_FILE = 'processed_ips.log'
LOG_FILE = 'suspicious_ips.log'
MAX_LOG_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

REQUEST_DELAY_SECONDS = 60

lock = Lock()

def generate_key():
    """Generate and save an encryption key."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)

def load_key():
    """Load the encryption key from the file."""
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, 'rb') as key_file:
        return key_file.read()

encryption_key = load_key()
cipher = Fernet(encryption_key)

def encrypt_api_key(api_key):
    """Encrypt the API key."""
    return cipher.encrypt(api_key.encode()).decode()

def decrypt_api_key(encrypted_api_key):
    """Decrypt the API key."""
    try:
        return cipher.decrypt(encrypted_api_key.encode()).decode()
    except Exception as e:
        print(f"Error decrypting API key: {e}")
        return ''

def load_config():
    """Load configuration from the file."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_config(config):
    """Save configuration to the file."""
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file)

def check_ip_on_virustotal(ip_address, api_key):
    """Check the IP address on VirusTotal."""
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        response_json = response.json()

        data = response_json.get('data', {})
        attributes = data.get('attributes', {})
        country = attributes.get('country', 'Unknown')
        last_analysis_results = attributes.get('last_analysis_results', {})

        category = 'undetected'
        for engine, result_data in last_analysis_results.items():
            if result_data['result'] in ['suspicious', 'malicious']:
                category = result_data['result']
                break

        result = f"IP Address: {ip_address}\nCountry: {country}\nCategory: {category}\nLast Analysis Results:\n"
        for engine, result_data in last_analysis_results.items():
            result += f"{engine}: {result_data['result']}\n"
        print(f"VirusTotal check complete for IP: {ip_address}, Category: {category}")
        return result, category
    except requests.exceptions.RequestException as e:
        print(f"RequestException during VirusTotal check for IP: {ip_address}, Error: {str(e)}")
        return f"An error occurred during the request: {str(e)}", "undetected"

def get_hostname(ip_address):
    """Get hostname from IP address."""
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        print(f"Hostname for IP {ip_address}: {hostname}")
        return hostname
    except socket.herror as e:
        print(f"Error getting hostname for IP {ip_address}: {e}")
        return "Unknown"

def get_process_info(ip_address):
    """Get process information associated with an IP address."""
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.raddr.ip == ip_address:
            try:
                process = psutil.Process(conn.pid)
                print(f"Process for IP {ip_address}: {process.name()} (PID: {process.pid})")
                return process.name(), process.pid
            except psutil.NoSuchProcess as e:
                print(f"No such process for IP {ip_address}: {e}")
                return "Unknown", "Unknown"
    print(f"No connection found for IP {ip_address}")
    return "Unknown", "Unknown"

def log_suspicious_ip(ip_address, result):
    """Log suspicious IP addresses with additional context."""
    print(f"Attempting to log suspicious IP: {ip_address}")
    hostname = get_hostname(ip_address)
    process_name, process_pid = get_process_info(ip_address)
    username = getpass.getuser()

    with open(LOG_FILE, 'a') as log_file:
        log_file.write(f"{time.ctime()} - IP: {ip_address}\n")
        log_file.write(f"Hostname: {hostname}\n")
        log_file.write(f"Process: {process_name} (PID: {process_pid})\n")
        log_file.write(f"User: {username}\n")
        log_file.write(f"{result}\n\n")
    print(f"Logged suspicious IP: {ip_address} to {LOG_FILE}")

def ensure_log_files_exist():
    """Ensure log files exist."""
    for log_file in [IP_LOG_FILE, PROCESSED_LOG_FILE, LOG_FILE]:
        if not os.path.exists(log_file):
            open(log_file, 'a').close()
            print(f"Created log file: {log_file}")

def monitor_traffic(stop_event):
    """Monitor network traffic and log IPs."""
    captured_ips = set()

    def process_packet(packet):
        if stop_event.is_set():
            return False

        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst

            for ip_address in [ip_src, ip_dst]:
                if ip_address not in captured_ips:
                    captured_ips.add(ip_address)
                    with lock:
                        with open(IP_LOG_FILE, 'a') as log_file:
                            log_file.write(f"{ip_address}\n")
                    print(f"Captured IP: {ip_address}")

    scapy.sniff(prn=process_packet, store=False, stop_filter=lambda _: stop_event.is_set())

def process_ips(api_key, stop_event, result_textbox):
    """Process IPs from log file."""
    while not stop_event.is_set():
        with lock:
            if os.path.getsize(IP_LOG_FILE) > 0:
                with open(IP_LOG_FILE, 'r') as log_file:
                    lines = log_file.readlines()
                if lines:
                    ip_address = lines[0].strip()
                    remaining_lines = lines[1:]
                    with open(IP_LOG_FILE, 'w') as log_file:
                        log_file.writelines(remaining_lines)

                    result, category = check_ip_on_virustotal(ip_address, api_key)
                    print(f"Category for IP {ip_address}: {category}")
                    if category in ["suspicious", "malicious"]:
                        log_suspicious_ip(ip_address, result)
                        result_textbox.insert(tk.END, f"Checked IP: {ip_address}\n{result}\n\n")
                        print(f"Logged suspicious IP: {ip_address}")
                    else:
                        result_textbox.insert(tk.END, f"Checked IP: {ip_address}\n{result}\n\n")
                    result_textbox.update_idletasks()

                    # Log processed IP
                    with open(PROCESSED_LOG_FILE, 'a') as processed_log_file:
                        processed_log_file.write(f"{ip_address}\n")

                    # Check file size and truncate if necessary
                    if os.path.getsize(PROCESSED_LOG_FILE) > MAX_LOG_FILE_SIZE:
                        with open(PROCESSED_LOG_FILE, 'w') as processed_log_file:
                            processed_log_file.truncate(0)

                    time.sleep(REQUEST_DELAY_SECONDS)
            else:
                time.sleep(1)

def inject_test_ip():
    """Inject a known suspicious IP address for testing."""
    test_ip = "1.2.3.4"  # Replace with a known suspicious IP address
    with lock:
        with open(IP_LOG_FILE, 'a') as log_file:
            log_file.write(f"{test_ip}\n")
    print(f"Injected test IP: {test_ip}")

def create_gui():
    """Main function to create the GUI and start monitoring."""
    config = load_config()
    saved_api_key_encrypted = config.get('api_key', '')
    saved_api_key = decrypt_api_key(saved_api_key_encrypted) if saved_api_key_encrypted else ''

    ensure_log_files_exist()

    root = tk.Tk()
    root.title("IP Address Checker")
    root.geometry("800x600")
    root.resizable(True, True)

    style = ttk.Style()
    style.theme_use('clam')

    input_frame = ttk.Frame(root, padding=10)
    input_frame.pack(fill=tk.X)

    input_api_frame = ttk.Frame(root, padding=10)
    input_api_frame.pack(fill=tk.X)

    api_label = ttk.Label(input_api_frame, text="Enter API Key:")
    api_label.pack(side=tk.LEFT, padx=5)
    api_entry = ttk.Entry(input_api_frame, width=40)
    api_entry.pack(side=tk.LEFT, padx=5)

    if saved_api_key:
        api_entry.insert(0, saved_api_key)

    save_api_var = tk.BooleanVar(value=bool(saved_api_key))
    save_api_checkbox = ttk.Checkbutton(input_api_frame, text="Save API Key", variable=save_api_var)
    save_api_checkbox.pack(side=tk.LEFT, padx=5)

    start_button = ttk.Button(input_api_frame, text="Start Monitoring")
    start_button.pack(side=tk.LEFT, padx=5)

    stop_button = ttk.Button(input_api_frame, text="Stop Monitoring")
    stop_button.pack(side=tk.LEFT, padx=5)
    stop_button.config(state=tk.DISABLED)

    test_button = ttk.Button(input_api_frame, text="Inject Test IP", command=inject_test_ip)
    test_button.pack(side=tk.LEFT, padx=5)

    result_frame = ttk.Frame(root, padding=10)
    result_frame.pack(fill=tk.BOTH, expand=True)

    result_textbox = tk.Text(result_frame, wrap=tk.WORD)
    result_scrollbar = ttk.Scrollbar(result_frame, command=result_textbox.yview)
    result_textbox.config(yscrollcommand=result_scrollbar.set)
    result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    result_textbox.pack(fill=tk.BOTH, expand=True)

    def on_start_button_click():
        api_key = api_entry.get()
        result_textbox.delete(1.0, tk.END)  # Clear previous results

        if save_api_var.get():
            encrypted_api_key = encrypt_api_key(api_key)
            config['api_key'] = encrypted_api_key
        else:
            config['api_key'] = ''
        save_config(config)

        stop_event = Event()
        monitor_thread = Thread(target=monitor_traffic, args=(stop_event,))
        monitor_thread.start()
        process_thread = Thread(target=process_ips, args=(api_key, stop_event, result_textbox))
        process_thread.start()

        def on_stop_button_click():
            stop_event.set()
            while monitor_thread.is_alive() or process_thread.is_alive():
                time.sleep(0.1)
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)

        stop_button.config(command=on_stop_button_click, state=tk.NORMAL)
        start_button.config(state=tk.DISABLED)

        def on_close():
            stop_event.set()
            while monitor_thread.is_alive() or process_thread.is_alive():
                time.sleep(0.1)
            root.destroy()

        root.protocol("WM_DELETE_WINDOW", on_close)

    start_button.config(command=on_start_button_click)

    style.configure('TButton', font=('Helvetica', 12))

    root.mainloop()

if __name__ == "__main__":
    gui_thread = Thread(target=create_gui)
    gui_thread.start()
