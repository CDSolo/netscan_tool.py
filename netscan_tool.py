#!/usr/bin/env python3
"""
WATCH DOGS 1.1 — Red Teaming Toolkit (Safe / Legal)
Author: CDSolo
"""

import os, socket, time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colors
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except:
    class Fore:
        RED=GREEN=YELLOW=CYAN=MAGENTA=BLUE=WHITE=RESET=""
    class Style:
        BRIGHT=RESET_ALL=""

# ASCII Banner
try:
    import pyfiglet
    banner = pyfiglet.figlet_format("WATCH DOGS 1.1", font="big")
except:
    banner = """
 __        __   _    ____  ____   ___  ____   ___  ____  ___
 \ \      / /  / \  |  _ \|  _ \ / _ \|  _ \ / _ \|  _ \|_ _|
  \ \ /\ / /  / _ \ | | | | | | | | | | | | | | | | | | | |
   \ V  V /  / ___ \| |_| | |_| | |_| | |_| | |_| | |_| | | |
    \_/\_/  /_/   \_\____/|____/ \___/|____/ \___/|____/|___|
"""
print(Fore.RED + Style.BRIGHT + banner)
print(Fore.GREEN + "Author: CDSolo — Mobile Red Team Toolkit\n")

# ---------------- Menu ----------------
menu_options = {
    "01": "Network Scanner",
    "02": "Port Scanner",
    "03": "WHOIS / DNS Info",
    "04": "Password Generator",
    "05": "Wordlist Generator",
    "06": "IP Calculator",
    "07": "Exit"
}

def print_menu():
    print(Fore.CYAN + Style.BRIGHT + "Available Tools:\n")
    for key, val in menu_options.items():
        print(Fore.YELLOW + f"[{key}] " + Fore.GREEN + val)

# ---------------- Utility Functions ----------------
def tcp_scan(ip, port, timeout=0.5):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        banner = None
        try:
            s.settimeout(0.3)
            data = s.recv(1024)
            if data:
                banner = data.decode(errors="ignore").strip()
        except: pass
        s.close()
        return (port, True, banner)
    except:
        s.close()
        return (port, False, None)

def scan_ports(ip, ports, threads=50):
    print(Fore.CYAN + f"\nScanning {ip}...\n")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(tcp_scan, ip, p): p for p in ports}
        for fut in as_completed(futures):
            p, ok, banner = fut.result()
            if ok:
                print(Fore.GREEN + f"[OPEN] {ip}:{p}" + (f" --> {banner}" if banner else ""))
            else:
                print(Fore.BLUE + f"[closed] {ip}:{p}", end="\r")
            results.append((p, ok, banner))
    return results

# ---------------- CLI ----------------
def main():
    while True:
        print_menu()
        choice = input(Fore.MAGENTA + "\nSelect an option: ").strip()
        if choice=="01":
            target = input(Fore.CYAN + "Enter IP or hostname: ").strip()
            scan_ports(target, [21,22,23,25,53,80,110,139,143,443,445,3389,8080,8443])
        elif choice=="02":
            target = input(Fore.CYAN + "Enter IP or hostname: ").strip()
            ports = input(Fore.CYAN + "Enter ports (comma-separated or 1-1024): ").strip()
            port_list = [int(p.strip()) for p in ports.replace("-",",").split(",") if p.strip().isdigit()]
            scan_ports(target, port_list)
        elif choice=="07":
            print(Fore.RED + "Exiting...")
            break
        else:
            print(Fore.YELLOW + "Feature not yet implemented. Coming soon!\n")

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt:
        print(Fore.RED + "\nInterrupted by user. Exiting.")
