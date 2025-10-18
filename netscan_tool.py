#!/usr/bin/env python3
# WATCH DOGS 1.1 — Mobile Red Team Recon Toolkit (terminal-only output)
# Author: CDSolo
# NOTE: Only scan systems you own or have explicit permission to test.

import socket, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------- Colors & ASCII ----------------
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
except Exception:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

try:
    import pyfiglet
    def make_banner(text):
        try:
            return pyfiglet.figlet_format(text, font="slant")
        except:
            return pyfiglet.figlet_format(text)
except Exception:
    pyfiglet = None
    def make_banner(text):
        return (
            " __        __   _    ____  ____   ___  ____   ___  ____  ___ \n"
            " \\ \\      / /  / \\  |  _ \\|  _ \\ / _ \\|  _ \\ / _ \\|  _ \\|_ _|\n"
            "  \\ \\ /\\ / /  / _ \\ | | | | | | | | | | | | | | | | | | | | \n"
            "   \\ V  V /  / ___ \\| |_| | |_| | |_| | |_| | |_| | |_| | | \n"
            "    \\_/\\_/  /_/   \\_\\____/|____/ \\___/|____/ \\___/|____/|___|\n"
        )

BANNER_TEXT = "WATCH DOGS 1.1"
BANNER = make_banner(BANNER_TEXT)

# ---------------- Defaults ----------------
COMMON_PORTS = [21,22,23,25,53,80,110,139,143,161,389,443,445,3389,5900,8080,8443]
DEFAULT_TIMEOUT = 0.6
DEFAULT_THREADS = 40

# ---------------- Helpers ----------------
def print_banner():
    print(Fore.RED + Style.BRIGHT + BANNER)
    print(Fore.GREEN + "Author: CDSolo — Mobile Red Team Recon Toolkit (terminal-only)\n")

def safe_input(prompt, default=None):
    try:
        v = input(Fore.CYAN + prompt).strip()
        if v == "" and default is not None:
            return default
        return v
    except (KeyboardInterrupt, EOFError):
        print()
        return ""

def parse_ports(port_text):
    """Return sorted list of ports from input like '1-100,80,443'."""
    if not port_text:
        return COMMON_PORTS[:]
    ports = set()
    for part in port_text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a,b = part.split("-",1)
                a,b = int(a), int(b)
                a = max(1,a); b = min(65535,b)
                if a <= b:
                    ports.update(range(a,b+1))
            except:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except:
                continue
    ports = sorted(ports)
    return ports if ports else COMMON_PORTS[:]

# ---------------- Network primitives ----------------
def tcp_connect_scan(target, port, timeout=0.6):
    """Try TCP connect and do a light banner grab. Returns (port, open_bool, banner)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))
        banner = None
        try:
            s.settimeout(0.5)
            data = s.recv(1024)
            if data:
                banner = data.decode(errors="ignore").strip()
            else:
                if port in (80,8080,8000,8443,8888):
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                        data = s.recv(1024)
                        if data: banner = data.decode(errors="ignore").strip()
                    except:
                        pass
        except:
            pass
        finally:
            s.close()
        return (port, True, banner)
    except:
        try:
            s.close()
        except:
            pass
        return (port, False, None)

def scan_ports(target, ports, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS):
    """Concurrent port scan; prints live results to terminal."""
    print(Fore.CYAN + f"\n[+] Scanning {target} ({len(ports)} ports)  threads={threads} timeout={timeout}\n")
    results = []
    with ThreadPoolExecutor(max_workers=max(2,threads)) as ex:
        futures = {ex.submit(tcp_connect_scan, target, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            p, ok, banner = fut.result()
            if ok:
                if banner:
                    print(Fore.GREEN + Style.BRIGHT + f"[OPEN]   {target}:{p}  --> {banner}")
                else:
                    print(Fore.GREEN + Style.BRIGHT + f"[OPEN]   {target}:{p}")
            else:
                # avoid flooding: print closed with carriage return
                print(Fore.BLUE + f"[closed] {target}:{p}", end="\r")
            results.append((p, ok, banner))
    open_count = sum(1 for _,ok,_ in results if ok)
    print(Fore.MAGENTA + f"\n[+] Scan finished: {open_count}/{len(ports)} open on {target}\n")
    return sorted(results, key=lambda x: x[0])

def discover_hosts(subnet_base, probe_ports=(80,443), timeout=0.3, threads=120):
    """TCP-based discovery across x.x.x.1..254 for given subnet base string (e.g. '192.168.1.')."""
    print(Fore.MAGENTA + f"\n[+] Discovering hosts in {subnet_base}1-254 (probes={probe_ports}) ...")
    alive = []
    ips = [f"{subnet_base}{i}" for i in range(1,255)]
    def probe(ip):
        for p in probe_ports:
            ok = tcp_connect_scan(ip,p,timeout)[1]
            if ok:
                return ip
        return None
    with ThreadPoolExecutor(max_workers=max(4,threads)) as ex:
        futures = {ex.submit(probe, ip): ip for ip in ips}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                print(Fore.CYAN + f"[ALIVE] {res}")
                alive.append(res)
    print(Fore.MAGENTA + f"[+] Discovery done: {len(alive)} hosts found.\n")
    return alive

# ---------------- DNS / WHOIS helpers ----------------
def dns_lookup(domain):
    try:
        info = socket.gethostbyname_ex(domain)
        print(Fore.CYAN + f"\nDNS lookup for {domain}:")
        print(Fore.GREEN + f"  Hostname: {info[0]}")
        print(Fore.GREEN + f"  Aliases: {info[1]}")
        print(Fore.GREEN + f"  IPs: {info[2]}\n")
    except Exception as e:
        print(Fore.RED + f"DNS lookup failed: {e}\n")

def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        print(Fore.CYAN + f"\nReverse DNS for {ip}: {host[0]} (aliases: {host[1]})\n")
    except Exception as e:
        print(Fore.RED + f"Reverse DNS failed: {e}\n")

def whois_query(q):
    servers = ["whois.iana.org","whois.arin.net","whois.ripe.net","whois.apnic.net","whois.lacnic.net","whois.nic.io"]
    for srv in servers:
        try:
            s = socket.create_connection((srv,43), timeout=6)
            s.sendall((q + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
            s.close()
            text = data.decode(errors="ignore")
            print(Fore.CYAN + f"\nWHOIS from {srv} for {q}:\n")
            print(Fore.GREEN + (text[:4000] + ("\n... (truncated)\n" if len(text)>4000 else "\n")))
            return
        except Exception:
            continue
    print(Fore.RED + "[!] WHOIS failed on known servers.\n")

# ---------------- Utility ----------------
def infer_local_subnet_base():
    """Try to infer local subnet base (best effort)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        base = ".".join(ip.split(".")[:-1]) + "."
        return base
    except:
        return "192.168.1."

# ---------------- CLI ----------------
def main_menu():
    print_banner()
    while True:
        print(Fore.YELLOW + "Menu:")
        print(Fore.CYAN + " 1) Scan single host (IP or hostname)")
        print(Fore.CYAN + " 2) Discover local subnet & scan discovered hosts")
        print(Fore.CYAN + " 3) Quick common ports scan (single host)")
        print(Fore.CYAN + " 4) DNS lookup (domain -> IPs)")
        print(Fore.CYAN + " 5) Reverse DNS (IP -> domain)")
        print(Fore.CYAN + " 6) WHOIS lookup (domain or IP)")
        print(Fore.CYAN + " 7) Exit\n")

        choice = safe_input("Choice [1-7]: ", default="7")
        if choice == "7" or choice == "":
            print(Fore.GREEN + "Exiting WATCH DOGS. Stay legal.")
            break

        # common params
        timeout = DEFAULT_TIMEOUT
        threads = DEFAULT_THREADS
        t_in = safe_input(f"Socket timeout seconds [{DEFAULT_TIMEOUT}]: ", default=str(DEFAULT_TIMEOUT))
        try: timeout = float(t_in)
        except: timeout = DEFAULT_TIMEOUT
        th_in = safe_input(f"Max threads [{DEFAULT_THREADS}]: ", default=str(DEFAULT_THREADS))
        try: threads = int(th_in)
        except: threads = DEFAULT_THREADS

        if choice == "1":
            target = safe_input("Target IP or hostname: ")
            if not target:
                print(Fore.RED + "No target entered.")
                continue
            ports_str = safe_input("Ports (e.g. 1-1024,80,443) [enter=common]: ", default="")
            ports = parse_ports(ports_str)
            scan_ports(target, ports, timeout, threads)

        elif choice == "3":
            target = safe_input("Target IP or hostname: ")
            if not target:
                print(Fore.RED + "No target entered.")
                continue
            scan_ports(target, COMMON_PORTS, timeout, threads)

        elif choice == "2":
            base_guess = infer_local_subnet_base()
            print(Fore.YELLOW + f"Inferred local subnet base: {base_guess}")
            base = safe_input("Subnet base (e.g. 192.168.1.) [enter=use inferred]: ", default=base_guess)
            probes = safe_input("Probe ports for discovery (comma list) [80,443]: ", default="80,443")
            probe_ports = [int(p.strip()) for p in probes.split(",") if p.strip().isdigit()]
            alive = discover_hosts(base, probe_ports and tuple(probe_ports) or (80,443), timeout, threads)
            if not alive:
                print(Fore.YELLOW + "No hosts discovered.")
            else:
                for ip in alive:
                    print(Fore.YELLOW + f"\nNow scanning discovered host {ip}")
                    scan_ports(ip, COMMON_PORTS, timeout, threads)

        elif choice == "4":
            d = safe_input("Domain to lookup (example.com): ")
            if d: dns_lookup(d)

        elif choice == "5":
            ip = safe_input("IP to reverse lookup: ")
            if ip: reverse_dns(ip)

        elif choice == "6":
            q = safe_input("WHOIS query (domain or IP): ")
            if q: whois_query(q)

        else:
            print(Fore.RED + "Invalid choice. Pick 1-7.\n")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(Fore.RED + "\nInterrupted. Exiting.")
        sys.exit(0)
