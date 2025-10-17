import socket, time, json, sys, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import partial

# Optional libs for UI; tool falls back if not present
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    class Fore:
        RED = ''
        GREEN = ''
        YELLOW = ''
        CYAN = ''
        MAGENTA = ''
        RESET = ''
    class Style:
        BRIGHT = ''
        RESET_ALL = ''

try:
    import pyfiglet
except Exception:
    pyfiglet = None

try:
    from rich.table import Table
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    console = Console()
    USE_RICH = True
except Exception:
    USE_RICH = False
    console = None

try:
    import requests
except Exception:
    requests = None

# ---------------- Configuration defaults ----------------
DEFAULT_TIMEOUT = 0.6
DEFAULT_THREADS = 60
COMMON_PORTS = [21,22,23,25,53,80,110,139,143,161,389,443,445,587,8080,8443,3306,5432,5900]

# ---------------- Helper functions ----------------
def banner():
    text = "NetScan"
    if pyfiglet:
        print(Fore.CYAN + pyfiglet.figlet_format(text))
    else:
        print(Fore.CYAN + f"=== {text} ===")
    print(Fore.YELLOW + "Handheld netscan — only scan devices you own/are permitted to test\n")

def parse_ports(port_input):
    """Parse strings like '1-1024,3306,8080' into a sorted set of ints"""
    ports = set()
    parts = [p.strip() for p in port_input.split(',') if p.strip()]
    for p in parts:
        if '-' in p:
            a,b = p.split('-',1)
            try:
                a,b = int(a), int(b)
                ports.update(range(max(1,a), min(65535,b)+1))
            except:
                pass
        else:
            try:
                ports.add(int(p))
            except:
                pass
    return sorted([p for p in ports if 1 <= p <= 65535])

def tcp_connect_scan(target, port, timeout):
    """Try to connect; return (port, True/False, banner_str_or_none)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))
        # attempt a small banner grab
        banner = None
        try:
            s.settimeout(0.6)
            # send nothing normally; some services send a greeting
            data = s.recv(1024)
            if data:
                banner = data.decode(errors='ignore').strip()
            else:
                # try a polite probe for HTTP:
                if port in (80, 8080, 8000, 8888, 3000):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    data = s.recv(1024)
                    banner = data.decode(errors='ignore').strip()
        except Exception:
            pass
        finally:
            s.close()
        return (port, True, banner)
    except Exception:
        try:
            s.close()
        except:
            pass
        return (port, False, None)

def http_check(target, port, timeout):
    """If requests available, try simple HTTP HEAD to get server header"""
    if not requests:
        return None
    proto = "https" if port in (443, 8443) else "http"
    url = f"{proto}://{target}:{port}/"
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
        server = r.headers.get('Server')
        return server or f"HTTP {r.status_code}"
    except Exception:
        return None

def scan_ports_for_target(target, ports, timeout, max_workers, show_progress=True):
    results = []
    if USE_RICH and show_progress:
        with Progress(SpinnerColumn(), TextColumn("{task.fields[target]}"), BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeElapsedColumn()) as progress:
            task = progress.add_task("scan", total=len(ports), target=f"Scanning {target}")
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(tcp_connect_scan, target, p, timeout): p for p in ports}
                for fut in as_completed(futures):
                    p, success, banner = fut.result()
                    if success:
                        progress.console.print(Fore.GREEN + f"[{target}] OPEN {p}" + (f" - {banner}" if banner else ""))
                    progress.advance(task)
                    results.append({'port': p, 'open': success, 'banner': banner})
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(tcp_connect_scan, target, p, timeout): p for p in ports}
            for fut in as_completed(futures):
                p, success, banner = fut.result()
                if success:
                    print(Fore.GREEN + f"[{target}] OPEN {p}" + (f" - {banner}" if banner else ""))
                else:
                    print(Fore.RED + f"[{target}] closed {p}", end="\r")
                results.append({'port': p, 'open': success, 'banner': banner})
    return sorted(results, key=lambda x: x['port'])

def host_discovery(subnet_base, ports_to_probe=(80,443), timeout=0.6, threads=120):
    """Given '192.168.1.' check .1-.254 for any host accepting a TCP connect on ports_to_probe"""
    alive = []
    ips = [f"{subnet_base}{i}" for i in range(1,255)]
    def probe(ip):
        for p in ports_to_probe:
            p_open = tcp_connect_scan(ip, p, timeout)[1]
            if p_open:
                return ip
        return None
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, ip): ip for ip in ips}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                print(Fore.CYAN + f"Host alive: {res}")
                alive.append(res)
    return alive

def save_reports(report, basename="netscan_report"):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    json_name = f"{basename}_{ts}.json"
    with open(json_name, "w") as f:
        json.dump(report, f, indent=2)
    # simple HTML
    html_name = f"{basename}_{ts}.html"
    rows = []
    for host in report.get('hosts', []):
        for p in host.get('ports', []):
            rows.append(f"<tr><td>{host['target']}</td><td>{p['port']}</td><td>{'OPEN' if p['open'] else 'CLOSED'}</td><td>{(p['banner'] or '')}</td></tr>")
    html = f"""<html><head><meta charset="utf-8"><title>NetScan Report</title></head>
    <body><h1>NetScan Report - {ts}</h1><table border="1" cellpadding="6"><tr><th>host</th><th>port</th><th>status</th><th>banner</th></tr>{''.join(rows)}</table></body></html>"""
    with open(html_name, "w") as f:
        f.write(html)
    print(Fore.YELLOW + f"Saved JSON: {json_name}  HTML: {html_name}")
    return json_name, html_name

# ---------------- CLI & Main flow ----------------
def main():
    banner()
    while True:
        print(Fore.MAGENTA + "Menu:")
        print(Fore.GREEN + " 1) Scan single host")
        print(Fore.GREEN + " 2) Scan subnet (host discovery + port scan)")
        print(Fore.GREEN + " 3) Quick common ports on host")
        print(Fore.GREEN + " 4) Exit")
        choice = input(Fore.YELLOW + "Choose option: ").strip()
        if choice == "4":
            print(Fore.CYAN + "Goodbye.")
            break
        if choice not in ("1","2","3"):
            print(Fore.RED + "Invalid choice")
            continue

        timeout = input(Fore.YELLOW + f"Socket timeout secs [{DEFAULT_TIMEOUT}]: ").strip() or str(DEFAULT_TIMEOUT)
        try:
            timeout = float(timeout)
        except:
            timeout = DEFAULT_TIMEOUT
        threads = input(Fore.YELLOW + f"Max threads [{DEFAULT_THREADS}]: ").strip() or str(DEFAULT_THREADS)
        try:
            threads = int(threads)
        except:
            threads = DEFAULT_THREADS

        report = {'metadata': {'started': datetime.utcnow().isoformat() + "Z", 'timeout': timeout, 'threads': threads}, 'hosts': []}

        if choice == "1":
            target = input(Fore.YELLOW + "Target IP or hostname: ").strip()
            port_input = input(Fore.YELLOW + "Ports (e.g. 1-1024,80,443) [common ports]: ").strip() or ",".join(str(p) for p in COMMON_PORTS)
            ports = parse_ports(port_input)
            print(Fore.CYAN + f"Scanning {target} ports: {ports[:10]}{'...' if len(ports)>10 else ''}")
            results = scan_ports_for_target(target, ports, timeout, threads)
            report['hosts'].append({'target': target, 'ports': results})
            save_reports(report)
        elif choice == "3":
            target = input(Fore.YELLOW + "Target IP: ").strip()
            ports = COMMON_PORTS
            print(Fore.CYAN + f"Quick scanning {target} common ports")
            results = scan_ports_for_target(target, ports, timeout, threads)
            report['hosts'].append({'target': target, 'ports': results})
            save_reports(report)
        elif choice == "2":
            subnet_base = input(Fore.YELLOW + "Subnet base (e.g. 192.168.1.): ").strip()
            probe_ports = input(Fore.YELLOW + "Probe ports for host discovery (comma list) [80,443]: ").strip() or "80,443"
            probe_ports = [int(p) for p in probe_ports.split(",") if p.strip().isdigit()]
            print(Fore.CYAN + f"Discovering hosts in {subnet_base}1-254...")
            alive = host_discovery(subnet_base, probe_ports, timeout, threads)
            print(Fore.CYAN + f"Found {len(alive)} hosts.")
            for host in alive:
                print(Fore.CYAN + f"Now scanning {host}")
                ports = parse_ports(input(Fore.YELLOW + "Ports for host (enter e.g. 1-1024) [common ports]: ").strip() or ",".join(str(p) for p in COMMON_PORTS))
                results = scan_ports_for_target(host, ports, timeout, threads)
                report['hosts'].append({'target': host, 'ports': results})
            save_reports(report)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "Interrupted. Exiting.")
        sys.exit(0)
