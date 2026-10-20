#!/usr/bin/env python3
"""
VoidMap - A fast, multithreaded network scanner.
Author: xzz
"""

import socket
import argparse
import concurrent.futures
from datetime import datetime
import sys

# Default ports if none are specified (Common Web, SSH, FTP, DB ports)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

def get_banner(s):
    """Attempt to grab the service banner from an open port."""
    try:
        # Send a generic HTTP request just in case it's a web server
        s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner
    except:
        return ""

def scan_port(target, port, timeout):
    """Scan a single port and return its status and banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            
            if result == 0:
                banner = get_banner(s)
                return (port, True, banner)
            else:
                return (port, False, "")
    except Exception:
        return (port, False, "")

def main():
    parser = argparse.ArgumentParser(
        description="VoidMap: A lightweight, multithreaded port scanner.",
        epilog="Example: python3 voidmap.py 192.168.1.1 -p 1-1000 -t 200"
    )
    parser.add_argument("target", help="The IP address or hostname to scan")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., '1-1000' or '22,80,443'). Defaults to top 20 ports.")
    parser.add_argument("-t", "--threads", type=int, default=150, help="Number of concurrent threads (default: 150)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    
    args = parser.parse_args()
    
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {args.target}")
        sys.exit(1)
    
    # Parse the port arguments
    ports_to_scan = []
    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports_to_scan = list(range(start, end + 1))
        else:
            ports_to_scan = [int(p) for p in args.ports.split(',')]
    else:
        ports_to_scan = COMMON_PORTS

    print("\n" + "=" * 60)
    print(f"[*] VoidMap Target   : {target_ip} ({args.target})")
    print(f"[*] Time Started     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Threads Active   : {args.threads}")
    print("=" * 60 + "\n")
    
    open_ports = []
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            # Dispatch all scanning tasks to the thread pool
            futures = {executor.submit(scan_port, target_ip, port, args.timeout): port for port in ports_to_scan}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    open_ports.append((port, banner))
                    # Clean up the banner output for terminal readability
                    clean_banner = banner.replace('\r', '').replace('\n', ' ')[:45]
                    if clean_banner:
                        print(f"[+] Port {port:<5} : OPEN    | {clean_banner}")
                    else:
                        print(f"[+] Port {port:<5} : OPEN")
                        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(1)

    print("\n" + "=" * 60)
    print(f"[*] Scan completed. Found {len(open_ports)} open ports.")
    print("=" * 60)

if __name__ == "__main__":
    main()
