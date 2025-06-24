# modules/scanner/port_scanner.py  
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import socket
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sr1, IP, TCP  # For SYN scan (optional)

def tcp_scan(host, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def syn_scan(host, port):  # Requires root
    pkt = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout=2, verbose=0)
    if pkt and pkt.haslayer(TCP) and pkt[TCP].flags == 0x12:  # SYN-ACK
        return port
    return None

def scan_ports(host, ports, scan_type="tcp", threads=100):
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for port in ports:
            if scan_type == "syn":
                futures.append(executor.submit(syn_scan, host, port))
            else:
                futures.append(executor.submit(tcp_scan, host, port))
        
        for future in futures:
            if future.result():
                open_ports.append(future.result())
    return sorted(open_ports)
def scan_port(host, port, timeout=3):  # Increased from 1 second
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return port if result == 0 else None
    except:
        return None