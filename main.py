#!/usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
import sys
from pathlib import Path
from typing import List, Optional, Dict, Tuple

# Add project root to Python path
sys.path.append(str(Path(__file__).parent.resolve))

# Import modules
from modules.scanner import (
    port_scanner,
    subdomain,
    banner_graber
)
from modules.attacker import (
    brute_forcer,
    vuln_checker
)

def scan_ports_command(args) -> None:
    """Handle port scanning logic"""
    try:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
        open_ports = port_scanner.scan_ports(
            host=args.host,
            ports=ports,
            scan_type="syn" if args.syn else "tcp",
            threads=args.threads
        )
        
        # Grab banners for open ports
        banners = {}
        if args.banner:
            for port in open_ports:
                banners[port] = banner_graber.grab_banner(
                    host=args.host,
                    port=port,
                    ssl_context=(port in {443, 8443, 3389})
                )  # Fixed: Added missing parenthesis
                
        print("\n[+] Port Scan Results:")
        print(f"Open Ports: {open_ports}")
        if banners:
            print("\nService Banners:")
            for port, banner in banners.items():
                print(f"{port}/tcp: {banner[:100]}{'...' if len(banner) > 100 else ''}")

    except ValueError:
        print("[-] Invalid port range format. Use 'START-END' (e.g., 20-80)")
    except Exception as e:
        print(f"[-] Scan failed: {str(e)}")

def scan_subdomains_command(args) -> None:
    """Handle subdomain enumeration"""
    try:
        subs = subdomain.scan_subdomains(
            domain=args.domain,
            wordlist_path=args.wordlist
        )
        print(f"\n[+] Found {len(subs)} subdomains:")
        for sub in subs:
            print(f"• {sub}")
            
    except FileNotFoundError:
        print(f"[-] Wordlist not found at: {args.wordlist}")
    except Exception as e:
        print(f"[-] Subdomain scan failed: {str(e)}")

def brute_force_command(args) -> Optional[Tuple[str, str]]:
    """Handle brute force attacks"""
    try:
        result = brute_forcer.http_brute_force(
            url=args.url,
            username=args.username,
            wordlist_path=args.wordlist,
            threads=args.threads
        )
        
        if result:
            print(f"\n[+] Success! Credentials found: {result[0]}:{result[1]}")
            return result
        else:
            print("\n[-] No valid credentials found")
            return None
            
    except Exception as e:
        print(f"[-] Brute-force failed: {str(e)}")
        return None

def check_vulns_command(args) -> None:
    """Handle vulnerability checks"""
    try:
        scanner = vuln_checker.VulnerabilityScanner()
        
        if args.banner:
            # Check banner against CVE database
            findings = scanner.check_vulns(args.banner)
        elif args.url:
            # Full web vulnerability scan
            findings = scanner.scan_web(args.url)
        else:
            raise ValueError("Must specify either --banner or --url")
            
        print("\n[+] Vulnerability Scan Results:")
        for vuln, details in findings.items():
            if isinstance(details, list):
                print(f"• {vuln}: {', '.join(details)}")
            else:
                print(f"• {vuln}: {details}")
            
    except Exception as e:
        print(f"[-] Vulnerability check failed: {str(e)}")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Advanced Penetration Testing Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Port Scanner
    ps_parser = subparsers.add_parser("scan-ports", help="Port scanning module")
    ps_parser.add_argument("host", help="Target IP address or hostname")
    ps_parser.add_argument("-p", "--ports", default="1-1024", 
                         help="Port range (e.g., 20-80)")
    ps_parser.add_argument("-t", "--threads", type=int, default=100,
                         help="Number of threads (default: 100)")
    ps_parser.add_argument("--syn", action="store_true",
                         help="Use SYN scan (requires root)")
    ps_parser.add_argument("-b", "--banner", action="store_true",
                         help="Grab banners for open ports")
    ps_parser.set_defaults(func=scan_ports_command)

    # Subdomain Scanner
    sd_parser = subparsers.add_parser("scan-subs", aliases=['scan-subdomains'], help="Subdomain enumeration")
    sd_parser.add_argument("domain", help="Target domain (e.g., example.com)")
    sd_parser.add_argument("-w", "--wordlist", required=True,
                         help="Path to subdomain wordlist")
    sd_parser.set_defaults(func=scan_subdomains_command)

    # Brute-Forcer
    bf_parser = subparsers.add_parser("brute", help="HTTP brute-force attacks")
    bf_parser.add_argument("url", help="Target login URL")
    bf_parser.add_argument("-u", "--username", required=True,
                         help="Username to brute-force")
    bf_parser.add_argument("-w", "--wordlist", required=True,
                         help="Path to password wordlist")
    bf_parser.add_argument("-t", "--threads", type=int, default=50,
                         help="Number of threads (default: 50)")
    bf_parser.set_defaults(func=brute_force_command)

    # Vulnerability Checker
    vuln_parser = subparsers.add_parser("check-vulns", help="Vulnerability scanning")
    vuln_group = vuln_parser.add_mutually_exclusive_group(required=True)
    vuln_group.add_argument("-b", "--banner",
                          help="Check vulnerabilities from service banner")
    vuln_group.add_argument("-u", "--url",
                          help="URL for web vulnerability scanning")
    vuln_parser.set_defaults(func=check_vulns_command)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()