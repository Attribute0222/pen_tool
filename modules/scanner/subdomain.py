# modules/scanner/subdomain.py  
import dns.resolver

def scan_subdomains(domain, wordlist_path="wordlists/subdomains.txt"):
    subdomains = []
    with open(wordlist_path, "r") as f:
        for line in f:
            subdomain = f"{line.strip()}.{domain}"
            try:
                dns.resolver.resolve(subdomain, "A")  # Check if resolves
                subdomains.append(subdomain)
            except:
                pass
    return subdomains