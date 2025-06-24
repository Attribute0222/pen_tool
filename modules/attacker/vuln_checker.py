import re
import requests
from typing import Dict, List

class VulnerabilityScanner:
    CVE_DATABASE = {
        "Apache/2.4.49": ["CVE-2021-41773", "Path traversal vulnerability"],
        "OpenSSH 8.2p1": ["CVE-2020-15778", "Command injection"],
        "nginx/1.18.0": ["CVE-2021-23017", "DoS vulnerability"]
    }

    @staticmethod
    def check_vulns(banner: str) -> Dict[str, List[str]]:
        """
        Checks banner against known vulnerabilities.
        
        Args:
            banner: Service banner string
            
        Returns:
            Dict of {vulnerability: [description]}
        """
        results = {}
        for software, (cve, desc) in VulnerabilityScanner.CVE_DATABASE.items():
            if re.search(re.escape(software), banner, re.IGNORECASE):
                results[cve] = [software, desc]
        return results or {"status": "No known vulnerabilities detected"}

    @staticmethod
    def scan_web(url: str, timeout: int = 5) -> Dict[str, str]:
        """
        Scans web applications for common vulnerabilities.
        
        Args:
            url: Target URL (e.g., http://example.com)
            timeout: Request timeout
            
        Returns:
            Dict of vulnerability findings
        """
        try:
            resp = requests.get(url, timeout=timeout, verify=False)
            
            # Check for common issues
            findings = {}
            
            # 1. Check server headers
            server = resp.headers.get('Server', '')
            if server:
                findings.update(VulnerabilityScanner.check_vulns(server))
            
            # 2. Check insecure cookies
            if 'Set-Cookie' in resp.headers:
                if 'Secure' not in resp.headers['Set-Cookie']:
                    findings['INSECURE_COOKIE'] = "Missing Secure/HttpOnly flags"
            
            return findings
            
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}