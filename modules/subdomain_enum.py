"""Subdomain enumeration using multiple OSINT sources"""
import requests
import dns.resolver
import re
import time
from typing import List, Set, Optional
from urllib.parse import quote


class SubdomainEnumerator:
    """Enumerate subdomains for a given domain"""
    
    def __init__(self, domain: str, config_loader=None, verbose: bool = False):
        self.domain = domain
        self.config_loader = config_loader
        self.verbose = verbose
        self.subdomains: Set[str] = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
    
    def _log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[SUBDOMAIN_ENUM] {message}")
    
    def enumerate_all(self) -> List[str]:
        """Run all enumeration methods and return unique subdomains"""
        self._log(f"Starting subdomain enumeration for: {self.domain}")
        
        # Free sources
        self._enumerate_crtsh()
        self._enumerate_dns_dumpster()
        
        # Paid/API sources (if keys available)
        if self.config_loader:
            if self.config_loader.has_api_key('virustotal'):
                self._enumerate_virustotal()
            if self.config_loader.has_api_key('securitytrails'):
                self._enumerate_securitytrails()
            if self.config_loader.has_api_key('shodan'):
                self._enumerate_shodan()
        
        subdomains = sorted(list(self.subdomains))
        self._log(f"Found {len(subdomains)} unique subdomains")
        return subdomains
    
    def _enumerate_crtsh(self):
        """Enumerate subdomains from Certificate Transparency logs"""
        self._log("Querying crt.sh...")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        subdomains = name_value.split('\n')
                        for subdomain in subdomains:
                            subdomain = subdomain.strip().lower()
                            # Remove wildcards
                            subdomain = subdomain.replace('*.', '')
                            if subdomain.endswith(self.domain) and self._is_valid_subdomain(subdomain):
                                self.subdomains.add(subdomain)
                    self._log(f"crt.sh: Found {len(self.subdomains)} subdomains so far")
                except Exception as e:
                    self._log(f"Error parsing crt.sh response: {e}")
        except Exception as e:
            self._log(f"Error querying crt.sh: {e}")
    
    def _enumerate_dns_dumpster(self):
        """Enumerate subdomains from DNSDumpster (simulated)"""
        self._log("Simulating DNSDumpster query...")
        # Note: DNSDumpster requires CSRF token handling
        # For production, implement proper scraping with session handling
        # or use their API if available
        pass
    
    def _enumerate_virustotal(self):
        """Enumerate subdomains using VirusTotal API"""
        self._log("Querying VirusTotal API...")
        api_key = self.config_loader.get_api_key('virustotal')
        if not api_key:
            return
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            headers = {'x-apikey': api_key}
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain and self._is_valid_subdomain(subdomain):
                        self.subdomains.add(subdomain)
                self._log(f"VirusTotal: Found {len(self.subdomains)} subdomains so far")
            elif response.status_code == 401:
                self._log("VirusTotal: Invalid API key")
            else:
                self._log(f"VirusTotal returned status code: {response.status_code}")
        except Exception as e:
            self._log(f"Error querying VirusTotal: {e}")
    
    def _enumerate_securitytrails(self):
        """Enumerate subdomains using SecurityTrails API"""
        self._log("Querying SecurityTrails API...")
        api_key = self.config_loader.get_api_key('securitytrails')
        if not api_key:
            return
        
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': api_key}
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for subdomain_prefix in data.get('subdomains', []):
                    subdomain = f"{subdomain_prefix}.{self.domain}"
                    if self._is_valid_subdomain(subdomain):
                        self.subdomains.add(subdomain)
                self._log(f"SecurityTrails: Found {len(self.subdomains)} subdomains so far")
            elif response.status_code == 401:
                self._log("SecurityTrails: Invalid API key")
            else:
                self._log(f"SecurityTrails returned status code: {response.status_code}")
        except Exception as e:
            self._log(f"Error querying SecurityTrails: {e}")
    
    def _enumerate_shodan(self):
        """Enumerate subdomains using Shodan API"""
        self._log("Querying Shodan API...")
        api_key = self.config_loader.get_api_key('shodan')
        if not api_key:
            return
        
        try:
            url = f"https://api.shodan.io/dns/domain/{self.domain}?key={api_key}"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for subdomain in data.get('subdomains', []):
                    full_subdomain = f"{subdomain}.{self.domain}"
                    if self._is_valid_subdomain(full_subdomain):
                        self.subdomains.add(full_subdomain)
                self._log(f"Shodan: Found {len(self.subdomains)} subdomains so far")
            elif response.status_code == 401:
                self._log("Shodan: Invalid API key")
            else:
                self._log(f"Shodan returned status code: {response.status_code}")
        except Exception as e:
            self._log(f"Error querying Shodan: {e}")
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format"""
        if not subdomain or not subdomain.endswith(self.domain):
            return False
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, subdomain))
