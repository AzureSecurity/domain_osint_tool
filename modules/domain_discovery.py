"""Company domain discovery using OSINT techniques"""
import requests
import re
import time
from typing import List, Set
from urllib.parse import quote


class DomainDiscovery:
    """Discover domains associated with a company name"""
    
    def __init__(self, company_name: str, verbose: bool = False):
        self.company_name = company_name
        self.verbose = verbose
        self.discovered_domains: Set[str] = set()
    
    def _log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[DOMAIN_DISCOVERY] {message}")
    
    def discover_all(self) -> List[str]:
        """Run all discovery methods and return unique domains"""
        self._log(f"Starting domain discovery for: {self.company_name}")
        
        # Try multiple sources
        self._discover_from_crtsh()
        self._discover_from_web_search()
        
        domains = sorted(list(self.discovered_domains))
        self._log(f"Found {len(domains)} unique domains")
        return domains
    
    def _discover_from_crtsh(self):
        """Discover domains from Certificate Transparency logs via crt.sh"""
        self._log("Querying crt.sh for Certificate Transparency logs...")
        try:
            # Search for company name in certificate CN/SAN fields
            url = f"https://crt.sh/?q={quote(self.company_name)}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        # Extract domain names (excluding wildcards and subdomains for now)
                        domains = self._extract_root_domains(name_value)
                        self.discovered_domains.update(domains)
                except Exception as e:
                    self._log(f"Error parsing crt.sh response: {e}")
            else:
                self._log(f"crt.sh returned status code: {response.status_code}")
        except Exception as e:
            self._log(f"Error querying crt.sh: {e}")
    
    def _discover_from_web_search(self):
        """Discover domains from simulated web search patterns"""
        self._log("Analyzing web search patterns...")
        # In a real implementation, you might use Google Custom Search API
        # or scrape search results (respecting robots.txt and ToS)
        # For now, we'll use certificate transparency as the main source
        pass
    
    def _extract_root_domains(self, text: str) -> Set[str]:
        """Extract root domains from text (certificates often have multiple SANs)"""
        domains = set()
        # Split by newlines (crt.sh returns multiple domains per entry)
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            # Remove wildcards
            line = line.replace('*.', '')
            
            # Basic domain validation
            if self._is_valid_domain(line):
                # Extract root domain (e.g., sub.example.com -> example.com)
                root = self._get_root_domain(line)
                if root:
                    domains.add(root)
        
        return domains
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        if not domain or len(domain) < 4:
            return False
        
        # Basic regex for domain validation
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def _get_root_domain(self, domain: str) -> str:
        """Extract root domain from a full domain"""
        # Simple extraction - gets last two parts for most TLDs
        # For more accuracy, use a library like tldextract
        parts = domain.split('.')
        if len(parts) >= 2:
            # Handle common TLDs and country codes
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'ac', 'gov', 'org']:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        return domain
