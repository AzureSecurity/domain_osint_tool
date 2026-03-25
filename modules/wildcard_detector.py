"""Wildcard DNS detection using multiple methods"""
import dns.resolver
import random
import string
from typing import List, Tuple, Optional
import socket


class WildcardDetector:
    """Detect wildcard DNS configurations"""
    
    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain
        self.verbose = verbose
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
    
    def _log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[WILDCARD_DETECTOR] {message}")
    
    def detect(self) -> Tuple[bool, Optional[str], List[str]]:
        """Detect wildcard DNS configuration
        
        Returns:
            Tuple of (is_wildcard, detection_method, wildcard_ips)
        """
        self._log(f"Starting wildcard detection for: {self.domain}")
        
        # Method 1: Random subdomain testing
        is_wildcard_random, random_ips = self._test_random_subdomains()
        if is_wildcard_random:
            self._log("Wildcard detected via random subdomain testing")
            return (True, "random_subdomain_testing", random_ips)
        
        # Method 2: DNS query analysis for wildcard records
        is_wildcard_dns, dns_ips = self._test_wildcard_records()
        if is_wildcard_dns:
            self._log("Wildcard detected via DNS record analysis")
            return (True, "dns_record_analysis", dns_ips)
        
        self._log("No wildcard DNS configuration detected")
        return (False, None, [])
    
    def _test_random_subdomains(self, num_tests: int = 5) -> Tuple[bool, List[str]]:
        """Test random subdomains to detect wildcard DNS"""
        self._log("Testing random subdomains...")
        resolved_ips = []
        
        for i in range(num_tests):
            # Generate random subdomain
            random_subdomain = self._generate_random_subdomain()
            full_domain = f"{random_subdomain}.{self.domain}"
            
            # Try to resolve it
            ips = self._resolve_domain(full_domain)
            if ips:
                resolved_ips.extend(ips)
                self._log(f"Random subdomain {full_domain} resolved to: {ips}")
        
        # If multiple random subdomains resolve, likely a wildcard
        if len(resolved_ips) >= 2:
            # Check if they resolve to the same IP(s)
            unique_ips = list(set(resolved_ips))
            return (True, unique_ips)
        
        return (False, [])
    
    def _test_wildcard_records(self) -> Tuple[bool, List[str]]:
        """Check for explicit wildcard DNS records"""
        self._log("Checking for wildcard DNS records...")
        wildcard_domain = f"*.{self.domain}"
        
        # Try to resolve wildcard domain
        ips = self._resolve_domain(wildcard_domain)
        if ips:
            self._log(f"Wildcard record found: {wildcard_domain} -> {ips}")
            return (True, ips)
        
        return (False, [])
    
    def _generate_random_subdomain(self, length: int = 16) -> str:
        """Generate a random subdomain name"""
        # Use lowercase letters and numbers
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        ips = []
        
        try:
            # Try A records
            answers = self.resolver.resolve(domain, 'A')
            for rdata in answers:
                ips.append(str(rdata))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            pass
        
        # Also try AAAA (IPv6) records
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                ips.append(str(rdata))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            pass
        
        return ips
    
    def get_wildcard_info(self) -> dict:
        """Get comprehensive wildcard information"""
        is_wildcard, method, ips = self.detect()
        
        return {
            'domain': self.domain,
            'has_wildcard': is_wildcard,
            'detection_method': method,
            'wildcard_ips': ips,
            'warning': 'Subdomains may contain false positives due to wildcard DNS' if is_wildcard else None
        }
