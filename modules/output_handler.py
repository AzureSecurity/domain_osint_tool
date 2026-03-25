"""Output handler for formatting and saving results"""
import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path


class OutputHandler:
    """Handle output formatting and file saving"""
    
    def __init__(self, output_dir: str = "output", verbose: bool = False):
        self.output_dir = output_dir
        self.verbose = verbose
        self._ensure_output_dir()
    
    def _ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    def _log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[OUTPUT] {message}")
    
    def display_results(self, results: Dict[str, Any]):
        """Display results in console with formatting"""
        print("\n" + "="*80)
        print("OSINT DOMAIN ENUMERATION RESULTS")
        print("="*80)
        
        # Company and timestamp
        if 'company' in results:
            print(f"\nCompany: {results['company']}")
        print(f"Timestamp: {results.get('timestamp', datetime.now().isoformat())}")
        
        # Discovered domains
        if 'domains' in results and results['domains']:
            print(f"\n{'─'*80}")
            print(f"DISCOVERED DOMAINS ({len(results['domains'])})")
            print(f"{'─'*80}")
            for domain in results['domains']:
                print(f"  • {domain}")
        
        # Subdomains for each domain
        if 'subdomains' in results:
            for domain, data in results['subdomains'].items():
                print(f"\n{'─'*80}")
                print(f"SUBDOMAINS FOR: {domain}")
                print(f"{'─'*80}")
                
                # Wildcard info
                if 'wildcard_info' in data:
                    wc_info = data['wildcard_info']
                    if wc_info.get('has_wildcard'):
                        print(f"⚠️  WILDCARD DNS DETECTED")
                        print(f"   Method: {wc_info.get('detection_method')}")
                        print(f"   IPs: {', '.join(wc_info.get('wildcard_ips', []))}")
                        print(f"   Warning: Results may contain false positives\n")
                    else:
                        print(f"✓ No wildcard DNS detected\n")
                
                # Subdomain list
                subdomain_list = data.get('list', [])
                print(f"Found {len(subdomain_list)} subdomains:")
                for subdomain in subdomain_list:
                    print(f"  • {subdomain}")
        
        print(f"\n{'='*80}\n")
    
    def save_json(self, results: Dict[str, Any], filename: str = None) -> str:
        """Save results as JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"osint_results_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        self._log(f"Results saved to: {filepath}")
        return filepath
    
    def save_csv(self, results: Dict[str, Any], filename: str = None) -> str:
        """Save results as CSV"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"osint_results_{timestamp}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Domain', 'Subdomain', 'Type', 'Has_Wildcard', 'Notes'])
            
            # Write discovered domains
            for domain in results.get('domains', []):
                writer.writerow([domain, '', 'root_domain', '', ''])
            
            # Write subdomains
            for domain, data in results.get('subdomains', {}).items():
                has_wildcard = data.get('wildcard_info', {}).get('has_wildcard', False)
                for subdomain in data.get('list', []):
                    writer.writerow([domain, subdomain, 'subdomain', has_wildcard, ''])
        
        self._log(f"Results saved to: {filepath}")
        return filepath
    
    def save_text(self, results: Dict[str, Any], filename: str = None) -> str:
        """Save results as plain text"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"osint_results_{timestamp}.txt"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write("="*80 + "\n")
            f.write("OSINT DOMAIN ENUMERATION RESULTS\n")
            f.write("="*80 + "\n\n")
            
            if 'company' in results:
                f.write(f"Company: {results['company']}\n")
            f.write(f"Timestamp: {results.get('timestamp', datetime.now().isoformat())}\n\n")
            
            # Discovered domains
            if 'domains' in results and results['domains']:
                f.write("-"*80 + "\n")
                f.write(f"DISCOVERED DOMAINS ({len(results['domains'])})\n")
                f.write("-"*80 + "\n")
                for domain in results['domains']:
                    f.write(f"  • {domain}\n")
                f.write("\n")
            
            # Subdomains
            if 'subdomains' in results:
                for domain, data in results['subdomains'].items():
                    f.write("-"*80 + "\n")
                    f.write(f"SUBDOMAINS FOR: {domain}\n")
                    f.write("-"*80 + "\n")
                    
                    # Wildcard info
                    if 'wildcard_info' in data:
                        wc_info = data['wildcard_info']
                        if wc_info.get('has_wildcard'):
                            f.write(f"⚠️  WILDCARD DNS DETECTED\n")
                            f.write(f"   Method: {wc_info.get('detection_method')}\n")
                            f.write(f"   IPs: {', '.join(wc_info.get('wildcard_ips', []))}\n")
                            f.write(f"   Warning: Results may contain false positives\n\n")
                        else:
                            f.write(f"✓ No wildcard DNS detected\n\n")
                    
                    # Subdomain list
                    subdomain_list = data.get('list', [])
                    f.write(f"Found {len(subdomain_list)} subdomains:\n")
                    for subdomain in subdomain_list:
                        f.write(f"  • {subdomain}\n")
                    f.write("\n")
        
        self._log(f"Results saved to: {filepath}")
        return filepath
    
    def save_all_formats(self, results: Dict[str, Any], base_filename: str = None) -> Dict[str, str]:
        """Save results in all formats (JSON, CSV, TXT)"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = base_filename or f"osint_results_{timestamp}"
        
        saved_files = {
            'json': self.save_json(results, f"{base}.json"),
            'csv': self.save_csv(results, f"{base}.csv"),
            'text': self.save_text(results, f"{base}.txt")
        }
        
        return saved_files
