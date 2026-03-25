#!/usr/bin/env python3
"""
OSINT Domain Enumeration Tool
A comprehensive tool for domain discovery, subdomain enumeration, and wildcard DNS detection
"""

import argparse
import sys
import os
from datetime import datetime
from pathlib import Path

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from config_loader import ConfigLoader
from domain_discovery import DomainDiscovery
from subdomain_enum import SubdomainEnumerator
from wildcard_detector import WildcardDetector
from output_handler import OutputHandler


def print_banner():
    """Print tool banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║          OSINT Domain Enumeration & Wildcard Detection            ║
    ║                     Version 1.0.0                                 ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='OSINT Domain Enumeration and Wildcard DNS Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover domains for a company
  %(prog)s --company "Example Corp"
  
  # Enumerate subdomains for a specific domain
  %(prog)s --domain example.com
  
  # Both discovery and enumeration
  %(prog)s --company "Example Corp" --enumerate-subdomains
  
  # With API keys from config file
  %(prog)s --domain example.com --config config.json
  
  # Save output in all formats
  %(prog)s --domain example.com --output all --output-dir ./results
  
  # Verbose mode for detailed logging
  %(prog)s --domain example.com --verbose
        """
    )
    
    # Main options
    parser.add_argument('-c', '--company', 
                        help='Company name for domain discovery')
    parser.add_argument('-d', '--domain', 
                        help='Domain for subdomain enumeration')
    parser.add_argument('--domains-file',
                        help='File containing list of domains to enumerate (one per line)')
    
    # Enumeration options
    parser.add_argument('--enumerate-subdomains', action='store_true',
                        help='Enumerate subdomains for discovered domains (when using --company)')
    parser.add_argument('--skip-wildcard-detection', action='store_true',
                        help='Skip wildcard DNS detection')
    
    # API configuration
    parser.add_argument('--config', default='config.json',
                        help='Path to configuration file (default: config.json)')
    parser.add_argument('--virustotal-key',
                        help='VirusTotal API key (overrides config file)')
    parser.add_argument('--securitytrails-key',
                        help='SecurityTrails API key (overrides config file)')
    parser.add_argument('--shodan-key',
                        help='Shodan API key (overrides config file)')
    
    # Output options
    parser.add_argument('-o', '--output', choices=['json', 'csv', 'text', 'all'],
                        default='all', help='Output format (default: all)')
    parser.add_argument('--output-dir', default='output',
                        help='Output directory (default: ./output)')
    parser.add_argument('--output-file',
                        help='Base filename for output files (default: auto-generated with timestamp)')
    parser.add_argument('--no-console', action='store_true',
                        help='Disable console output, only save to files')
    
    # Other options
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    
    return parser.parse_args()


def setup_api_keys(args, config_loader):
    """Setup API keys from command-line arguments"""
    if args.virustotal_key:
        os.environ['VIRUSTOTAL_API_KEY'] = args.virustotal_key
    if args.securitytrails_key:
        os.environ['SECURITYTRAILS_API_KEY'] = args.securitytrails_key
    if args.shodan_key:
        os.environ['SHODAN_API_KEY'] = args.shodan_key


def discover_company_domains(company_name: str, verbose: bool = False) -> list:
    """Discover all domains associated with a company"""
    print(f"\n[*] Discovering domains for: {company_name}")
    print(f"[*] This may take a moment...\n")
    
    discovery = DomainDiscovery(company_name, verbose=verbose)
    domains = discovery.discover_all()
    
    if domains:
        print(f"\n[✓] Found {len(domains)} domain(s)")
    else:
        print(f"\n[!] No domains found for {company_name}")
    
    return domains


def enumerate_domain_subdomains(domain: str, config_loader, verbose: bool = False):
    """Enumerate subdomains for a single domain"""
    print(f"\n[*] Enumerating subdomains for: {domain}")
    print(f"[*] This may take a moment...\n")
    
    # Enumerate subdomains
    enumerator = SubdomainEnumerator(domain, config_loader, verbose=verbose)
    subdomains = enumerator.enumerate_all()
    
    print(f"[✓] Found {len(subdomains)} subdomain(s)")
    
    return subdomains


def detect_wildcard_dns(domain: str, verbose: bool = False):
    """Detect wildcard DNS configuration"""
    print(f"\n[*] Checking for wildcard DNS configuration...")
    
    detector = WildcardDetector(domain, verbose=verbose)
    wildcard_info = detector.get_wildcard_info()
    
    if wildcard_info['has_wildcard']:
        print(f"[!] Wildcard DNS detected - results may contain false positives")
    else:
        print(f"[✓] No wildcard DNS detected")
    
    return wildcard_info


def save_results(results: dict, output_handler, output_format: str, output_file: str = None):
    """Save results in specified format(s)"""
    print(f"\n[*] Saving results...")
    
    saved_files = {}
    
    if output_format == 'all':
        saved_files = output_handler.save_all_formats(results, output_file)
        print(f"[✓] Results saved in all formats:")
        for fmt, filepath in saved_files.items():
            print(f"    - {fmt.upper()}: {filepath}")
    else:
        if output_format == 'json':
            filepath = output_handler.save_json(results, output_file)
        elif output_format == 'csv':
            filepath = output_handler.save_csv(results, output_file)
        elif output_format == 'text':
            filepath = output_handler.save_text(results, output_file)
        
        saved_files[output_format] = filepath
        print(f"[✓] Results saved to: {filepath}")
    
    return saved_files


def main():
    """Main function"""
    args = parse_arguments()
    
    # Print banner
    if not args.no_console:
        print_banner()
    
    # Validate arguments
    if not args.company and not args.domain and not args.domains_file:
        print("[ERROR] Must specify --company, --domain, or --domains-file")
        sys.exit(1)
    
    # Load configuration
    config_loader = ConfigLoader(args.config)
    setup_api_keys(args, config_loader)
    
    # Initialize output handler
    output_handler = OutputHandler(args.output_dir, verbose=args.verbose)
    
    # Prepare results structure
    results = {
        'timestamp': datetime.now().isoformat(),
        'domains': [],
        'subdomains': {}
    }
    
    # Mode 1: Company domain discovery
    if args.company:
        results['company'] = args.company
        domains = discover_company_domains(args.company, args.verbose)
        results['domains'] = domains
        
        # Optionally enumerate subdomains for discovered domains
        if args.enumerate_subdomains and domains:
            print(f"\n[*] Enumerating subdomains for {len(domains)} discovered domain(s)...")
            for domain in domains:
                subdomains = enumerate_domain_subdomains(domain, config_loader, args.verbose)
                
                # Detect wildcard DNS
                wildcard_info = None
                if not args.skip_wildcard_detection:
                    wildcard_info = detect_wildcard_dns(domain, args.verbose)
                
                results['subdomains'][domain] = {
                    'list': subdomains,
                    'wildcard_info': wildcard_info
                }
    
    # Mode 2: Direct domain subdomain enumeration
    if args.domain:
        domain = args.domain
        results['domains'].append(domain)
        
        subdomains = enumerate_domain_subdomains(domain, config_loader, args.verbose)
        
        # Detect wildcard DNS
        wildcard_info = None
        if not args.skip_wildcard_detection:
            wildcard_info = detect_wildcard_dns(domain, args.verbose)
        
        results['subdomains'][domain] = {
            'list': subdomains,
            'wildcard_info': wildcard_info
        }
    
    # Mode 3: Multiple domains from file
    if args.domains_file:
        if not os.path.exists(args.domains_file):
            print(f"[ERROR] Domains file not found: {args.domains_file}")
            sys.exit(1)
        
        with open(args.domains_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        results['domains'].extend(domains)
        
        print(f"\n[*] Processing {len(domains)} domain(s) from file...")
        for domain in domains:
            subdomains = enumerate_domain_subdomains(domain, config_loader, args.verbose)
            
            # Detect wildcard DNS
            wildcard_info = None
            if not args.skip_wildcard_detection:
                wildcard_info = detect_wildcard_dns(domain, args.verbose)
            
            results['subdomains'][domain] = {
                'list': subdomains,
                'wildcard_info': wildcard_info
            }
    
    # Display results in console
    if not args.no_console:
        output_handler.display_results(results)
    
    # Save results to file(s)
    saved_files = save_results(results, output_handler, args.output, args.output_file)
    
    print(f"\n[✓] Enumeration complete!")
    print(f"[*] Total domains: {len(results['domains'])}")
    total_subdomains = sum(len(data['list']) for data in results['subdomains'].values())
    print(f"[*] Total subdomains: {total_subdomains}\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
