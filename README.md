# OSINT Domain Enumeration & Wildcard Detection Tool

A comprehensive Python-based OSINT (Open Source Intelligence) tool for domain discovery, subdomain enumeration, and wildcard DNS detection. This tool helps security researchers, penetration testers, and bug bounty hunters discover the attack surface of target organizations.

## Features

### 🔍 Company Domain Discovery
- Enumerate all public domains associated with a company name
- Uses Certificate Transparency (CT) logs via crt.sh
- Automatic root domain extraction from discovered certificates

### 🌐 Subdomain Enumeration
**Free Sources:**
- Certificate Transparency logs (crt.sh)
- DNS queries and zone transfers (when available)
- Public DNS databases

**Paid/API Sources (Optional):**
- VirusTotal API
- SecurityTrails API
- Shodan API

### 🎯 Wildcard DNS Detection
Two detection methods:
1. **Random Subdomain Testing**: Generates random subdomains to detect wildcard configurations
2. **DNS Record Analysis**: Queries for explicit wildcard A/CNAME records

### 📊 Multiple Output Formats
- **Console**: Beautiful formatted output with progress indicators
- **JSON**: Structured data for programmatic processing
- **CSV**: Spreadsheet-compatible format
- **Text**: Human-readable plain text reports

### ⚙️ Advanced Features
- Modular code architecture
- Configuration file support for API keys
- Command-line arguments for all options
- Verbose logging mode
- Error handling and timeout management
- Batch domain processing from files

---

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. **Clone or download this repository:**
```bash
cd /path/to/domain_osint_tool
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure API keys (optional but recommended):**
```bash
# Copy the example configuration file
cp config.json.example config.json

# Edit config.json and add your API keys
nano config.json
```

4. **Make the script executable:**
```bash
chmod +x domain_osint.py
```

---

## Configuration

### API Keys Setup

The tool supports multiple API providers. While the tool works with free sources only, adding API keys significantly increases the number of discovered subdomains.

#### Option 1: Configuration File (Recommended)
Edit `config.json`:
```json
{
  "api_keys": {
    "virustotal": "your_virustotal_api_key",
    "securitytrails": "your_securitytrails_api_key",
    "shodan": "your_shodan_api_key"
  },
  "settings": {
    "timeout": 30,
    "max_retries": 3
  }
}
```

#### Option 2: Environment Variables
```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export SECURITYTRAILS_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
```

#### Option 3: Command-Line Arguments
```bash
python domain_osint.py --domain example.com \
  --virustotal-key "your_key" \
  --securitytrails-key "your_key" \
  --shodan-key "your_key"
```

### Getting API Keys

| Service | Free Tier | Sign Up URL |
|---------|-----------|-------------|
| VirusTotal | ✅ Yes (4 requests/min) | https://www.virustotal.com/gui/join-us |
| SecurityTrails | ✅ Yes (50 requests/month) | https://securitytrails.com/pricing |
| Shodan | ❌ Paid only | https://account.shodan.io/register |

---

## Usage

### Basic Usage

#### 1. Discover domains for a company
```bash
python domain_osint.py --company "Example Corp"
```

#### 2. Enumerate subdomains for a specific domain
```bash
python domain_osint.py --domain example.com
```

#### 3. Discover company domains AND enumerate subdomains
```bash
python domain_osint.py --company "Example Corp" --enumerate-subdomains
```

### Advanced Usage

#### Process multiple domains from a file
```bash
python domain_osint.py --domains-file domains.txt
```

Example `domains.txt`:
```
example.com
test.org
sample.net
```

#### Specify output format
```bash
# JSON only
python domain_osint.py --domain example.com --output json

# CSV only
python domain_osint.py --domain example.com --output csv

# All formats (default)
python domain_osint.py --domain example.com --output all
```

#### Custom output directory and filename
```bash
python domain_osint.py --domain example.com \
  --output-dir ./results \
  --output-file example_scan_2024
```

#### Skip wildcard detection
```bash
python domain_osint.py --domain example.com --skip-wildcard-detection
```

#### Verbose mode for debugging
```bash
python domain_osint.py --domain example.com --verbose
```

#### Silent mode (no console output)
```bash
python domain_osint.py --domain example.com --no-console
```

### Complete Example
```bash
python domain_osint.py \
  --company "Example Corp" \
  --enumerate-subdomains \
  --config config.json \
  --output all \
  --output-dir ./results/example_corp \
  --verbose
```

---

## Command-Line Arguments Reference

### Main Options
| Argument | Description |
|----------|-------------|
| `-c, --company` | Company name for domain discovery |
| `-d, --domain` | Single domain for subdomain enumeration |
| `--domains-file` | File with list of domains (one per line) |

### Enumeration Options
| Argument | Description |
|----------|-------------|
| `--enumerate-subdomains` | Enumerate subdomains for discovered domains |
| `--skip-wildcard-detection` | Skip wildcard DNS detection |

### API Configuration
| Argument | Description |
|----------|-------------|
| `--config` | Path to config file (default: config.json) |
| `--virustotal-key` | VirusTotal API key |
| `--securitytrails-key` | SecurityTrails API key |
| `--shodan-key` | Shodan API key |

### Output Options
| Argument | Description |
|----------|-------------|
| `-o, --output` | Format: json, csv, text, or all (default: all) |
| `--output-dir` | Output directory (default: ./output) |
| `--output-file` | Base filename for output |
| `--no-console` | Disable console output |

### Other Options
| Argument | Description |
|----------|-------------|
| `-v, --verbose` | Enable verbose logging |
| `--version` | Show version information |
| `-h, --help` | Show help message |

---

## Output Examples

### Console Output
```
    ╔═══════════════════════════════════════════════════════════════════╗
    ║          OSINT Domain Enumeration & Wildcard Detection            ║
    ║                     Version 1.0.0                                 ║
    ╚═══════════════════════════════════════════════════════════════════╝

[*] Enumerating subdomains for: example.com
[*] This may take a moment...

[✓] Found 45 subdomain(s)

[*] Checking for wildcard DNS configuration...
[✓] No wildcard DNS detected

════════════════════════════════════════════════════════════════════════════════
OSINT DOMAIN ENUMERATION RESULTS
════════════════════════════════════════════════════════════════════════════════

Timestamp: 2024-03-25T10:30:45.123456

────────────────────────────────────────────────────────────────────────────────
SUBDOMAINS FOR: example.com
────────────────────────────────────────────────────────────────────────────────
✓ No wildcard DNS detected

Found 45 subdomains:
  • api.example.com
  • www.example.com
  • mail.example.com
  ...
```

### JSON Output
```json
{
  "timestamp": "2024-03-25T10:30:45.123456",
  "domains": ["example.com"],
  "subdomains": {
    "example.com": {
      "list": [
        "api.example.com",
        "www.example.com",
        "mail.example.com"
      ],
      "wildcard_info": {
        "domain": "example.com",
        "has_wildcard": false,
        "detection_method": null,
        "wildcard_ips": [],
        "warning": null
      }
    }
  }
}
```

### CSV Output
```csv
Domain,Subdomain,Type,Has_Wildcard,Notes
example.com,,,false,
example.com,api.example.com,subdomain,false,
example.com,www.example.com,subdomain,false,
```

---

## Project Structure

```
domain_osint_tool/
├── domain_osint.py          # Main script
├── modules/                 # Core modules
│   ├── __init__.py
│   ├── config_loader.py     # Configuration management
│   ├── domain_discovery.py  # Company domain discovery
│   ├── subdomain_enum.py    # Subdomain enumeration
│   ├── wildcard_detector.py # Wildcard DNS detection
│   └── output_handler.py    # Output formatting
├── output/                  # Default output directory
├── examples/                # Example files
│   └── domains.txt
├── config.json.example      # Example configuration
├── config.json             # Your configuration (gitignored)
├── requirements.txt        # Python dependencies
├── .gitignore
└── README.md
```

---

## How It Works

### Domain Discovery Process
1. Query Certificate Transparency logs for company name
2. Extract all domain names from certificates
3. Parse and deduplicate root domains
4. Return unique list of discovered domains

### Subdomain Enumeration Process
1. **Free Sources:**
   - Query crt.sh for certificate transparency logs
   - Parse all Subject Alternative Names (SANs)
   
2. **API Sources (if configured):**
   - VirusTotal: Historical DNS data
   - SecurityTrails: DNS history and passive DNS
   - Shodan: Internet-wide scanning data

3. **Deduplication:**
   - Remove duplicates
   - Validate domain format
   - Sort alphabetically

### Wildcard Detection Methods

#### Method 1: Random Subdomain Testing
```
1. Generate 5 random subdomain names
2. Attempt DNS resolution for each
3. If 2+ random subdomains resolve → Wildcard detected
4. Record the IPs they resolve to
```

#### Method 2: DNS Record Analysis
```
1. Query for *.domain.com A records
2. Query for *.domain.com CNAME records
3. If wildcard records exist → Wildcard detected
```

---

## Limitations & Considerations

### Rate Limiting
- Free API tiers have rate limits
- Tool respects timeouts to avoid overwhelming services
- Consider adding delays between requests for large-scale scans

### Wildcard DNS
- Some domains use wildcard DNS configurations
- This can lead to false positives in subdomain enumeration
- The tool detects and warns about wildcard configurations
- Consider filtering results based on wildcard detection

### Legal & Ethical Considerations
⚠️ **Important**: This tool is for authorized security research only.

- Only scan domains you own or have explicit permission to test
- Respect robots.txt and Terms of Service
- Some countries have laws against unauthorized network scanning
- API providers have Terms of Service - review and comply with them

### DNS Queries
- The tool performs DNS queries which are visible to:
  - Your DNS resolver
  - The target domain's DNS servers
  - Any intermediate DNS servers

For stealth, consider:
- Using VPN or proxy
- Spacing out queries
- Using passive-only sources

---

## Troubleshooting

### Common Issues

**Issue**: No subdomains found
- **Solution**: Check if API keys are configured correctly
- **Solution**: Try with verbose mode (-v) to see detailed errors
- **Solution**: Verify domain name is correct

**Issue**: API errors (401 Unauthorized)
- **Solution**: Verify API keys are valid and not expired
- **Solution**: Check API quota hasn't been exceeded

**Issue**: Timeout errors
- **Solution**: Check internet connectivity
- **Solution**: Some services may be temporarily down
- **Solution**: Increase timeout in config.json

**Issue**: DNS resolution errors
- **Solution**: Check your DNS settings
- **Solution**: Try using a different DNS resolver

### Debug Mode
Run with verbose flag to see detailed logging:
```bash
python domain_osint.py --domain example.com --verbose
```

---

## Contributing

Contributions are welcome! Areas for improvement:
- Additional OSINT sources
- Better domain parsing (TLD handling)
- Performance optimizations
- Additional output formats
- GUI interface
- Docker support

---

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for misuse or damage caused by this tool. Users are responsible for ensuring they have proper authorization before scanning any targets.

---

## License

This project is provided as-is for educational purposes.

---

## Version History

### Version 1.0.0 (2024-03-25)
- Initial release
- Company domain discovery via CT logs
- Subdomain enumeration (free & paid sources)
- Wildcard DNS detection (2 methods)
- Multiple output formats (JSON, CSV, TXT)
- Modular architecture
- CLI interface

---

## Support & Contact

For questions, issues, or feature requests, please open an issue in the project repository.

---

## Acknowledgments

This tool leverages several excellent services and libraries:
- [crt.sh](https://crt.sh) - Certificate Transparency search
- [VirusTotal](https://www.virustotal.com) - Threat intelligence
- [SecurityTrails](https://securitytrails.com) - DNS & security data
- [Shodan](https://www.shodan.io) - Internet-wide scanning
- [dnspython](https://www.dnspython.org/) - DNS toolkit
- [requests](https://requests.readthedocs.io/) - HTTP library

---

**Happy Hunting! 🎯**
