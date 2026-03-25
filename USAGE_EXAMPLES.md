# Usage Examples

This file contains practical examples of using the OSINT Domain Enumeration Tool.

## Quick Start Examples

### 1. Basic Subdomain Enumeration
```bash
# Enumerate subdomains for a single domain
python3 domain_osint.py --domain example.com
```

### 2. Company Domain Discovery
```bash
# Find all domains associated with a company
python3 domain_osint.py --company "Tesla"
```

### 3. Full Scan (Discovery + Enumeration)
```bash
# Discover company domains AND enumerate all subdomains
python3 domain_osint.py --company "Tesla" --enumerate-subdomains
```

## Advanced Examples

### 4. Using API Keys for Enhanced Results
```bash
# With config file
python3 domain_osint.py --domain example.com --config config.json

# With command-line API keys
python3 domain_osint.py --domain example.com \
  --virustotal-key "YOUR_VT_KEY" \
  --securitytrails-key "YOUR_ST_KEY"
```

### 5. Batch Processing Multiple Domains
```bash
# Create a domains file
cat > targets.txt << EOF
example.com
tesla.com
google.com
EOF

# Process all domains
python3 domain_osint.py --domains-file targets.txt
```

### 6. Custom Output Options
```bash
# JSON output only
python3 domain_osint.py --domain example.com --output json

# Custom output directory
python3 domain_osint.py --domain example.com \
  --output-dir ./scan_results \
  --output-file tesla_scan

# Silent mode (no console output)
python3 domain_osint.py --domain example.com --no-console
```

### 7. Verbose Mode for Debugging
```bash
# See detailed logging
python3 domain_osint.py --domain example.com --verbose
```

### 8. Skip Wildcard Detection
```bash
# Useful when you know there's no wildcard DNS
python3 domain_osint.py --domain example.com --skip-wildcard-detection
```

## Real-World Scenarios

### Bug Bounty Hunting
```bash
# 1. Discover all company domains
python3 domain_osint.py --company "Target Company" --output json

# 2. Enumerate subdomains for each domain found
python3 domain_osint.py --domains-file discovered_domains.txt \
  --output all \
  --output-dir ./bugbounty/target_company
```

### Security Assessment
```bash
# Full assessment with all sources
python3 domain_osint.py --domain target.com \
  --config config.json \
  --verbose \
  --output all \
  --output-dir ./assessments/target_$(date +%Y%m%d)
```

### Asset Inventory
```bash
# Inventory all company assets
python3 domain_osint.py --company "Your Company" \
  --enumerate-subdomains \
  --output csv \
  --output-file company_assets_$(date +%Y%m%d)
```

## Using with Environment Variables

```bash
# Set API keys as environment variables
export VIRUSTOTAL_API_KEY="your_key_here"
export SECURITYTRAILS_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"

# Run scan (will automatically use env vars)
python3 domain_osint.py --domain example.com
```

## Output Analysis

### Parse JSON Output
```bash
# Count total subdomains found
cat output/osint_results_*.json | jq '.subdomains | to_entries | map(.value.list | length) | add'

# Extract all subdomains to a file
cat output/osint_results_*.json | jq -r '.subdomains[].list[]' > all_subdomains.txt

# Check for wildcard domains
cat output/osint_results_*.json | jq '.subdomains | to_entries | map(select(.value.wildcard_info.has_wildcard))'
```

### Process CSV Output
```bash
# Import to spreadsheet or database
import-csv output/osint_results_*.csv -to-database subdomain_db

# Filter only subdomains (not root domains)
grep ",subdomain," output/osint_results_*.csv
```

## Automation Examples

### Daily Monitoring Script
```bash
#!/bin/bash
# monitor_domains.sh

DATE=$(date +%Y%m%d)
OUTPUT_DIR="./monitoring/$DATE"

# Monitor multiple domains
for domain in example.com test.org sample.net; do
    python3 domain_osint.py \
        --domain $domain \
        --output json \
        --output-dir $OUTPUT_DIR \
        --no-console
done

# Compare with previous results
# (implement your diff logic here)
```

### Continuous Discovery
```bash
#!/bin/bash
# continuous_discovery.sh

COMPANY="Target Company"
OUTPUT_BASE="./scans"

while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    python3 domain_osint.py \
        --company "$COMPANY" \
        --enumerate-subdomains \
        --output all \
        --output-dir "$OUTPUT_BASE/$TIMESTAMP" \
        --verbose
    
    # Wait 24 hours
    sleep 86400
done
```

## Integration Examples

### Pipe to Other Tools
```bash
# Extract subdomains and pipe to other security tools
python3 domain_osint.py --domain example.com --output json --no-console

# Then process with other tools:
cat output/osint_results_*.json | jq -r '.subdomains[].list[]' | \
  while read subdomain; do
    # Run additional tools on each subdomain
    nmap -sV $subdomain
    # or
    nuclei -u https://$subdomain
  done
```

### Use in Python Scripts
```python
import subprocess
import json

def enumerate_subdomains(domain):
    result = subprocess.run(
        ['python3', 'domain_osint.py', 
         '--domain', domain, 
         '--output', 'json', 
         '--no-console'],
        capture_output=True,
        text=True
    )
    
    # Parse the output file
    with open('output/osint_results_*.json') as f:
        data = json.load(f)
    
    return data['subdomains'][domain]['list']

# Use in your script
subdomains = enumerate_subdomains('example.com')
for sub in subdomains:
    print(f"Found: {sub}")
```

## Performance Tips

### 1. Parallel Processing for Multiple Domains
```bash
# Using GNU parallel
cat domains.txt | parallel -j 4 \
  "python3 domain_osint.py --domain {} --output json --output-dir ./results/{}"
```

### 2. Rate Limiting
```bash
# Add delays between scans to respect rate limits
for domain in $(cat domains.txt); do
    python3 domain_osint.py --domain $domain
    sleep 60  # Wait 1 minute between scans
done
```

## Troubleshooting Examples

### Debug API Issues
```bash
# Test with verbose mode
python3 domain_osint.py --domain example.com --verbose 2>&1 | tee debug.log

# Check API key validity
python3 domain_osint.py --domain example.com \
  --virustotal-key "test_key" \
  --verbose 2>&1 | grep -i "virustotal"
```

### Test Wildcard Detection
```bash
# Verbose wildcard detection
python3 domain_osint.py --domain example.com --verbose 2>&1 | grep -i "wildcard"
```

---

For more information, see the main README.md file.
