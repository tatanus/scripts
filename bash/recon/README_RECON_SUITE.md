# External Reconnaissance Suite

A comprehensive, modular external reconnaissance framework for penetration testing engagements.

## Overview

This suite provides a structured approach to external reconnaissance with the following features:

- **Modular Task Architecture**: Easy to extend with new reconnaissance tasks
- **Configurable Profiles**: Default, Quick, and Aggressive scanning profiles
- **Comprehensive Tooling**: Integration with industry-standard tools
- **Detailed Logging**: All outputs logged and timestamped
- **Flexible Execution**: Run all tasks or specific individual tasks

## Architecture

```
run_external_recon_suite.sh    # Main orchestrator
├── tasks/
│   ├── 00-validate.sh         # Input validation and CIDR expansion
│   ├── 01-osint.sh            # OSINT reconnaissance
│   ├── 02-nmap.sh             # Network mapping and port scanning
│   ├── 03-http-scan.sh        # HTTP/HTTPS reconnaissance
│   └── 04-testssl.sh          # SSL/TLS security testing
├── config/
│   ├── default.conf           # Default configuration
│   ├── quick.conf             # Fast scanning profile
│   └── aggressive.conf        # Comprehensive scanning profile
└── README_RECON_SUITE.md      # This file
```

## Prerequisites

### Required Tools

- `bash` (4.0+)
- `curl`
- `jq`
- `nmap`

### Optional Tools (Recommended)

- **OSINT**: `subfinder`, `dnsx`, `asnmap`, `cdncheck`
- **HTTP**: `httpx`, `nuclei`, `gowitness`, `whatweb`
- **SSL/TLS**: `testssl.sh`

### Installation of Optional Tools

```bash
# Install Go (required for many tools)
# macOS
brew install go

# Linux
sudo apt install golang-go

# Install ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest

# Install other tools
go install github.com/sensepost/gowitness@latest

# Install testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/tools/testssl.sh
sudo ln -s ~/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Update nuclei templates
nuclei -update-templates
```

## Quick Start

### 1. Prepare Your Engagement Directory

```bash
# Create engagement directory
export ENGAGEMENT_DIR="/path/to/your/engagement"
mkdir -p "${ENGAGEMENT_DIR}"

# Create targets file (IPs, CIDRs, FQDNs)
cat > "${ENGAGEMENT_DIR}/targets.txt" << EOF
192.168.1.0/24
10.0.0.5
example.com
EOF

# Create domains file (for OSINT)
cat > "${ENGAGEMENT_DIR}/domains.txt" << EOF
example.com
example.net
EOF
```

### 2. Set Environment Variables

```bash
export ENGAGEMENT_DIR="/path/to/your/engagement"
export TARGETS_FILE="${ENGAGEMENT_DIR}/targets.txt"
export DOMAINS_FILE="${ENGAGEMENT_DIR}/domains.txt"
```

### 3. Run Reconnaissance

```bash
# Run with default configuration
./run_external_recon_suite.sh

# Run with quick scan profile
./run_external_recon_suite.sh --config config/quick.conf

# Run with aggressive scan profile
./run_external_recon_suite.sh --config config/aggressive.conf
```

## Usage Examples

### Run Specific Task Only

```bash
# Run only OSINT
./run_external_recon_suite.sh --task 01-osint

# Run only Nmap scanning
./run_external_recon_suite.sh --task 02-nmap

# Run only HTTP scanning
./run_external_recon_suite.sh --task 03-http-scan
```

### Skip Specific Tasks

```bash
# Skip SSL/TLS testing
./run_external_recon_suite.sh --skip 04-testssl

# Skip multiple tasks
./run_external_recon_suite.sh --skip 01-osint --skip 04-testssl
```

### Dry Run Mode

```bash
# See what would be executed without running
./run_external_recon_suite.sh --dry-run
```

### List Available Tasks

```bash
./run_external_recon_suite.sh --list
```

## Task Descriptions

### 00-validate

**Purpose**: Validate input files and expand CIDR ranges

**What it does**:
- Validates existence of required files and directories
- Expands CIDR notation to individual IPs
- Validates required and optional tools
- Creates expanded target list for subsequent tasks

**Outputs**:
- `RECON/targets_expanded_*.txt`

### 01-osint

**Purpose**: Open-Source Intelligence gathering

**What it does**:
- Subdomain enumeration (subfinder)
- DNS resolution and record retrieval (dnsx)
- ASN mapping (asnmap)
- CDN detection (cdncheck)
- Microsoft 365/Azure AD reconnaissance
- Certificate transparency log queries

**Outputs**:
- `RECON/osint_*/subfinder.json`
- `RECON/osint_*/dnsx.json`
- `RECON/osint_*/asnmap.json`
- `RECON/osint_*/cdncheck.jsonl`
- `RECON/osint_*/crtsh.json`

### 02-nmap

**Purpose**: Network mapping and port scanning

**What it does**:
- Host discovery scan
- Top 1000 ports scan with service version detection
- Optional: Full TCP port scan (1-65535)
- Optional: UDP port scan on common ports
- Optional: NSE vulnerability scanning
- Service and OS detection

**Outputs**:
- `RECON/nmap_*/01_discovery.*`
- `RECON/nmap_*/02_top_ports.*`
- `RECON/nmap_*/live_hosts.txt`
- `RECON/nmap_*/web_services.txt`

### 03-http-scan

**Purpose**: HTTP/HTTPS service reconnaissance and vulnerability scanning

**What it does**:
- HTTP/HTTPS service probing (httpx)
- Technology detection
- Vulnerability scanning with Nuclei templates:
  - CVEs
  - Known vulnerabilities
  - Exposures
  - Misconfigurations
  - Default credentials
  - Exposed panels
- Screenshot capture (gowitness)
- Technology fingerprinting (whatweb)

**Outputs**:
- `RECON/http_scan_*/httpx.json`
- `RECON/http_scan_*/live_urls.txt`
- `RECON/http_scan_*/nuclei_*.txt`
- `RECON/http_scan_*/nuclei_all_findings.json`
- `RECON/http_scan_*/screenshots/`

### 04-testssl

**Purpose**: SSL/TLS security testing

**What it does**:
- Comprehensive SSL/TLS testing
- Cipher suite analysis
- Protocol vulnerability detection
- Certificate validation
- Weak configuration identification

**Outputs**:
- `RECON/testssl_*/results/*.txt`
- `RECON/testssl_*/results/*.json`
- `RECON/testssl_*/results/*.html`
- `RECON/testssl_*/aggregate_summary.txt`
- `RECON/testssl_*/vulnerable_hosts.txt`

## Output Structure

After running the suite, your engagement directory will contain:

```
/path/to/engagement/
├── targets.txt                      # Your input targets
├── domains.txt                      # Your input domains
├── RECON/                           # All reconnaissance outputs
│   ├── targets_expanded_*.txt       # Expanded targets
│   ├── osint_*/                     # OSINT results
│   ├── nmap_*/                      # Nmap results
│   ├── http_scan_*/                 # HTTP scan results
│   └── testssl_*/                   # SSL/TLS test results
├── OUTPUT/
│   └── TEE/                         # Command output logs
└── LOGS/                            # Suite logs
```

## Configuration

### Environment Variables

#### Required
- `ENGAGEMENT_DIR` - Base directory for engagement outputs
- `TARGETS_FILE` - Path to targets file

#### Optional
- `DOMAINS_FILE` - Path to domains file
- `RECON_VERBOSE` - Enable verbose output (true/false)
- `RECON_DRY_RUN` - Dry run mode (true/false)

### Configuration Files

Configuration files allow you to customize scanning behavior:

```bash
# Use custom configuration
./run_external_recon_suite.sh --config /path/to/custom.conf
```

See [config/default.conf](config/default.conf) for all available options.

## Adding Custom Tasks

To add a new reconnaissance task:

1. Create a new task file in `tasks/` (e.g., `05-custom.sh`)
2. Implement the task function:

```bash
#!/usr/bin/env bash
set -uo pipefail
IFS=$'\n\t'

run_task_05_custom() {
    LOG info "Starting custom task"

    # Your task implementation here

    LOG pass "Custom task completed"
    return 0
}
```

3. Update the main orchestrator to include your task:

```bash
# In run_external_recon_suite.sh
TASK_ENABLED[05-custom]=true
TASK_REQUIRED[05-custom]=false
TASK_ORDER+=("05-custom")
```

## Best Practices

1. **Always use a dedicated engagement directory** to keep results organized
2. **Start with quick.conf** to get a feel for the suite
3. **Review logs** in `OUTPUT/TEE/` for detailed command outputs
4. **Use --dry-run** first when testing new configurations
5. **Keep tools updated** regularly (especially nuclei templates)
6. **Respect rate limits** when scanning production systems
7. **Always have authorization** before running reconnaissance

## Troubleshooting

### "Tool not found" errors

Install missing tools using the prerequisites section above.

### "Permission denied" errors

Ensure you have write permissions to the engagement directory.

### Nmap requires root

Some Nmap scans (SYN scan, OS detection) require root:

```bash
sudo -E ./run_external_recon_suite.sh
```

### Slow performance

- Use `config/quick.conf` for faster scans
- Disable full TCP scans: `NMAP_FULL_TCP_SCAN=false`
- Reduce thread counts in configuration
- Skip TestSSL for large target lists

### Out of memory

- Reduce `HTTPX_THREADS` and `NUCLEI_BULK_SIZE`
- Process targets in smaller batches
- Disable parallel mode

## Integration with Existing Scripts

This suite integrates with your existing reconnaissance scripts:

- `m365_recon_NG.sh` - Automatically used in OSINT task
- `dns_email_recon.sh` - Can be added as custom task
- Common utilities from `common_utils.sh` - Automatically sourced

## License

This tool is for authorized security testing only. Always obtain proper authorization before scanning.

## Support

For issues or questions:
1. Check the logs in `ENGAGEMENT_DIR/LOGS/`
2. Review command outputs in `ENGAGEMENT_DIR/OUTPUT/TEE/`
3. Run with `RECON_VERBOSE=true` for detailed output

## Changelog

### Version 1.0.0 (2026-01-03)
- Initial release
- Modular task architecture
- Support for OSINT, Nmap, HTTP scanning, and SSL/TLS testing
- Three scanning profiles (default, quick, aggressive)
- Comprehensive logging and reporting
