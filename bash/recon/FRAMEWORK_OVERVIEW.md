# External Reconnaissance Framework - Complete Overview

## Executive Summary

A production-ready, modular external reconnaissance framework designed for penetration testing engagements. Built with enterprise-grade practices including proper error handling, comprehensive logging, flexible configuration, and extensible architecture.

## Key Features

### ✅ Modular Architecture
- **Task-Based Design**: Each reconnaissance phase is a separate, self-contained module
- **Easy Extension**: Add new tasks by creating a new script in `tasks/`
- **Dependency Management**: Tasks export variables for downstream tasks
- **Independent Execution**: Run specific tasks without running the full suite

### ✅ Comprehensive Tooling Integration
- **OSINT**: subfinder, dnsx, asnmap, cdncheck, crt.sh
- **Network Mapping**: nmap (host discovery, port scanning, service detection)
- **HTTP/HTTPS**: httpx, nuclei, gowitness, whatweb
- **SSL/TLS**: testssl.sh
- **Microsoft 365**: Custom M365 reconnaissance integration

### ✅ Enterprise-Grade Logging
- **Multiple Log Levels**: debug, info, warn, error, pass
- **Dual Output**: Console and file logging
- **TEE Outputs**: All command outputs saved for review
- **Timestamped Results**: All outputs include timestamps

### ✅ Flexible Configuration
- **Three Built-in Profiles**: Default, Quick, Aggressive
- **Custom Configurations**: Easy to create custom config files
- **Environment Variables**: Override any setting via environment
- **Runtime Options**: Command-line flags for common operations

### ✅ Production Features
- **Input Validation**: Validates files, directories, tools before execution
- **CIDR Expansion**: Automatically expands CIDR ranges to individual IPs
- **Error Handling**: Graceful degradation when tools are missing
- **Dry Run Mode**: Test configuration without executing
- **Task Dependencies**: Automatic variable passing between tasks

## Directory Structure

```
scripts/bash/recon/
├── run_external_recon_suite.sh      # Main orchestrator
├── setup_engagement.sh              # Engagement setup helper
│
├── tasks/                           # Modular task scripts
│   ├── 00-validate.sh              # Input validation & expansion
│   ├── 01-osint.sh                 # OSINT reconnaissance
│   ├── 02-nmap.sh                  # Network mapping
│   ├── 03-http-scan.sh             # HTTP/HTTPS reconnaissance
│   └── 04-testssl.sh               # SSL/TLS testing
│
├── config/                          # Configuration profiles
│   ├── default.conf                # Balanced scanning
│   ├── quick.conf                  # Fast scanning
│   └── aggressive.conf             # Comprehensive scanning
│
├── examples/                        # Example files
│   ├── targets.txt.example
│   └── domains.txt.example
│
├── README_RECON_SUITE.md           # User documentation
└── FRAMEWORK_OVERVIEW.md           # This file

Existing Integration:
├── common_utils.sh                 # Logging and helper functions
├── dns_utils.sh                    # DNS utilities
├── smtp_utils.sh                   # SMTP utilities
├── web_utils.sh                    # Web utilities
├── m365_recon_NG.sh               # Microsoft 365 recon
└── dns_email_recon.sh             # DNS/Email intelligence
```

## Task Workflow

```
┌─────────────────────────────────────────────────────────┐
│ 00-validate: Input Validation & CIDR Expansion          │
│ ├─ Validate targets.txt and domains.txt                 │
│ ├─ Expand CIDR ranges to individual IPs                 │
│ ├─ Validate required and optional tools                 │
│ └─ Export: EXPANDED_TARGETS_FILE                        │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│ 01-osint: Open-Source Intelligence                      │
│ ├─ Subdomain enumeration (subfinder)                    │
│ ├─ DNS resolution (dnsx)                                │
│ ├─ ASN mapping (asnmap)                                 │
│ ├─ CDN detection (cdncheck)                             │
│ ├─ Certificate transparency (crt.sh)                    │
│ ├─ Microsoft 365 reconnaissance                         │
│ └─ Export: Subdomain lists, DNS records                 │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│ 02-nmap: Network Mapping & Port Scanning                │
│ ├─ Host discovery scan                                  │
│ ├─ Top 1000 ports scan                                  │
│ ├─ Service version detection                            │
│ ├─ Optional: Full TCP scan (1-65535)                    │
│ ├─ Optional: UDP scan                                   │
│ ├─ Optional: NSE vulnerability scan                     │
│ ├─ Extract live hosts                                   │
│ ├─ Extract web services                                 │
│ └─ Export: NMAP_LIVE_HOSTS, NMAP_WEB_SERVICES          │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│ 03-http-scan: HTTP/HTTPS Reconnaissance                 │
│ ├─ HTTP service probing (httpx)                         │
│ ├─ Technology detection                                 │
│ ├─ Vulnerability scanning (nuclei):                     │
│ │  ├─ CVEs                                              │
│ │  ├─ Known vulnerabilities                             │
│ │  ├─ Exposures & misconfigurations                     │
│ │  ├─ Default credentials                               │
│ │  └─ Exposed panels                                    │
│ ├─ Screenshot capture (gowitness)                       │
│ ├─ Technology fingerprinting (whatweb)                  │
│ └─ Export: HTTPX_LIVE_URLS                             │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│ 04-testssl: SSL/TLS Security Testing                    │
│ ├─ Cipher suite analysis                                │
│ ├─ Protocol vulnerability detection                     │
│ ├─ Certificate validation                               │
│ ├─ Weak configuration identification                    │
│ ├─ Generate aggregate reports                           │
│ └─ Export: TESTSSL_VULNERABLE_HOSTS                    │
└─────────────────────────────────────────────────────────┘
```

## Configuration System

### Configuration Hierarchy

1. **Built-in Defaults** (in code)
2. **Configuration File** (--config option)
3. **Environment Variables** (highest priority)

### Configuration Profiles

#### Default Profile (`config/default.conf`)
- **Use Case**: Balanced reconnaissance for most engagements
- **Speed**: Moderate
- **Coverage**: Good
- **Notable Settings**:
  - Top 1000 ports
  - No full TCP scan
  - No UDP scan
  - All Nuclei severities

#### Quick Profile (`config/quick.conf`)
- **Use Case**: Fast initial reconnaissance or large target lists
- **Speed**: Fast
- **Coverage**: Basic
- **Notable Settings**:
  - Top 1000 ports only
  - TestSSL disabled
  - Critical/High nuclei findings only
  - Reduced timeouts

#### Aggressive Profile (`config/aggressive.conf`)
- **Use Case**: Comprehensive deep-dive reconnaissance
- **Speed**: Slow
- **Coverage**: Comprehensive
- **Notable Settings**:
  - Full TCP port scan (1-65535)
  - UDP scanning enabled
  - NSE vulnerability scans
  - All severity levels
  - Extended timeouts

## Integration Points

### With Common Core Library

The framework integrates with your `common_core` library:

```bash
# Automatic sourcing
source "${COMMON_CORE_LIB}/utils/logger.sh"
source "${COMMON_CORE_LIB}/utils/util_cmd.sh"

# Uses logger instance-based logging
logger_init "recon" "${ENGAGEMENT_DIR}/recon.log" "info" "true" "true"

# Fallback to local utilities if common_core not available
source "${SCRIPT_DIR}/common_utils.sh"
```

### With Existing Reconnaissance Scripts

```bash
# M365 Reconnaissance
if [[ -f "${SCRIPT_DIR}/m365_recon_NG.sh" ]]; then
    bash "${m365_script}" "${domain}" "${output_file}"
fi

# DNS/Email Intelligence
# Can be integrated as custom task (05-dns-email.sh)
source "${SCRIPT_DIR}/dns_email_recon.sh"
```

## Usage Patterns

### Pattern 1: Quick Initial Recon

```bash
# Setup
./setup_engagement.sh client-pentest
cd client-pentest
vim targets.txt  # Add targets
vim domains.txt  # Add domains
source env.sh

# Quick scan
/path/to/run_external_recon_suite.sh --config /path/to/quick.conf
```

### Pattern 2: Comprehensive Full Scan

```bash
# Setup
source env.sh

# Full scan with aggressive profile
/path/to/run_external_recon_suite.sh --config /path/to/aggressive.conf
```

### Pattern 3: Targeted Task Execution

```bash
# Run only OSINT
./run_external_recon_suite.sh --task 01-osint

# Run only HTTP scanning after nmap
./run_external_recon_suite.sh --task 03-http-scan
```

### Pattern 4: Incremental Scanning

```bash
# Day 1: OSINT and discovery
./run_external_recon_suite.sh --skip 03-http-scan --skip 04-testssl

# Day 2: HTTP and SSL testing
./run_external_recon_suite.sh --task 03-http-scan
./run_external_recon_suite.sh --task 04-testssl
```

## Extending the Framework

### Adding a New Task

1. **Create task script**: `tasks/05-custom.sh`

```bash
#!/usr/bin/env bash
set -uo pipefail
IFS=$'\n\t'

run_task_05_custom() {
    LOG info "Starting custom reconnaissance task"

    local targets="${EXPANDED_TARGETS_FILE:-${TARGETS_FILE}}"
    local output_dir="${ENGAGEMENT_DIR}/RECON/custom_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "${output_dir}"

    # Your custom reconnaissance logic here
    # Use variables from previous tasks:
    # - EXPANDED_TARGETS_FILE
    # - NMAP_LIVE_HOSTS
    # - HTTPX_LIVE_URLS
    # etc.

    # Export results for downstream tasks
    export CUSTOM_TASK_OUTPUT="${output_dir}/results.txt"

    LOG pass "Custom task completed"
    return 0
}
```

2. **Register task in orchestrator**:

Edit `run_external_recon_suite.sh`:

```bash
TASK_ENABLED[05-custom]=true
TASK_REQUIRED[05-custom]=false
TASK_ORDER+=("05-custom")
```

3. **Add configuration options** (optional):

In `config/default.conf`:

```bash
# Custom Task Configuration
CUSTOM_TASK_OPTION=true
CUSTOM_TASK_THREADS=10
```

### Adding a New Configuration Profile

Create `config/stealth.conf`:

```bash
#!/usr/bin/env bash

# Stealth profile - slow and careful

# Enable only passive tasks
TASK_ENABLED_00_VALIDATE=true
TASK_ENABLED_01_OSINT=true
TASK_ENABLED_02_NMAP=false
TASK_ENABLED_03_HTTP_SCAN=false
TASK_ENABLED_04_TESTSSL=false

# Slow scan timing
HTTPX_THREADS=5
NUCLEI_RATE_LIMIT=10
```

## Output Analysis

### Key Output Files

```
ENGAGEMENT_DIR/
├── RECON/
│   ├── targets_expanded_*.txt           # All targets (CIDR expanded)
│   │
│   ├── osint_*/
│   │   ├── subfinder.json              # All subdomains found
│   │   ├── subdomains.txt              # Subdomains (text)
│   │   ├── dnsx.json                   # DNS resolution results
│   │   ├── asnmap.json                 # ASN information
│   │   └── summary.txt                 # OSINT summary
│   │
│   ├── nmap_*/
│   │   ├── live_hosts.txt              # Live hosts
│   │   ├── web_services.txt            # HTTP/HTTPS URLs
│   │   ├── *.nmap, *.gnmap, *.xml      # Nmap scan results
│   │   └── summary.txt                 # Nmap summary
│   │
│   ├── http_scan_*/
│   │   ├── live_urls.txt               # All live web services
│   │   ├── httpx.json                  # HTTPx results
│   │   ├── nuclei_all_findings.json    # All Nuclei findings
│   │   ├── nuclei_severity_summary.txt # Findings by severity
│   │   ├── screenshots/                # Website screenshots
│   │   └── summary.txt                 # HTTP scan summary
│   │
│   └── testssl_*/
│       ├── results/*.json              # Per-host SSL/TLS results
│       ├── aggregate_results.json      # Combined results
│       ├── aggregate_summary.txt       # Summary report
│       └── vulnerable_hosts.txt        # Hosts with issues
│
└── OUTPUT/TEE/                          # All command outputs
    ├── subfinder_*.tee
    ├── nmap_*.tee
    ├── httpx_*.tee
    ├── nuclei_*.tee
    └── testssl_*.tee
```

### Priority Review Order

1. **Start Here**:
   - `http_scan_*/nuclei_severity_summary.txt`
   - `testssl_*/aggregate_summary.txt`

2. **High-Value Targets**:
   - `http_scan_*/httpx_interesting.txt`
   - `nmap_*/web_services.txt`

3. **Detailed Analysis**:
   - `nuclei_all_findings.json`
   - `testssl_*/aggregate_results.json`

4. **Visual Review**:
   - `http_scan_*/screenshots/`

## Performance Considerations

### Small Engagements (< 256 IPs)
- Use **default.conf**
- Expected time: 2-4 hours
- Enable all tasks

### Medium Engagements (256-4096 IPs)
- Use **quick.conf** for initial scan
- Follow up with targeted **default.conf** on interesting hosts
- Expected time: 4-12 hours initial scan
- Consider disabling TestSSL

### Large Engagements (> 4096 IPs)
- Use **quick.conf** with task splitting
- Process in batches of 1024 IPs
- Disable full TCP and UDP scans
- Expected time: 12-48 hours
- Run tasks independently: `--task 01-osint`, etc.

### Performance Tuning

```bash
# Faster HTTP scanning
export HTTPX_THREADS=100
export NUCLEI_RATE_LIMIT=300

# Faster Nmap scanning (more aggressive)
export NMAP_TIMING=4  # T4

# Reduce tool timeouts
export HTTPX_TIMEOUT=5
export NUCLEI_TIMEOUT=5
```

## Security Considerations

### Authorization
- **Always obtain written authorization** before scanning
- Document scope boundaries in `NOTES.md`
- Respect exclusions and out-of-scope systems

### Rate Limiting
- Default configurations include rate limiting
- Monitor target systems for impact
- Use **quick.conf** for production systems
- Consider running during maintenance windows

### Tool Behavior
- **Nmap**: Can be detected by IDS/IPS
- **Nuclei**: Makes HTTP requests to test for vulnerabilities
- **TestSSL**: Establishes SSL/TLS connections
- All tools generate logs on target systems

### Data Handling
- Engagement directories contain sensitive information
- Encrypt engagement directories at rest
- Use secure file transfer for results
- Follow client data handling requirements

## Troubleshooting

### Common Issues

#### "Permission denied" on ENGAGEMENT_DIR
```bash
# Fix permissions
chmod 755 "${ENGAGEMENT_DIR}"
# Or run with correct user
sudo -u ${USER} ./run_external_recon_suite.sh
```

#### "Tool not found" errors
```bash
# Check which tool is missing
./run_external_recon_suite.sh --task 00-validate

# Install missing tools (see README)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### Nmap requires root for some scans
```bash
# Run with sudo (preserving environment)
sudo -E ./run_external_recon_suite.sh

# Or disable scans requiring root
export NMAP_SYN_SCAN=false
```

#### Out of disk space
```bash
# Check engagement directory size
du -sh "${ENGAGEMENT_DIR}"

# Clean old results
rm -rf "${ENGAGEMENT_DIR}"/RECON/*_old

# Compress large files
gzip "${ENGAGEMENT_DIR}"/RECON/*/*.json
```

## Best Practices

1. **Always start with validation**: `--task 00-validate`
2. **Use dry-run for testing**: `--dry-run`
3. **Start with quick scans**: Use `quick.conf` first
4. **Review logs regularly**: Check `OUTPUT/TEE/` for errors
5. **Document findings**: Use `NOTES.md` throughout engagement
6. **Keep tools updated**: Especially Nuclei templates
7. **Batch large scans**: Split very large target lists
8. **Monitor resources**: Watch CPU, memory, and disk usage
9. **Backup results**: Regularly backup engagement directory
10. **Clean up**: Archive or delete old engagements

## Future Enhancements

Potential areas for expansion:

- [ ] Parallel task execution
- [ ] Web-based reporting dashboard
- [ ] Database backend for results
- [ ] API for programmatic access
- [ ] Docker containerization
- [ ] Distributed scanning support
- [ ] Real-time notification system
- [ ] Integration with vulnerability databases
- [ ] Automated report generation
- [ ] JIRA/Ticketing system integration

## Conclusion

This framework provides a solid foundation for external reconnaissance while maintaining:

- **Flexibility**: Easy to customize and extend
- **Reliability**: Proper error handling and logging
- **Maintainability**: Modular design and clear structure
- **Usability**: Multiple profiles and configurations
- **Integration**: Works with existing tools and scripts

The modular architecture allows you to easily add new reconnaissance techniques as new tools become available or as requirements evolve.
