#!/usr/bin/env bash

###############################################################################
# Setup Script for External Reconnaissance Engagement
###############################################################################

set -uo pipefail
IFS=$'\n\t'

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    printf '%b\n' "${BLUE}"
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════════════════╗
║            External Reconnaissance Suite - Setup                           ║
╚════════════════════════════════════════════════════════════════════════════╝
EOF
    printf '%b\n' "${NC}"
}

usage() {
    cat << EOF
Usage: ${0##*/} <engagement_name> [engagement_path]

Arguments:
  engagement_name   Name of the engagement (e.g., "acme-corp-pentest")
  engagement_path   Optional: Base path for engagements (default: ~/engagements)

Example:
  ${0##*/} acme-corp-pentest
  ${0##*/} acme-corp-pentest /opt/engagements

This will create:
  ~/engagements/acme-corp-pentest/
  ├── targets.txt           # Edit this with your targets
  ├── domains.txt           # Edit this with your domains
  ├── RECON/                # Recon outputs will go here
  ├── OUTPUT/
  │   └── TEE/              # Command output logs
  └── LOGS/                 # Suite logs

EOF
}

main() {
    if [[ $# -lt 1 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        usage
        exit 0
    fi

    print_banner

    local engagement_name="$1"
    local base_path="${2:-${HOME}/engagements}"
    local engagement_dir="${base_path}/${engagement_name}"

    printf '%b\n' "${BLUE}[*]${NC} Setting up engagement: ${engagement_name}"
    printf '%b\n' "${BLUE}[*]${NC} Engagement directory: ${engagement_dir}"
    echo ""

    # Check if directory already exists
    if [[ -d "${engagement_dir}" ]]; then
        printf '%b\n' "${YELLOW}[!]${NC} Warning: Engagement directory already exists: ${engagement_dir}"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! ${REPLY} =~ ^[Yy]$ ]]; then
            printf '%b\n' "${RED}[✗]${NC} Aborted"
            exit 1
        fi
    fi

    # Create directory structure
    printf '%b\n' "${BLUE}[*]${NC} Creating directory structure..."
    if mkdir -p "${engagement_dir}"/{RECON,OUTPUT/TEE,LOGS}; then
        printf '%b\n' "${GREEN}[✓]${NC} Directory structure created"
    else
        printf '%b\n' "${RED}[✗]${NC} Failed to create directory structure"
        exit 1
    fi

    # Create targets file
    printf '%b\n' "${BLUE}[*]${NC} Creating targets.txt..."
    cat > "${engagement_dir}/targets.txt" << 'EOF'
# External Reconnaissance Targets
# Add your targets below (one per line)
# Supports: IPs, CIDR ranges, FQDNs
#
# Examples:
# 192.168.1.10
# 10.0.0.0/24
# example.com

EOF

    printf '%b\n' "${GREEN}[✓]${NC} Created: ${engagement_dir}/targets.txt"

    # Create domains file
    printf '%b\n' "${BLUE}[*]${NC} Creating domains.txt..."
    cat > "${engagement_dir}/domains.txt" << 'EOF'
# Domains for OSINT Reconnaissance
# Add your domains below (one per line)
#
# Examples:
# example.com
# example.net

EOF

    printf '%b\n' "${GREEN}[✓]${NC} Created: ${engagement_dir}/domains.txt"

    # Create environment file
    printf '%b\n' "${BLUE}[*]${NC} Creating environment file..."
    cat > "${engagement_dir}/env.sh" << EOF
#!/usr/bin/env bash
# Environment configuration for ${engagement_name}
# Source this file before running reconnaissance:
#   source env.sh

export ENGAGEMENT_DIR="${engagement_dir}"
export TARGETS_FILE="\${ENGAGEMENT_DIR}/targets.txt"
export DOMAINS_FILE="\${ENGAGEMENT_DIR}/domains.txt"

# Optional: Uncomment to customize
# export NMAP_FULL_TCP_SCAN=false
# export NMAP_UDP_SCAN=false
# export RECON_VERBOSE=true

echo "[*] Environment configured for: ${engagement_name}"
echo "[*] ENGAGEMENT_DIR: \${ENGAGEMENT_DIR}"
echo "[*] TARGETS_FILE: \${TARGETS_FILE}"
echo "[*] DOMAINS_FILE: \${DOMAINS_FILE}"
EOF

    chmod +x "${engagement_dir}/env.sh"
    printf '%b\n' "${GREEN}[✓]${NC} Created: ${engagement_dir}/env.sh"

    # Create README
    printf '%b\n' "${BLUE}[*]${NC} Creating README..."
    cat > "${engagement_dir}/README.md" << EOF
# ${engagement_name}

Engagement directory created: $(date)

## Quick Start

1. Edit the target files:
   - \`targets.txt\` - Add IPs, CIDR ranges, FQDNs
   - \`domains.txt\` - Add domains for OSINT

2. Load environment:
   \`\`\`bash
   source env.sh
   \`\`\`

3. Run reconnaissance:
   \`\`\`bash
   # Quick scan
   /path/to/run_external_recon_suite.sh --config /path/to/quick.conf

   # Default scan
   /path/to/run_external_recon_suite.sh

   # Aggressive scan
   /path/to/run_external_recon_suite.sh --config /path/to/aggressive.conf
   \`\`\`

## Directory Structure

- \`RECON/\` - All reconnaissance outputs
- \`OUTPUT/TEE/\` - Command output logs
- \`LOGS/\` - Suite execution logs

## Notes

Add your engagement notes here.
EOF

    printf '%b\n' "${GREEN}[✓]${NC} Created: ${engagement_dir}/README.md"

    # Create notes file
    printf '%b\n' "${BLUE}[*]${NC} Creating notes file..."
    cat > "${engagement_dir}/NOTES.md" << EOF
# ${engagement_name} - Notes

## Engagement Information

- **Client**:
- **Date**: $(date +%Y-%m-%d)
- **Tester**:
- **Scope**:

## Findings

### High Risk

### Medium Risk

### Low Risk

### Informational

## Timeline

- $(date +%Y-%m-%d): Engagement setup

EOF

    printf '%b\n' "${GREEN}[✓]${NC} Created: ${engagement_dir}/NOTES.md"

    echo ""
    printf '%b\n' "${GREEN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    printf '%b\n' "${GREEN}║                    Setup Complete!                                         ║${NC}"
    printf '%b\n' "${GREEN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    printf '%b\n' "${BLUE}Next steps:${NC}"
    echo ""
    printf '%b\n' "  1. Edit targets:"
    printf '%b\n' "     ${YELLOW}vim ${engagement_dir}/targets.txt${NC}"
    echo ""
    printf '%b\n' "  2. Edit domains:"
    printf '%b\n' "     ${YELLOW}vim ${engagement_dir}/domains.txt${NC}"
    echo ""
    printf '%b\n' "  3. Load environment:"
    printf '%b\n' "     ${YELLOW}source ${engagement_dir}/env.sh${NC}"
    echo ""
    printf '%b\n' "  4. Run reconnaissance:"
    printf '%b\n' "     ${YELLOW}cd $(dirname "${BASH_SOURCE[0]}")${NC}"
    printf '%b\n' "     ${YELLOW}./run_external_recon_suite.sh${NC}"
    echo ""
}

main "$@"
