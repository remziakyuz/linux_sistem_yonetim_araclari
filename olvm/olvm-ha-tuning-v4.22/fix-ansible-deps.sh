#!/bin/bash
#
# fix-ansible-deps.sh
# Version: 4.22
# Install required Python packages on OLVM hosts for Ansible (CONTROL NODE)
#
# Changes in v4.22:
#   - Added -i / --inventory FILE so dependencies can be installed against the
#     lab/prod inventories that ship with the project. Default stays
#     inventory.yml.
#
# Tested on:
#   - Oracle Linux 8.10 hosts
#   - Python 3.6 / 3.12
#   - Ansible Core 2.16+
#
# IMPORTANT:
#   Runs on the CONTROL NODE. Targets hosts defined in inventory.yml.
#
# Required packages (installed on each OLVM host):
#   - python3-rpm: For package_facts module
#   - python3-dnf: For dnf operations
#   - python3-libselinux: For SELinux operations
#
# Changes in v4.6:
#   - Version aligned with project
#   - Inventory readability check (not just existence)
#   - Stricter shellcheck-clean structure
#
# Changes in v4.5:
#   - Improved package installer detection (dnf preferred over yum)
#   - Better error reporting when one host fails but others succeed
#   - Added --check flag to verify without installing
#

set -euo pipefail

# ============================================================
# Constants & Configuration
# ============================================================
readonly SCRIPT_VERSION="4.22"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Inventory is overridable with -i/--inventory (default: inventory.yml).
readonly DEFAULT_INVENTORY="${SCRIPT_DIR}/inventory.yml"
INVENTORY="${DEFAULT_INVENTORY}"
LOG_FILE="/tmp/olvm-fix-deps-$(date +%Y%m%d-%H%M%S).log"

# Required packages (single source of truth)
readonly REQUIRED_PACKAGES=(
    "python3-rpm"
    "python3-dnf"
    "python3-libselinux"
)

# Flags
CHECK_ONLY=false

# ============================================================
# Color codes
# ============================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# ============================================================
# Output functions
# ============================================================
log_info()    { echo -e "${BLUE}[INFO]${NC}    $*" | tee -a "${LOG_FILE}"; }
log_success() { echo -e "${GREEN}[OK]${NC}      $*" | tee -a "${LOG_FILE}"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC}    $*" | tee -a "${LOG_FILE}"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*" | tee -a "${LOG_FILE}"; }

print_header() {
    local msg="$1"
    echo ""
    echo -e "${CYAN}====================================================${NC}"
    echo -e "${CYAN}  ${msg}${NC}"
    echo -e "${CYAN}====================================================${NC}"
    echo ""
}

# ============================================================
# Inventory resolution (for -i / --inventory)
# ============================================================
resolve_inventory() {
    local p="${1:-}"
    if [ -z "${p}" ]; then
        log_error "-i / --inventory requires a file argument"
        exit 1
    fi
    if [ -f "${p}" ]; then
        INVENTORY="$(cd "$(dirname "${p}")" && pwd)/$(basename "${p}")"
    elif [ -f "${SCRIPT_DIR}/${p}" ]; then
        INVENTORY="${SCRIPT_DIR}/${p}"
    else
        log_error "Inventory file not found: ${p}"
        log_info  "Tried: ${p}"
        log_info  "  and: ${SCRIPT_DIR}/${p}"
        exit 1
    fi
    if [ ! -r "${INVENTORY}" ]; then
        log_error "Inventory file not readable: ${INVENTORY}"
        exit 1
    fi
}

# ============================================================
# Argument parsing
# ============================================================
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -i|--inventory)
                shift
                if [ $# -eq 0 ]; then
                    log_error "-i / --inventory requires a file argument"
                    exit 1
                fi
                resolve_inventory "$1"
                shift
                ;;
            --inventory=*)
                resolve_inventory "${1#--inventory=}"
                shift
                ;;
            -i*)
                resolve_inventory "${1#-i}"
                shift
                ;;
            --check)
                CHECK_ONLY=true
                shift
                ;;
            --help|-h)
                cat << EOF
OLVM Ansible Dependencies Fix v${SCRIPT_VERSION}

USAGE:
    fix-ansible-deps.sh [OPTIONS]

OPTIONS:
    -i, --inventory FILE   Use a specific inventory file (default inventory.yml)
    --check        Verify dependencies without installing
    --help, -h     Show this help

PACKAGES INSTALLED:
$(printf '    - %s\n' "${REQUIRED_PACKAGES[@]}")

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                exit 1
                ;;
        esac
    done
}

# ============================================================
# Pre-flight checks
# ============================================================
check_prerequisites() {
    print_header "Prerequisites Check"
    
    # Check Ansible
    if ! command -v ansible &>/dev/null; then
        log_error "Ansible not installed on control node"
        log_info  "Install with: sudo apt install ansible (Debian/Ubuntu)"
        log_info  "             sudo dnf install ansible (RHEL/CentOS)"
        exit 1
    fi
    log_success "Ansible: $(ansible --version | head -n1)"
    
    # Check inventory
    if [ ! -f "${INVENTORY}" ]; then
        log_error "Inventory file not found: ${INVENTORY}"
        exit 1
    fi
    if [ ! -r "${INVENTORY}" ]; then
        log_error "Inventory file not readable: ${INVENTORY}"
        exit 1
    fi
    log_success "Inventory: ${INVENTORY}"
    
    # Check ansible-playbook
    if ! command -v ansible-playbook &>/dev/null; then
        log_error "ansible-playbook command not found"
        exit 1
    fi
}

# ============================================================
# Test connectivity
# ============================================================
test_connectivity() {
    print_header "Connectivity Test"
    
    log_info "Testing SSH connectivity to all hosts..."
    
    if ansible -i "${INVENTORY}" ovirt_hosts -m raw -a "echo 'OK'" --one-line 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "All hosts reachable"
    else
        log_error "Some hosts not reachable"
        log_info  "Check SSH access:"
        log_info  "  ssh-copy-id root@<hostname>"
        log_info  "  Or update inventory.yml with credentials"
        exit 1
    fi
}

# ============================================================
# Install Python packages (prefer dnf, fallback to yum)
# ============================================================
install_packages() {
    print_header "Installing Python Dependencies"
    
    local packages_str="${REQUIRED_PACKAGES[*]}"
    log_info "Packages: ${packages_str}"
    
    # Prefer dnf if available; fallback to yum. -y for non-interactive.
    # Quiet output to reduce log noise, but errors still surface via $?.
    if ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "command -v dnf >/dev/null && dnf install -y ${packages_str} 2>&1 || yum install -y ${packages_str} 2>&1" \
        --become 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "Packages installed successfully"
    else
        log_error "Package installation failed"
        log_info  "Check ${LOG_FILE} for details"
        exit 1
    fi
}

# ============================================================
# Verify installation
# ============================================================
verify_installation() {
    print_header "Verification"
    
    local failed=0
    
    # Test Python rpm module
    log_info "Testing Python rpm module..."
    if ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "python3 -c 'import rpm' && echo 'rpm OK'" \
        --become \
        --one-line 2>&1 | tee -a "${LOG_FILE}" | grep -q "rpm OK"; then
        log_success "Python rpm module: OK"
    else
        log_error "Python rpm module: FAILED"
        failed=1
    fi
    
    # Test Python dnf module
    log_info "Testing Python dnf module..."
    if ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "python3 -c 'import dnf' && echo 'dnf OK'" \
        --become \
        --one-line 2>&1 | tee -a "${LOG_FILE}" | grep -q "dnf OK"; then
        log_success "Python dnf module: OK"
    else
        log_error "Python dnf module: FAILED"
        failed=1
    fi
    
    # Test Ansible ping
    log_info "Testing Ansible ping module..."
    if ansible -i "${INVENTORY}" ovirt_hosts -m ping --one-line 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "Ansible ping: OK"
    else
        log_error "Ansible ping: FAILED"
        failed=1
    fi
    
    return ${failed}
}

# ============================================================
# Main
# ============================================================
main() {
    parse_args "$@"
    
    # Initialize log
    : > "${LOG_FILE}"
    
    print_header "OLVM Ansible Dependencies Fix v${SCRIPT_VERSION}"
    log_info "Log file: ${LOG_FILE}"
    log_info "Mode: $(if [ "${CHECK_ONLY}" = "true" ]; then echo "CHECK ONLY"; else echo "INSTALL"; fi)"
    
    check_prerequisites
    test_connectivity
    
    if [ "${CHECK_ONLY}" != "true" ]; then
        install_packages
    fi
    
    if verify_installation; then
        print_header "Success"
        log_success "All dependencies installed and verified"
        echo ""
        log_info "Next steps:"
        echo "  1. Run: ansible-playbook -i inventory.yml test-connection.yml"
        echo "  2. Run: ./setup.sh balanced"
        echo ""
        exit 0
    else
        print_header "Verification Failed"
        log_error "Some checks failed. Review ${LOG_FILE} for details"
        if [ "${CHECK_ONLY}" = "true" ]; then
            log_info "Run without --check to install missing dependencies"
        fi
        exit 1
    fi
}

main "$@"
