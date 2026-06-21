#!/bin/bash
#
# verify-olvm-ha.sh
# OLVM HA Verification Wrapper (CONTROL NODE)
# Version: 4.22
#
# Changes in v4.22:
#   - Added -i / --inventory FILE so the lab/prod inventories that ship with
#     the project (inventory-lab-akyuz.yml, inventory-prod-dell-me5.yml) can be
#     verified directly, matching setup.sh. Default stays inventory.yml.
#
# Tested on:
#   - Ansible Core 2.16+
#   - Targets: OLVM 4.5.5-1.67.el8 hosts
#
# IMPORTANT:
#   This script runs on the CONTROL/MANAGEMENT node (NOT on OLVM hosts).
#   It invokes verify-olvm-ha.yml via Ansible to query hosts defined
#   in inventory.yml.
#
# Changes in v4.6:
#   - Architecture redesign: now a thin Ansible wrapper (was: local bash on host)
#   - All data gathered via Ansible playbook (verify-olvm-ha.yml)
#   - Per-host and aggregate reports produced by playbook
#   - Failover math runs in Jinja2 with integer division (no bash float bug)
#   - --host <name> filter to verify a single host
#   - --tags passthrough to Ansible (full / quick / logs / vdsm / multipath etc.)
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
readonly PLAYBOOK="${SCRIPT_DIR}/verify-olvm-ha.yml"
readonly LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/verify-$(date +%Y%m%d-%H%M%S).log"

# Defaults
REPORT_MODE="full"
LOG_LOOKBACK_MINUTES=10
HOST_FILTER=""
EXTRA_TAGS=""
VERBOSE=false
QUIET=false

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
# Logging
# ============================================================
mkdir -p "${LOG_DIR}"

log_info()    { echo -e "${BLUE}[INFO]${NC}    $*" | tee -a "${LOG_FILE}" >&2; }
log_success() { echo -e "${GREEN}[OK]${NC}      $*" | tee -a "${LOG_FILE}" >&2; }
log_warning() { echo -e "${YELLOW}[WARN]${NC}    $*" | tee -a "${LOG_FILE}" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*" | tee -a "${LOG_FILE}" >&2; }

print_header() {
    echo "" >&2
    echo -e "${CYAN}====================================================${NC}" >&2
    echo -e "${CYAN}  $1${NC}" >&2
    echo -e "${CYAN}====================================================${NC}" >&2
    echo "" >&2
}

# Graceful shutdown
on_interrupt() {
    echo "" >&2
    log_warning "Interrupted by user"
    log_info  "Partial log: ${LOG_FILE}"
    exit 130
}
trap on_interrupt INT TERM

# ============================================================
# Help
# ============================================================
show_usage() {
    cat << EOF
OLVM HA Verification Tool v${SCRIPT_VERSION}
=========================================

This script runs on the CONTROL NODE and verifies HA configuration on
OLVM hosts defined in inventory.yml via Ansible.

USAGE:
    verify-olvm-ha.sh [OPTIONS]

OPTIONS:
    -i, --inventory FILE    Use a specific inventory file instead of the
                            default inventory.yml (e.g. inventory-lab-akyuz.yml)
    -f, --full              Full check (default)
    -q, --quick             Quick status summary only
    --version               Version info (alias for --quick)
    --vdsm                  VDSM configuration only
    --sanlock               Sanlock configuration only
    --multipath             Multipath configuration only
    --ha                    HA Agent configuration only
    --libvirt               Libvirt configuration only
    --storage               Storage status only
    --engine                Engine (manager) tuning verification only
    --failover              Calculate estimated failover time only
    --logs [MINUTES]        Recent error/warning logs (default: 10 min)
    --host <NAME>           Verify only one host (must exist in inventory)
    --tags <TAGLIST>        Pass arbitrary tags to ansible-playbook
    --verbose, -v           Verbose ansible output
    --quiet                 Suppress wrapper info messages
    -h, --help              Show this help

EXAMPLES:
    verify-olvm-ha.sh                       # Full check on all hosts
    verify-olvm-ha.sh -i inventory-lab-akyuz.yml --quick   # Lab inventory
    verify-olvm-ha.sh --quick               # Quick status all hosts
    verify-olvm-ha.sh --host olvm01      # Single host
    verify-olvm-ha.sh --failover            # Failover estimate only
    verify-olvm-ha.sh --logs 60             # Logs from last hour
    verify-olvm-ha.sh --tags vdsm,multipath # Custom tag set

EXIT CODES:
    0   Success - all hosts verified
    1   Configuration/prerequisites error
    2   One or more hosts failed verification
    130 Interrupted by user

LOGS:
    ${LOG_DIR}/

EOF
}

# ============================================================
# Prerequisites
# ============================================================
check_prerequisites() {
    if ! command -v ansible-playbook &>/dev/null; then
        log_error "ansible-playbook not found on control node"
        log_info  "Install: sudo dnf install ansible-core (RHEL/Oracle Linux)"
        log_info  "         sudo apt install ansible-core (Debian/Ubuntu)"
        exit 1
    fi
    
    if [ ! -f "${INVENTORY}" ]; then
        log_error "Inventory not found: ${INVENTORY}"
        exit 1
    fi
    
    if [ ! -r "${INVENTORY}" ]; then
        log_error "Inventory not readable: ${INVENTORY}"
        exit 1
    fi
    
    if [ ! -f "${PLAYBOOK}" ]; then
        log_error "Playbook not found: ${PLAYBOOK}"
        exit 1
    fi
    
    if [ ! -r "${PLAYBOOK}" ]; then
        log_error "Playbook not readable: ${PLAYBOOK}"
        exit 1
    fi
}

# ============================================================
# Inventory resolution (for -i / --inventory)
# ============================================================
# Resolve a user-supplied inventory path to an existing, readable file. Tries
# the path as given (CWD/absolute), then relative to the script directory.
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
            -f|--full)
                EXTRA_TAGS="full"
                REPORT_MODE="full"
                shift
                ;;
            -q|--quick)
                EXTRA_TAGS="quick"
                REPORT_MODE="quick"
                shift
                ;;
            --version)
                # No dedicated 'version' tag exists in the playbook; the quick
                # report already prints OS/package versions. Alias to quick.
                EXTRA_TAGS="quick"
                REPORT_MODE="quick"
                log_warning "--version: showing quick report (includes version info)"
                shift
                ;;
            --vdsm)
                EXTRA_TAGS="vdsm"
                shift
                ;;
            --sanlock)
                EXTRA_TAGS="sanlock"
                shift
                ;;
            --multipath)
                EXTRA_TAGS="multipath"
                shift
                ;;
            --ha)
                EXTRA_TAGS="ha"
                shift
                ;;
            --libvirt)
                EXTRA_TAGS="libvirt"
                shift
                ;;
            --storage)
                EXTRA_TAGS="storage"
                shift
                ;;
            --engine)
                EXTRA_TAGS="engine"
                shift
                ;;
            --failover)
                EXTRA_TAGS="failover"
                shift
                ;;
            --logs)
                EXTRA_TAGS="logs"
                shift
                # Optional integer next arg
                if [ $# -gt 0 ] && [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]; then
                    LOG_LOOKBACK_MINUTES="$1"
                    shift
                fi
                ;;
            --host)
                shift
                if [ $# -eq 0 ]; then
                    log_error "--host requires a hostname argument"
                    exit 1
                fi
                HOST_FILTER="$1"
                shift
                ;;
            --tags)
                shift
                if [ $# -eq 0 ]; then
                    log_error "--tags requires a tag list argument"
                    exit 1
                fi
                EXTRA_TAGS="$1"
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --quiet)
                QUIET=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# ============================================================
# Main
# ============================================================
main() {
    parse_args "$@"
    
    # Initialize log file
    : > "${LOG_FILE}"
    
    if [ "${QUIET}" != "true" ]; then
        print_header "OLVM HA Verification (control node) v${SCRIPT_VERSION}"
        log_info "Log file:    ${LOG_FILE}"
        log_info "Inventory:   ${INVENTORY}"
        log_info "Playbook:    ${PLAYBOOK}"
        log_info "Tags:        ${EXTRA_TAGS:-(none / default)}"
        [ -n "${HOST_FILTER}" ] && log_info "Host filter: ${HOST_FILTER}"
    fi
    
    check_prerequisites
    
    # Build ansible-playbook arguments
    local ansible_args=(
        "-i" "${INVENTORY}"
        "${PLAYBOOK}"
        "-e" "report_mode=${REPORT_MODE}"
        "-e" "log_lookback_minutes=${LOG_LOOKBACK_MINUTES}"
    )
    
    if [ -n "${EXTRA_TAGS}" ]; then
        ansible_args+=("--tags" "${EXTRA_TAGS}")
    fi
    
    if [ -n "${HOST_FILTER}" ]; then
        ansible_args+=("--limit" "${HOST_FILTER}")
    fi
    
    if [ "${VERBOSE}" = "true" ]; then
        ansible_args+=("-vv")
    fi
    
    # Run playbook - output goes to stdout AND log file
    local rc=0
    if ansible-playbook "${ansible_args[@]}" 2>&1 | tee -a "${LOG_FILE}"; then
        rc=0
    else
        rc=${PIPESTATUS[0]}
    fi
    
    if [ "${QUIET}" != "true" ]; then
        echo ""
        if [ ${rc} -eq 0 ]; then
            log_success "Verification completed successfully"
        else
            log_error "Verification reported issues (ansible-playbook exit code: ${rc})"
            log_info  "Review log: ${LOG_FILE}"
        fi
    fi
    
    # Map ansible exit codes to ours:
    # 0 = success, 2 = task failure (host issues), others = config errors
    case "${rc}" in
        0)   exit 0 ;;
        2|4) exit 2 ;;  # Host failures or unreachable
        *)   exit 1 ;;
    esac
}

main "$@"
