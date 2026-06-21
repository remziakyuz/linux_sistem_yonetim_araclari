#!/bin/bash
#
# setup.sh
# OLVM HA Tuning - Enterprise Setup Script (CONTROL NODE)
# Version: 4.22
#
# Changes in v4.22:
#   - BUGFIX: setup.sh now accepts -i / --inventory FILE (was: "Unknown
#     argument: -i"). The command documented in the REVIEW and in the lab/prod
#     vars files
#       ./setup.sh custom -i inventory-lab-akyuz.yml -e @vars/lab-akyuz.yml --no-restart
#     previously aborted at argument parsing because only the fixed
#     inventory.yml was supported. The path is resolved relative to the current
#     directory first, then relative to the script directory, and validated for
#     existence/readability before use. verify-olvm-ha.sh and fix-ansible-deps.sh
#     gained the same -i / --inventory option for a consistent toolset.
#
# Tested on:
#   - OLVM 4.5.5-1.67.el8
#   - VDSM 4.50.5.1-8.el8
#   - Oracle Linux 8.10
#   - Ansible Core 2.16+
#
# IMPORTANT:
#   This script runs on the CONTROL/MANAGEMENT node, NOT on OLVM hosts.
#   It invokes Ansible playbooks against hosts in inventory.yml.
#
# Changes in v4.6:
#   - Architecture clarified: setup.sh and verify-olvm-ha.sh are
#     CONTROL-NODE wrappers, not host-local scripts
#   - verify-olvm-ha.sh now invokes verify-olvm-ha.yml via Ansible
#     (previously ran local bash on host)
#   - Added --check-syntax option (ansible-playbook --syntax-check only)
#   - Added show_inventory_summary() pre-flight (lists target hosts)
#   - Improved exit-code semantics (0=ok, 1=config, 2=host issues, 130=intr)
#   - confirm() helper unifies all yes/no prompts
#   - YAML parser now also validates value is non-empty
#
# Changes in v4.5:
#   - Replaced bc-based failover calc with integer arithmetic
#     (avoids "115.0" float output that broke comparisons in verify script)
#   - Robust profile-file value parsing (ignores inline comments)
#   - Rollback date format validation (YYYYMMDDTHHMMSS or "latest")
#   - Profile-file existence + readability checks
#   - Trap on SIGINT/SIGTERM to log graceful interruption
#

set -euo pipefail

# ============================================================
# Constants & Configuration
# ============================================================
readonly SCRIPT_VERSION="4.22"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Inventory is overridable with -i/--inventory (default: inventory.yml next to
# this script). Kept non-readonly so parse_args() can point it at e.g.
# inventory-lab-akyuz.yml / inventory-prod-dell-me5.yml.
readonly DEFAULT_INVENTORY="${SCRIPT_DIR}/inventory.yml"
INVENTORY="${DEFAULT_INVENTORY}"
readonly PLAYBOOK="${SCRIPT_DIR}/olvm-ha-tuning.yml"
readonly ROLLBACK_PLAYBOOK="${SCRIPT_DIR}/olvm-ha-rollback.yml"
readonly TEST_PLAYBOOK="${SCRIPT_DIR}/test-connection.yml"
readonly VARS_DIR="${SCRIPT_DIR}/vars"
readonly LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/setup-$(date +%Y%m%d-%H%M%S).log"

# Default profile
readonly DEFAULT_PROFILE="balanced"
PROFILE="${DEFAULT_PROFILE}"

# Valid profiles (single source of truth)
readonly VALID_PROFILES="balanced aggressive conservative custom"

# Rollback date pattern (ISO8601 basic short - matches Ansible iso8601_basic_short)
readonly ROLLBACK_DATE_PATTERN='^[0-9]{8}T[0-9]{6}$'

# Flags
CHECK_ONLY=false
CHECK_SYNTAX=false
NO_RESTART=false
FORCE_NO_RESTART=false      # set by --no-restart (explicit stage-only)
FORCE_RESTART=false         # set by --restart    (explicit opt-in to restart)
SKIP_TEST=false
VERSION_CHECK_ONLY=false
ROLLBACK_MODE=false
ROLLBACK_DATE=""
FORCE=false
VERBOSE=false
EXTRA_VARS=()              # collected from -e / --extra-vars, forwarded to ansible-playbook

# ============================================================
# Color codes
# ============================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

# ============================================================
# Logging setup
# ============================================================
mkdir -p "${LOG_DIR}"

log_info()    { echo -e "${BLUE}[INFO]${NC}    $*" | tee -a "${LOG_FILE}"; }
log_success() { echo -e "${GREEN}[OK]${NC}      $*" | tee -a "${LOG_FILE}"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC}    $*" | tee -a "${LOG_FILE}"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*" | tee -a "${LOG_FILE}"; }

print_header() {
    local msg="$1"
    echo ""
    echo -e "${CYAN}====================================================${NC}" | tee -a "${LOG_FILE}"
    echo -e "${CYAN}  ${msg}${NC}" | tee -a "${LOG_FILE}"
    echo -e "${CYAN}====================================================${NC}" | tee -a "${LOG_FILE}"
    echo ""
}

# Graceful shutdown
on_interrupt() {
    echo ""
    log_warning "Interrupted by user (signal received)"
    log_info  "Partial log saved at: ${LOG_FILE}"
    exit 130
}
trap on_interrupt INT TERM

# ============================================================
# Failover calculation (integer arithmetic - matches verify-olvm-ha.sh)
# ============================================================

# Calculate failover time using pure integer math:
#   failover = (sanlock_io * 1.5) + (ha_mon * 3) + 25
# Implemented as: (sanlock_io * 3 / 2) + (ha_mon * 3) + 25
# Args: $1 = sanlock_io_timeout, $2 = ha_monitoring_interval
calculate_failover_integer() {
    local sanlock="${1:-0}"
    local ha_mon="${2:-0}"
    
    if ! [[ "${sanlock}" =~ ^[0-9]+$ ]] || [ "${sanlock}" -le 0 ]; then
        echo ""
        return 1
    fi
    if ! [[ "${ha_mon}" =~ ^[0-9]+$ ]] || [ "${ha_mon}" -le 0 ]; then
        echo ""
        return 1
    fi
    
    echo $(( (sanlock * 3 / 2) + (ha_mon * 3) + 25 ))
}

# ============================================================
# Help
# ============================================================
show_usage() {
    cat << EOF
OLVM HA Tuning - Enterprise Setup Script v${SCRIPT_VERSION}
=========================================

USAGE:
    setup.sh [PROFILE] [OPTIONS]
    setup.sh [PROFILE] -i INVENTORY -e @vars/FILE.yml [OPTIONS]
    setup.sh --rollback [DATE]
    setup.sh --help

PROFILES (failover figures are heuristic upper bounds, not measured):
    balanced       ~130s heuristic failover (RECOMMENDED for production)
    aggressive     ~115s heuristic failover (high risk)
    conservative   ~160s heuristic failover (low risk)
    custom         Use vars/custom.yml

OPTIONS:
    -i, --inventory FILE   Use a specific inventory file instead of the default
                           inventory.yml. The path is resolved relative to the
                           current directory first, then to the script
                           directory. Applies to apply, rollback, check and
                           syntax-check modes. Example:
                           -i inventory-lab-akyuz.yml
    --check-only           Display current configuration only
    --check-syntax         Validate playbook YAML syntax (no execution)
    --restart              Restart services after applying (opt-in; disruptive).
                           Without this flag you are ASKED, and the default
                           answer is NO. When a restart is requested interactively
                           you must confirm TWICE; if either prompt is declined,
                           the config is staged and nothing is restarted.
    -e KEY=VALUE           Pass an extra variable straight through to
    --extra-vars KEY=VALUE ansible-playbook (repeatable). Example:
                           -e multipath_me5_device_block=true
    --no-restart           Never restart services; stage config only (no prompt).
                           This is the default behavior if you answer "no" / use
                           --force without --restart. RECOMMENDED for production:
                           apply the staged config later by rebooting each host
                           via the OLVM web UI (Maintenance -> Restart -> Activate).
    --skip-test            Skip connectivity tests
    --version-check        Check OLVM versions only
    --rollback [DATE]      Rollback (use 'latest' or YYYYMMDDTHHMMSS)
    --force                Skip confirmations (use with caution!). With --force
                           and no --restart, services are NOT restarted (safe).
    --verbose, -v          Enable verbose output
    --help, -h             Show this help

SERVICE RESTART (IMPORTANT):
    By default this script does NOT restart sanlock/vdsmd/libvirtd. It asks you
    interactively and defaults to "no", because restarting those daemons on a
    live hypervisor is slow and can make the engine mark the host
    Non-Responsive. The safe path is: stage the config, then reboot each host
    one at a time from the OLVM web UI. Use --restart only if you accept a live
    restart.

EXAMPLES:
    # Standard usage
    setup.sh balanced
    
    # Test/validation only
    setup.sh --check-only
    setup.sh --check-syntax
    setup.sh --version-check
    
    # Apply without service restart (stage only)
    setup.sh balanced --no-restart

    # Lab cluster: custom profile with a specific inventory + vars (stage only)
    setup.sh custom -i inventory-lab-akyuz.yml -e @vars/lab-akyuz.yml --no-restart

    # Dell ME5 production cluster (stage only)
    setup.sh custom -i inventory-prod-dell-me5.yml -e @vars/prod-dell-me5.yml --no-restart

    # Apply AND restart services (opt-in, disruptive)
    setup.sh balanced --restart

    # Rollback
    setup.sh --rollback                       # Remove drop-in configs
    setup.sh --rollback 20260510T010146       # Restore from specific backup
    
    # Force mode (skip confirmations; stays safe = no restart unless --restart)
    setup.sh balanced --force

WORKFLOW:
    1. ./fix-ansible-deps.sh                       # Install Python deps
    2. ansible-playbook -i inventory.yml test-connection.yml
    3. ./setup.sh --check-only                     # Review current state
    4. ./setup.sh balanced                         # Stage config; answer "no"
                                                   #   to the restart prompt (safe)
    5. # Reboot each host from the OLVM web UI, one at a time:
       #   Compute > Hosts > <host> > Management > Maintenance -> Restart -> Activate
    6. ./verify-olvm-ha.sh --full                  # Verify
    7. # Test failover in a maintenance window

    (Answer "yes" to the prompt, or pass --restart, only if you accept that the
     playbook will restart sanlock/vdsmd live on each host.)

LOGS:
    All operations logged to: ${LOG_DIR}/

EXIT CODES:
    0   Success
    1   Configuration/prerequisites error
    2   Host execution failure
    130 Interrupted by user
EOF
}

# ============================================================
# Validation
# ============================================================
check_prerequisites() {
    print_header "Prerequisites Check"
    
    # Ansible
    if ! command -v ansible-playbook &>/dev/null; then
        log_error "Ansible not installed!"
        log_info  "Install: sudo dnf install ansible (or apt install ansible)"
        return 1
    fi
    
    local ansible_ver
    ansible_ver=$(ansible --version | head -n1)
    log_success "Ansible: ${ansible_ver}"
    
    # Check ansible-core version (informational)
    local core_version
    core_version=$(ansible --version | grep "core" | grep -oP '\d+\.\d+' | head -1 || true)
    if [ -n "${core_version}" ]; then
        log_info "Ansible Core: ${core_version}"
        log_info "Note: This playbook uses ONLY builtin modules (no collections needed)"
    fi
    
    # Required files
    local required_files=(
        "${INVENTORY}"
        "${PLAYBOOK}"
    )
    
    local f
    for f in "${required_files[@]}"; do
        if [ ! -f "${f}" ]; then
            log_error "Required file missing: ${f}"
            return 1
        fi
        if [ ! -r "${f}" ]; then
            log_error "Required file not readable: ${f}"
            return 1
        fi
    done
    log_success "All required files present and readable"
    
    # Profile file (only if not in rollback mode)
    if [ "${ROLLBACK_MODE}" != "true" ]; then
        local profile_file="${VARS_DIR}/${PROFILE}.yml"
        if [ ! -f "${profile_file}" ]; then
            log_error "Profile file not found: ${profile_file}"
            log_info  "Available profiles:"
            ls "${VARS_DIR}/"*.yml 2>/dev/null | xargs -n1 basename | sed 's/\.yml$//' | sed 's/^/  /' || true
            return 1
        fi
        if [ ! -r "${profile_file}" ]; then
            log_error "Profile file not readable: ${profile_file}"
            return 1
        fi
        log_success "Profile: ${PROFILE} (${profile_file})"
    fi
    
    # Rollback playbook
    if [ "${ROLLBACK_MODE}" = "true" ] && [ ! -f "${ROLLBACK_PLAYBOOK}" ]; then
        log_error "Rollback playbook not found: ${ROLLBACK_PLAYBOOK}"
        return 1
    fi
    
    return 0
}

# ============================================================
# Connectivity test
# ============================================================
test_connectivity() {
    if [ "${SKIP_TEST}" = "true" ]; then
        log_warning "Skipping connectivity test (--skip-test)"
        return 0
    fi
    
    print_header "Connectivity Test"
    
    log_info "Testing Ansible connection to all hosts..."
    
    if ansible -i "${INVENTORY}" all -m ping --one-line >> "${LOG_FILE}" 2>&1; then
        log_success "All hosts reachable"
        return 0
    else
        log_error "Some hosts unreachable"
        log_info  "Run: ansible -i ${INVENTORY} all -m ping"
        log_info  "Or:  ./fix-ansible-deps.sh"
        return 1
    fi
}

# ============================================================
# Version check
# ============================================================
check_olvm_version() {
    print_header "OLVM Environment Information"
    
    log_info "Querying VDSM version on hosts..."
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "rpm -q vdsm --queryformat 'VDSM: %{VERSION}-%{RELEASE}\n' 2>/dev/null || echo 'VDSM not found'" \
        --one-line 2>&1 | grep -E "VDSM|rc=" | tee -a "${LOG_FILE}" || true
    
    log_info "Querying OS version..."
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "cat /etc/oracle-release 2>/dev/null || cat /etc/redhat-release" \
        --one-line 2>&1 | tee -a "${LOG_FILE}" || true
}

# ============================================================
# Show current configuration
# ============================================================
show_current_config() {
    print_header "Current Configuration"
    
    log_info "VDSM drop-in config:"
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "cat /etc/vdsm/vdsm.conf.d/99-ha-tuning.conf 2>/dev/null || echo '  Not configured (using defaults)'" \
        2>&1 | grep -v "SUCCESS\|CHANGED\|^$" | tee -a "${LOG_FILE}" || true
    
    echo ""
    log_info "Multipath drop-in config:"
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "cat /etc/multipath/conf.d/99-ha-tuning.conf 2>/dev/null || echo '  Not configured (using defaults)'" \
        2>&1 | grep -v "SUCCESS\|CHANGED\|^$" | tee -a "${LOG_FILE}" || true
    
    echo ""
    log_info "HA Agent config:"
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "grep -E 'monitoring_interval|connection_timeout' /etc/ovirt-hosted-engine-ha/agent.conf 2>/dev/null || echo '  Default'" \
        2>&1 | grep -v "SUCCESS\|CHANGED\|^$" | tee -a "${LOG_FILE}" || true
}

# ============================================================
# Parse YAML scalar value (handles inline comments and whitespace)
# ============================================================
# Reads `key: value  # optional comment` lines and returns just the value
# Args: $1 = file path, $2 = key name
parse_yaml_value() {
    local file="$1"
    local key="$2"
    
    if [ ! -f "${file}" ]; then
        echo ""
        return 1
    fi
    
    # Match: key: VALUE (capture before any '#' comment, trim whitespace)
    awk -v key="^${key}:" '
        $0 ~ key {
            # Remove key and colon
            sub(key, "")
            # Remove inline comment
            sub(/#.*$/, "")
            # Trim leading/trailing whitespace
            gsub(/^[ \t]+|[ \t]+$/, "")
            print
            exit
        }
    ' "${file}"
}

# ============================================================
# Resolve whether to restart services (SAFE DEFAULT = do NOT restart)
#
# Rules:
#   - Default and recommended: DO NOT restart (stage only).
#   - --no-restart            : stage only, no prompt.
#   - --force (no --restart)  : stage only (safe non-interactive default).
#   - --force --restart       : restart, no prompt (explicit double opt-in).
#   - Otherwise (interactive) : ask TWICE; restart only if BOTH are accepted.
# ============================================================
ask_yes() {
    # $1 = prompt; returns 0 if the answer is an affirmative yes
    local ans=""
    read -r -p "$1" ans
    case "${ans}" in
        y|Y|yes|YES|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

resolve_restart_decision() {
    # Explicit stage-only wins.
    if [ "${FORCE_NO_RESTART}" = "true" ]; then
        NO_RESTART=true
        log_info "Service restart: DISABLED (--no-restart). Config will be staged only."
        return 0
    fi

    # Non-interactive, explicit double opt-in: --force --restart -> restart, no prompt.
    if [ "${FORCE}" = "true" ] && [ "${FORCE_RESTART}" = "true" ]; then
        NO_RESTART=false
        log_warning "Service restart: ENABLED (--force --restart, no prompt)."
        return 0
    fi

    # Non-interactive without an explicit restart request -> SAFE default.
    if [ "${FORCE}" = "true" ]; then
        NO_RESTART=true
        log_info "Service restart: DISABLED (safe default for --force runs)."
        log_info "  Use '--force --restart' if you really want a non-interactive live restart."
        return 0
    fi

    # ---------------- Interactive: TWO warnings, both must be accepted ----------------
    # WARNING 1 of 2
    print_header "Service Restart Decision - WARNING 1 of 2"
    log_warning "Restarting sanlock/vdsmd/libvirtd on a LIVE host - and ovirt-engine -"
    log_warning "is slow and risky: it can disrupt storage leases and the SPM role, and"
    log_warning "the engine may mark a host Non-Responsive (worst case: it is fenced)."
    echo ""
    log_info "RECOMMENDED (safe): stage the config now WITHOUT restarting, then reboot"
    log_info "each host one at a time from the OLVM web UI (drains VMs first):"
    echo "    Compute > Hosts > <host> > Management > Maintenance -> Restart -> Activate" | tee -a "${LOG_FILE}"
    echo ""
    if [ "${FORCE_RESTART}" = "true" ]; then
        log_warning "(--restart was passed; you must still confirm twice.)"
    fi
    if ! ask_yes "[1/2] Restart services now on all hosts? (yes/no) [no]: "; then
        NO_RESTART=true
        log_success "Safe path chosen: config will be STAGED; services left running."
        return 0
    fi

    # WARNING 2 of 2 (final, stronger)
    echo ""
    print_header "Service Restart Decision - WARNING 2 of 2 (FINAL)"
    log_warning "FINAL CONFIRMATION. If you proceed, this run WILL:"
    log_warning "  - restart sanlock / vdsmd / libvirtd on EVERY host in inventory, and"
    log_warning "  - restart ovirt-engine (if engine-config values changed)."
    log_warning "Running VMs may pause and a host can be fenced if it does not recover"
    log_warning "in time. This is NOT recommended on a production cluster during hours."
    echo ""
    if ! ask_yes "[2/2] Type 'yes' again to CONFIRM the restart: "; then
        NO_RESTART=true
        log_success "Second confirmation declined -> config will be STAGED (safe)."
        return 0
    fi

    NO_RESTART=false
    log_warning "Both confirmations received - services WILL be restarted this run."
    return 0
}

# ============================================================
# Apply configuration
# ============================================================
apply_configuration() {
    local profile="$1"
    local vars_file="${VARS_DIR}/${profile}.yml"
    
    print_header "Applying Profile: ${profile}"
    
    # Show profile summary
    echo -e "${MAGENTA}Profile values:${NC}"
    grep -E "^[a-z_]+:" "${vars_file}" | head -15 | sed 's/^/  /' | tee -a "${LOG_FILE}"
    echo ""
    
    # Estimate failover time using INTEGER arithmetic (matches verify-olvm-ha.sh)
    # Use parse_yaml_value to safely strip inline comments
    local sanlock ha_mon
    sanlock=$(parse_yaml_value "${vars_file}" "sanlock_io_timeout")
    ha_mon=$(parse_yaml_value "${vars_file}" "ha_monitoring_interval")
    
    local estimated
    estimated=$(calculate_failover_integer "${sanlock}" "${ha_mon}")
    
    if [ -n "${estimated}" ]; then
        echo -e "${MAGENTA}Estimated Failover Time: ~${estimated}s${NC}" | tee -a "${LOG_FILE}"
    else
        log_warning "Cannot estimate failover time (invalid profile values: sanlock='${sanlock}', ha_mon='${ha_mon}')"
    fi
    echo ""
    
    # Dry-run
    log_info "Running dry-run validation..."
    # One timestamp for ALL hosts so a single --rollback DATE restores everyone.
    local backup_stamp
    backup_stamp="$(date +%Y%m%dT%H%M%S)"
    local ansible_args=("-i" "${INVENTORY}" "${PLAYBOOK}" "-e" "@${vars_file}"
                        "-e" "backup_stamp=${backup_stamp}"
                        "-e" "report_profile=${profile}")
    if [ "${NO_RESTART}" = "true" ]; then
        ansible_args+=("-e" "restart_enabled=false")
        log_info "restart_enabled=false : services will be STAGED, not restarted."
    else
        ansible_args+=("-e" "restart_enabled=true")
        log_warning "restart_enabled=true : services WILL be restarted on each host."
    fi
    if [ "${VERBOSE}" = "true" ]; then
        ansible_args+=("-vv")
    fi
    # User-supplied -e / --extra-vars (forwarded last so they take precedence)
    if [ "${#EXTRA_VARS[@]}" -gt 0 ]; then
        ansible_args+=("${EXTRA_VARS[@]}")
        log_info "Extra vars forwarded to ansible: ${EXTRA_VARS[*]}"
    fi
    log_info "Backup timestamp for this run: ${backup_stamp}"
    log_info "  (rollback with: ${0} --rollback ${backup_stamp})"
    
    if ! ansible-playbook "${ansible_args[@]}" --check 2>&1 | tee -a "${LOG_FILE}" | tail -20; then
        log_error "Dry-run failed - check log: ${LOG_FILE}"
        return 1
    fi
    log_success "Dry-run completed successfully"
    
    # Confirmation
    if [ "${FORCE}" != "true" ]; then
        echo ""
        log_warning "This will modify configuration files on ALL hosts!"
        log_warning "Backup will be created automatically"
        if [ "${NO_RESTART}" != "true" ]; then
            echo ""
            log_warning "Service restart is ENABLED for this run (your choice)."
            log_warning "  Restarting sanlock/vdsmd on a LIVE host can take several"
            log_warning "  minutes and may briefly disrupt storage leases / SPM."
        else
            echo ""
            log_info "Service restart is DISABLED: config will be staged only (safe)."
        fi
        echo ""
        read -r -p "Continue with apply? (yes/no): " confirm
        if [ "${confirm}" != "yes" ]; then
            log_warning "Operation cancelled by user"
            exit 0
        fi
    fi
    
    # Apply
    log_info "Applying configuration..."
    if ansible-playbook "${ansible_args[@]}" 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "Configuration applied"
        return 0
    else
        log_error "Configuration failed - check log: ${LOG_FILE}"
        return 1
    fi
}

# ============================================================
# Restart services
# ============================================================
restart_services() {
    if [ "${NO_RESTART}" = "true" ]; then
        print_header "Service Restart - SKIPPED (config staged only)"
        log_warning "Services were NOT restarted; the new settings are NOT active yet."
        log_info  "Recommended: apply the staged config by rebooting each host"
        log_info  "from the OLVM web UI, ONE HOST AT A TIME (drains VMs first):"
        echo "    Compute > Hosts > <host> > Management > Maintenance" | tee -a "${LOG_FILE}"
        echo "    Compute > Hosts > <host> > Management > Restart (reboot the host)" | tee -a "${LOG_FILE}"
        echo "    Compute > Hosts > <host> > Management > Activate" | tee -a "${LOG_FILE}"
        echo "" | tee -a "${LOG_FILE}"
        log_info  "Verify after each host is back:"
        log_info  "  ./verify-olvm-ha.sh --host <host> --full"
        return 0
    fi

    print_header "Service Restart (performed by the playbook handlers)"

    log_warning "The playbook already restarted sanlock/vdsmd/libvirtd on each host."
    log_warning "On a live host this can take several minutes; the engine may show"
    log_warning "the host as Non-Responsive briefly until VDSM re-registers."
    log_info  "If a host does not recover on its own, reboot it cleanly via the"
    log_info  "OLVM web UI (Maintenance -> Restart -> Activate)."

    # Give services time to fully initialize, then report status.
    log_info "Waiting for services to settle..."
    sleep 10
    
    # Check service status
    log_info "Checking service status..."
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "systemctl is-active vdsmd sanlock libvirtd ovirt-ha-agent ovirt-ha-broker 2>&1 || true" \
        2>&1 | grep -v "SUCCESS\|CHANGED" | tee -a "${LOG_FILE}" || true
    
    log_success "Service restart phase complete"
}

# ============================================================
# Verification
# ============================================================
verify_deployment() {
    print_header "Post-Deployment Verification"
    
    log_info "Checking applied configuration..."
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "test -f /etc/vdsm/vdsm.conf.d/99-ha-tuning.conf && echo 'VDSM tuning: OK' || echo 'VDSM tuning: MISSING'" \
        --one-line 2>&1 | grep -v "SUCCESS\|CHANGED\|^$" | tee -a "${LOG_FILE}" || true
    
    log_info "Checking multipath validation..."
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "multipath -t > /dev/null 2>&1 && echo 'Multipath: OK' || echo 'Multipath: WARNINGS (run multipath -t)'" \
        --one-line 2>&1 | grep -v "SUCCESS\|CHANGED\|^$" | tee -a "${LOG_FILE}" || true
    
    log_info "Checking VDSM validation..."
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "vdsm-tool validate-config 2>&1 | head -5" \
        2>&1 | grep -v "SUCCESS\|CHANGED" | tee -a "${LOG_FILE}" || true
    
    log_info "Checking HA status..."
    ansible -i "${INVENTORY}" ovirt_hosts \
        -m raw \
        -a "hosted-engine --vm-status 2>/dev/null | grep -E 'Engine status|Score' | head -10 || echo 'Not a hosted-engine host'" \
        2>&1 | grep -v "SUCCESS\|CHANGED" | tee -a "${LOG_FILE}" || true
}

# ============================================================
# Rollback
# ============================================================
do_rollback() {
    print_header "Rollback Mode"
    
    # Validate rollback date format if provided
    if [ -n "${ROLLBACK_DATE}" ] && [ "${ROLLBACK_DATE}" != "latest" ]; then
        if ! [[ "${ROLLBACK_DATE}" =~ ${ROLLBACK_DATE_PATTERN} ]]; then
            log_error "Invalid rollback date format: '${ROLLBACK_DATE}'"
            log_info  "Expected format: YYYYMMDDTHHMMSS (e.g., 20260510T010146)"
            log_info  "Or use 'latest' to remove drop-in configs"
            return 1
        fi
        log_info "Restoring from backup: ${ROLLBACK_DATE}"
    else
        log_info "Removing drop-in configs (revert to defaults)"
    fi
    
    if [ "${FORCE}" != "true" ]; then
        log_warning "This will rollback HA tuning on all hosts!"
        read -r -p "Continue? (yes/no): " confirm
        if [ "${confirm}" != "yes" ]; then
            log_warning "Rollback cancelled"
            exit 0
        fi
    fi
    
    local rollback_args=("-i" "${INVENTORY}" "${ROLLBACK_PLAYBOOK}")
    if [ -n "${ROLLBACK_DATE}" ] && [ "${ROLLBACK_DATE}" != "latest" ]; then
        rollback_args+=("-e" "rollback_date=${ROLLBACK_DATE}")
    fi
    
    if ansible-playbook "${rollback_args[@]}" 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "Rollback completed"
        return 0
    else
        log_error "Rollback failed"
        return 1
    fi
}

# ============================================================
# Inventory resolution (for -i / --inventory)
# ============================================================
# Resolve a user-supplied inventory path to an existing, readable file.
# Tries the path as given (relative to CWD or absolute), then relative to the
# script directory. Stores the absolute path in the global INVENTORY.
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
            --check-only)
                CHECK_ONLY=true
                shift
                ;;
            --check-syntax)
                CHECK_SYNTAX=true
                shift
                ;;
            --no-restart)
                FORCE_NO_RESTART=true
                NO_RESTART=true
                shift
                ;;
            --restart)
                FORCE_RESTART=true
                shift
                ;;
            -i|--inventory)
                if [ $# -lt 2 ]; then
                    log_error "$1 requires a file argument (e.g. -i inventory-lab-akyuz.yml)"
                    exit 1
                fi
                resolve_inventory "$2"
                shift 2
                ;;
            --inventory=*)
                resolve_inventory "${1#--inventory=}"
                shift
                ;;
            -i*)
                # joined form: -iinventory-lab-akyuz.yml
                resolve_inventory "${1#-i}"
                shift
                ;;
            -e|--extra-vars)
                if [ $# -lt 2 ]; then
                    log_error "$1 requires an argument (e.g. -e key=value)"
                    exit 1
                fi
                EXTRA_VARS+=("-e" "$2")
                shift 2
                ;;
            -e*)
                # allow joined form: -ekey=value
                EXTRA_VARS+=("-e" "${1#-e}")
                shift
                ;;
            --extra-vars=*)
                EXTRA_VARS+=("-e" "${1#--extra-vars=}")
                shift
                ;;
            --skip-test)
                SKIP_TEST=true
                shift
                ;;
            --version-check)
                VERSION_CHECK_ONLY=true
                shift
                ;;
            --rollback)
                ROLLBACK_MODE=true
                shift
                if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
                    ROLLBACK_DATE="$1"
                    shift
                fi
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            balanced|aggressive|conservative|custom)
                PROFILE="$1"
                shift
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
    
    print_header "OLVM HA Tuning - Enterprise Setup v${SCRIPT_VERSION}"
    log_info "Log file:  ${LOG_FILE}"
    log_info "Inventory: ${INVENTORY}$([ "${INVENTORY}" = "${DEFAULT_INVENTORY}" ] && echo ' (default)' || echo ' (-i)')"
    log_info "Mode: $(
        if [ "${ROLLBACK_MODE}" = "true" ]; then echo "ROLLBACK"
        elif [ "${CHECK_SYNTAX}" = "true" ]; then echo "SYNTAX CHECK"
        elif [ "${CHECK_ONLY}" = "true" ]; then echo "CHECK ONLY"
        elif [ "${VERSION_CHECK_ONLY}" = "true" ]; then echo "VERSION CHECK"
        else echo "APPLY (${PROFILE})"
        fi)"
    
    # Prerequisites
    if ! check_prerequisites; then
        exit 1
    fi
    
    # Syntax check only - no connectivity needed
    if [ "${CHECK_SYNTAX}" = "true" ]; then
        print_header "Ansible Syntax Check"
        local ok=0
        for pb in "${PLAYBOOK}" "${ROLLBACK_PLAYBOOK}" "${TEST_PLAYBOOK}" \
                  "${SCRIPT_DIR}/verify-olvm-ha.yml"; do
            if [ -f "${pb}" ]; then
                log_info "Checking: $(basename "${pb}")"
                if ansible-playbook --syntax-check -i "${INVENTORY}" "${pb}" 2>&1 | tee -a "${LOG_FILE}"; then
                    log_success "$(basename "${pb}"): syntax OK"
                else
                    log_error "$(basename "${pb}"): syntax FAILED"
                    ok=1
                fi
            else
                log_warning "Skipping (not found): ${pb}"
            fi
        done
        exit ${ok}
    fi
    
    # Connectivity
    if ! test_connectivity; then
        exit 1
    fi
    
    # Version check only
    if [ "${VERSION_CHECK_ONLY}" = "true" ]; then
        check_olvm_version
        exit 0
    fi
    
    # Rollback mode
    if [ "${ROLLBACK_MODE}" = "true" ]; then
        do_rollback
        exit $?
    fi
    
    # Show environment
    check_olvm_version
    show_current_config
    
    # Check only mode
    if [ "${CHECK_ONLY}" = "true" ]; then
        log_info "Check-only mode complete. Exiting."
        exit 0
    fi

    # Decide restart behavior (safe default = stage only; asks interactively)
    resolve_restart_decision

    # Apply
    if ! apply_configuration "${PROFILE}"; then
        log_error "Apply failed - check log: ${LOG_FILE}"
        log_info  "To rollback: ${0} --rollback"
        exit 1
    fi
    
    # Restart
    restart_services
    
    # Verify
    verify_deployment
    
    # Summary
    print_header "Setup Complete"
    log_success "Profile applied: ${PROFILE}"
    log_info    "Log file: ${LOG_FILE}"
    echo ""
    log_info "Next steps (from this control node):"
    echo "  1. Review log: ${LOG_FILE}"
    echo "  2. Open the run report: ${SCRIPT_DIR}/reports/olvm-ha-report-<stamp>.html"
    echo "  3. Run: ./verify-olvm-ha.sh --quick"
    echo "  4. Run: ./verify-olvm-ha.sh --full"
    echo "  5. Test failover in maintenance window"
    echo "  6. Monitor on hosts:"
    echo "       ansible -i inventory.yml ovirt_hosts -m shell \\"
    echo "         -a 'journalctl -u vdsmd -u ovirt-ha-agent -n 50 --no-pager'"
    echo ""
    log_info "To rollback if needed:"
    echo "  ${0} --rollback"
    echo ""
}

main "$@"
