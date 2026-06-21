# OLVM HA Timeout Tuning - Enterprise Edition

> Production-ready Ansible automation to optimize HA failover times for Oracle
> Linux Virtualization Manager.


![image](https://img.shields.io/badge/version-4.22-blue.svg)
 

![image](https://img.shields.io/badge/OLVM-4.5.5-green.svg)
 

![image](https://img.shields.io/badge/VDSM-4.50.5.1-green.svg)
 

![image](https://img.shields.io/badge/OS-Oracle Linux 8.10-red.svg)


## 🎯 Purpose

Reduce HA failover time on OLVM hosts from default **3-5 minutes** down to **
~90-100 seconds** safely.

## ✅ Tested Environment


|Component|Version|
|-|-|
|**OLVM**|4.5.5-1.67.el8|
|**VDSM**|4.50.5.1-8.el8|
|**Operating System**|Oracle Linux 8.10|
|**Kernel**|5.15.0-uek (UEK7)|
|**KVM**|7.2.0|
|**Libvirt**|9.0.0|
|**Sanlock**|(auto-detected)|
|**Multipath**|device-mapper-multipath|
|**Ansible**|Core 2.16+|
|**Python**|3.6+ / 3.12|

## 🎯 Zero-Dependency Design

**This playbook uses ONLY ansible-core builtin modules:**

- `file`, `copy`, `lineinfile`, `template`
- `systemd`, `command`, `shell`
- `stat`, `set_fact`, `assert`, `debug`

**NO external collections required** (no `community.general`, etc.)

This makes it compatible with:

- ✅ Minimal `ansible-core` installations
- ✅ Air-gapped/offline environments
- ✅ Older Ansible versions (2.9+)
- ✅ Enterprise hardened systems

## 📁 File Structure

All files live on the **CONTROL NODE** (your Ansible management host). Nothing is
copied to OLVM hosts — Ansible drives everything via SSH.

```
~/olvm-ha-tuning/                ← runs on CONTROL NODE only
├── inventory.yml                # Host inventory
├── olvm-ha-tuning.yml           # Main playbook (apply config)
├── olvm-ha-rollback.yml         # Rollback playbook
├── verify-olvm-ha.yml           # Verification playbook (v4.6+)
├── test-connection.yml          # Pre-flight validation
├── fix-ansible-deps.sh          # Install Python deps on hosts via Ansible
├── setup.sh                     # Wrapper for apply/rollback
├── verify-olvm-ha.sh            # Wrapper for verification (v4.6+: Ansible-driven)
├── README.md                    # This file
├── vars/
│   ├── balanced.yml             # ⭐ RECOMMENDED (~130s heuristic)
│   ├── aggressive.yml           # ⚠️ Risky (~115s heuristic)
│   ├── conservative.yml         # 🛡️ Safe (~160s heuristic)
│   └── custom.yml               # Custom template
└── logs/                        # Auto-generated logs
    ├── setup-*.log
    └── verify-*.log
```
## 🏗️ Architecture

```
┌────────────────────────────┐         ┌───────────────────────┐
│    CONTROL NODE            │  SSH    │    OLVM HOSTS         │
│    (your management VM)    │ ──────► │    (smvigia01, ...)   │
│                            │         │                       │
│  ./setup.sh balanced       │         │  /etc/vdsm/...        │
│  ./verify-olvm-ha.sh -q    │         │  /etc/multipath/...   │
│  ./fix-ansible-deps.sh     │         │  /etc/ovirt-...       │
│                            │         │                       │
│  inventory.yml ────────────┼──────►  │  reads & modifies     │
│  *.yml playbooks           │         │  via Ansible modules  │
└────────────────────────────┘         └───────────────────────┘
```
You **never log into OLVM hosts** to run these scripts. Everything is driven from
the control node through Ansible.

## 🚨 Critical Information

### What's Different in v4.8

Full engine HA coverage — reconciled against actual OLVM 4.5.5-1.67.el8 
`engine-config -l` output:

1.  **Engine tunable parameters: 9 → 17** ✅ (v4.8)
  - Added 8 new parameters, all confirmed available in your OLVM version:
    - `VdsRefreshRate` (2s) — Host status poll interval
    - `VdsRecoveryTimeoutInMinutes` (3 min) — Host recovery timeout
    - `NetworkConnectivityCheckTimeoutInSeconds` (120s) — Network rollback
    - `HostPreparingForMaintenanceIdleTime` (300s) — Maintenance idle retry
    - `MaxStorageVdsDelayCheckSec` (5s) — Storage check max delay
    - `MaxStorageVdsTimeoutCheckSec` (30s) — Storage check timeout
    - `NumberOfFailedRunsOnVds` (3) — VM rerun fail count
    - `MaxRerunVmOnVdsCount` (3) — VM max rerun attempts
2.  **New: `engine_verify_only` (10 informational params)** ✅ (v4.8)
  - These are SHOWN in `\--quick` / `\--full` / `\--engine` reports for operator
    awareness, but **never modified**:
    - `vdsTimeout` (default 180s — DO NOT change per oVirt HA guidance)
    - `vdsRetries` (default 0 — keeps fencing predictable)
    - `EnableAutomaticHostPowerManagement` (needs PM agent infra)
    - `PMHealthCheckEnabled` (boolean, default fine)
    - `FenceKdumpListenerTimeout`, `FenceKdumpMessageInterval` (must be tuned in
      lockstep with fence_kdump listener config)
    - `FenceStartStatusRetries`, `FenceStopStatusRetries` (fence-agent-specific
      behavior)
    - `AsyncTaskPollingRate`, `StorageDomainFailureTimeoutInMinutes`
3.  **Two-tier engine report** ✅ (v4.8)
  - `\[Tunable HA Parameters]` — what we actively manage
  - `\[Informational - NOT tuned]` — visible for awareness
  - Clear notes block explaining why certain params are left alone

### What's Different in v4.7

This release expands tuning coverage to the **OLVM Engine** (manager) and adds
engine-side verification:

1.  **Engine HA parameters: 3 → 9** ✅ (v4.8)
  - Previous versions only tuned 3 engine parameters (`ServerRebootTimeout`, `
    StoragePoolRefreshTimeInSeconds`, `TimeoutToResetVdsInSeconds`).
  - v4.7 adds 6 more, all guarded by dynamic `engine-config -l` validation —
    parameters not present in your OLVM version are silently skipped:
    - `vdsConnectionTimeout` (default 20s → 5s) — engine-to-VDSM connect timeout
    - `VDSAttemptsToResetCount` — retry count before reset
    - `SpmCommandFailOverRetries` — SPM command failover retries
    - `SPMFailOverAttempts` — SPM connection failover attempts
    - `FenceQuietTimeBetweenOperationsInSec` — power-mgmt operation spacing
    - `PMHealthCheckIntervalInSec` — power-mgmt health check interval
  - References: 
    [oVirt HA Timeouts](https://www.ovirt.org/develop/sla/ha-timeouts.html), 
    [oVirt engine-config properties](https://github.com/oVirt/ovirt-engine/blob/master/packaging/etc/engine-config/engine-config.properties)
2.  **Engine verification added** ✅ (v4.8)
  - New `\--engine` tag in `verify-olvm-ha.sh` queries the engine via `
    inventory.yml` and reports current value for each tuning parameter.
  - The standard `\--quick` / `\--full` reports now include an Engine
    Verification section after the host reports.
  - The aggregate summary at the end lists engine tuning status.
3.  **What's intentionally NOT tuned on the engine**
  - `vdsTimeout` (default 180s): VDSM operations legitimately need this long
  - `vdsRetries` (default 0 in 3.3+): keeping at 0 makes fencing predictable

### What's Different in v4.6

This release introduces a **major architectural correction** plus enterprise
hardening:

0.  **Architecture: control-node-only execution** ✅ (v4.6) **IMPORTANT**
  - **Misuse seen in v4.5**: Some users ran `verify-olvm-ha.sh` directly on OLVM
    hosts. It would report "VDSM: Not installed" because the script was
    checking the control node itself, not the hosts.
  - **Fix**: `verify-olvm-ha.sh` is now a thin Ansible wrapper that invokes the
    new `verify-olvm-ha.yml` playbook. All host data is gathered remotely via
    Ansible. You never log into OLVM hosts.
  - **Result**: Same `./verify-olvm-ha.sh --quick` command, but now accurately
    reports the state of every host in `inventory.yml`.
1.  **New: `verify-olvm-ha.yml` playbook**
  - Pure Ansible verification (no host-side bash dependency)
  - Per-host detailed reports + aggregate summary on control node
  - Integer-safe failover math in Jinja2 (no more `bc` float issues)
  - Granular tags: `quick`, `full`, `vdsm`, `sanlock`, `multipath`, `ha`, `
    libvirt`, `storage`, `failover`, `logs`
2.  **Wrapper improvements**
  - `\--host \<name>` to verify a single host (Ansible `\--limit` passthrough)
  - `\--tags \<list>` to run any custom tag combination
  - `\--check-syntax` in `setup.sh` for offline YAML validation
  - Consistent exit codes (0=ok, 1=config, 2=host issues, 130=intr)
  - SIGINT/SIGTERM traps for graceful logging
3.  **Playbook hardening**
  - `lineinfile` section anchors tightened: `^\\\[agent\\]$` (was `^\\\[agent\\]`
    ) prevents accidental match against `\[agent_x]` or similar.
  - File readability checks throughout (not just existence)

### What's Different in v4.5

1.  **CRITICAL FIX**: Integer-comparison error in `verify-olvm-ha.sh`
  - **Problem**: `bc` produced `115.0` (float) for `\* 1.5` multiplications even
    with `scale=0`, breaking bash `[ "$x" -lt 90 ]` comparisons:

```
./verify-olvm-ha.sh: line 515: [: 115.0: integer expression expected
**Fix**: Replaced all bc math with pure integer arithmetic: sanlock * 1.5 → (sanlock * 3 / 2) (truncating integer division)
**Result**: Same calculation, integer output, no bc runtime dependency.
```
2.  **Enterprise hardening** (v4.5)
  - Unified version stamp across all files (single source of truth)
  - `\--logs \[MINUTES]` parameter for custom log lookback
  - Robust YAML profile parsing (handles inline comments correctly)
  - Rollback date format validation (strict `YYYYMMDDTHHMMSS` regex)
  - Division-by-zero guard in multipath sync check
  - Calculation breakdown shown to operators for transparency
  - `\--check` flag in `fix-ansible-deps.sh` for non-destructive validation

### What's Different in v4.4

1.  **Verify script unbound variable error FIXED** ✅ (v4.4)
  - **Problem**: `./verify-olvm-ha.sh: line X: \<var>: unbound variable` in
    multipath sync check
  - **Fix**: Removed `set -u`, added explicit defaults via `${var:-}` syntax
  - **Result**: No crashes when config values are missing

### What's Different in v4.2

This version fixes critical bugs from previous versions:

1.  **Engine config errors fixed** ✅ (v4.2)
  - **Problem**: `HostMonitoringIntervalInSeconds` and `vdsHeartbeatInSeconds`
    don't exist in OLVM 4.5.5
  - **Error you saw**: `Cannot invoke "JsonNode.get(String)" because "node" is
    null`
  - **Fix**: Dynamic parameter validation - playbook checks `engine-config -l`
    first
  - **Result**: Only applies parameters that exist in your OLVM version
2.  **External collection dependency removed** ✅ (v4.1)
  - **Problem**: `ini_file` module requires `community.general` collection
  - **Error you saw**: `couldn't resolve module/action 'ini_file'`
  - **Fix**: Replaced with `copy` (templates) and `lineinfile` (builtin)
  - **Result**: Zero external dependencies
3.  **Multipath `polling_interval` placement** ✅ (v4.0)
  - **Problem**: Was placed in `overrides` section (invalid)
  - **Fix**: Moved to `defaults` section (correct per RHEL docs)
  - **Error you saw**: `invalid keyword in the overrides section:
    polling_interval`
4.  **Sanlock configuration** ✅
  - **Problem**: VDSM 4.5.5 default `io_timeout=10s` is too aggressive
  - **Fix**: Use 50s in balanced profile
5.  **Service restart order** ✅
  - **Problem**: Could leave system in bad state
  - **Fix**: `serial: 1` processes hosts one at a time
6.  **Validation** ✅
  - Pre-flight checks before any changes
  - Config validation (`vdsm-tool validate-config`, `multipath -t`)
  - Service health checks
7.  **Rollback support** ✅
  - Dedicated rollback playbook
  - Backup includes metadata

## 🚀 Quick Start

### Step 1: Prerequisites

On the **control node** (where you run Ansible):

```bash
# Install Ansible (if not present)
sudo dnf install ansible           # RHEL/Oracle Linux
sudo apt install ansible           # Debian/Ubuntu
# Verify
ansible --version
```
### Step 2: Setup Files

```bash
# Create directory
mkdir -p ~/olvm-ha-tuning/vars
cd ~/olvm-ha-tuning
# Copy all files from artifacts to their locations:
#   inventory.yml             -> ./
#   olvm-ha-tuning.yml        -> ./
#   olvm-ha-rollback.yml      -> ./
#   test-connection.yml       -> ./
#   *.sh                      -> ./
#   vars/*.yml                -> ./vars/
# Make scripts executable
chmod +x *.sh
```
### Step 3: Configure Inventory

Edit `inventory.yml` and update IP addresses:

```yaml
ovirt_hosts:
  hosts:
    your-hostname-01:
      ansible_host: 192.168.1.111  # ← UPDATE THIS
    your-hostname-02:
      ansible_host: 192.168.1.112  # ← UPDATE THIS
```
### Step 4: Setup SSH Access

```bash
# Generate SSH key if you don't have one
ssh-keygen -t rsa -b 4096
# Copy to all hosts
ssh-copy-id root@192.168.1.111
ssh-copy-id root@192.168.1.112
# Test
ssh root@192.168.1.111 'hostname'
```
### Step 5: Install Dependencies

```bash
./fix-ansible-deps.sh
```
This installs `python3-rpm`, `python3-dnf`, `python3-libselinux` on all hosts.

### Step 6: Validate Environment

```bash
ansible-playbook -i inventory.yml test-connection.yml
```
You should see:

- ✓ All packages installed
- ✓ Services running
- ✓ Python modules available

### Step 7: Apply Configuration

```bash
# RECOMMENDED: Balanced profile
./setup.sh balanced
```
The script will:

1.  Test connectivity
2.  Show current configuration
3.  Run dry-run validation
4.  Ask for confirmation
5.  Apply configuration (one host at a time)
6.  Restart services automatically (via handlers)
7.  Verify deployment

### Step 8: Verify (From Control Node)

In v4.6+, verification runs entirely from the control node via Ansible. No need
to SCP scripts to hosts.

```bash
# Quick status across all hosts
./verify-olvm-ha.sh --quick
# Full detailed report
./verify-olvm-ha.sh --full
# Single host
./verify-olvm-ha.sh --host smvigia01
# Component-specific
./verify-olvm-ha.sh --vdsm
./verify-olvm-ha.sh --multipath
./verify-olvm-ha.sh --failover
# Recent logs from all hosts (last 60 minutes)
./verify-olvm-ha.sh --logs 60
```
Expected --quick output per host:

```
====================================================
Quick Status: smvigia01 (192.168.1.111)
====================================================
OLVM:
  OS:            Oracle Linux Server release 8.10
  VDSM:          4.50.5.1-8.el8
  HE-HA:         2.5.1

Services:
  vdsmd:           active
  sanlock:         active
  ...

Tuning Status:
  Custom tuning APPLIED
  VDSM heartbeat_interval: 10s
  Sanlock io_timeout:      50s
  HA monitoring_interval:  10s
  Estimated failover:      ~130s (CONSERVATIVE)
====================================================
```
## 📊 Profile Comparison


|Profile|Failover|Sanlock|Risk|Best For|
|-|-|-|-|-|
|**Aggressive**|~115s|40s|High|Test environments|
|**Balanced** ⭐|~130s|50s|Medium|**Production (default)**|
|**Conservative**|~160s|60s|Low|Slow storage|
|**Custom**|Variable|Variable|Variable|Special needs|

## 🛠️ Common Commands

### Targeting a Specific Inventory

By default the wrappers use `inventory.yml`. Use `-i` / `--inventory` to point
them at one of the shipped environment inventories (or your own):

```bash
# Lab cluster (LIO-ORG iSCSI) - stage only
./setup.sh custom -i inventory-lab-akyuz.yml -e @vars/lab-akyuz.yml --no-restart

# Dell ME5 production cluster - stage only
./setup.sh custom -i inventory-prod-dell-me5.yml -e @vars/prod-dell-me5.yml --no-restart

# Verify / install deps against a specific inventory
./verify-olvm-ha.sh -i inventory-lab-akyuz.yml --quick
./fix-ansible-deps.sh -i inventory-lab-akyuz.yml --check
```

The path is resolved relative to the current directory first, then to the
script directory. `-i` works in apply, rollback, `--check-only` and
`--check-syntax` modes.

### Apply Configuration

```bash
# Balanced (recommended)
./setup.sh balanced
# Aggressive (risky)
./setup.sh aggressive
# Conservative (safe)
./setup.sh conservative
# Custom (edit vars/custom.yml first)
./setup.sh custom
```
### Check Without Applying

```bash
# Show current configuration
./setup.sh --check-only
# Just check OLVM versions
./setup.sh --version-check
# Apply without restarting services
./setup.sh balanced --no-restart
```
### Verification

All verification runs FROM the control node (v4.6+):

```bash
# Full check across all hosts AND engine
./verify-olvm-ha.sh --full
# Quick status all hosts + engine
./verify-olvm-ha.sh --quick
# Single host
./verify-olvm-ha.sh --host smvigia01
# Component-specific
./verify-olvm-ha.sh --vdsm
./verify-olvm-ha.sh --sanlock
./verify-olvm-ha.sh --multipath
./verify-olvm-ha.sh --ha
./verify-olvm-ha.sh --engine       # NEW in v4.7: engine HA params
./verify-olvm-ha.sh --failover
# Recent logs from all hosts (custom lookback)
./verify-olvm-ha.sh --logs 60
# Custom Ansible tag combination
./verify-olvm-ha.sh --tags vdsm,multipath,engine
```
### Rollback

```bash
# Remove tuning (revert to OLVM defaults)
./setup.sh --rollback
# Restore from specific backup
./setup.sh --rollback 20260510T010146
# List available backups (on host)
ssh root@host01 'ls -la /root/olvm-ha-backup-*'
```
## 🧪 Failover Testing

⚠️ **ONLY DO THIS IN MAINTENANCE WINDOW**

### Preparation

```bash
# 1. Apply tuning
./setup.sh balanced
# 2. Migrate VMs to one host (Engine UI)
#    Or use CLI:
ssh root@host02
hosted-engine --vm-shutdown --vm-name=test-vm
# 3. Get baseline
./verify-olvm-ha.sh --quick > baseline.log
```
### Test 1: Graceful Shutdown

```bash
# From control node
ssh root@host01 'shutdown -h now'
# Watch from host02
ssh root@host02
watch -n 2 'hosted-engine --vm-status | head -30'
# Note time when Engine becomes available on host02
# Expected: 30-60 seconds
```
### Test 2: Hard Power-Off (Real Failover)

```bash
# Note start time
date
# Force kernel panic on host01 (simulates power loss)
ssh root@host01 'echo b > /proc/sysrq-trigger'
# OR physically pull power cable
# Watch from host02
ssh root@host02
watch -n 2 'hosted-engine --vm-status'
# Note time when Engine becomes "EngineUp" on host02
# Expected: 90-100 seconds (balanced)
```
## 🔧 Troubleshooting

### Symptom: `./verify-olvm-ha.sh --quick` reports "VDSM: Not installed"

**This is fixed in v4.6!** Earlier versions allowed users to run `
verify-olvm-ha.sh` directly on OLVM hosts (after `scp`\-ing it there). That
worked, but if the same script was run on the **control node** by mistake, it
would inspect the control node itself — which has no VDSM, no sanlock, no
libvirtd — and show:

```
OLVM:
  VDSM: Not installed
Services:
  [✗] vdsmd (not running)
  [✗] sanlock (not running)
  ...
Tuning Status:
  [!] Using DEFAULT settings (slow failover)
```
**Fix in v4.6**: `verify-olvm-ha.sh` is now a thin Ansible wrapper. It always
runs from the control node and queries all hosts in `inventory.yml` via Ansible.
You never SCP the script to hosts anymore.

**Usage** (always from control node):

```bash
./verify-olvm-ha.sh --quick           # All hosts
./verify-olvm-ha.sh --host smvigia01  # Single host
```
### Error: `[: 115.0: integer expression expected` (in verify-olvm-ha.sh)

**This is fixed in v4.5!** The `bc` command produced `115.0` (float) for
multiplications by 1.5 even with `scale=0`, which broke bash's `\-lt`/`\-le`/`
\-gt` integer comparison operators.

v4.5+ uses pure integer arithmetic:

```bash
# Before (v4.4 and earlier): produces "115.0"
estimated=$(echo "scale=0; (${sanlock} * 1.5) + ..." | bc)
# After (v4.5+): produces "115" (integer)
estimated=$(( (sanlock * 3 / 2) + (ha_mon * 3) + 25 ))
```
### Error: `Cannot invoke "JsonNode.get(String)" because "node" is null`

**This is fixed in v4.2!** Some engine-config parameters don't exist in OLVM
4.5.5:

- ❌ `HostMonitoringIntervalInSeconds` \- Not in 4.5.5
- ❌ `vdsHeartbeatInSeconds` \- Not in 4.5.5

v4.2 dynamically validates parameters before applying them.

### Error: `couldn't resolve module/action 'ini_file'`

**This is fixed in v4.1!** The playbook now uses only builtin modules.

If you have a v4.0 file, replace it with v4.1.

Alternatively, you can install the collection manually:

```bash
ansible-galaxy collection install community.general
```
But v4.1 is the recommended approach (no extra dependencies).

### Error: `invalid keyword in the overrides section: polling_interval`

**This is fixed in v4.0!** If you still see it:

```bash
# Check your multipath config
cat /etc/multipath/conf.d/99-ha-tuning.conf
# Should have polling_interval in DEFAULTS section (not overrides)
# If wrong, re-run:
./setup.sh balanced
```
### Error: `Could not detect a supported package manager`

```bash
./fix-ansible-deps.sh
```
### SSH Connection Issues

```bash
# Verify SSH key
ssh -v root@192.168.1.111
# Re-copy key
ssh-copy-id -f root@192.168.1.111
```
### Service Won't Start

Check the order:

```bash
# Correct order
systemctl start sanlock
systemctl start multipathd  # if multipath used
systemctl start vdsmd
systemctl start libvirtd
systemctl start ovirt-ha-agent
systemctl start ovirt-ha-broker
```
### VDSM Validation Fails

```bash
# Check the config syntax
cat /etc/vdsm/vdsm.conf.d/99-ha-tuning.conf
# Validate
vdsm-tool validate-config
# If problems, rollback:
./setup.sh --rollback
```
### Multipath Validation Fails

```bash
# Check syntax
multipath -t 2>&1 | grep -i "error\|invalid"
# Verify drop-in
cat /etc/multipath/conf.d/99-ha-tuning.conf
# Should look like:
# defaults {
#     polling_interval     5
#     max_polling_interval 20
# }
# overrides {
#     no_path_retry 80
#     fast_io_fail_tmo 5
#     dev_loss_tmo infinity
# }
```
### False Positive Failover

If you see unwanted failovers during normal operation:

```bash
# Switch to conservative profile
./setup.sh conservative
```
## 📈 Expected Results


|State|Failover Time|Improvement|
|-|-|-|
|Default OLVM 4.5.5|180-300s|baseline|
|**Balanced profile**|**~130s (heuristic)**|**vs ~5-10min default**|
|Aggressive profile|~115s (heuristic)|faster, higher risk|

## 🔬 Technical Details

### Failover Calculation (Integer-Safe Math)

The failover time estimation uses pure integer arithmetic to avoid
floating-point comparison errors in bash:

```
Estimated Time = (sanlock_io_timeout * 3 / 2) + (ha_monitoring * 3) + 25

Mathematically equivalent to (sanlock * 1.5) but uses truncating
integer division to keep all values as integers throughout.

Balanced Example:
= (50 * 3 / 2) + (10 * 3) + 25
= 75 + 30 + 25
= 130s heuristic upper bound (NOT a measured value - verify with a real failover test)
```
> **Note**: Earlier versions (≤ v4.4) used `bc` with `\* 1.5` which produced
> values like `115.0` that broke bash integer comparisons. v4.5 fixed this across `
> verify-olvm-ha.sh`, `setup.sh`, and `olvm-ha-tuning.yml`.

### Multipath-Sanlock Synchronization

```
no_path_retry = (sanlock_io_timeout × 8) / polling_interval

Balanced: (50 × 8) / 5 = 80
```
### Why polling_interval is in `defaults` Section

Per 
[RHEL 8 Multipath Documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html-single/configuring_device_mapper_multipath/index)
:

> The `defaults` section recognizes the `polling_interval` keyword. The `
> overrides` section does NOT support `polling_interval`.

This is why v3.0 of this tool produced the error:

```
invalid keyword in the overrides section: polling_interval
```
### Service Dependencies

```
multipathd → sanlock → vdsmd → libvirtd → ovirt-ha-agent → ovirt-ha-broker
```
The playbook respects this order via Ansible handlers.

### Configuration File Locations


|File|Purpose|Source|
|-|-|-|
|`/etc/vdsm/vdsm.conf.d/99-ha-tuning.conf`|VDSM + Sanlock|New (drop-in)|
|`/etc/multipath/conf.d/99-ha-tuning.conf`|Multipath|New (drop-in)|
|`/etc/sanlock/sanlock.conf`|Legacy Sanlock|Modified|
|`/etc/ovirt-hosted-engine-ha/agent.conf`|HA Agent|Modified|
|`/etc/ovirt-hosted-engine-ha/broker.conf`|HA Broker|Modified|
|`/etc/libvirt/libvirtd.conf`|Libvirt|Modified|

## 🛡️ Safety Features

This package includes:

- ✅ **Pre-flight validation** \- Checks environment before changes
- ✅ **Automatic backups** \- Saved to `/root/olvm-ha-backup-*`
- ✅ **Dry-run mode** \- Preview changes before applying
- ✅ **Config validation** \- `vdsm-tool` and `multipath -t`
- ✅ **Sequential processing** \- One host at a time (`serial: 1`)
- ✅ **Service health checks** \- After each restart
- ✅ **Rollback support** \- Multiple rollback options
- ✅ **Comprehensive logging** \- All operations logged

## ⚠️ Important Warnings

1.  **Test in non-production first**
2.  **Use a maintenance window** for production changes
3.  **Migrate VMs** off hosts before testing failover
4.  **Verify backups** are present before applying
5.  **Monitor for 24 hours** after applying changes
6.  **Have rollback plan** ready

## 📚 References

- 
  [Red Hat: Configuring DM Multipath (RHEL 8)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html-single/configuring_device_mapper_multipath/index)
- [Multipath.conf man page](https://man.archlinux.org/man/multipath.conf.5.en)
- [oVirt VDSM Configuration](https://github.com/oVirt/vdsm)
- 
  [Oracle Linux Virtualization Manager Documentation](https://docs.oracle.com/en/virtualization/oracle-linux-virtualization-manager/)

## 📝 Version History

### v4.22 (2026-06-21) ⭐ CURRENT

- 🐞 **BUGFIX — the documented lab/prod command now works.** `setup.sh`,
  `verify-olvm-ha.sh` and `fix-ansible-deps.sh` now accept `-i` / `--inventory
  FILE`. Previously only the fixed `inventory.yml` was used, so the command
  printed in the REVIEW and in the lab/prod vars files —
  `./setup.sh custom -i inventory-lab-akyuz.yml -e @vars/lab-akyuz.yml --no-restart`
  — aborted at argument parsing with `Unknown argument: -i`. The path is
  resolved relative to the current directory first, then to the script
  directory, and is validated for existence/readability before use. The
  shipped `inventory-lab-akyuz.yml` and `inventory-prod-dell-me5.yml` are now
  usable end-to-end (apply, rollback, check, syntax-check, verify, deps).
- 🧰 No playbook task logic changed; all v4.21 behaviour and safety features are
  preserved. See `REVIEW-v4.22.md`.

### v4.21 (2026-06-20)

- 🛑 **CRITICAL fix — a real host went Not Responding after reboot.** The VDSM
  drop-in deploy task rendered with a literal leading `\"` (the task read
  `content: \"{{ ... }}\"` — escaped quotes), so the file began with `\"#...`.
  On vdsmd start, VDSM's `configparser` raised `MissingSectionHeaderError`,
  vdsmd failed to start and VM device hooks crashed. The deploy tasks now use
  plain `content: "{{ ... }}"` (this also affected the multipath drop-in).
- 🧪 **Defense-in-depth:** the VDSM drop-in copy now `validate:`s the staged temp
  file as INI before installing — a non-parseable drop-in can never reach vdsmd.
- 🧹 **VDSM drop-in is now `[vars]`-only.** The stray `[sanlock]` section was
  removed (sanlock does not read `vdsm.conf.d`; `io_timeout` is written to
  `/etc/sanlock/sanlock.conf` by the sanlock section).
- 🔌 **`vdsm_apply_vars_section` now defaults FALSE.** When false the managed
  drop-in is **removed**, so a host that got a bad file **self-heals** on the
  next run. Converged re-runs stay `changed=0`.
- 📦 Only the current REVIEW file is shipped; the v4.21 findings are carried
  forward into `REVIEW-v4.22.md`.

See `REVIEW-v4.22.md` (it includes the v4.21 recovery steps).

### v4.20 (2026-06-20)

- 🔍 **`verify-olvm-ha.yml` fixes surfaced by a real staged run** (apply playbook
  unchanged):
  - No longer calls `vdsm-tool validate-config` (absent on VDSM 4.50.x → always
    "FAILED or skipped"); validates the VDSM drop-in as INI with Python instead
    (the same non-fatal approach the apply playbook took in v4.17). Report line
    relabelled **"VDSM drop-in INI parse"**.
  - HA quick-status no longer says "Not a hosted-engine host" when
    `hosted-engine --vm-status` returns nothing but `ovirt-ha-agent` is active;
    it now reflects the real service state.
- ✅ The real run confirmed the apply playbook is clean: engine 4/4 changes,
  **libvirt keepalive correctly left at the vdsm-managed value** (v4.18 fix
  validated on the live host), multipath validated, services stayed active.
  See `REVIEW-v4.20.md`.

### v4.19 (2026-06-20)

- 🎯 **Lab → Dell ME5 production path completed.** The lab (LIO-ORG iSCSI) and the
  Dell ME5 production cluster run the same OLVM 4.5.5 / VDSM 4.50 / OEL 8.10
  hosted-engine software, so all of the v4.10–v4.18 fixes are software-level and
  apply to **both** (engine tuning, idempotency, two-stage restart, drift-gated
  backups, non-fatal validation, version-stable drop-ins, the per-section
  toggles). The only storage-specific difference is the multipath device block.
- 🟧 **The multipath built-in table has no DellEMC/ME5 entry** (verified from the
  lab discovery), so ME5 **requires** the explicit `device {}` ALUA stanza, while
  the lab's LIO-ORG auto-detects ALUA and uses the global overrides.
- 📦 **New production files:** `vars/prod-dell-me5.yml` and
  `inventory-prod-dell-me5.yml` — same correct toggle decisions as the lab, with
  the ME5 device block **on**. See `REVIEW-v4.19.md`.

### v4.18 (2026-06-20)

- 🔭 Adapted to the discovered lab (LIO-ORG, not ME5): per-section apply toggles
  with `apply_libvirt_keepalive` defaulting false; `vars/lab-akyuz.yml`.

### v4.17 (2026-06-19)

- 🐞 Fixed an abort caused by `vdsm-tool validate-config` (absent on some VDSM
  builds); validation is now version-independent and non-fatal; drop-ins are
  version-stable.

### v4.16 (2026-06-19)

- ✅ True no-op on a converged re-run: read-only drift detection gates the backup
  section, so when nothing differs there is no backup, `changed=0`, and the play
  reports "All managed settings are already current."

### v4.15 (2026-06-19)

- 📝 Self-documenting ME5 multipath block (each line annotated with purpose, Dell
  value, and default); Dell ME5 compatibility verified against the 2024 guide.

### v4.14 (2026-06-19)

- 🔧 `setup.sh` accepts `-e` / `--extra-vars`; two-stage restart confirmation;
  ME5/multipath variables moved into the profiles (`vars/*.yml`).

### v4.13 (2026-06-19)

- 🔌 **Multipath is configured the VDSM-supported way (ME5 now ALUA-correct).**
  Drop-in in `/etc/multipath/conf.d/` is the supported override mechanism;
  `vdsm-tool` cannot inject device tuning. The Dell ME5 device block now sets the
  required ALUA path attributes in addition to the HA timeouts.

### v4.12 (2026-06-19)

- 🐞 **Engine idempotency bugfix (critical).** The regex that parsed the current
  value out of `engine-config -g NAME` output was over-escaped, so the
  comparison always reported a mismatch and re-applied all 17 parameters every
  run. Parsing is now backslash-free; a no-op re-run changes nothing and does
  not restart the engine.

### v4.11 (2026-06-19)

- 🛟 **Safe by default — services are NOT restarted unless you opt in.**
  `restart_enabled` now defaults to **false** in both the apply play and the
  engine play. `setup.sh` **asks interactively** ("Restart services now? [no]")
  and only restarts if you answer *yes* or pass `--restart`.
- 🔌 **Engine restart is now gated too** — previously `ovirt-engine` was
  restarted unconditionally whenever an engine-config value changed. Now it
  follows `restart_enabled`; when staged, the values are written to the engine
  DB and the playbook prints the manual step (`systemctl restart ovirt-engine`).
- 🐞 **Dry-run fix** — `setup.sh <profile>` failed during the `--check` dry-run
  at *"Verify engine is active after restart"* (10 retries → *"Command would
  have run if not in check mode"*; empty stdout never satisfied the `until`).
  The post-restart wait/verify are now skipped under check mode, so the dry-run
  completes cleanly.

### v4.10 (2026-06-18)

- 🐞 **Idempotency completed (critical)** — the VDSM and multipath **drop-in
  files embedded the run timestamp in their content**, so every apply reported
  `changed` and bounced `sanlock` / `vdsmd` / `multipathd` on a live hypervisor
  even on a pure no-op re-run. v4.9 fixed engine idempotency but missed this.
  The volatile timestamp is removed; an unchanged re-apply is now a true no-op
  (changed=0, no restarts).
- 📄 **NEW: run report** — after a successful apply, an **HTML and Markdown
  report** is rendered to `./reports/`, documenting every operation performed
  per host (drop-in/lineinfile changed vs already-correct, backups, service
  state, failover estimate) plus the engine parameter changes (old → new).
  Toggle with `-e generate_report=false`.
- 🟧 **NEW (opt-in): ME5-scoped multipath** — `multipath_me5_device_block: true`
  scopes the HA storage settings to a Dell EMC ME5 `device {}` stanza instead of
  the global `overrides {}` block (REVIEW 2.3). Default `false` keeps prior
  behavior.
- 🔧 **NEW (opt-in): `vdsm_apply_vars_section`** (default `true`) — lets an
  operator who confirmed the VDSM `[vars]` keys are not in their schema disable
  just that section while still writing the always-valid `[sanlock]` block.
- 🧾 Doc consistency: failover figures relabeled as **heuristic upper bounds**
  everywhere; `inventory.yml` header version corrected (4.8 → 4.10).
- 📄 See `REVIEW-v4.10.md` for the full findings and per-item rationale.

### v4.9 (2026-06-18)

- 🐞 **Engine config is now idempotent** — values are compared
  current-vs-desired; only mismatched parameters are applied, so unchanged runs
  no longer restart `ovirt-engine` needlessly.
- 🔎 **Engine parameters reconciled against a real `engine-config --all` dump** —
  corrected wrong defaults (e.g. `ServerRebootTimeout` default is **600**, not
  300), and exposed that only 4 of the 17 listed parameters actually differ
  from the 4.5.5 default (the other 13 are now grouped as an explicit
  drift-guard block). `ServerRebootTimeout` set to **300** (bare-metal POST/RAID
  can take ~3 min, so 90s was unsafe).
- 🛟 **Service restart made opt-out and safer** — `\--no-restart` now truly
  stages config without touching services; both the script and the playbook
  recommend applying changes by rebooting each host via the OLVM web UI
  (Maintenance → Restart → Activate), one at a time.
- 🐞 Fixed: aggregate summary "params tuned: X / 0"; failover classification
  bands (balanced now reports BALANCED, not CONSERVATIVE); `\--no-restart` was a
  no-op; inconsistent backup timestamp across hosts; simple rollback now also
  reverts the in-place `lineinfile` keys; `meta: end_play` → `end_host`; VDSM
  minor-version gate; dead `\--version` option.
- 📄 See `REVIEW-v4.9.md` for the full findings and per-item rationale.

### v4.8 (2026-05-15)

- ✅ **Engine HA coverage expanded: 9 → 17 tunable parameters**
  - All confirmed against actual OLVM 4.5.5-1.67.el8 `engine-config -l`
  - New: `VdsRefreshRate`, `VdsRecoveryTimeoutInMinutes`, `
    NetworkConnectivityCheckTimeoutInSeconds`, `
    HostPreparingForMaintenanceIdleTime`, `MaxStorageVdsDelayCheckSec`, `
    MaxStorageVdsTimeoutCheckSec`, `NumberOfFailedRunsOnVds`, `
    MaxRerunVmOnVdsCount`
- ✅ **NEW: `engine_verify_only` informational tier (10 params)**
  - `vdsTimeout`, `vdsRetries`, `PMHealthCheckEnabled`, kdump fence settings,
    fence retries — shown in reports, never modified
- ✅ Two-tier engine report (Tunable + Informational sections)
- ✅ Notes section explains why certain params are left at defaults

### v4.7 (2026-05-15)

- ✅ **Engine HA tuning expanded** from 3 to 9 parameters:
  - `vdsConnectionTimeout`, `VDSAttemptsToResetCount`, `SpmCommandFailOverRetries`
    , `SPMFailOverAttempts`, `FenceQuietTimeBetweenOperationsInSec`, `
    PMHealthCheckIntervalInSec`
  - All guarded by dynamic `engine-config -l` validation (safely skip
    unsupported)
- ✅ Engine verification added to `verify-olvm-ha.yml` (new play)
- ✅ `\--engine` flag in `verify-olvm-ha.sh` (engine-only report)
- ✅ Aggregate summary now includes engine tuning status
- ✅ Documented intentionally untuned engine parameters (`vdsTimeout`, `vdsRetries`
  )

### v4.6 (2026-05-14)

- ✅ **MAJOR**: Architecture correction — control-node-only execution
  - `verify-olvm-ha.sh` was being run on OLVM hosts by mistake, causing "VDSM:
    Not installed" reports
  - Rewritten as a thin Ansible wrapper invoking new `verify-olvm-ha.yml`
- ✅ New `verify-olvm-ha.yml` playbook (Ansible-driven verification)
- ✅ Per-host detailed reports + aggregate summary on control node
- ✅ Granular tags: quick, full, vdsm, sanlock, multipath, ha, libvirt, storage,
  failover, logs
- ✅ `\--host \<name>` to verify a single host (`\--limit` passthrough)
- ✅ `\--tags \<list>` to pass arbitrary tag sets to Ansible
- ✅ `\--check-syntax` in `setup.sh` for offline YAML validation
- ✅ Tightened `lineinfile` regex anchors (`^\\\[agent\\]$`)
- ✅ Consistent exit codes across all wrappers
- ✅ Updated README with explicit architecture diagram

### v4.5 (2026-05-14)

- ✅ **CRITICAL FIX**: Integer-comparison error in `verify-olvm-ha.sh`
  - `bc` returned `115.0` for float multiplications, breaking `[ "$x" -lt 90 ]`
  - Replaced with pure integer math: `(sanlock * 3 / 2)` instead of `(sanlock *
    1.5)`
- ✅ Unified version stamps across all project files (single source of truth)
- ✅ Added `\--logs \[MINUTES]` parameter for custom log lookback windows
- ✅ Robust YAML profile parsing (handles inline comments correctly)
- ✅ Rollback date format validation (strict `YYYYMMDDTHHMMSS` regex)
- ✅ SIGINT/SIGTERM trap in `setup.sh` for graceful interruption logging
- ✅ File readability checks throughout (not just existence)
- ✅ Division-by-zero guard in multipath synchronization check
- ✅ Removed `bc` runtime dependency

### v4.4 (2026-05-11)

- ✅ Fixed unbound variable error in multipath sync check
- ✅ Improved variable initialization (safe defaults via `${var:-}`)
- ✅ Better error handling for missing config values
- ✅ Updated VDSM and Multipath template version stamps

### v4.3 (2026-05-11)

- ✅ Engine restart now GUARANTEED after config changes (no longer relying on
  handlers alone)
- ✅ Engine restart uses direct task with `wait_for` and verification
- ✅ Added retries and polling for engine availability
- ✅ Host services post-restart verification with `flush_handlers`
- ✅ Service status assertion after all restarts
- ✅ Improved error messages

### v4.2 (2026-05-11)

- ✅ Fixed engine-config errors for missing parameters in OLVM 4.5.5
- ✅ Dynamic engine parameter validation via `engine-config -l`
- ✅ Removed deprecated parameters: `HostMonitoringIntervalInSeconds`, `
  vdsHeartbeatInSeconds`
- ✅ Improved backup with file existence pre-checks
- ✅ Better handling of missing broker.conf (normal for 4.5.5)
- ✅ Improved `\--check` mode compatibility
- ✅ Cleaner output with informative messages

### v4.1 (2026-05-11)

- ✅ Removed `community.general` dependency
- ✅ All `ini_file` calls replaced with `copy` (templates) and `lineinfile`
- ✅ Works with bare `ansible-core` installations
- ✅ Compatible with Ansible Core 2.16+ (and older)
- ✅ Fixed: `couldn't resolve module/action 'ini_file'` error

### v4.0 (2026-05-10)

- ✅ Fixed multipath `polling_interval` placement
- ✅ Added pre-flight validation playbook
- ✅ Added rollback playbook
- ✅ Added config validation (`vdsm-tool`, `multipath -t`)
- ✅ Sequential processing (`serial: 1`)
- ✅ Comprehensive error handling
- ✅ Enterprise-grade logging

### v3.0 (Deprecated)

- ❌ `polling_interval` in `overrides` section (invalid)
- ❌ Required `community.general` collection
- ❌ No pre-flight validation

## 🆘 Support

When reporting issues, include:

```bash
# System info
./verify-olvm-ha.sh --version
# Full check output
./verify-olvm-ha.sh --full > full-check.log
# Setup logs
ls -la logs/
```
## 📄 License

This automation is provided as-is for OLVM/oVirt environments.

- - -
**Version**: 4.22 (Enterprise)

**Last Updated**: 2026-05-15

**Tested**: ✅ OLVM 4.5.5-1.67.el8 / Oracle Linux 8.10sm

