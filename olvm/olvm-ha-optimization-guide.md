# OLVM HA & Performance Optimization — Beyond Timeout Tuning

> Scope: Oracle Linux Virtualization Manager (OLVM) 4.5.x / oVirt 4.5, hosted-engine
> deployments on Oracle Linux 8.10. Companion to the `olvm-ha-tuning` automation
> (which already covers the timeout layer: VDSM / sanlock / multipath / HA-agent /
> engine-config). This document lists the layers **outside** that automation that
> matter most in a critical environment, then gives a prioritized, step-by-step
> rollout order.

> [!IMPORTANT]
> Most items below involve hardware- and version-specific trade-offs. Treat the
> values as **starting points**, not prescriptions. Confirm every engine
> parameter exists with `engine-config -l`, confirm multipath/ALUA with
> `multipath -v3`, and **always validate fencing and failover in a maintenance
> window** before relying on them. Roll out lab → one host → cluster.

---

## Part 1 — The Optimization Layers

### 1. Fencing / Power Management (the real determinant of HA)

No matter how low you push the timeouts, **HA does not actually work without a
functioning fence device.** When the engine sees a host as *Non-Responsive*, it
will not restart that host's VMs elsewhere until it can **power-fence** the
suspect host — otherwise it risks split-brain. Without fencing it waits
indefinitely.

- Define a real PM agent per host: iDRAC (`fence_idrac` / `fence_drac5` for Dell
  PowerEdge + ME5 stacks), iLO, or generic IPMI (`fence_ipmilan`). Enable
  IPMI-over-LAN on the BMC.
- Configure **`fence_kdump`** so a host taking a kernel crash dump is not fenced
  mid-dump (which would lose the dump). Tune it in lockstep with the engine
  params `FenceKdumpListenerTimeout` / `FenceKdumpMessageInterval` and the
  kdump listener config (the automation intentionally leaves these
  *informational*).
- The **fence confirmation budget** dominates real failover time:
  `FenceStartStatusRetries` / `FenceStopStatusRetries` (~18) ×
  `...DelayBetweenRetriesInSec` (~10) ≈ up to ~180 s per device. If failover
  feels slow, look here first — but lowering too far causes false fences.
- Add multiple PM **proxies** (neighbor hosts relay the fence request) and,
  where possible, **two fence methods** per host (concurrent or sequential).
- **Test it for real** in a maintenance window: Power Management → *Test*, then
  hard-power-off a host and watch recovery.

### 2. Time synchronization (the silent killer)

sanlock leases and certificates are highly time-sensitive. Run **chrony** on
every host and the engine against the same NTP source with only a few ms of
skew. Clock drift can break lease renewal and trigger false fences. Also monitor
**certificate expiry** (oVirt CA and per-host VDSM certs) — expiry silently
drops a host out of the cluster.

### 3. Storage: leases, LVM filter, iSCSI

- **VM storage lease (HA lease):** assign a lease (on a storage domain) to
  HA-flagged VMs. This is the hardware-level guard that prevents the same VM
  from running on two hosts (split-brain) when a host is isolated. For critical
  VMs combine: HA flag + lease + an appropriate resume/kill behavior.
- **`vdsm-tool config-lvm-filter`:** stops the host's own LVM from scanning or
  locking guest LUNs. On shared block storage (e.g. Dell ME5) this is
  **critical** — without it a host can grab the wrong PVs at boot.
- **iSCSI (LIO and ME5):** keep `node.session.timeo.replacement_timeout` aligned
  with multipath behavior (usually keep iSCSI replacement_timeout low and let
  multipath's `no_path_retry` × `polling_interval` own path handling). Use a
  dedicated storage network and iSCSI multipathing/bonding.
- **I/O scheduler:** `none` / `mq-deadline` for SSD/NVMe back-ends;
  `mq-deadline` for spinning disk. The tuned `virtual-host` profile sets sane
  defaults.
- **Thin provisioning:** monitor domain fill thresholds and `discard_after_delete`
  behavior.

### 4. Network separation and migration

- **Traffic separation:** split `ovirtmgmt` (management), **migration**,
  **storage**, display, and VM traffic onto separate logical networks / VLANs.
  A management network saturated by migration or storage I/O is the leading
  cause of false *Non-Responsive* events — which is exactly what drives the
  automation's `vdsConnectionTimeout`.
- **Migration settings:** dedicated migration network, bandwidth limit,
  concurrent-migration count, and a migration policy
  (`post-copy`, `auto-converge` / suspend-workload-if-needed). Post-copy speeds
  up heavy-write VMs but carries a brief interruption risk.
- **Bonding:** LACP (mode 4) with a reasonable `miimon` (e.g. 100 ms);
  **jumbo frames (MTU 9000)** end-to-end on storage/migration networks give a
  measurable gain when consistent.

### 5. Hosted-engine specifics

- Use **global maintenance** (`hosted-engine --set-maintenance --mode=global`)
  before updating or restarting the engine, so HA does not fence the engine VM
  during the work.
- Give the engine VM enough resources at scale; tune PostgreSQL and
  `ENGINE_HEAP_MAX`; keep DWH/Grafana separate or disabled if not needed.
- Leave `vdsTimeout` (180 s) and `vdsRetries` (0) at defaults — as the
  automation notes, lowering them produces false positives.

### 6. Host performance (tuned + KSM + NUMA)

- **`tuned-adm profile virtual-host`** — sets the CPU governor to performance and
  tunes scheduler / THP / sysctl for virtualization. For latency-sensitive
  workloads, restricting deep C-states adds a further gain.
- **KSM / ksmtuned:** saves memory via overcommit but costs CPU and adds
  latency; consider disabling it for latency-critical VMs.
- **Huge pages** for large VMs; **CPU/NUMA pinning** for low-latency VMs.
- Cluster-level: CPU/RAM overcommit, scheduling policy
  (`evenly_distributed` vs `power_saving`), and resilience policy
  (migrate / migrate only HA / do not migrate).

### 7. Observability and DR

External monitoring (or DWH + Grafana), event notifications (email/SNMP),
especially for fence and storage events; regular `engine-backup`; and
verification that kdump actually captures a dump.

---

## Part 2 — Prioritized, Step-by-Step Rollout

Ordering principle: **first make HA actually work and protect data integrity,
then remove false-positive triggers (stability), then optimize performance, then
operability/DR.** A lower number = do it earlier.

### Tier 0 — Prerequisites & data integrity (do these first)

| # | Item | Why it's first | Risk to apply |
|---|------|----------------|---------------|
| 1 | **Time sync (chrony)** on all hosts + engine | Prerequisite for sanlock leases and certs; prevents false fences | Very low |
| 2 | **Fencing / Power Management** + test | Without it, HA does **not** restart VMs at all | Low config, but **must be tested** |
| 3 | **VM storage leases + HA flag** on critical VMs | Prevents split-brain / dual-run corruption | Low |
| 4 | **`vdsm-tool config-lvm-filter`** on each host | Prevents the host grabbing guest LUNs at boot (data integrity) | Low–medium (validate filter) |
| 5 | **Certificate expiry check** (oVirt CA + VDSM) | Silent host drop-out when expired | Very low (read-only check) |

> Cross-cutting practice from step 2 onward: use **global maintenance** before
> any engine/host disruptive action.

### Tier 1 — Stability (remove false-positive triggers)

| # | Item | Why here | Risk |
|---|------|----------|------|
| 6 | **Network traffic separation** (mgmt / migration / storage VLANs) | Biggest cause of false *Non-Responsive*; directly affects engine timeouts | Medium (network change) |
| 7 | **iSCSI + multipath alignment** (replacement_timeout vs `no_path_retry`) | Path failures should be ridden out or failed deliberately, not randomly | Medium |
| 8 | **Timeout tuning** = your `olvm-ha-tuning` automation (engine-config / vdsm / sanlock / HA-agent / multipath) | Safe to apply once 1–7 are in place; staged with `--no-restart` | Low (staged) → Medium (on restart) |

### Tier 2 — Performance

| # | Item | Why here | Risk |
|---|------|----------|------|
| 9 | **`tuned-adm profile virtual-host`** + I/O scheduler | Broad, low-effort host performance baseline | Low |
| 10 | **Migration policy + bandwidth + dedicated network** | Faster, safer live migrations and maintenance drains | Low–medium |
| 11 | **KSM / NUMA / huge pages / overcommit** per workload | Targeted gains; trade-offs per VM | Medium (workload-specific) |
| 12 | **Hosted-engine resources + PostgreSQL/heap** | Scales the manager under load | Low–medium |

### Tier 3 — Operability & DR

| # | Item | Why here | Risk |
|---|------|----------|------|
| 13 | **Monitoring + event notifications** (fence/storage events) | You can't run critical HA blind | Low |
| 14 | **`engine-backup`** schedule + restore test | Recover the manager after disaster | Low |
| 15 | **kdump capture verification** | Confirms crash diagnostics actually land | Low |

### One-line summary of the order

```
1 time sync → 2 fencing(+test) → 3 VM leases/HA → 4 LVM filter → 5 cert check
→ 6 network separation → 7 iSCSI/multipath alignment → 8 timeout tuning (your tool)
→ 9 tuned/scheduler → 10 migration policy → 11 KSM/NUMA/hugepages → 12 engine sizing
→ 13 monitoring → 14 engine-backup → 15 kdump verify
```

---

## Verification checklist (per change)

- [ ] Confirm the parameter/feature exists in **this** version
      (`engine-config -l`, `multipath -v3`, `multipath -t`).
- [ ] Apply in **lab first**, then **one host**, then the cluster (`serial: 1`).
- [ ] For HA-affecting changes, run a **real failover test** (fence a host) in a
      maintenance window — heuristic numbers are not measurements.
- [ ] Capture a rollback path (backups, `--rollback`, global maintenance).
- [ ] Re-run `./verify-olvm-ha.sh --full` after host-level changes.

---

*This guide is a planning aid, not a turnkey configuration. Values and
availability vary by hardware, storage vendor, and OLVM/oVirt build — validate
in your own environment.*
