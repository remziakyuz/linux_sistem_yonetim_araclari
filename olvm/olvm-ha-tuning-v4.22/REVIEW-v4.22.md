# OLVM HA Tuning – v4.22 (fix: `-i/--inventory` in the control-node wrappers)

The command printed in the previous REVIEW and in the lab/prod vars files

```bash
./setup.sh custom -i inventory-lab-akyuz.yml -e @vars/lab-akyuz.yml --no-restart
```

did not run. It aborted immediately with:

```
[ERROR]   Unknown argument: -i
```

This release fixes that and makes the shipped per-environment inventories
usable end-to-end. **No playbook task logic changed**; every v4.21 behaviour and
safety feature is preserved. The v4.21 recovery steps (still relevant) are
carried forward in section 4 below.

---

## 1. What went wrong

`setup.sh` hard-coded its inventory:

```bash
readonly INVENTORY="${SCRIPT_DIR}/inventory.yml"
```

and its argument parser had **no case for `-i` / `--inventory`**, so any `-i`
fell through to the catch-all and the script exited with
`Unknown argument: -i`. The same was true of `verify-olvm-ha.sh` and
`fix-ansible-deps.sh`. As a result, the two inventories that ship with the
project — `inventory-lab-akyuz.yml` and `inventory-prod-dell-me5.yml` — could
not be selected from the wrappers at all, even though the README, the REVIEW and
`vars/lab-akyuz.yml` / `vars/prod-dell-me5.yml` all told you to run with
`-i <that file>`.

## 2. The fix (v4.22)

1. **`-i` / `--inventory FILE` added** to `setup.sh`, `verify-olvm-ha.sh` and
   `fix-ansible-deps.sh`. All three accept the separated form (`-i file`), the
   `--inventory=file` form, and the joined form (`-ifile`).
2. **Path resolution + validation.** The given path is resolved relative to the
   current directory first, then relative to the script directory, and is
   checked for existence and readability before use. A bad path produces a clear
   error (it lists both locations it tried) instead of a confusing failure
   later.
3. **Default unchanged.** With no `-i`, the wrappers still use `inventory.yml`,
   so existing usage and docs keep working. `setup.sh` now prints which
   inventory it is using (and whether it came from `-i` or the default).
4. **Covers every mode.** `-i` applies to apply, `--rollback`, `--check-only`
   and `--check-syntax`, because all of them already used the single `INVENTORY`
   variable.
5. **Extra-vars precedence is unchanged.** `-e @vars/lab-akyuz.yml` is still
   forwarded to `ansible-playbook` *after* the profile file, so the
   environment file overrides the profile (e.g. the lab/prod section toggles).

## 3. What this means for your environment

Run exactly what the lab profile documents:

```bash
./setup.sh custom -i inventory-lab-akyuz.yml -e @vars/lab-akyuz.yml --no-restart
```

and for the Dell ME5 cluster:

```bash
./setup.sh custom -i inventory-prod-dell-me5.yml -e @vars/prod-dell-me5.yml --no-restart
```

Verify and install dependencies against the same inventory:

```bash
./verify-olvm-ha.sh -i inventory-lab-akyuz.yml --quick
./fix-ansible-deps.sh -i inventory-lab-akyuz.yml --check
```

## 4. Recovery steps carried forward from v4.21

v4.21 fixed a real failure where a malformed VDSM drop-in (a stray leading `"`)
kept `vdsmd` from starting after a host reboot, leaving the host **Not
Responding**. The lab and Dell profiles set `vdsm_apply_vars_section: false`, so
re-running with one of them **removes** any bad `99-ha-tuning.conf` and leaves
the host on the stock VDSM config — the correct state for this stack (the
effective tuning surface here is engine-config + multipath). The recommended
recovery, unchanged:

1. Update to this release.
2. Re-run staged with the lab profile (removes the bad drop-in, applies only the
   effective surface):
   ```bash
   ./setup.sh custom -i inventory-lab-akyuz.yml -e @vars/lab-akyuz.yml --no-restart
   ```
3. On each host, confirm the drop-in is gone and vdsmd is healthy:
   ```bash
   ls /etc/vdsm/vdsm.conf.d/99-ha-tuning.conf   # should be: No such file
   systemctl restart vdsmd && systemctl is-active vdsmd
   ```
4. Activate one host at a time, then restart the engine.
5. (Dell) on the ME5 cluster use `inventory-prod-dell-me5.yml` +
   `vars/prod-dell-me5.yml` — same behaviour, plus the ME5 multipath device
   block.

The v4.21 defenses remain in place: the VDSM drop-in copy still `validate:`s the
staged temp file as INI before installing it, the drop-in is `[vars]`-only, and
when `vdsm_apply_vars_section` is false the managed drop-in is removed so a host
self-heals on the next run.

## 5. Validation

- `bash -n` passes on all three scripts.
- `-i` was exercised in every form (`-i file`, `--inventory=file`, `-ifile`),
  for the default path, for a missing path (clean error), and across
  `setup.sh` / `verify-olvm-ha.sh` / `fix-ansible-deps.sh`; each run invoked
  `ansible-playbook` / `ansible` with the resolved inventory.
- All playbooks and vars files still parse as YAML; the user's `-e` override is
  still forwarded last.
