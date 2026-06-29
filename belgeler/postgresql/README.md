# patroni-kurulum — Kurulum ve Yapılandırma Kılavuzu

**Sürüm:** v1.1 (2026-06-28)

3 düğümlü Patroni PostgreSQL 18 HA kümesini kuran, güvenlik sertleştiren,
performans izleyen ve test eden eksiksiz Ansible otomasyon projesi.

---

## Sürüm Geçmişi

| Sürüm | Tarih | Değişiklikler |
|-------|-------|---------------|
| v1.0 | 2026-06-28 | patroni-kvm + patroni-test birleştirildi. Tek inventory (infra.yml), numaralı playbook'lar (01-07), admin alias sistemi, PCP izleme, pgbench testi, sağlık raporu, pg_tune OS optimizasyon rolü, PostgreSQL 18 kapsamlı tuning (io_uring, lz4 WAL, summarize_wal), auto_tune rolü (donanım bazlı otomatik parametre hesaplama), HAProxy multi-thread + 25G ağ tuning, NVMe I/O scheduler, kullanıcı bellek limitleri, kurulum raporlarında auto-tune raporu bölümü |

---

## İçindekiler

1. [Mimari](#1-mimari)
2. [Desteklenen Platformlar ve Ön Koşullar](#2-desteklenen-platformlar-ve-ön-koşullar)
3. [Playbook'lar ve Akış](#3-playbook'lar-ve-akış)
4. [Değişken Dosyaları ve Yapılandırma](#4-değişken-dosyaları-ve-yapılandırma)
5. [Roller Rehberi](#5-roller-rehberi)
6. [Adım Adım Kurulum](#6-adım-adım-kurulum)
7. [Admin Alias Sistemi](#7-admin-alias-sistemi)
8. [Kurulum Raporları](#8-kurulum-raporları)
9. [Yaşam Döngüsü Yönetimi](#9-yaşam-döngüsü-yönetimi)
10. [Güvenlik](#10-güvenlik)
11. [İzleme ve Alarm](#11-izleme-ve-alarm)
12. [Sorun Giderme](#12-sorun-giderme)
13. [Temizlik](#13-temizlik)
14. [Hızlı Referans](#14-hızlı-referans)

---

## 1. Mimari

### Katmanlı HA Altyapısı

```
Uygulama Sunucuları
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│  Sanal IP (VIP): 10.253.10.56  ← Keepalived VRRP        │
│                                                          │
│  PgBouncer :6432  (yazma → primary)                      │
│  PgBouncer :6433  (okuma → replikalar)                   │
│                                                          │
│  haproxy01: 10.253.10.54  [MASTER]                       │
│  haproxy02: 10.253.10.55  [BACKUP]                       │
│                                                          │
│  HAProxy Stats: :7000                                    │
└──────────────────────────────────────────────────────────┘
     │ :5432 (GET /primary → HTTP 200 = UP)
     │ :5433 (GET /replica → HTTP 200 = UP)
     ▼
┌──────────────────────────────────────────────────────────┐
│  Patroni Kümesi — pg-cluster                             │
│                                                          │
│  patroni01             patroni02             patroni03   │
│  10.253.10.51          10.253.10.52          10.253.10.53│
│  PostgreSQL 18         PostgreSQL 18         PostgreSQL 18│
│  etcd  Patroni         etcd  Patroni         etcd Patroni│
│  [Replica]             [Replica]             [Leader]    │
│                                                          │
│  ─── Cluster ağı: etcd + replikasyon ─────────────────  │
│  10.255.255.51         10.255.255.52         10.255.255.53│
└──────────────────────────────────────────────────────────┘
```

### Bileşenler

| Bileşen | Sürüm | Amaç |
|---------|-------|------|
| PostgreSQL | 18 (PGDG) | Veritabanı motoru |
| Patroni | 3.x | HA yönetimi, otomatik failover |
| etcd | 3.x | DCS (Dağıtık Yapılandırma Deposu) |
| HAProxy | 2.x | Yük dengeleme, health check |
| Keepalived | — | VRRP ile VIP yönetimi |
| PgBouncer | — | Bağlantı havuzlama |
| PCP | — | Performans metrikleri |

### İki Ağ Tasarımı

| NIC | Ağ | Subnet | Amaç |
|-----|-----|--------|------|
| `pub0` / `enp1s0` | patroni-public (NAT) | 10.253.10.0/24 | İstemci + REST API :8008 |
| `clu0` / `enp10s0` | patroni-cluster (izole) | 10.255.255.0/24 | etcd + replikasyon |

### Disk Düzeni (Her Patroni Düğümü)

| Disk | LVM / FS | Mount | Amaç |
|------|----------|-------|------|
| vda | OS (XFS) | `/` | İşletim sistemi |
| vdb | `vg_pgdata/lv_pgdata` → XFS | `/var/lib/pgsql` | PGDATA |
| vdc | `vg_pgwal/lv_pgwal` → XFS | `/var/lib/pgwal` | WAL (`separate_wal: true` ise) |

---

## 2. Desteklenen Platformlar ve Ön Koşullar

### Desteklenen Platformlar

| Mimari | İşletim Sistemi | `vm_arch` |
|--------|-----------------|-----------|
| x86_64 | RHEL 9 / AlmaLinux 9 / Rocky Linux 9 | `x86_64` |
| aarch64 | Oracle Linux 9 (OEL9) | `aarch64` |

`vm_arch` tek değişkeni tüm platform seçimlerini yönetir: paket URL'leri,
UEFI firmware, seed ISO bağlama yöntemi, EPEL kaynak seçimi otomatik değişir.

### Controller Gereksinimleri

```bash
# Ansible koleksiyonları (ilk kurulumda bir kez)
cd patroni-kurulum
ansible-galaxy collection install -r requirements.yml

# sshpass (parola tabanlı SSH için)
dnf install -y sshpass
```

### Patroni Düğümü Ön Koşulları

- VM veya fiziksel sunucu, RHEL 9 / AlmaLinux 9 / OEL9 kurulu
- SSH ile root erişimi aktif
- `/var/lib/pgsql` ve `/var/lib/pgwal` için bağlanabilir disk (`separate_wal: true` ise)
- Düğümler birbirini cluster IP'den çözebilmeli (DNS veya `/etc/hosts`)
- İnternet erişimi — PGDG + EPEL için (veya yerel mirror)

### HAProxy Düğümü Ön Koşulları

- İki VM çalışıyor, SSH root erişimi aktif
- Patroni düğümlerine (public IP, :8008) erişebiliyor

---

## 3. Playbook'lar ve Akış

### Giriş Noktası

```bash
# Tam kurulum — tüm adımlar sırayla
ansible-playbook playbooks/patroni-infra-kur.yml

# Seçici (tag ile)
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni
ansible-playbook playbooks/patroni-infra-kur.yml --tags haproxy
ansible-playbook playbooks/patroni-infra-kur.yml --tags security
ansible-playbook playbooks/patroni-infra-kur.yml --tags pg_tune
ansible-playbook playbooks/patroni-infra-kur.yml --tags pcp
ansible-playbook playbooks/patroni-infra-kur.yml --tags test
ansible-playbook playbooks/patroni-infra-kur.yml --tags health
ansible-playbook playbooks/patroni-infra-kur.yml --tags aliases

# Tek düğüm
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni --limit patroni01

# Dry-run
ansible-playbook playbooks/patroni-infra-kur.yml --check --diff
```

### Playbook Hiyerarşisi

```
playbooks/
├── patroni-infra-kur.yml          ← Giriş noktası (import_playbook)
│
├── 01-patroni.yml   [tag: patroni]   Patroni kümesi
│   ├── Play 0 — Precheck             SSH ping, assert
│   ├── Play 1 — auto_tune ★          Donanım tespiti → PG parametre hesaplama
│   ├── Play 2 — common + storage     Sistem + disk hazırlığı
│   ├── Play 2b — pg_tune             OS PostgreSQL optimizasyonu
│   ├── Play 3 — etcd                 DCS kümesi
│   ├── Play 4 — patroni              PostgreSQL 18 + Patroni
│   ├── Play 5 — resource_limits      OOM koruması, cgroup
│   ├── Play 6 — verify               Küme doğrulama
│   └── Rapor   → reports/patroni-kurulum-*.{txt,html}  (AUTO-TUNE bölümü dahil)
│
├── 02-haproxy.yml   [tag: haproxy]   HAProxy + Keepalived + PgBouncer
│   ├── Play 0 — Precheck
│   ├── Play 1 — auto_tune ★          Donanım tespiti → HAProxy/PgBouncer parametre hesaplama
│   ├── Play 2 — haproxy
│   ├── Play 3 — keepalived
│   ├── Play 4 — pgbouncer
│   ├── Play 5 — resource_limits
│   ├── Play 6 — verify
│   └── Rapor   → reports/haproxy-kurulum-*.{txt,html}  (AUTO-TUNE bölümü dahil)
│
├── 03-security.yml  [tag: security]  Güvenlik sertleştirme
│   ├── Aşama 1 — Snapshot (öncesi durum)
│   ├── Aşama 2 — security rolü
│   ├── Aşama 3 — Seri rolling reboot
│   ├── Aşama 4 — Doğrulama
│   └── Aşama 5 — reports/security-report-*.html
│
├── 04-pcp-setup.yml [tag: pcp]       PCP izleme ajanı
├── 05-db-test.yml   [tag: test]      pgbench performans testi
├── 06-health-report.yml [tag: health] Kapsamlı sağlık raporu
└── 07-admin-aliases.yml [tag: aliases] Shell alias sistemi
```

---

## 4. Değişken Dosyaları ve Yapılandırma

### Dosya Yapısı

```
inventory/
├── infra.yml                     ← TEK inventory (patroni + haproxy + localhost)
└── group_vars/
    └── all/
        ├── vars.yml              ← Tüm değişkenler (A–G bölümleri)
        └── vault.yml             ← Şifreli parolalar (ansible-vault)
```

### vars.yml Bölümleri

| Bölüm | Değişkenler |
|-------|-------------|
| **0** | `auto_tune_enabled` — donanım bazlı otomatik hesaplama açma/kapama |
| **A** | `vm_arch`, donanım, ağlar, `postgres_version: 18`, `patroni_scope` |
| **B** | HAProxy VIP/portları, PgBouncer portları, Patroni düğümleri |
| **C** | vBMC (IPMI) host ve port ayarları |
| **D** | Reboot zaman aşımları ve gecikmeler |
| **E** | PostgreSQL 18 tuning — `auto_tune: true` iken FALLBACK; kapalıyken aktif |
| **F** | pgbench test parametreleri (scale, clients, threads, duration) |
| **G** | Sağlık raporu parametreleri ve uyarı eşikleri |

### Kritik Değişkenler

```yaml
# inventory/group_vars/all/vars.yml

# ── BÖLÜM 0 — Auto-tune (varsayılan: true) ───────────────────────────
# true  → roles/auto_tune RAM/vCPU'yu okur, PG+HAProxy değerlerini override eder
# false → aşağıdaki BÖLÜM E sabit değerleri kullanılır
auto_tune_enabled: true

# ── Platform ──────────────────────────────────────────────────────────
vm_arch: x86_64
postgres_version: 18

# ── Ağ ───────────────────────────────────────────────────────────────
haproxy_vip: 10.253.10.56
haproxy_write_port: 5432
haproxy_read_port: 5433
haproxy_stats_port: 7000
pgbouncer_write_port: 6432
pgbouncer_read_port: 6433

# ── Patroni ──────────────────────────────────────────────────────────
patroni_scope: pg-cluster
separate_wal: true

# ── PostgreSQL 18 Tuning (Bölüm E — auto_tune: false iken geçerli) ──
pg_shared_buffers: "16GB"        # FALLBACK — auto_tune override eder (RAM × 0.25)
pg_effective_cache_size: "48GB"  # FALLBACK — auto_tune override eder (RAM × 0.75)
pg_work_mem: "16MB"              # FALLBACK — auto_tune override eder
pg_wal_compression: "lz4"        # PG 18: pglz | lz4 | zstd
pg_io_method: "io_uring"         # PG 18: Linux async I/O (kernel 5.1+)
pg_huge_pages: "on"              # pg_tune rolü hugepages.yml otomatik hesaplar
pg_summarize_wal: "off"          # Artımlı yedekleme için "on" yapın
pg_jit: "on"

# ── OS Tuning (Bölüm E — pg_os_*) ────────────────────────────────────
pg_os_thp_mode: "madvise"        # THP: madvise (PG önerisi)
pg_os_io_scheduler: "mq-deadline"# virtio-blk/SSD; NVMe için "none"
pg_os_nr_hugepages: 0            # 0 = shared_buffers'dan otomatik hesapla
```

### Parola Yönetimi — Ansible Vault

```bash
# Vault şifresini ayarla (.vault_pass — ansible.cfg tarafından okunur)
echo 'VaultSifreniz' > .vault_pass
chmod 0400 .vault_pass

# Yeni şifreli değer üret
ansible-vault encrypt_string 'GuvenliParola!' --name 'super_password'

# Vault dosyasını düzenle
ansible-vault edit inventory/group_vars/all/vault.yml
```

**Şifreli değişkenler (vault.yml):**

| Değişken | Açıklama |
|----------|----------|
| `super_password` | PostgreSQL superuser parolası |
| `repl_password` | Replikasyon kullanıcısı parolası |
| `vbmc_password` | Virtual IPMI erişim parolası |
| `keepalived_auth_pass` | VRRP kimlik doğrulama parolası |

---

## 5. Roller Rehberi

### Rol Haritası

| Rol | Çalıştığı yer | Temel görev |
|-----|--------------|-------------|
| `auto_tune` | Tüm VM | Donanım tespiti (RAM/vCPU) → PG + HAProxy parametrelerini otomatik hesapla |
| `common` | Patroni VM | chrony, /etc/hosts, PGDG/EPEL repo, paketler, firewalld, SELinux port, softdog |
| `storage` | Patroni VM | LVM (vg_pgdata/vg_pgwal), XFS, mount, SELinux fcontext |
| `pg_tune` | Patroni VM | OS sysctl, THP→madvise, I/O scheduler, PAM limits, huge pages |
| `etcd` | Patroni VM | /etc/etcd/etcd.conf, systemd override, başlatma, sağlık kontrolü |
| `patroni` | Patroni VM | /etc/patroni/patroni.yml (PG 18 parametreleriyle), patroni.service, leader bekleme |
| `resource_limits` | Tüm VM | OOMScoreAdjust=-1000, user.slice limitleri, PAM limits, SSH uyarısı |
| `haproxy` | HAProxy VM | haproxy.cfg (nbthread/maxconn/timeout vars ile), SELinux modülleri, firewall |
| `keepalived` | HAProxy VM | keepalived.conf, VRRP instance, VIP |
| `pgbouncer` | HAProxy VM | pgbouncer.ini + pgbouncer-ro.ini, userlist.txt, firewall |
| `security` | Tüm VM | sysctl, PAM, SSH sertleştirme, auditd kuralları, SELinux |
| `pcp_setup` | Patroni VM | PCP ajanı kurulumu, SELinux modülleri |
| `db_test` | HAProxy VM | pgbench kurulumu ve çalıştırma, sonuç raporu |
| `infra_health` | Tüm VM | 11 adımlı kapsamlı sağlık raporu (HTML + TXT) |
| `admin_aliases` | Tüm VM | /etc/profile.d/99-patroni-aliases.sh — 50+ alias |

### `auto_tune` Rolü — Donanım Bazlı Otomatik Parametre Hesaplama

`auto_tune` rolü `tags: [always]` ile çalışır — kurulumun **her adımında** (seçici tag kullansanız bile) tetiklenir. Ansible fact'lerinden (`ansible_memtotal_mb`, `ansible_processor_vcpus`) gerçek donanımı okur, optimal değerleri hesaplar ve `set_fact` ile override eder.

```
auto_tune/
├── defaults/main.yml         ← Formül sabitleri (oran, üst sınır, tüm override edilebilir)
└── tasks/
    ├── main.yml              ← Dispatch: patroni vs haproxy grubu
    ├── patroni.yml           ← 13 PG parametresi: shared_buffers, work_mem, vb.
    └── haproxy.yml           ← 5 HAProxy/PgBouncer parametresi: nbthread, maxconn, vb.
```

**Hesaplanan parametreler:**

| Parametre | Formül | Örnek (256GB / 32 vCPU) |
|-----------|--------|------------------------|
| `shared_buffers` | RAM × 0.25 | 64GB |
| `effective_cache_size` | RAM × 0.75 | 192GB |
| `work_mem` | shared_buffers ÷ (max_conn × 4) | 81MB |
| `maintenance_work_mem` | min(2GB, RAM × 0.05) | 2GB |
| `wal_buffers` | min(128MB, shared_buffers × 2%) | 128MB |
| `max_wal_size` | max(4GB, RAM × 6.25%) | 16GB |
| `max_worker_processes` | vCPU | 32 |
| `max_parallel_workers` | max(2, vCPU/2) | 16 |
| `autovacuum_max_workers` | max(3, min(8, vCPU/4)) | 8 |
| `haproxy_nbthread` | max(2, min(8, vCPU/4)) | 8 |
| `haproxy_maxconn` | nbthread × 2000 | 16000 |
| `pgbouncer_max_client_conn` | max(1000, min(10000, nbthread×1500)) | 10000 |
| `pgbouncer_default_pool_size` | max(25, min(150, max_connections/2)) | 100 |

**Kapatmak veya özelleştirmek:**

```yaml
# vars.yml — auto_tune tamamen kapat
auto_tune_enabled: false

# defaults/main.yml üzerinden oranları değiştir
auto_tune_shared_buffers_ratio: 0.30    # %25 yerine %30
auto_tune_work_mem_max_mb: 512          # üst sınırı artır
auto_tune_haproxy_thread_divisor: 6     # daha az thread
```

**Sadece hesaplamaları görmek (değişiklik yapmadan):**

```bash
ansible-playbook playbooks/patroni-infra-kur.yml --tags auto_tune --check
```

### `pg_tune` Rolü — OS PostgreSQL Optimizasyonu

```
pg_tune/
├── tasks/main.yml          ← Orkestrasyon
├── tasks/thp.yml           ← THP madvise modu + kalıcı systemd servisi
├── tasks/io_scheduler.yml  ← udev kuralı + runtime uygulama
├── tasks/hugepages.yml     ← shared_buffers'dan otomatik hesaplama
├── templates/sysctl-postgresql.conf.j2  → /etc/sysctl.d/90-postgresql.conf
└── templates/limits-postgresql.conf.j2 → /etc/security/limits.d/20-postgresql.conf
```

**Uygulanan optimizasyonlar:**

| Parametre | Değer | Açıklama |
|-----------|-------|----------|
| `vm.swappiness` | 1 | RAM mümkün olduğunca kullanılır |
| `vm.dirty_ratio` | 15 | Checkpoint baskısını kontrol altında tutar |
| `vm.dirty_background_ratio` | 5 | Arka plan flush başlangıç eşiği |
| `fs.aio-max-nr` | 1048576 | io_uring için async I/O kuyruğu |
| `kernel.sem` | 512 131072 128 512 | PG shared memory semaphore'ları |
| THP | madvise | PG huge_pages=try ile çalışır |
| I/O scheduler | mq-deadline | virtio-blk/SSD için; NVMe → none |
| Huge pages | otomatik | shared_buffers / 2MB × 1.15 |

### `resource_limits` Rolü — user.slice Bellek Limitleri

| Sistem RAM | MemoryHigh (soft) | MemoryMax (hard) |
|-----------|-------------------|------------------|
| ≤ 4 GB | 1 GB | 1.5 GB |
| > 4 GB | 1.5 GB | 2 GB |

Manuel override: `user_slice_memory_high`, `user_slice_memory_max` değişkenleri.

---

## 6. Adım Adım Kurulum

### 6.1 Ön Hazırlık

```bash
cd patroni-kurulum

# 1. Ansible koleksiyonları
ansible-galaxy collection install -r requirements.yml

# 2. Vault şifresini ayarla
echo 'VaultSifreniz' > .vault_pass && chmod 0400 .vault_pass

# 3. inventory/infra.yml — IP adreslerini düzenle
vim inventory/infra.yml

# 4. Değişkenleri gözden geçir
vim inventory/group_vars/all/vars.yml

# 5. Parolaları güncelle
ansible-vault edit inventory/group_vars/all/vault.yml

# 6. Sözdizimi kontrolü
ansible-playbook playbooks/patroni-infra-kur.yml --syntax-check

# 7. Bağlantı testi
ansible -m ping patroni:haproxy
```

### 6.2 Tam Kurulum

```bash
ansible-playbook playbooks/patroni-infra-kur.yml
```

### 6.3 Sık Yapılan Hatalar

| Hata | Neden | Çözüm |
|------|-------|-------|
| `node_name is defined` assert | inventory'de `node_name` eksik | infra.yml'de her hosta ekle |
| `nodes listesi eşleşmiyor` | nodes sayısı ≠ host sayısı | İkisini de 3 yap |
| `Connection refused` | VM çalışmıyor / SSH kapalı | VM başlat, SSH kontrol et |
| `etcd cluster not healthy` | Cluster ağı sorunlu | enp10s0 bağlantısını kontrol et |
| `HAProxy 503 Backend` | Patroni henüz hazır değil | `pt-list` ile küme durumunu kontrol et |
| `rc: 137` (Ansible OOM) | user.slice MemoryMax çok düşük | `user_slice_memory_max: "2G"` ayarla |
| `io_uring not supported` | Kernel veya güvenlik politikası | `pg_io_method: "worker"` yap |
| `huge_pages başlamıyor` | nr_hugepages yetersiz | `pg_huge_pages: "try"` kullan |

---

## 7. Admin Alias Sistemi

`playbooks/07-admin-aliases.yml` ile tüm düğümlere dağıtılır.

```bash
# Yeni oturumda otomatik yüklenir
# Mevcut oturumda:
source /etc/profile.d/99-patroni-aliases.sh
```

### Patroni Düğümü (pt-/pg-/etcd-)

| Alias | Açıklama |
|-------|----------|
| `pt-list` | Küme durumu |
| `pt-switchover` | Planlı leader devri |
| `pt-failover` | Acil failover |
| `pt-pause` / `pt-resume` | Failover durdur/devam |
| `pt-reload` | Konfigürasyon yeniden yükle |
| `pt-reinit NODE` | Replica'yı sıfırla |
| `pt-diagnose` | Otomatik aksaklık analizi |
| `pg-repl-status` | Replikasyon gecikmesi |
| `pg-slow-queries` | Yavaş sorgular (>1s) |
| `pg-connections` | Bağlantı dağılımı |
| `pg-locks` | Aktif kilitler |
| `pg-cache-hit` | Buffer hit oranı |
| `pg-txid-age` | Transaction ID wraparound |
| `pg-wal-info` | WAL üretim hızı |
| `pg-checkpoint-stats` | Checkpoint istatistikleri |
| `pg-bloat` | Tablo/index şişme |
| `etcd-health` | etcd sağlık kontrolü |
| `etcd-snapshot` | Manuel snapshot |
| `etcd-diagnose` | etcd aksaklık analizi |

### HAProxy Düğümü (ha-/kl-/pb-)

| Alias | Açıklama |
|-------|----------|
| `ha-backends` | Backend server durumu |
| `ha-reload` | Bağlantı kesmeden reload |
| `ha-disable-server BACKEND SERVER` | Backend'den çıkar |
| `ha-enable-server BACKEND SERVER` | Backend'e ekle |
| `ha-diagnose` | HAProxy aksaklık analizi |
| `kl-vip` | VIP hangi düğümde? |
| `kl-failover` | Manuel VIP geçişi |
| `kl-diagnose` | VIP aksaklık analizi |
| `pb-pools` | Bağlantı havuzu durumu |
| `pb-reload` | Konfigürasyon yeniden yükle |
| `pb-diagnose` | PgBouncer aksaklık analizi |

### Altyapı Geneli (infra-)

| Alias | Açıklama |
|-------|----------|
| `infra-disk` | Disk kullanımı |
| `infra-mem` | Bellek durumu |
| `infra-services` | HA servis durumları |
| `infra-oom-check` | OOM kill kontrolü |
| `infra-cgroup` | user.slice cgroup limitleri |

---

## 8. Kurulum Raporları

| Playbook | Rapor | Format |
|----------|-------|--------|
| `01-patroni.yml` | `reports/patroni-kurulum-raporu.txt` | TXT |
| `02-haproxy.yml` | `reports/haproxy-kurulum-YYYY-MM-DD-HHmm.txt` | TXT |
| `02-haproxy.yml` | `reports/haproxy-kurulum-YYYY-MM-DD-HHmm.html` | HTML |
| `03-security.yml` | `reports/security-report-YYYY-MM-DD-HHmm.html` | HTML |
| `05-db-test.yml` | `reports/pgbench-YYYY-MM-DD-HHmm.txt` | TXT |
| `06-health-report.yml` | `reports/infra-health-YYYY-MM-DD-HHmm.html` | HTML |

```bash
ls -lt reports/    # Tüm raporları listele

# Raporu yeniden oluştur
ansible-playbook playbooks/patroni-infra-kur.yml --tags health
ansible-playbook playbooks/patroni-infra-kur.yml --tags verify
```

---

## 9. Yaşam Döngüsü Yönetimi

### 9.1 Günlük Kontroller

```bash
pt-list          # 1 Leader + 2 Replica streaming?
etcd-health      # 3 üye sağlıklı?
ha-backends      # Backend'ler UP?
kl-vip           # VIP nerede?
infra-disk       # Disk doluluk?
infra-oom-check  # OOM kill var mı?
```

### 9.2 Planlı Switchover

```bash
pt-list
pt-switchover    # İnteraktif — hangi node'a geçeceğini sorar
pt-list          # Yeni leader'ı doğrula
```

### 9.3 Yapılandırma Değişikliği

```bash
# Dinamik parametre (restart gerektirmez)
pt-edit-config
pt-reload

# Restart gerektiren (shared_buffers, max_connections vb.)
pt-edit-config
pt-list               # "Pending restart" işaretini gör
patronictl -c /etc/patroni/patroni.yml restart pg-cluster --scheduled now
```

### 9.4 Ansible ile Güncelleme

```bash
# Sadece Patroni konfigürasyonu
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni

# Sadece OS tuning (sysctl, hugepages, I/O)
ansible-playbook playbooks/patroni-infra-kur.yml --tags pg_tune

# Kaynak limitleri (RAM değişti)
ansible-playbook playbooks/patroni-infra-kur.yml --tags limits

# Alias'ları güncelle
ansible-playbook playbooks/patroni-infra-kur.yml --tags aliases

# Tek düğümde
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni --limit patroni01
```

### 9.5 etcd Yedekleme

```bash
# Manuel
etcd-snapshot

# Otomatik cron (Ansible kurulur, 04:00, etcd kullanıcısı)
crontab -u etcd -l
```

### 9.6 PostgreSQL Yedekleme

```bash
# pg_basebackup — replica üzerinden (primary'ye yük bindirme)
pg_basebackup \
  -h 10.255.255.52 -p 5432 \
  -U replicator \
  -D /backup/pg-$(date +%F) \
  -Ft -Xs -P --checkpoint=fast

# pgBackRest (önerilir — artımlı yedek, PITR)
dnf install -y pgbackrest
pgbackrest --stanza=pg-cluster backup --type=full
pgbackrest --stanza=pg-cluster backup --type=incr
pgbackrest --stanza=pg-cluster restore --target="2026-06-28 14:00:00"

# PG 18 Artımlı Yedek (summarize_wal: on ise)
# summarize_wal'ı etkinleştir:
# inventory/group_vars/all/vars.yml → pg_summarize_wal: "on"
# ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni
pg_basebackup -h 10.255.255.52 -p 5432 -U replicator \
  --incremental=/backup/pg-full-2026-06-01/backup_manifest \
  -D /backup/pg-incr-$(date +%F) -Ft --checkpoint=fast
```

### 9.7 DR Tatbikat (6 Ayda Bir)

```bash
# Test ortamında gerçekleştirin. Her madde manuel doğrulama gerektirir.

# 1. etcd snapshot + geri yükleme testi
etcd-snapshot
ETCDCTL_API=3 etcdctl snapshot info /backup/etcd-$(date +%F)*.db

# 2. Failover simülasyonu
ssh patroni01 "systemctl stop patroni"
pt-list    # Yeni leader seçildi mi?
ssh patroni01 "systemctl start patroni"
pt-list    # streaming geri döndü mü?

# 3. VIP geçiş testi
ssh haproxy01 "systemctl stop keepalived"
kl-vip     # haproxy02'ye geçti mi?
ssh haproxy01 "systemctl start keepalived"

# 4. Replica reinit testi
ssh patroni02 "rm -rf /var/lib/pgwal/*"
pt-reinit patroni02.local.lab
pt-list    # streaming oldu mu?

# 5. RTO ölçümü: failover başlangıcından yeni leader'a kadar geçen süre
```

---

## 10. Güvenlik

### 10.1 Sertleştirme

```bash
# Tüm altyapı
ansible-playbook playbooks/patroni-infra-kur.yml --tags security

# Raporu incele
ls -lt reports/security-report-*.html | head -1
```

### 10.2 Uygulanan Kontroller

| Kategori | Öne Çıkanlar |
|----------|-------------|
| sysctl güvenlik | ASLR=2, SYN flood, IP spoofing, ptrace kısıtı |
| sysctl PostgreSQL | vm.swappiness=1, dirty ratios, fs.aio-max-nr=1M |
| PAM | Fork bomb (nproc), nofile, core dump engeli |
| Systemd | NoNewPrivileges, PrivateTmp, ProtectSystem |
| SSH | MaxAuthTries=3, rate limit |
| Audit | Kimlik, yetki, config, fork (50+ kural), PG 18 config dosyaları |
| SELinux | Enforcing, custom modüller (haproxy, keepalived, pcp) |
| OOM | Kritik servisler: OOMScoreAdjust=-1000 |

### 10.3 TLS Eklemek (Üretim)

**etcd TLS:**
```yaml
# /etc/etcd/etcd.conf
client-transport-security:
  cert-file: /etc/etcd/tls/server.crt
  key-file: /etc/etcd/tls/server.key
  trusted-ca-file: /etc/etcd/tls/ca.crt
```

**Patroni REST API:**
```yaml
# /etc/patroni/patroni.yml → restapi:
certfile: /etc/patroni/tls/server.crt
keyfile: /etc/patroni/tls/server.key
```

**PostgreSQL:**
```bash
pt-edit-config
# parameters: ssl: "on"   (vars.yml'de pg_ssl: "off" → "on")
```

---

## 11. İzleme ve Alarm

### 11.1 PCP

```bash
systemctl status pmcd pmlogger
pmstat -s 5 -t 2sec          # Anlık metrikler
pminfo postgresql              # PG metrikleri
```

### 11.2 Prometheus Alert Önerileri

```yaml
groups:
  - name: patroni-pg18-ha
    rules:
      - alert: PatroniLeaderYok
        expr: count(patroni_master) == 0
        for: 30s
        annotations: {severity: critical}

      - alert: ReplikasyonGecikmesi
        expr: pg_replication_lag_bytes > 104857600
        for: 5m
        annotations: {severity: warning}

      - alert: EtcdQuorumKaybi
        expr: etcd_server_has_quorum == 0
        annotations: {severity: critical}

      - alert: DiskDoluluk
        expr: >
          (node_filesystem_free_bytes{mountpoint=~"/var/lib/pgsql|/var/lib/pgwal"}
          / node_filesystem_size_bytes) < 0.20
        for: 10m
        annotations: {severity: warning}

      - alert: OOMKill
        expr: increase(node_vmstat_oom_kill[5m]) > 0
        annotations: {severity: critical}

      - alert: VIPKaybi
        expr: absent(keepalived_vrrp_state{state="master"})
        for: 30s
        annotations: {severity: critical}

      - alert: HugePagesAzaldi
        expr: node_memory_HugePages_Free < 50
        for: 5m
        annotations: {severity: warning}
```

---

## 12. Sorun Giderme

### 12.1 etcd Başlamıyor

```bash
journalctl -u etcd -n 50 --no-pager

# Cluster ağı test
ping -I enp10s0 10.255.255.52

# Kirli veri temizle (3 node'da eş zamanlı)
systemctl stop etcd && rm -rf /var/lib/etcd/* && systemctl start etcd

# Config doğrulama
/usr/bin/etcd --config-file /etc/etcd/etcd.conf --validate-config
```

### 12.2 Patroni Başlamıyor

```bash
journalctl -u patroni -n 100 --no-pager
ls /var/lib/pgsql/18/data/           # PGDATA boş mu?
curl http://10.255.255.51:2379/health  # etcd erişilebilir mi?

# Manuel başlatma (hata mesajını görmek için)
sudo -u postgres /usr/bin/patroni /etc/patroni/patroni.yml
```

### 12.3 io_uring Çalışmıyor

```bash
# Kernel desteği
grep io_uring /boot/config-$(uname -r)

# Geçici devre dışı
pt-edit-config    # io_method: worker

# Kalıcı: vars.yml → pg_io_method: "worker"
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni
```

### 12.4 Huge Pages Yetersiz

```bash
grep HugePages /proc/meminfo

# Otomatik hesaplamayı çalıştır
ansible-playbook playbooks/patroni-infra-kur.yml --tags pg_tune

# Manuel (1GB shared_buffers, 2MB huge page → min 590)
# vars.yml: pg_os_nr_hugepages: 600
```

### 12.5 HAProxy Backend DOWN

```bash
ha-backends
curl -v http://10.253.10.51:8008/primary    # 200 = primary
curl -v http://10.253.10.51:8008/replica    # 200 = replica
ausearch -m avc -ts recent | grep haproxy  # SELinux AVC
```

### 12.6 VIP Geçişi Çalışmıyor

```bash
kl-vip                # VIP hangi node'da?
kl-diagnose           # Otomatik analiz
journalctl -u keepalived | grep -E "MASTER|BACKUP|FAULT"
firewall-cmd --list-rich-rules | grep vrrp
```

### 12.7 OOM Kill Sonrası

```bash
infra-oom-check
infra-cgroup                # user.slice limitleri

# Geçici: root için limit kaldır
systemd-run --scope --uid=0 -p MemoryMax=infinity -- <komut>

# Kalıcı: vars.yml → user_slice_memory_max: "2G"
ansible-playbook playbooks/patroni-infra-kur.yml --tags limits
```

---

## 13. Temizlik

### Patroni Kümesini Sıfırla

```bash
# Tüm node'larda (veri KAYBOLUR)
for node in patroni01 patroni02 patroni03; do
  ssh $node "systemctl stop patroni etcd"
  ssh $node "rm -rf /var/lib/etcd/* /var/lib/pgsql/18/data/* /var/lib/pgwal/*"
done
# Yeniden kur
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni
```

### Tek Düğümü Yeniden Entegre Et

```bash
ssh patroni02 "rm -rf /var/lib/pgwal/*"   # separate_wal: true ise
pt-reinit patroni02.local.lab
pt-list
```

---

## 14. Hızlı Referans

### Kritik Dosyalar

| Dosya | Konum |
|-------|-------|
| Patroni config | `/etc/patroni/patroni.yml` |
| etcd config | `/etc/etcd/etcd.conf` |
| etcd override | `/etc/systemd/system/etcd.service.d/override.conf` |
| HAProxy config | `/etc/haproxy/haproxy.cfg` |
| PgBouncer yazma | `/etc/pgbouncer/pgbouncer.ini` |
| PgBouncer okuma | `/etc/pgbouncer/pgbouncer-ro.ini` |
| PgBouncer kullanıcılar | `/etc/pgbouncer/userlist.txt` |
| Keepalived config | `/etc/keepalived/keepalived.conf` |
| PG sysctl (performans) | `/etc/sysctl.d/90-postgresql.conf` |
| Güvenlik sysctl | `/etc/sysctl.d/90-security.conf` |
| PG PAM limits | `/etc/security/limits.d/20-postgresql.conf` |
| user.slice limitleri | `/etc/systemd/system/user.slice.d/10-limits.conf` |
| OOM koruması | `/etc/systemd/system/<svc>.service.d/oom-protect.conf` |
| Admin alias'ları | `/etc/profile.d/99-patroni-aliases.sh` |
| PG data | `/var/lib/pgsql/18/data/` |
| PG WAL | `/var/lib/pgwal/` |
| PG binary | `/usr/pgsql-18/bin/` |

### Port Referansı

| Port | Protokol | Servis | Açıklama |
|------|----------|--------|----------|
| 5432 | TCP | PostgreSQL / HAProxy yazma | Primary bağlantısı |
| 5433 | TCP | HAProxy okuma | Replica bağlantısı |
| 6432 | TCP | PgBouncer yazma | Uygulama yazma (VIP) |
| 6433 | TCP | PgBouncer okuma | Uygulama okuma (VIP) |
| 7000 | TCP | HAProxy stats | Web istatistik paneli |
| 8008 | TCP | Patroni REST API | Health check + yönetim |
| 2379 | TCP | etcd client | Patroni ↔ etcd |
| 2380 | TCP | etcd peer | etcd ↔ etcd (Raft) |
| 44321 | TCP | PCP pmcd | PCP metrik ajanı |

### Kurulum Sonrası Kontrol Listesi

- [ ] `pt-list` — 1 Leader + 2 Replica streaming ✓
- [ ] `etcd-health` — 3 üye sağlıklı ✓
- [ ] `ha-backends` — pg_primary UP, pg_replicas UP ✓
- [ ] `kl-vip` — VIP aktif ✓
- [ ] `pb-pools` — cl_waiting = 0 ✓
- [ ] PG 18 parametreler: `SHOW io_method; SHOW wal_compression;`
- [ ] Huge pages: `grep HugePages /proc/meminfo` — Free > 0 ✓
- [ ] Güvenlik raporu: `reports/security-report-*.html` — 0 AVC ✓
- [ ] pgbench testi: `reports/pgbench-*.txt` ✓
- [ ] Sağlık raporu: `reports/infra-health-*.html` ✓
- [ ] Vault parolalarını üretim değerleriyle güncelle
- [ ] SSH parola girişini kapat (`PasswordAuthentication no`)
- [ ] TLS yapılandır (etcd + Patroni REST API + PostgreSQL)
- [ ] HAProxy stats'a kimlik doğrulama ekle
- [ ] Yedekleme stratejisi kur ve test et (pgBackRest)
- [ ] Failover senaryosunu test et: `pt-switchover`
- [ ] Disaster recovery tatbikatı planla
