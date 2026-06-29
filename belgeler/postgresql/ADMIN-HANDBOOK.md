# PATRONI HA KÜMESİ — SİSTEM YÖNETİCİSİ EL KİTABI

**Sürüm:** v1.2 (2026-06-28)
**Kapsam:** Linux Sunucu Yönetimi · Patroni · etcd · HAProxy · Keepalived · PgBouncer · PCP

---

## İçindekiler

1. [Ortam Bilgisi ve Mimari](#1-ortam-bilgisi-ve-mimari)
2. [Hızlı Başvuru Kartı](#2-hızlı-başvuru-kartı)
3. [Admin Alias Sistemi](#3-admin-alias-sistemi)
4. [Günlük Rutin Kontroller](#4-günlük-rutin-kontroller)
5. [Linux Servis Yönetimi](#5-linux-servis-yönetimi)
6. [PostgreSQL 18 Yönetimi](#6-postgresql-18-yönetimi)
7. [Patroni Yönetimi](#7-patroni-yönetimi)
8. [etcd Yönetimi](#8-etcd-yönetimi)
9. [HAProxy Yönetimi](#9-haproxy-yönetimi)
10. [Keepalived Yönetimi](#10-keepalived-yönetimi)
11. [PgBouncer Yönetimi](#11-pgbouncer-yönetimi)
12. [PCP İzleme](#12-pcp-izleme)
13. [OS Performans Ayarları (pg_tune + auto_tune)](#13-os-performans-ayarları-pg_tune--auto_tune)
14. [Log Yönetimi](#14-log-yönetimi)
15. [Kaynak İzleme ve cgroup Limitleri](#15-kaynak-izleme-ve-cgroup-limitleri)
16. [Yedekleme ve Geri Yükleme](#16-yedekleme-ve-geri-yükleme)
17. [Güncelleme Prosedürleri](#17-güncelleme-prosedürleri)
18. [Aksaklık Giderme Rehberi](#18-aksaklık-giderme-rehberi)
19. [Disaster Recovery](#19-disaster-recovery)
20. [Güvenlik Yönetimi](#20-güvenlik-yönetimi)

**Ekler:**
- [Ek A: Üretim Geçiş Kontrol Listesi](#ek-a-üretim-geçiş-kontrol-listesi)
- [Ek B: Günlük Rutin Kontrol Listesi](#ek-b-günlük-rutin-kontrol-listesi)
- [Ek C: DR Tatbikat Checklist (6 Ayda Bir)](#ek-c-dr-tatbikat-checklist-6-ayda-bir)
- [Ek D: Performans Ayarı](#ek-d-performans-ayarı)

---

## 1. Ortam Bilgisi ve Mimari

### 1.1 Sunucu Envanteri

| Rol | Hostname | Public IP | Cluster IP | OS |
|-----|----------|-----------|------------|----|
| Patroni / etcd | patroni01.local.lab | 10.253.10.51 | 10.255.255.51 | RHEL 9 / OEL 9 |
| Patroni / etcd | patroni02.local.lab | 10.253.10.52 | 10.255.255.52 | RHEL 9 / OEL 9 |
| Patroni / etcd | patroni03.local.lab | 10.253.10.53 | 10.255.255.53 | RHEL 9 / OEL 9 |
| HAProxy / Keepalived / PgBouncer | haproxy01 | 10.253.10.54 | — | RHEL 9 / OEL 9 |
| HAProxy / Keepalived / PgBouncer | haproxy02 | 10.253.10.55 | — | RHEL 9 / OEL 9 |
| Sanal IP (VIP) | — | **10.253.10.56** | — | Keepalived yönetir |

### 1.2 Port Haritası

| Servis | Port | Protokol | Açıklama |
|--------|------|----------|----------|
| PostgreSQL 18 | 5432 | TCP | Doğrudan PG bağlantısı |
| Patroni REST API | 8008 | HTTP | Sağlık kontrolü, yönetim |
| etcd client | 2379 | HTTP | DCS istemci (cluster ağı) |
| etcd peer | 2380 | HTTP | Düğümlerarası (cluster ağı) |
| HAProxy yazma | 5432 | TCP | VIP üzerinden Primary |
| HAProxy okuma | 5433 | TCP | VIP üzerinden Replica'lar |
| HAProxy stats | 7000 | HTTP | İstatistik paneli |
| PgBouncer yazma | 6432 | TCP | Bağlantı havuzu → Primary |
| PgBouncer okuma | 6433 | TCP | Bağlantı havuzu → Replica |
| PCP pmcd | 44321 | TCP | Performans metrik ajanı |

### 1.3 Ağ Tasarımı

```
                    ┌───────────────────────────────────────┐
   Uygulama         │   VIP: 10.253.10.56                   │
   Sunucuları ──────┤   PgBouncer :6432 (yazma → Primary)   │
                    │   PgBouncer :6433 (okuma → Replica)   │
                    └──────────────┬────────────────────────┘
                                   │ Public Network (10.253.10.0/24)
                 ┌─────────────────┼─────────────────┐
                 │                 │                 │
          haproxy01           haproxy02         [doğrudan]
          10.253.10.54        10.253.10.55      10.253.10.51-53
          (VRRP MASTER)       (VRRP BACKUP)
                 │                 │
                 └────────┬────────┘
                          │ Health Check: GET /primary, /replica (8008)
              ┌───────────┼───────────┐
              │           │           │
        patroni01    patroni02    patroni03
        10.253.10.51  .52         .53  ← Public NIC (pub0)
        10.255.255.51 .52         .53  ← Cluster NIC (clu0)
        [LEADER]     [Replica]    [Replica]
        etcd peer    etcd peer    etcd peer
              │           │           │
              └───────────┴───────────┘
                   Cluster Network (10.255.255.0/24)
                   etcd peer :2380 | etcd client :2379
                   PostgreSQL replikasyon :5432
```

**İki ağ tasarımının amacı:**
- **pub0** (`patroni-public`, 10.253.10.0/24): İstemci trafiği + Patroni REST API (8008)
- **clu0** (`patroni-cluster`, 10.255.255.0/24): etcd DCS + PostgreSQL replikasyon

Bu ayrım, replikasyon trafiğinin uygulama trafiğini etkilememesini sağlar.

---

### 1.4 Kritik Dosya Konumları

| Dosya | Konum | Açıklama |
|-------|-------|----------|
| Patroni config | `/etc/patroni/patroni.yml` | Küme, PG 18, etcd, watchdog |
| etcd config | `/etc/etcd/etcd.conf` | Dinleme adresleri, peer, data-dir |
| etcd override | `/etc/systemd/system/etcd.service.d/override.conf` | ExecStart zorlaması |
| HAProxy config | `/etc/haproxy/haproxy.cfg` | Backend'ler, health check |
| PgBouncer yazma | `/etc/pgbouncer/pgbouncer.ini` | Primary havuzu :6432 |
| PgBouncer okuma | `/etc/pgbouncer/pgbouncer-ro.ini` | Replica havuzu :6433 |
| PgBouncer kullanıcılar | `/etc/pgbouncer/userlist.txt` | MD5 hash kimlik bilgileri |
| PG data | `/var/lib/pgsql/18/data/` | PGDATA |
| PG WAL | `/var/lib/pgwal/` | Ayrı WAL diski |
| PG binary | `/usr/pgsql-18/bin/` | PG 18 araçları |
| Admin alias'ları | `/etc/profile.d/99-patroni-aliases.sh` | 50+ sistem geneli alias |
| PG sysctl | `/etc/sysctl.d/90-postgresql.conf` | pg_tune optimizasyonları |
| Güvenlik sysctl | `/etc/sysctl.d/90-security.conf` | Güvenlik sertleştirme |
| PG PAM limits | `/etc/security/limits.d/20-postgresql.conf` | postgres kullanıcı limitleri |
| user.slice | `/etc/systemd/system/user.slice.d/10-limits.conf` | SSH kullanıcı kaynakları |
| OOM koruması | `/etc/systemd/system/<svc>.service.d/oom-protect.conf` | Servis OOM skoru |

---

## 2. Hızlı Başvuru Kartı

```bash
# ── KÜME DURUMU ─────────────────────────────────────────────────────────
pt-list

# ── etcd SAĞLIK ─────────────────────────────────────────────────────────
etcd-health

# ── PATRONI REST API (tüm node'lar) ─────────────────────────────────────
for ip in 10.253.10.51 10.253.10.52 10.253.10.53; do
  echo -n "$ip: "
  curl -s http://$ip:8008/health | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('role','?').upper(), d.get('state','?'))"
done

# ── HAProxy BACKEND ─────────────────────────────────────────────────────
ha-backends

# ── VIP SAHİBİ ──────────────────────────────────────────────────────────
kl-vip

# ── SERVİS DURUMU ───────────────────────────────────────────────────────
# Patroni node'larında:
systemctl status patroni etcd
# HAProxy node'larında:
systemctl status haproxy keepalived pgbouncer pgbouncer-ro

# ── REPLIKASYON (Primary psql ile) ──────────────────────────────────────
pg-repl-status

# ── LOG TAKIBI ──────────────────────────────────────────────────────────
journalctl -u patroni -f
journalctl -u etcd -f
journalctl -u haproxy -f

# ── PLANLI SWITCHOVER ───────────────────────────────────────────────────
pt-switchover

# ── ACİL FAILOVER ───────────────────────────────────────────────────────
pt-failover

# ── AKSAKLIK ANALİZİ ────────────────────────────────────────────────────
pt-diagnose      # Patroni düğümünde
ha-diagnose      # HAProxy düğümünde
etcd-diagnose    # Patroni düğümünde
```

---

## 3. Admin Alias Sistemi

Kurulumda `/etc/profile.d/99-patroni-aliases.sh` tüm düğümlere dağıtılır.
Yeni SSH oturumunda otomatik yüklenir.

```bash
# Mevcut oturumda yükle
source /etc/profile.d/99-patroni-aliases.sh

# Alias'ları güncelle (Ansible ile)
ansible-playbook playbooks/patroni-infra-kur.yml --tags aliases
```

### Ortam Değişkenleri (Otomatik Ayarlı)

| Değişken | Değer |
|----------|-------|
| `PATRONI_CONFIG` | `/etc/patroni/patroni.yml` |
| `ETCDCTL_API` | `3` |
| `ETCD_ENDPOINTS` | `http://10.255.255.51:2379,http://10.255.255.52:2379,...` |
| `PGPASSWORD` | vault'tan gelen super_password |
| `PSQL_BIN` | `/usr/pgsql-18/bin/psql` |

### Alias Grupları

**Patroni düğümleri:** `pt-*` (Patroni), `pg-*` (PostgreSQL), `etcd-*` (etcd)
**HAProxy düğümleri:** `ha-*` (HAProxy), `kl-*` (Keepalived), `pb-*` (PgBouncer)
**Tüm düğümler:** `infra-*`

Her grup `*-diagnose` fonksiyonu içerir — sorunları otomatik analiz eder.

---

## 4. Günlük Rutin Kontroller

### 4.1 Küme Genel Sağlık

```bash
# Patroni küme durumu
pt-list

# Beklenen çıktı:
# + Cluster: pg-cluster ---+-----------+-----+
# | Member              | Role    | State     | TL | Lag |
# | patroni01.local.lab | Leader  | running   |  2 |   0 |
# | patroni02.local.lab | Replica | streaming |  2 |   0 |
# | patroni03.local.lab | Replica | streaming |  2 |   0 |

# Dikkat edilecekler:
# - State: running (Leader) / streaming (Replica) — başka değer sorun işareti
# - TL: Tüm node'larda aynı olmalı
# - Lag: Replica'larda 0 veya düşük olmalı (MB)
```

### 4.2 etcd Sağlık

```bash
etcd-health      # Tüm üyelerin durumu
etcd-members     # Üye listesi ve Raft rolleri
```

### 4.3 Replikasyon Gecikmesi

```bash
pg-repl-status   # Alias (primary'de çalıştır)

# Manuel:
PGPASSWORD=<super_password> /usr/pgsql-18/bin/psql -U postgres -c "
SELECT client_addr, state,
       pg_size_pretty(sent_lsn - replay_lsn) AS lag,
       sync_state
FROM pg_stat_replication;"
```

### 4.4 HAProxy ve VIP

```bash
ha-backends   # Backend'lerin UP/DOWN durumu
kl-vip        # VIP hangi node'da
```

### 4.5 Disk Kullanımı

```bash
infra-disk     # Alias

# Manuel:
df -h /var/lib/pgsql /var/lib/pgwal /var/lib/etcd
# Uyarı: %80 doluluğa gelince aksiyon al
```

### 4.6 OOM ve Sistem Olayları

```bash
infra-oom-check     # OOM kill kontrolü

# Detaylı:
journalctl --since "24 hours ago" | grep -iE "oom|killed process|out of memory"
journalctl --since "24 hours ago" -p crit..emerg
```

### 4.7 PCP Metrikleri

```bash
# Anlık sistem metrikleri
pmstat -s 3 -t 2sec

# PostgreSQL metrikleri
pminfo -f postgresql.connections.total
```

---

## 5. Linux Servis Yönetimi

### 5.1 systemctl Temel Komutları

```bash
# Durum (detaylı — cgroup limitleri dahil)
systemctl status patroni
systemctl status etcd
systemctl status haproxy
systemctl status keepalived
systemctl status pgbouncer pgbouncer-ro

# Kontrol
systemctl start|stop|restart|reload patroni

# Reload (bağlantı kesmeden — HAProxy ve PgBouncer destekler)
systemctl reload haproxy
systemctl reload pgbouncer
systemctl reload pgbouncer-ro

# Önyükleme
systemctl enable|disable patroni

# Script kullanımı
systemctl is-active patroni && echo "çalışıyor" || echo "durmuş"
```

### 5.2 systemd Journal

```bash
# Son N satır
journalctl -u patroni -n 100

# Canlı takip
journalctl -u patroni -f

# Zaman aralığı
journalctl -u patroni --since "2026-06-28 08:00" --until "2026-06-28 09:00"

# Sadece hata+
journalctl -u patroni -p err

# Birden fazla servis
journalctl -u patroni -u etcd -f

# Boot'tan itibaren
journalctl -u patroni -b

# Disk kullanımı
journalctl --disk-usage

# Temizleme (30 günden eski)
journalctl --vacuum-time=30d
journalctl --vacuum-size=500M
```

### 5.3 Drop-in Dosyaları

```bash
# Mevcut drop-in'leri gör
ls /etc/systemd/system/patroni.service.d/
# OOM koruması: oom-protect.conf
# etcd ExecStart zorlaması: override.conf

# Yeni drop-in ekle (mevcut unit'i değiştirmeden)
mkdir -p /etc/systemd/system/patroni.service.d/
cat > /etc/systemd/system/patroni.service.d/custom.conf << 'EOF'
[Service]
Environment="PATRONI_SCOPE=pg-cluster"
EOF
systemctl daemon-reload && systemctl restart patroni
```

### 5.4 Systemd Timer (Zamanlanmış Görevler)

systemd timer'lar cron'un yerini alır; journal entegrasyonu ve bağımlılık yönetimi sunar.

```bash
# Mevcut timer'ları listele
systemctl list-timers

# etcd snapshot cron'u kontrol et (ansible ile kurulur)
crontab -u etcd -l

# Manuel cron çalıştırma testi
su -s /bin/bash etcd -c "ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379 \
  snapshot save /backup/etcd-test.db"
```

Özel timer örneği (haftalık VACUUM FULL):

```bash
# /etc/systemd/system/pg-weekly-vacuum.service
cat > /etc/systemd/system/pg-weekly-vacuum.service << 'EOF'
[Unit]
Description=PostgreSQL Weekly VACUUM ANALYZE

[Service]
Type=oneshot
User=postgres
ExecStart=/usr/pgsql-18/bin/psql -U postgres -c "VACUUM ANALYZE;"
EOF

# /etc/systemd/system/pg-weekly-vacuum.timer
cat > /etc/systemd/system/pg-weekly-vacuum.timer << 'EOF'
[Unit]
Description=Weekly PostgreSQL VACUUM ANALYZE
After=patroni.service

[Timer]
OnCalendar=Sun 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl enable --now pg-weekly-vacuum.timer
systemctl list-timers pg-weekly-vacuum.timer
```

---

## 6. PostgreSQL 18 Yönetimi

### 6.1 Bağlantı

```bash
# VIP üzerinden Primary (PgBouncer havuzu)
psql -h 10.253.10.56 -p 6432 -U postgres

# VIP üzerinden Replica
psql -h 10.253.10.56 -p 6433 -U postgres

# Doğrudan Patroni node'u (geliştirme/debug)
psql -h 10.253.10.51 -p 5432 -U postgres

# Alias ile
pg-primary   # Primary psql
pg-replica   # Replica psql
```

### 6.2 PostgreSQL 18 Yeni Özellikler — Yönetim Komutları

```sql
-- io_method kontrolü
SHOW io_method;        -- io_uring | worker | sync

-- WAL sıkıştırma
SHOW wal_compression;  -- lz4 | pglz | zstd | off

-- WAL özetleme durumu (artımlı yedekleme)
SHOW summarize_wal;
SELECT * FROM pg_stat_recovery_prefetch;

-- Huge pages durumu
SHOW huge_pages;
SELECT name, setting FROM pg_settings WHERE name LIKE '%huge%';

-- ALTER SYSTEM kısıtlaması
SHOW allow_alter_system;

-- pg_stat_io (PG 16+, PG 18'de genişletilmiş)
SELECT backend_type, object, context, reads, writes,
       pg_size_pretty(read_bytes) AS read_bytes,
       pg_size_pretty(write_bytes) AS write_bytes
FROM pg_stat_io
WHERE reads > 0 OR writes > 0
ORDER BY reads + writes DESC;

-- WAL istatistikleri (PG 15+)
SELECT wal_records, wal_fpi, wal_bytes, wal_buffers_full,
       wal_write, wal_sync, wal_write_time, wal_sync_time,
       stats_reset
FROM pg_stat_wal;
```

### 6.3 Temel Yönetim Sorguları

```sql
-- Sürüm ve derleme bilgisi
SELECT version();

-- Mevcut konfigürasyon
SELECT name, setting, unit, context
FROM pg_settings
WHERE name IN ('shared_buffers','work_mem','io_method','wal_compression',
               'huge_pages','max_connections','summarize_wal');

-- Bağlantı durumu
SELECT count(*), state FROM pg_stat_activity GROUP BY state;

-- Aktif uzun sorgular (>10s)
SELECT pid, now() - query_start AS duration, query, state, client_addr
FROM pg_stat_activity
WHERE now() - query_start > interval '10 seconds'
  AND state != 'idle'
ORDER BY duration DESC;

-- Kilitler
SELECT pid, wait_event_type, wait_event, query
FROM pg_stat_activity WHERE wait_event IS NOT NULL;

-- Veritabanı boyutları
SELECT datname, pg_size_pretty(pg_database_size(datname))
FROM pg_database ORDER BY pg_database_size(datname) DESC;

-- Replikasyon durumu (Primary'de)
SELECT client_addr, state, pg_size_pretty(sent_lsn-replay_lsn) AS lag, sync_state
FROM pg_stat_replication;

-- Recovery durumu (Replica'da)
SELECT pg_is_in_recovery(),
       now() - pg_last_xact_replay_timestamp() AS replication_delay;
```

### 6.4 Parametre Değişikliği (Patroni Üzerinden)

Patroni kümesinde `postgresql.conf` doğrudan düzenlenmez — her şey DCS üzerinden:

```bash
pt-edit-config                       # Düzenle
pt-list                              # Pending restart var mı?
patronictl -c /etc/patroni/patroni.yml reload pg-cluster      # Reload yeterli
patronictl -c /etc/patroni/patroni.yml restart pg-cluster --scheduled now  # Restart
```

```bash
# Hangi parametreler restart, hangisi reload gerektiriyor?
psql -U postgres -c "
SELECT name, context FROM pg_settings
WHERE context = 'postmaster'    -- restart gerekir
ORDER BY name;" | head -20
```

### 6.5 pg_hba.conf Yönetimi

`pg_hba.conf` Patroni DCS üzerinden yönetilir — doğrudan dosya düzenleme yapılmaz.

```bash
# Mevcut hba yapılandırmasını gör
patronictl -c /etc/patroni/patroni.yml show-config | grep -A 30 pg_hba

# pg_hba değişikliği — DCS üzerinden
pt-edit-config
```

```yaml
# edit-config içinde pg_hba örneği:
bootstrap:
  dcs:
    postgresql:
      pg_hba:
        - local  all          postgres                     peer
        - local  all          all                          scram-sha-256
        - host   all          all         127.0.0.1/32     scram-sha-256
        - host   replication  replicator  10.255.255.0/24  scram-sha-256
        - host   all          appuser     10.253.10.0/24   scram-sha-256
        # !! "host all all 0.0.0.0/0 trust" OLMAMALI — güvenlik açığı
```

```bash
# pg_hba için reload yeterli (restart gerekmez)
patronictl -c /etc/patroni/patroni.yml reload pg-cluster

# Değişikliğin uygulandığını doğrula
psql -U postgres -c "SELECT * FROM pg_hba_file_rules;" | head -20
```

### 6.6 Kullanıcı Yönetimi

```sql
-- Uygulama kullanıcısı oluştur
CREATE USER appuser WITH PASSWORD 'GuvenliParola123!'
  NOSUPERUSER NOCREATEDB NOCREATEROLE CONNECTION LIMIT 100;

-- Salt okunur rol oluştur ve ata
CREATE ROLE readonly;
GRANT CONNECT ON DATABASE mydb TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly;
GRANT readonly TO appuser;

-- Replikasyon kullanıcısı (Patroni otomatik oluşturur ama elle de yapılabilir)
CREATE USER replicator WITH REPLICATION PASSWORD 'ReplicatorParola!';

-- Parola değiştir (scram-sha-256 zorla)
ALTER USER appuser PASSWORD 'YeniGuvenliParola!';

-- Kullanıcıları listele
\du
SELECT usename, usesuper, usecreatedb, usecreaterole, valuntil, connlimit
FROM pg_user ORDER BY usename;

-- Kullanıcıya son erişim zamanı
SELECT usename, valuntil, pg_stat_activity.count
FROM pg_user
LEFT JOIN (SELECT usename, count(*) FROM pg_stat_activity GROUP BY usename) stats
  USING (usename);

-- Kullanıcı sil (önce bağlantıları kapat)
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity WHERE usename = 'eski_kullanici';
DROP USER eski_kullanici;
```

### 6.7 Veritabanı Yönetimi

```sql
-- Veritabanı oluştur
CREATE DATABASE mydb
  OWNER appuser
  ENCODING 'UTF8'
  LC_COLLATE 'en_US.UTF-8'
  LC_CTYPE   'en_US.UTF-8'
  TEMPLATE template0;

-- Yetki ver
GRANT ALL PRIVILEGES ON DATABASE mydb TO appuser;

-- Şema oluştur
\c mydb
CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION appuser;

-- Veritabanı bağlantısını kısıtla (bakım modu)
UPDATE pg_database SET datallowconn = false WHERE datname = 'mydb';

-- Mevcut bağlantıları kapat
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'mydb' AND pid <> pg_backend_pid();

-- Veritabanı sil
DROP DATABASE mydb;

-- Yeniden adlandır
ALTER DATABASE oldname RENAME TO newname;

-- Bağlantı limiti
ALTER DATABASE mydb CONNECTION LIMIT 50;

-- Tablo boyutları (en büyük 10)
SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS total_size,
       pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS table_size,
       pg_size_pretty(pg_indexes_size(schemaname||'.'||tablename)) AS index_size
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog','information_schema')
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 10;
```

### 6.8 VACUUM ve ANALYZE

```sql
-- Autovacuum durumunu izle
SELECT schemaname, tablename,
       n_dead_tup, n_live_tup,
       round(n_dead_tup::numeric/(n_live_tup+n_dead_tup+1)*100,1) AS dead_pct,
       last_autovacuum, last_autoanalyze
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC
LIMIT 20;

-- Manuel vacuum (tablo kilitlemez)
VACUUM VERBOSE ANALYZE public.my_table;

-- FULL vacuum (exclusive lock alır — dikkatli)
VACUUM FULL public.my_table;

-- Uzun sorguları listele (VACUUM engelleniyor mu?)
SELECT pid, now() - query_start AS duration, query, state
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC LIMIT 10;
```

```bash
# Autovacuum aktif mi?
psql -U postgres -c "SHOW autovacuum;"

# Autovacuum iş yükü
psql -U postgres -c "
SELECT pid, datname, usename, application_name, state, query
FROM pg_stat_activity
WHERE application_name LIKE '%autovacuum%';" 
```

### 6.9 Uzun Sorguları Sonlandırma

```sql
-- 10 dakikadan uzun çalışan sorgular
SELECT pid, usename, now() - query_start AS duration, query, state, client_addr
FROM pg_stat_activity
WHERE now() - query_start > interval '10 minutes'
  AND state != 'idle'
ORDER BY duration DESC;

-- Sorguyu iptal et (SIGINT — sadece sorguyu durdurur, bağlantı kalır)
SELECT pg_cancel_backend(12345);

-- Bağlantıyı tamamen kapat (SIGTERM)
SELECT pg_terminate_backend(12345);

-- Idle bağlantıları temizle (1 saatten uzun boşta olanlar)
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle'
  AND now() - state_change > interval '1 hour';
```

---

## 7. Patroni Yönetimi

### 7.1 Temel patronictl Komutları

```bash
# Alias ile (tüm patronictl komutları)
pt-list                              # Küme durumu
pt-config                            # DCS yapılandırması
pt-edit-config                       # Yapılandırma düzenle
pt-history                           # Geçmiş switchover/failover
patronictl -c /etc/patroni/patroni.yml list --member patroni01.local.lab
```

### 7.2 Planlı Switchover

```bash
pt-list                              # Mevcut durumu kontrol et
pt-switchover                        # İnteraktif

# Belirli node'a
patronictl -c /etc/patroni/patroni.yml switchover pg-cluster \
  --primary patroni01.local.lab --candidate patroni02.local.lab --force

pt-list                              # Doğrula
```

**Switchover süreci:**
1. Primary'e `pg_ctl stop -m fast` → clean shutdown
2. Aday replica leader seçilir, yeni timeline başlar
3. Eski primary replica olarak klonlanır

### 7.3 Acil Failover

```bash
pt-list
pt-failover   # Patroni en uygun candidate'i seçer

# Belirli node'a
patronictl -c /etc/patroni/patroni.yml failover pg-cluster \
  --primary patroni01.local.lab --candidate patroni03.local.lab
pt-list && pt-history
```

### 7.4 Maintenance Modu

```bash
pt-pause             # Otomatik failover'ı durdur
pt-list              # "paused" görmeli
# Bakım işlemi...
pt-resume            # Devam et
```

**Uyarı:** `pause` modunda Leader düşse failover olmaz. Kısa tutun.

### 7.5 Replica Yeniden Klonlama

```bash
pt-list

# separate_wal: true ise WAL dizinini temizle
ssh patroni02 "rm -rf /var/lib/pgwal/*"

# Reinit
pt-reinit patroni02.local.lab

# İlerlemeyi izle
ssh patroni02 "journalctl -u patroni -f"
pt-list
```

### 7.6 Rolling Restart

```bash
pt-pause

# Replica'lardan başla
patronictl -c /etc/patroni/patroni.yml restart pg-cluster patroni03.local.lab
patronictl -c /etc/patroni/patroni.yml restart pg-cluster patroni02.local.lab

# Switchover + Primary restart
pt-switchover
patronictl -c /etc/patroni/patroni.yml restart pg-cluster patroni01.local.lab

pt-resume
pt-list
```

### 7.7 Patroni REST API

```bash
# Node durumu
curl -s http://10.253.10.51:8008/health | python3 -m json.tool

# Primary kontrolü (200=OK, 503=hayır)
curl -o /dev/null -w "%{http_code}" http://10.253.10.51:8008/primary

# Replica kontrolü
curl -o /dev/null -w "%{http_code}" http://10.253.10.51:8008/replica

# Tüm node'lar (alias ile benzer işlev)
pt-diagnose
```

### 7.8 TTL ve Timeout Ayarları

```bash
pt-edit-config
```

```yaml
bootstrap:
  dcs:
    ttl: 30               # Leader kilidin geçerlilik süresi (sn)
    loop_wait: 10         # Patroni kontrol döngüsü
    retry_timeout: 10     # etcd operasyon timeout
    maximum_lag_on_failover: 1048576  # Max lag (1MB) failover'da
    synchronous_mode: false           # true = senkron replikasyon
```

**Önerilen değerler:**
- LAN (< 1ms): Varsayılan yeterli
- WAN (> 10ms): `ttl: 60`, `loop_wait: 20`, `retry_timeout: 20`

### 7.9 Watchdog

```bash
lsmod | grep softdog           # Modül yüklü mü?
ls -la /dev/watchdog           # Aygıt var mı?
grep -i watchdog /etc/patroni/patroni.yml  # Patroni kullanıyor mu?
```

---

## 8. etcd Yönetimi

### 8.1 Sağlık Kontrolü

```bash
etcd-health    # Tüm üyelerin sağlık durumu (alias)
etcd-members   # Üye listesi ve lider bilgisi

# Manuel:
ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379,http://10.255.255.52:2379,http://10.255.255.53:2379 \
  endpoint status --write-out=table
```

### 8.2 Patroni Anahtarlarını İnceleme

```bash
etcd-leader-key    # Alias

# Manuel:
ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379 \
  get /service/pg-cluster/leader

ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379 \
  get /service/pg-cluster/ --prefix --keys-only
```

### 8.3 Snapshot Yedekleme

```bash
etcd-snapshot    # Alias (manuel anlık yedek)

# Manuel:
ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379,http://10.255.255.52:2379,http://10.255.255.53:2379 \
  snapshot save /backup/etcd-$(date +%F-%H%M).db

# Doğrulama
ETCDCTL_API=3 etcdctl snapshot info /backup/etcd-<tarih>.db --write-out=table

# Otomatik cron durumunu gör
crontab -u etcd -l
```

### 8.4 Compaction ve Defrag

```bash
# Revizyon al
LATEST_REV=$(ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379 \
  endpoint status --write-out=json | \
  python3 -c "import sys,json; print(json.load(sys.stdin)[0]['Status']['header']['revision'])")

# Compaction
ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379,http://10.255.255.52:2379,http://10.255.255.53:2379 \
  compact $LATEST_REV

# Defrag (her üye için ayrı)
for ep in http://10.255.255.51:2379 http://10.255.255.52:2379 http://10.255.255.53:2379; do
  echo "Defrag: $ep"
  ETCDCTL_API=3 etcdctl --endpoints=$ep defrag
done
```

**Not:** etcd DB'si >100MB olduğunda aylık defrag yapın.

### 8.5 etcd Üye Yönetimi

**Dikkat:** Üye kaldırma/ekleme işlemleri quorum'u etkileyebilir. 3 üyeli kümede tek adımda en fazla 1 üye kaldırın.

```bash
# Üye listesi (ID, isim, peer URL)
ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379,http://10.255.255.52:2379,http://10.255.255.53:2379 \
  member list --write-out=table

# Sağlıksız üyeyi kaldır
# Adım 1: Üye ID'sini al
ETCDCTL_API=3 etcdctl --endpoints=http://10.255.255.51:2379 \
  member list --write-out=json | \
  python3 -c "import sys,json; [print(m['ID'], m['name']) for m in json.load(sys.stdin)['members']]"

# Adım 2: Üyeyi kaldır (onaltılık ID ile)
ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379,http://10.255.255.52:2379 \
  member remove <MEMBER_ID_HEX>

# Adım 3: Yeni üye ekle (peer-urls ile)
ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379,http://10.255.255.52:2379 \
  member add patroni03 --peer-urls=http://10.255.255.53:2380

# Adım 4: Yeni üyede etcd data dizinini temizle ve başlat
ssh patroni03 "systemctl stop etcd && rm -rf /var/lib/etcd/member && systemctl start etcd"

# Adım 5: Doğrula
ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379,http://10.255.255.52:2379,http://10.255.255.53:2379 \
  endpoint health
```

### 8.6 etcd Yapılandırma Özeti

```bash
# Mevcut yapılandırma
cat /etc/etcd/etcd.conf

# systemd override (ExecStart komutunu zorlar)
cat /etc/systemd/system/etcd.service.d/override.conf
```

---

## 9. HAProxy Yönetimi

### 9.1 Servis Kontrolü

```bash
ha-status     # Alias: systemctl status haproxy
ha-reload     # Bağlantı kesmeden reload
ha-backends   # Backend UP/DOWN durumu

# Yapılandırma doğrula (reload öncesi)
haproxy -c -f /etc/haproxy/haproxy.cfg
```

### 9.2 Stats Socket

```bash
ha-connections   # Aktif bağlantı sayısı
ha-backends      # Backend durumu (alias)

# Manuel CSV:
echo "show stat" | socat stdio /var/run/haproxy/admin.sock | \
  cut -d',' -f1,2,18,19 | grep -E "pg_primary|pg_replicas"
```

### 9.3 Stats Web Paneli

```
http://10.253.10.56:7000/
```

### 9.4 Backend Sunucu Kontrolü

```bash
# Bakım için backend'den çıkar
ha-disable-server pg_primary patroni01

# Geri ekle
ha-enable-server pg_primary patroni01

# Durum
ha-backends | grep patroni01
```

### 9.5 Health Check Mantığı

```
pg_primary  → GET /primary  → 200 = UP (primary) / 503 = DOWN
pg_replicas → GET /replica  → 200 = UP (replica) / 503 = DOWN
```

Doğrudan test:
```bash
curl -v http://10.253.10.51:8008/primary   # 200 = primary
curl -v http://10.253.10.51:8008/replica   # 200 = replica
```

### 9.6 HAProxy Yapılandırması

```bash
# Yapılandırma dosyasını gör
cat /etc/haproxy/haproxy.cfg
```

Kritik yapılandırma bölümleri:

```haproxy
global
    maxconn 100000
    nbthread 4                  # CPU sayısına göre auto_tune ayarlar
    log /dev/log local0

defaults
    mode tcp
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout queue   10s
    retries 3

frontend pgsql_write
    bind *:5432
    default_backend pg_primary

frontend pgsql_read
    bind *:5433
    default_backend pg_replicas

backend pg_primary
    option httpchk GET /primary     # Patroni REST API → 200=primary, 503=diğer
    http-check expect status 200
    default-server inter 3s fall 3 rise 2
    server patroni01 10.253.10.51:5432 check port 8008
    server patroni02 10.253.10.52:5432 check port 8008
    server patroni03 10.253.10.53:5432 check port 8008

backend pg_replicas
    option httpchk GET /replica
    http-check expect status 200
    balance roundrobin
    default-server inter 3s fall 3 rise 2
    server patroni01 10.253.10.51:5432 check port 8008
    server patroni02 10.253.10.52:5432 check port 8008
    server patroni03 10.253.10.53:5432 check port 8008

listen stats
    bind *:7000
    stats enable
    stats uri /
    stats refresh 10s
```

```bash
# Yapılandırmayı doğrula (reload öncesi her zaman yap)
haproxy -c -f /etc/haproxy/haproxy.cfg && echo "Yapılandırma geçerli"

# Bağlantı kesmeden reload
systemctl reload haproxy
```

### 9.7 HAProxy Loglama

```bash
# HAProxy erişim logları
journalctl -u haproxy -f

# Son 1 saatteki bağlantı hataları
journalctl -u haproxy --since "1 hour ago" | grep -i "error\|timeout\|refused"

# Backend UP/DOWN geçişleri (kritik olaylar)
journalctl -u haproxy | grep -i "UP\|DOWN\|health\|Server"

# Bağlantı sayısı değişimleri
journalctl -u haproxy | grep -E "CurrConns|maxconn"

# Başlangıçtan itibaren tüm olaylar
journalctl -u haproxy -b | grep -E "server|backend"
```

---

## 10. Keepalived Yönetimi

### 10.1 Servis ve VIP Kontrolü

```bash
kl-status     # systemctl status keepalived
kl-vip        # VIP hangi node'da?
kl-vrrp       # VRRP paket izleme (tcpdump)

journalctl -u keepalived | grep -E "MASTER|BACKUP|FAULT"
```

### 10.2 Manuel VIP Geçişi (Bakım)

```bash
# MASTER node'da keepalived'i durdur
systemctl stop keepalived

# BACKUP node MASTER olur — doğrula
ssh haproxy02 "ip addr show | grep 10.253.10.56"

# Bakım tamamlandı
systemctl start keepalived
```

### 10.3 Kritik Parametreler

```bash
cat /etc/keepalived/keepalived.conf
```

- `virtual_router_id`: Ağda benzersiz (1–255)
- `priority`: MASTER yüksek (101), BACKUP düşük (100)
- `auth_pass`: Her iki node'da aynı (vault'tan)
- `vrrp_script`: HAProxy sağlık kontrolü (`systemctl is-active haproxy`)

**VIP geçiş süresi:** 1–3 saniye (VRRP advertisement aralığına bağlı)

---

## 11. PgBouncer Yönetimi

### 11.1 Servis Kontrolü

```bash
pb-status     # Her iki PgBouncer servisinin durumu
pb-pools      # Bağlantı havuzu durumu
pb-reload     # Konfigürasyon yeniden yükle (bağlantı kesmeden)
```

### 11.2 Admin Konsol

```bash
# Yazma havuzu
psql -h /var/run/pgbouncer -p 6432 -U pgbouncer pgbouncer

# Okuma havuzu
psql -h /var/run/pgbouncer -p 6433 -U pgbouncer pgbouncer
```

```sql
SHOW POOLS;     -- cl_waiting > 0 ise pool_size artır
SHOW STATS;     -- Throughput
SHOW CLIENTS;   -- Aktif istemciler
SHOW SERVERS;   -- PG backend bağlantıları
SHOW CONFIG;    -- Yapılandırma
RELOAD;         -- Bağlantı kesmeden yeniden yükle
```

### 11.3 Kullanıcı Yönetimi

```bash
# Mevcut kullanıcılar
cat /etc/pgbouncer/userlist.txt

# Yeni kullanıcı ekle
# 1. PostgreSQL'den SCRAM hash al
PGPASSWORD=<super_pass> psql -U postgres -h 10.253.10.51 -t -A \
  -c "SELECT concat('\"', usename, '\" \"', passwd, '\"') FROM pg_shadow WHERE usename='appuser';"

# 2. userlist.txt'e ekle
echo '"appuser" "SCRAM-SHA-256$..."' >> /etc/pgbouncer/userlist.txt

# 3. Reload (bağlantı kesmeden)
systemctl reload pgbouncer pgbouncer-ro
```

### 11.4 PgBouncer Yapılandırması

```bash
# Yazma havuzu yapılandırması
cat /etc/pgbouncer/pgbouncer.ini

# Okuma havuzu yapılandırması
cat /etc/pgbouncer/pgbouncer-ro.ini
```

Kritik parametreler:

```ini
[pgbouncer]
listen_port = 6432
listen_addr = *

# Pool modu
pool_mode = transaction     # session / transaction / statement
# transaction: her transaction için PG bağlantısı paylaşımı (önerilen)
# session:     her istemciye ayrı PG bağlantısı (en uyumlu, en az verimli)
# statement:   COPY ve prepared statement ile sorunlu — üretimde kullanmayın

# Kapasite
max_client_conn = 1000      # Toplam istemci bağlantısı
default_pool_size = 25      # Her db/user çifti için PG bağlantısı
reserve_pool_size = 5       # Acil durum için rezerv bağlantı
reserve_pool_timeout = 3    # Rezerv havuza geçiş süresi (saniye)
max_db_connections = 50     # Veritabanı başına toplam PG bağlantısı

# Timeout
client_idle_timeout = 600   # Boşta istemci timeout (saniye)
server_idle_timeout = 600   # Boşta PG bağlantısı timeout
query_timeout = 0           # 0 = sınırsız (uygulama katmanında ayarla)
idle_transaction_timeout = 0

# Kimlik doğrulama
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt

# Backend bağlantı
server_tls_sslmode = prefer

[databases]
mydb = host=10.253.10.56 port=5432 dbname=mydb
```

```bash
# Yapılandırma değişikliği sonrası test
psql -h /var/run/pgbouncer -p 6432 -U pgbouncer pgbouncer -c "SHOW CONFIG;" | \
  grep -E "pool_mode|max_client|default_pool"
```

### 11.5 Pool Boyutlandırma

**Formül:**

```
default_pool_size = postgresql_max_connections / (veritabanı_sayısı × kullanıcı_sayısı)

Örnek: 200 PG bağlantısı, 4 uygulama kullanıcısı, 2 veritabanı:
  default_pool_size = 200 / (4 × 2) = 25

max_client_conn = uygulama_thread_sayısı × güvenlik_katsayısı (1.5-2)
Örnek: 500 uygulama thread'i → max_client_conn = 750-1000
```

Pool boyutunu artırma:

```bash
# Admin konsola bağlan
psql -h /var/run/pgbouncer -p 6432 -U pgbouncer pgbouncer

-- cl_waiting > 0 ise pool sıkıştı
SHOW POOLS;

-- İstatistiklerden throughput'u görün
SHOW STATS;

-- Gerçek zamanlı izle
\watch 2
SHOW POOLS;
\q
```

Pool doluluk uyarısı — `cl_waiting` > 0 ise:

```bash
# /etc/pgbouncer/pgbouncer.ini içinde artır:
# default_pool_size = 25 → 40
# reserve_pool_size = 5  → 10
systemctl reload pgbouncer
```

---

## 12. PCP İzleme

### 12.1 Temel Komutlar

```bash
# Servis durumu
systemctl status pmcd pmlogger pmie

# Anlık metrikler (5 örnek, 2 saniyelik)
pmstat -s 5 -t 2sec

# Disk I/O
pmdiskstat -s 5 -t 2sec

# Bellek kullanımı
pmrep -s 5 -t 2sec mem.util.used mem.util.free

# CPU kullanımı
pmrep -s 5 -t 2sec kernel.cpu.util.user kernel.cpu.util.sys
```

### 12.2 PostgreSQL 18 PCP Metrikleri

```bash
# PG metrik listesi
pminfo postgresql

# Bağlantı sayısı
pminfo -f postgresql.connections.total

# Veritabanı istatistikleri
pminfo -f postgresql.stat.database.tup_fetched

# Log arşivini görüntüle
pcp | tail -20

# Geçmiş analiz (son 24 saat)
pmrep -S "24 hours ago" -s 720 -t 2min mem.util.used
```

### 12.3 pmlogger — Kalıcı Kayıt

```bash
# Log dizini
ls /var/log/pcp/pmlogger/

# Arşiv analizi
pmdumplog /var/log/pcp/pmlogger/$(hostname)/<arşiv>

# PCP web arayüzü (kuruluysa)
# http://<node-ip>:44323/grafana
```

---

## 13. OS Performans Ayarları (pg_tune + auto_tune)

### 13.0 auto_tune — Donanım Bazlı Otomatik Parametre Hesaplama

`auto_tune` rolü kurulumun başında **her zaman** çalışır (`tags: always`). Sunucunun gerçek RAM ve vCPU sayısını okur, PostgreSQL + HAProxy için optimal değerleri hesaplar ve `set_fact` ile sonraki rollere iletir.

```bash
# Hesaplanan değerleri GÖRMEK (değişiklik yapmadan):
ansible-playbook playbooks/patroni-infra-kur.yml --tags auto_tune --check

# Çıktı örneği (256GB RAM / 32 vCPU):
# "shared_buffers         → 64GB"
# "effective_cache_size   → 192GB"
# "work_mem               → 81MB"
# "maintenance_work_mem   → 2GB"
# "max_worker_processes   → 32"
# "autovacuum_max_workers → 8"
# "haproxy_nbthread       → 8"
# "haproxy_maxconn        → 16000"
# "pgbouncer_max_client_conn   → 10000"
```

**Hesaplama formülleri:**

| Parametre | Formül |
|-----------|--------|
| `shared_buffers` | RAM × 0.25 |
| `effective_cache_size` | RAM × 0.75 |
| `work_mem` | shared_buffers ÷ (max_connections × 4), max 256MB |
| `maintenance_work_mem` | min(2GB, RAM × 0.05) |
| `wal_buffers` | min(128MB, shared_buffers × 2%) |
| `max_wal_size` | max(4GB, RAM × 6.25%) |
| `max_worker_processes` | vCPU |
| `max_parallel_workers` | max(2, vCPU / 2) |
| `autovacuum_max_workers` | max(3, min(8, vCPU / 4)) |
| `haproxy_nbthread` | max(2, min(8, vCPU / 4)) |
| `haproxy_maxconn` | nbthread × 2000 |
| `pgbouncer_max_client_conn` | max(1000, min(10000, nbthread × 1500)) |

**Kurulum raporunda görme:** Her kurulum raporunun (`reports/patroni-kurulum-*.txt`, `reports/haproxy-kurulum-*.txt`) sonunda `AUTO-TUNE RAPORU` bölümü vardır. Her parametre için:
- Tespit edilen donanım (vCPU + RAM)
- Hesaplanan değer
- Formül açıklaması
- Neden o değerin seçildiği

**Kapatmak (elle sabit değer kullanmak için):**

```yaml
# inventory/group_vars/all/vars.yml
auto_tune_enabled: false

# Ardından BÖLÜM E değerlerini elle düzenleyin:
pg_shared_buffers: "32GB"
pg_work_mem: "64MB"
# ...
```

**Formül oranlarını değiştirmek:**

```yaml
# inventory/group_vars/all/vars.yml (veya host_vars/<host>.yml)
# roles/auto_tune/defaults/main.yml değerlerini override eder:
auto_tune_shared_buffers_ratio: 0.20    # %25 yerine %20 (başka işlemler için RAM bırak)
auto_tune_work_mem_max_mb: 512          # 256MB üst sınırını artır
auto_tune_haproxy_thread_divisor: 6     # vCPU/6 thread (daha az)
auto_tune_maintenance_work_mem_max_mb: 4096  # max 4GB (büyük index rebuild)
```

**Yeniden hesapla ve uygula (donanım değişikliğinden sonra):**

```bash
# Tüm parametreleri yeniden hesapla + uygula
ansible-playbook playbooks/patroni-infra-kur.yml --tags pg_tune,patroni

# Sadece HAProxy/PgBouncer için
ansible-playbook playbooks/02-haproxy.yml --tags haproxy,pgbouncer
```

---

`pg_tune` rolü ile kurulan OS optimizasyonları.

### 13.1 Mevcut Ayarları Doğrulama

```bash
# sysctl dosyası
cat /etc/sysctl.d/90-postgresql.conf

# THP modu
cat /sys/kernel/mm/transparent_hugepage/enabled
# Beklenen: always madvise [never] → [madvise] seçili olmalı

# I/O scheduler (tüm diskler)
for dev in $(lsblk -d -o NAME -n); do
  echo -n "$dev: "
  cat /sys/block/$dev/queue/scheduler 2>/dev/null || echo "N/A"
done

# Huge pages
grep -E "HugePages_Total|HugePages_Free|Hugepagesize" /proc/meminfo

# PAM limits
cat /etc/security/limits.d/20-postgresql.conf
```

### 13.2 Huge Pages — Manuel Ayar

```bash
# Gerekli sayıyı hesapla
# shared_buffers=1GB, huge_page_size=2MB
# 1024MB / 2MB × 1.15 = 590 huge page

# Geçici
echo 600 > /proc/sys/vm/nr_hugepages

# Kalıcı (ansible)
# inventory/group_vars/all/vars.yml:
#   pg_os_nr_hugepages: 600
ansible-playbook playbooks/patroni-infra-kur.yml --tags pg_tune

# PostgreSQL'in huge page kullandığını doğrula
grep HugePages /proc/meminfo
# HugePages_Total: 600
# HugePages_Free:  540  (PostgreSQL 60 huge page kullanıyor)
```

### 13.3 I/O Scheduler Değişikliği

```bash
# Geçici (reboot'a kadar)
echo "none" > /sys/block/vdb/queue/scheduler  # NVMe için

# Kalıcı (udev + ansible)
# inventory/group_vars/all/vars.yml:
#   pg_os_io_scheduler: "none"
ansible-playbook playbooks/patroni-infra-kur.yml --tags pg_tune
```

### 13.4 vm.swappiness

```bash
sysctl vm.swappiness     # 1 olmalı (pg_tune ile ayarlı)

# PostgreSQL için en kritik: swap kullanımı I/O latency'yi artırır
# 0: swap kullanma (OOM riski), 1: son çare olarak kullan (önerilen)
```

---

## 14. Log Yönetimi

### 14.1 HA Servisleri

```bash
# Patroni node'larında
journalctl -u patroni -u etcd --since "1 hour ago"

# HAProxy node'larında
journalctl -u haproxy -u keepalived -u pgbouncer --since "1 hour ago"

# Kritik seviye (tüm sistemde)
journalctl -p crit..emerg --since "24 hours ago"

# Belirli event arama
journalctl --since "1 week ago" | grep -iE "promoted|failover|FATAL|panic"
```

### 14.2 PostgreSQL 18 Logları

```bash
# Journal üzerinden (varsayılan)
journalctl -u patroni | grep -iE "LOG|ERROR|FATAL|PANIC|checkpoint|replication"

# Doğrudan dosya (log_directory ayarlıysa)
ls /var/lib/pgsql/18/data/log/
tail -f /var/lib/pgsql/18/data/log/postgresql-$(date +%a).log
```

### 14.3 Önemli Log Mesajları

| Mesaj | Anlamı | Aksiyon |
|-------|--------|---------|
| `promoted to leader` | Bu node Primary oldu | Normal — TL arttı |
| `demoted` | Bu node Replica'ya düştü | Normal switchover/failover |
| `DCS is not accessible` | etcd'ye erişilemiyor | etcd servisini kontrol et |
| `lost the leader lock` | Leader kilidi kaybedildi | etcd bağlantısını kontrol et |
| `no healthy members` | Sağlıklı replica yok | Replica'ları kontrol et |
| `io_uring not available` | io_uring kernel desteği yok | `pg_io_method: "worker"` yap |
| `FATAL: database system identifier differs` | Yanlış PGDATA | Reinit gerekebilir |
| `timeline does not match` | TL uyuşmazlığı | Reinit gerekebilir |

### 14.4 Log Rotasyonu

```bash
ls /etc/logrotate.d/haproxy /etc/logrotate.d/pgbouncer

# Manuel çalıştır
logrotate -f /etc/logrotate.d/haproxy

# Journal boyut yönetimi
journalctl --disk-usage
journalctl --vacuum-time=30d
journalctl --vacuum-size=500M
```

---

## 15. Kaynak İzleme ve cgroup Limitleri

### 15.1 Anlık Kaynak Kullanımı

```bash
infra-mem      # Bellek özeti
infra-cpu      # CPU yükü
infra-services # HA servis durumları

# Servis bazında kaynak
systemctl status patroni   # Memory: ve CPU: gösterir

# Gerçek zamanlı
top    # veya htop (dnf install htop)
iotop  # Disk I/O (dnf install iotop)
```

### 15.2 cgroup Limitlerini Kontrol

```bash
infra-cgroup   # user.slice limitleri (alias)

# Manuel:
systemctl show user.slice -p CPUQuota,CPUWeight,MemoryMax,MemoryHigh,TasksMax
cat /etc/systemd/system/user.slice.d/10-limits.conf

# Kernel'den doğrudan
cat /sys/fs/cgroup/user.slice/memory.max
cat /sys/fs/cgroup/user.slice/memory.high
cat /sys/fs/cgroup/user.slice/cpu.max
```

### 15.3 user.slice Bellek Limitleri

| RAM | MemoryHigh (soft) | MemoryMax (hard) |
|-----|-------------------|------------------|
| ≤ 4 GB | 1 GB (throttle başlar) | 1.5 GB (OOM öldürür) |
| > 4 GB | 1.5 GB | 2 GB |

```bash
# Limiti değiştirmek için
# inventory/group_vars/all/vars.yml:
#   user_slice_memory_max: "2G"
#   user_slice_memory_high: "1600M"
ansible-playbook playbooks/patroni-infra-kur.yml --tags limits
systemctl show user.slice -p MemoryMax
```

### 15.4 OOM Koruması Hiyerarşisi

| Bileşen | OOM Skoru | Sonuç |
|---------|-----------|-------|
| etcd, patroni, haproxy, keepalived, pgbouncer | −1000 | OOM Killer asla seçmez |
| sshd | −1000 | Yönetim erişimi korunur |
| Root SSH | değişmez (~0) | Normal |
| Non-root SSH | +500 | Bellek baskısında önce hedef |

```bash
# OOM skoru kontrolü
for svc in etcd patroni; do
  pid=$(systemctl show $svc -p MainPID | cut -d= -f2)
  echo "$svc (PID $pid): $(cat /proc/$pid/oom_score_adj)"
done
```

### 15.5 OOM Kill Sonrası

```bash
infra-oom-check
dmesg | grep "oom_kill" | tail -20

# user.slice'tan öldürüldüyse geçici çözüm
systemd-run --scope --uid=0 -p MemoryMax=infinity -- <komut>

# Kalıcı: memory limitini artır
# inventory/group_vars/all/vars.yml → user_slice_memory_max: "2G"
ansible-playbook playbooks/patroni-infra-kur.yml --tags limits
```

### 15.6 Swap Yönetimi

```bash
# Swap durumu
swapon --show
free -h

# Swappiness değeri (kernel parametresi)
sysctl vm.swappiness
# pg_tune ile 1 olarak ayarlanmış olmalı — PostgreSQL için önerilir
# 0: swap kullanma (OOM riski yüksek)
# 1: son çare olarak kullan (PostgreSQL ortamları için önerilen)
# 10+: daha agresif swap (varsayılan 60 — üretimde uygun değil)

# Geçici swappiness değişikliği (reboot'a kadar geçerli)
sysctl -w vm.swappiness=1

# Kalıcı değişiklik
echo "vm.swappiness = 1" > /etc/sysctl.d/90-postgresql.conf
sysctl -p /etc/sysctl.d/90-postgresql.conf

# Swap kullanımını anlık izle
watch -n 2 free -h

# Hangi süreçler swap kullanıyor?
for pid in $(ls /proc | grep '^[0-9]'); do
  swap=$(grep VmSwap /proc/$pid/status 2>/dev/null | awk '{print $2}')
  if [ -n "$swap" ] && [ "$swap" -gt 0 ] 2>/dev/null; then
    comm=$(cat /proc/$pid/comm 2>/dev/null)
    echo "$pid ($comm): ${swap} kB"
  fi
done | sort -t: -k2 -rn | head -10

# user.slice'ta swap engeli (üretimde tercih edilir)
# /etc/systemd/system/user.slice.d/10-limits.conf:
# MemorySwapMax=0   ← SSH kullanıcı oturumları için swap yok

# Geçici swap kapatma (dikkatli kullanın — OOM riski)
swapoff -a

# Swap tekrar aktif et
swapon -a

# /etc/fstab'dan swap satırını kaldır (kalıcı devre dışı)
sed -i '/\bswap\b/d' /etc/fstab
```

---

## 16. Yedekleme ve Geri Yükleme

### 16.1 etcd Snapshot

```bash
# Manuel
etcd-snapshot

# Doğrulama
ETCDCTL_API=3 etcdctl snapshot info /backup/etcd-<tarih>.db --write-out=table

# Otomatik cron (04:00)
crontab -u etcd -l

# Son snapshot'lar
ls -lh /backup/etcd-*.db
find /backup -name "etcd-*.db" -mtime +14 -ls
```

### 16.2 etcd Geri Yükleme

**Dikkat:** Quorum kaybında kullanın. Tüm Patroni de durdurulur.

```bash
# 1. Tüm node'larda durdur
for node in patroni01 patroni02 patroni03; do
  ssh $node "systemctl stop etcd patroni"
done

# 2. Veri dizinini temizle
for node in patroni01 patroni02 patroni03; do
  ssh $node "rm -rf /var/lib/etcd/member"
done

# 3. Her node'da geri yükle (adresler değişerek)
ETCDCTL_API=3 etcdctl snapshot restore /backup/etcd-2026-06-28.db \
  --name patroni01 \
  --initial-cluster "patroni01=http://10.255.255.51:2380,patroni02=http://10.255.255.52:2380,patroni03=http://10.255.255.53:2380" \
  --initial-cluster-token etcd-cluster-token \
  --initial-advertise-peer-urls http://10.255.255.51:2380 \
  --data-dir /var/lib/etcd

# 4. Sahipliği düzelt
chown -R etcd:etcd /var/lib/etcd

# 5. etcd başlat (3 node eş zamanlı)
for node in patroni01 patroni02 patroni03; do
  ssh $node "systemctl start etcd" &
done; wait

# 6. Sağlık doğrula
etcd-health

# 7. Patroni başlat
for node in patroni01 patroni02 patroni03; do
  ssh $node "systemctl start patroni"
done
```

### 16.3 PostgreSQL Yedekleme — pg_basebackup

```bash
pg_basebackup \
  -h 10.255.255.52 -p 5432 \
  -U replicator \
  -D /backup/pgbase/$(date +%F) \
  -Ft -Xs -P -z --checkpoint=fast
```

### 16.4 pgBackRest (Önerilen)

```bash
dnf install -y pgbackrest

cat > /etc/pgbackrest/pgbackrest.conf << 'EOF'
[global]
repo1-path=/backup/pgbackrest
repo1-retention-full=2
repo1-retention-diff=7
[pg-cluster]
pg1-path=/var/lib/pgsql/18/data
pg1-user=postgres
pg1-host=10.253.10.56
EOF

pgbackrest --stanza=pg-cluster stanza-create
pgbackrest --stanza=pg-cluster backup --type=full
pgbackrest --stanza=pg-cluster backup --type=incr    # Artımlı
pgbackrest --stanza=pg-cluster info                  # Yedek listesi

# PITR kurtarma
pgbackrest --stanza=pg-cluster restore \
  --target="2026-06-28 14:00:00" \
  --target-action=promote
```

---

## 17. Güncelleme Prosedürleri

### 17.1 Sistem Paketi Güncelleme (Rolling)

```bash
pt-pause                            # Failover'ı durdur

# Replica'lardan başla
ssh patroni03 "dnf update -y && systemctl reboot"
# SSH dönüşü bekle
ssh patroni03 "systemctl is-active patroni"
pt-list                             # streaming olduğunu doğrula

ssh patroni02 "dnf update -y && systemctl reboot"
ssh patroni02 "systemctl is-active patroni"
pt-list

pt-resume                           # Failover'ı aç

# Primary (switchover ile)
pt-switchover
ssh patroni01 "dnf update -y && systemctl reboot"
pt-list
```

### 17.2 PostgreSQL Minor Versiyon Güncelleme

```bash
# Mevcut versiyon
psql -U postgres -c "SELECT version();"

# Mevcut paket kontrolü
dnf check-update postgresql18-server

# Rolling update
for node in patroni03 patroni02; do
  ssh $node "dnf update -y postgresql18-server postgresql18 && systemctl restart patroni"
  sleep 30
  pt-list
done

# Primary
pt-switchover
ssh patroni01 "dnf update -y postgresql18-server postgresql18 && systemctl restart patroni"
pt-list && psql -U postgres -c "SELECT version();"
```

### 17.3 Ansible ile Yapılandırma Güncellemesi

```bash
# Patroni konfigürasyonu değişti
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni

# OS tuning güncellendi
ansible-playbook playbooks/patroni-infra-kur.yml --tags pg_tune

# Kaynak limitleri değişti
ansible-playbook playbooks/patroni-infra-kur.yml --tags limits

# Tek node
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni --limit patroni01

# Dry-run (önizleme)
ansible-playbook playbooks/patroni-infra-kur.yml --check --diff
```

### 17.4 Patroni Güncelleme (Rolling)

Patroni güncelleme sırasında küme çalışmaya devam eder; önce Replica'lar, sonra Primary güncellenir.

```bash
# 1. Mevcut Patroni sürümünü kontrol et
patronictl version   # veya: patroni --version

# 2. Yeni sürümü kontrol et
dnf check-update patroni

# 3. Küme durumunu doğrula (tüm node'lar sağlıklı olmalı)
pt-list

# 4. Replica'lardan başla (birer birer)
for node in patroni03 patroni02; do
  echo "=== $node güncelleniyor ==="
  ssh $node "dnf update -y patroni"
  ssh $node "systemctl restart patroni"
  sleep 15                    # Patroni yeniden başlamasını bekle
  pt-list                     # Durum kontrolü
  # "streaming" durumuna döndüğünü doğrula
done

# 5. Primary'i güncelle (önce switchover ile Primary değiştir)
pt-switchover                 # patroni03 veya patroni02'ye geç
ssh patroni01 "dnf update -y patroni"
ssh patroni01 "systemctl restart patroni"
sleep 15
pt-list                       # patroni01 replica olarak döndü mü?

# 6. Final durum kontrolü
pt-list && pt-history
patronictl version            # Tüm node'lar güncellendi mi?
```

**Geri alma (rollback):**

```bash
# Önceki pakete dön (yum geçmişi ile)
dnf history list patroni
dnf history undo <transaction_id>
systemctl restart patroni
```

---

## 18. Aksaklık Giderme Rehberi

### 18.1 Küme Primary Yok

**Belirtiler:** `pt-list` → `no leader`, uygulama bağlanamıyor.

```bash
pt-diagnose    # Otomatik analiz

# Manuel:
pt-list
etcd-health
journalctl -u patroni -n 100 | tail -30

# etcd sağlıklıysa ama leader yoksa
systemctl restart patroni   # Tüm node'larda
pt-failover                 # Son çare

# etcd erişilebiliyor mu?
etcd-leader-key
```

### 18.2 Replica Lag Yüksek

```bash
pg-repl-status

# Replica üzerinde
ssh patroni02 "psql -U postgres -c \"SELECT now() - pg_last_xact_replay_timestamp() AS delay;\""

# Ağ testi
ping -c 4 10.255.255.52
iperf3 -s   # Replica'da
iperf3 -c 10.255.255.52   # Primary'den

# Son çare: reinit
ssh patroni02 "rm -rf /var/lib/pgwal/*"
pt-reinit patroni02.local.lab
```

### 18.3 etcd Quorum Kaybı

```bash
etcd-diagnose   # Otomatik analiz

# Hangi üyeler çevrimdışı?
etcd-health 2>&1

# Çevrimdışı node'da etcd'yi yeniden başlatmayı dene
ssh patroni02 "systemctl restart etcd"
journalctl -u etcd -n 50   # patroni02'de

# Veri dizini bozulmuşsa (son çare — iki sağlıklı node kaldı)
ssh patroni02 "systemctl stop etcd && rm -rf /var/lib/etcd/member && systemctl start etcd"
```

### 18.4 Split-Brain Şüphesi

```bash
# Her node'un kendi rolünü söylediğine bak
for ip in 10.253.10.51 10.253.10.52 10.253.10.53; do
  echo -n "$ip: "
  curl -s http://$ip:8008/health | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('role','?'))"
done

# etcd'nin gerçek leader'ı
etcd-leader-key

# Sahte Primary'yi durdur (etcd'nin gösterdiği dışındaki)
systemctl stop patroni   # Sahte Primary'de

# Yeniden başlat (replica olarak gelecek)
systemctl start patroni
pt-list
```

### 18.5 VIP Yanıt Vermiyor

```bash
kl-diagnose    # Otomatik analiz
kl-vip         # VIP nerede?

# Keepalived durumu
ssh haproxy01 "systemctl status keepalived"
ssh haproxy02 "systemctl status keepalived"

# VRRP paket izleme
kl-vrrp

# VRRP firewall kuralı
firewall-cmd --list-rich-rules | grep vrrp
# Eksikse:
firewall-cmd --add-rich-rule='rule protocol value="vrrp" accept' --permanent
firewall-cmd --reload

# Keepalived yeniden başlat
ssh haproxy01 "systemctl restart keepalived"
ssh haproxy02 "systemctl restart keepalived"
```

### 18.6 PgBouncer Bağlantı Hatası

```bash
pb-diagnose    # Otomatik analiz
pb-pools       # cl_waiting > 0 ise pool_size artır

# Backend bağlantılar sağlıklı mı?
psql -h /var/run/pgbouncer -p 6432 -U pgbouncer pgbouncer -c "SHOW SERVERS;"

# Kullanıcı userlist'te var mı?
grep "appuser" /etc/pgbouncer/userlist.txt

# Doğrudan PG bağlantısı çalışıyor mu?
psql -h 10.253.10.56 -p 5432 -U postgres
```

### 18.7 io_uring Hatası (PG 18 Özgü)

```bash
journalctl -u patroni | grep -i io_uring

# Kernel desteği
grep io_uring /boot/config-$(uname -r)

# Güvenlik politikası
grep io_uring /etc/sysctl.d/90-security.conf

# Geçici: io_uring kapat
pt-edit-config
# parameters: io_method: worker

# Kalıcı:
# inventory/group_vars/all/vars.yml: pg_io_method: "worker"
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni
```

### 18.8 Huge Pages Yetersiz (PG 18 Özgü)

```bash
grep HugePages /proc/meminfo
# HugePages_Total: 0  ← sorun!

# pg_tune ile otomatik yeniden hesapla
ansible-playbook playbooks/patroni-infra-kur.yml --tags pg_tune

# Manuel
# 1GB shared_buffers, 2MB huge page:
echo 600 > /proc/sys/vm/nr_hugepages

# PostgreSQL yeniden başlat
systemctl restart patroni

grep HugePages_Free /proc/meminfo
```

### 18.9 Disk Doldu

```bash
# Hangi dizin?
df -h /var/lib/pgsql /var/lib/pgwal /var/lib/etcd /backup
du -sh /var/lib/pgsql/18/data/* | sort -rh | head -10

# WAL segment sayısı
ls /var/lib/pgwal/pg_wal/ | wc -l

# Checkpoint zorla
psql -U postgres -c "CHECKPOINT;"

# Eski yedekleri temizle
find /backup -name "etcd-*.db" -mtime +14 -delete

# Şişmiş tabloları temizle
psql -U postgres -d mydb -c "VACUUM FULL VERBOSE;"
```

### 18.10 Yüksek CPU/Bellek

```bash
# En çok tüketen süreç
ps aux --sort=-%cpu | head -10

# Uzun sorgular
pg-slow-queries

# Kilitler
pg-locks

# Buffer cache hit oranı
pg-cache-hit
# 0.99 altındaysa shared_buffers artır

# cgroup memory durumu
infra-cgroup
cat /sys/fs/cgroup/system.slice/patroni.service/memory.current
```

### 18.11 Senaryo: Patroni Timeline Uyuşmazlığı

**Belirtiler:** Replica Primary'ye bağlanamıyor, log'da şu mesaj görünür:
`timeline X of the base backup is not in the history of the current timeline Y`

```bash
# 1. TL uyuşmazlığını gör
pt-list
# TL kolonu: Replica'lar farklı TL gösteriyorsa reinit gerekir

# 2. Her node'un TL'sini kontrol et
for node in patroni01 patroni02 patroni03; do
  echo -n "$node TL: "
  curl -s http://10.253.10.5$((${node: -1})):8008/health | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('timeline','?'))"
done

# 3. Hangi node Primary olduğunu doğrula
for ip in 10.253.10.51 10.253.10.52 10.253.10.53; do
  role=$(curl -s http://$ip:8008/health | python3 -c "import sys,json; print(json.load(sys.stdin).get('role','?'))" 2>/dev/null)
  echo "$ip: $role"
done

# 4. Sorunlu Replica'yı reinit et (separate_wal: true ise önce WAL dizini temizle)
ssh patroni02 "rm -rf /var/lib/pgwal/*"
pt-reinit patroni02.local.lab

# 5. Reinit ile ilerlemeyi izle
ssh patroni02 "journalctl -u patroni -f" &
pt-list   # streaming olana kadar bekle

# 6. Reinit çalışmıyorsa — manual pg_basebackup
# Önce Patroni'yi durdur
ssh patroni02 "systemctl stop patroni"
# PGDATA ve WAL'ı temizle
ssh patroni02 "rm -rf /var/lib/pgsql/18/data/* /var/lib/pgwal/*"
# Primary'den klonla
ssh patroni02 "pg_basebackup -h 10.255.255.51 -p 5432 -U replicator \
  -D /var/lib/pgsql/18/data -Fp -Xs -R -P"
# Patroni'yi başlat
ssh patroni02 "systemctl start patroni"
pt-list
```

**Kök neden:** Timeline uyuşmazlıkları genellikle şunlardan kaynaklanır:
- Replica kapalıyken birden fazla failover yaşandı
- Replica'da WAL segment eksikliği
- Yanlış zaman noktasına geri yükleme yapıldı

---

## 19. Disaster Recovery

### 19.1 Senaryo A: Tek Node Çöktü (Quorum Sağlam)

```bash
# Otomatik failover gerçekleşmiş olmalı
pt-list

# Node'u geri getir
ssh patroni01 "systemctl start etcd && systemctl start patroni"

# Replica olarak klonlanacak
pt-list   # streaming olmasını bekle
```

### 19.2 Senaryo B: İki Node Çöktü (Quorum Kaybı)

```bash
# Son sağlıklı node var mı?
etcd-health

# Tek node ile devam et
ETCDCTL_API=3 etcdctl --endpoints=http://10.255.255.51:2379 member list
ETCDCTL_API=3 etcdctl --endpoints=http://10.255.255.51:2379 member remove <ID_02>
ETCDCTL_API=3 etcdctl --endpoints=http://10.255.255.51:2379 member remove <ID_03>

# patroni01'i leader yap
pt-failover

# Diğer node'ları tamir et ve geri ekle
ssh patroni02 "systemctl start etcd patroni"
ssh patroni03 "systemctl start etcd patroni"
```

### 19.3 Senaryo C: Tüm Patroni Node'ları Çöktü

```bash
# 1. etcd snapshot'tan geri yükle (bkz. §16.2)
# 2. pg_basebackup / pgBackRest ile PG verisini geri yükle
# 3. WAL arşivleri varsa PITR uygula
# 4. Kümeyi başlat
for node in patroni01 patroni02 patroni03; do
  ssh $node "systemctl start etcd"
done
sleep 15
etcd-health

for node in patroni01 patroni02 patroni03; do
  ssh $node "systemctl start patroni"
done
pt-list
```

### 19.4 Senaryo D: HAProxy Katmanı Tamamen Çöktü

```bash
# Patroni node'larına doğrudan bağlan (geçici)
psql -h 10.253.10.51 -p 5432 -U postgres   # patroni01 primary ise

# Yeni leader'ı bul
pt-list | grep Leader

# HAProxy'yi yeniden kur
ansible-playbook playbooks/patroni-infra-kur.yml --tags haproxy
```

---

## 20. Güvenlik Yönetimi

### 20.1 Sertleştirme Uygulama

```bash
ansible-playbook playbooks/patroni-infra-kur.yml --tags security

# Raporu incele
ls -lt reports/security-report-*.html | head -1
# Hedef: 0 AVC, tüm sysctl ✓
```

### 20.2 SELinux

```bash
getenforce       # Enforcing olmalı
setenforce 1     # Geçici permissive moddan dön

# Custom modüller
semodule -l | grep -E "haproxy-local|keepalived-local|my-rsyslogd|pcp"

# AVC log
ausearch -m avc -ts recent | tail -20
audit2why -a   # AVC açıklaması

# ASLA
# setenforce 0     ← üretimde yasak
# selinux=0 kernel parametresi ← yasak
```

### 20.3 Ansible Vault — Üretim Geçişi

```bash
# 1. Vault şifresi
echo 'GuvenliVaultSifresi' > .vault_pass
chmod 0400 .vault_pass

# 2. Parolaları şifrele ve güncelle
ansible-vault encrypt_string 'YeniSuperParola' --name 'super_password'
# Çıktıyı vault.yml'e kopyala

ansible-vault edit inventory/group_vars/all/vault.yml

# 3. Değişiklikleri uygula
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni
```

### 20.4 SSH Güvenliği

```bash
# SSH parola girişini kapat (kurulum tamamlandıktan sonra)
# /etc/ssh/sshd_config:
PasswordAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
ClientAliveInterval 300

systemctl reload sshd

# SSH erişimini belirli subnet ile kısıtla
firewall-cmd --add-rich-rule='rule family=ipv4 source address=10.253.0.0/16 service name=ssh accept' --permanent
firewall-cmd --remove-service=ssh --permanent
firewall-cmd --reload
```

### 20.5 Firewall Durumu

```bash
# Açık portlar
firewall-cmd --list-all

# Patroni node'larında açık olması gerekenler
firewall-cmd --list-ports
# 5432/tcp 8008/tcp 2379/tcp 2380/tcp 44321/tcp

# HAProxy node'larında
# 5432/tcp 5433/tcp 7000/tcp 6432/tcp 6433/tcp
```

### 20.6 Audit Log

```bash
# Auditd durumu
systemctl status auditd

# Yetki değişikliklerini ara
ausearch -m avc,USER_AUTH,USER_ROLE_CHANGE -ts recent

# PostgreSQL konfigürasyon değişikliği (PG 18 dosyaları izleniyor)
ausearch -k pg_config -ts today

# Tüm kuralları listele
auditctl -l
```

### 20.7 TLS/SSL Yapılandırması (Üretim)

Bu bölüm varsayılan kurulumda pasif olan TLS katmanını etkinleştirir.
Üretim ortamında tüm iletişim şifrelenmelidir.

#### etcd TLS

```bash
# CA ve sertifika oluştur (her Patroni node'unda tekrarlanır — adres değişir)
CA_DIR=/etc/etcd/tls
mkdir -p $CA_DIR

# CA
openssl genrsa -out $CA_DIR/ca.key 4096
openssl req -new -x509 -days 3650 -key $CA_DIR/ca.key \
  -out $CA_DIR/ca.crt -subj "/CN=etcd-ca"

# Node sertifikası (patroni01 için — SAN ile)
openssl genrsa -out $CA_DIR/server.key 2048
openssl req -new -key $CA_DIR/server.key \
  -out $CA_DIR/server.csr \
  -subj "/CN=patroni01" \
  -addext "subjectAltName=IP:10.255.255.51,IP:127.0.0.1"
openssl x509 -req -days 365 -in $CA_DIR/server.csr \
  -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key -CAcreateserial \
  -out $CA_DIR/server.crt \
  -extfile <(printf "subjectAltName=IP:10.255.255.51,IP:127.0.0.1")

chown etcd:etcd $CA_DIR/*.{crt,key}
chmod 600 $CA_DIR/*.key
```

```yaml
# /etc/etcd/etcd.conf — TLS bölümleri ekle
client-transport-security:
  cert-file: /etc/etcd/tls/server.crt
  key-file:  /etc/etcd/tls/server.key
  trusted-ca-file: /etc/etcd/tls/ca.crt
  client-cert-auth: false

peer-transport-security:
  cert-file: /etc/etcd/tls/server.crt
  key-file:  /etc/etcd/tls/server.key
  trusted-ca-file: /etc/etcd/tls/ca.crt
  peer-client-cert-auth: false
```

```bash
# etcd TLS sonrası test
ETCDCTL_API=3 etcdctl \
  --endpoints=https://10.255.255.51:2379 \
  --cacert=/etc/etcd/tls/ca.crt \
  endpoint health
```

#### Patroni REST API TLS

```bash
mkdir -p /etc/patroni/tls

openssl genrsa -out /etc/patroni/tls/server.key 2048
openssl req -new -x509 -days 365 \
  -key /etc/patroni/tls/server.key \
  -out /etc/patroni/tls/server.crt \
  -subj "/CN=patroni-cluster" \
  -addext "subjectAltName=IP:10.253.10.51,IP:127.0.0.1"

chown postgres:postgres /etc/patroni/tls/*.{crt,key}
chmod 600 /etc/patroni/tls/server.key
```

```yaml
# /etc/patroni/patroni.yml → restapi: bölümüne ekle
restapi:
  certfile: /etc/patroni/tls/server.crt
  keyfile:  /etc/patroni/tls/server.key
  # cafile:   /etc/patroni/tls/ca.crt  # istemci sertifika doğrulaması için
```

```bash
# REST API TLS testi
curl -k https://10.253.10.51:8008/health | python3 -m json.tool
curl --cacert /etc/patroni/tls/server.crt https://10.253.10.51:8008/primary
```

#### PostgreSQL SSL

```bash
pt-edit-config
```

```yaml
bootstrap:
  dcs:
    postgresql:
      parameters:
        ssl: "on"
        ssl_cert_file: "/etc/patroni/tls/server.crt"
        ssl_key_file:  "/etc/patroni/tls/server.key"
        ssl_ca_file:   "/etc/patroni/tls/ca.crt"
```

```bash
pt-reload   # SSL reload gerektirir (restart değil)

# Bağlantı testi
psql "host=10.253.10.51 port=5432 dbname=postgres user=postgres sslmode=require"
psql -c "SHOW ssl;"   # on
```

#### PgBouncer TLS

```bash
# /etc/pgbouncer/pgbouncer.ini (her iki pgbouncer servisinde)
[pgbouncer]
client_tls_sslmode = require
client_tls_cert_file = /etc/pgbouncer/tls/server.crt
client_tls_key_file  = /etc/pgbouncer/tls/server.key
server_tls_sslmode = require
server_tls_ca_file = /etc/patroni/tls/ca.crt

systemctl reload pgbouncer pgbouncer-ro
```

---

## Ek C: DR Tatbikat Checklist (6 Ayda Bir)

DR tatbikatı, gerçek bir felaket anında prosedürlerin işleyeceğini doğrular.
Test ortamında her 6 ayda bir yapılması önerilir.

```
[ ] 1.  etcd snapshot alındı → /backup/etcd-<tarih>.db doğrulandı
        etcd-snapshot && ETCDCTL_API=3 etcdctl snapshot info /backup/etcd-<tarih>.db

[ ] 2.  PostgreSQL basebackup test geri yüklemesi yapıldı
        pg_basebackup → yeni dizin → patroni başlatma → pt-list OK

[ ] 3.  Planlı switchover test edildi
        pt-switchover → pt-list → yeni leader doğrulandı → pt-history incelendi

[ ] 4.  Failover simülasyonu yapıldı (Primary'de Patroni durduruldu)
        ssh patroni01 "systemctl stop patroni"
        pt-list → yeni leader seçildi
        ssh patroni01 "systemctl start patroni" → replica olarak döndü

[ ] 5.  VIP geçişi test edildi
        ssh haproxy01 "systemctl stop keepalived"
        kl-vip → haproxy02 MASTER oldu
        ssh haproxy01 "systemctl start keepalived"

[ ] 6.  Replica reinit test edildi
        ssh patroni02 "rm -rf /var/lib/pgwal/*"
        pt-reinit patroni02.local.lab → pt-list → streaming oldu

[ ] 7.  etcd quorum kurtarma testi yapıldı
        Tek üye kaldı → member remove × 2 → yeni üyeler eklendi

[ ] 8.  HAProxy/VIP yeniden kurulumu test edildi
        ansible-playbook playbooks/02-haproxy.yml --check

[ ] 9.  RTO/RPO hedefleri ölçüldü ve belgelendi
        - Failover sonrası servis erişilebilir oluş süresi (RTO hedef: < 30sn)
        - Son başarılı checkpoint'ten itibaren veri kaybı (RPO hedef: < 60sn)

[ ] 10. Tüm prosedürler güncel ve çalışır durumda belgede yer alıyor
```

---

## Ek A: Üretim Geçiş Kontrol Listesi

Kurulum tamamlanıp üretime geçmeden önce her madde doğrulanmalıdır.

```
[ ] 1.  Tüm parolalar vault'ta üretim değerleriyle güncellendi
        ansible-vault edit inventory/group_vars/all/vault.yml
        # "changeme" veya varsayılan değer kalmamalı

[ ] 2.  .vault_pass dosyasının izni 0400 yapıldı
        ls -la .vault_pass   # -r-------- olmalı

[ ] 3.  pg_hba.conf'ta "0.0.0.0/0" kuralı kaldırıldı
        pt-edit-config → pg_hba listesini kontrol et

[ ] 4.  HAProxy stats sayfasına kimlik doğrulama eklendi
        # /etc/haproxy/haproxy.cfg → stats auth admin:GuvenliParola

[ ] 5.  TLS sertifikaları kuruldu (§20.7)
        - etcd TLS aktif
        - Patroni REST API TLS aktif
        - PostgreSQL SSL aktif
        - PgBouncer TLS aktif

[ ] 6.  SSH parola kimlik doğrulaması kapatıldı
        grep "PasswordAuthentication no" /etc/ssh/sshd_config

[ ] 7.  Yedekleme stratejisi kuruldu ve test edildi
        - etcd snapshot cron aktif: crontab -u etcd -l
        - pg_basebackup test geri yüklemesi başarılı
        - pgBackRest stanza kuruldu: pgbackrest --stanza=pg-cluster info

[ ] 8.  Failover testi başarıyla tamamlandı
        pt-switchover → pt-list → pt-history

[ ] 9.  DR tatbikatı yapıldı (Ek DR checklist)

[ ] 10. İzleme ve alarm sistemi kuruldu
        - Prometheus scrape konfigürasyonu
        - Alertmanager alert kuralları
        - Grafana dashboard'lar

[ ] 11. SELinux Enforcing modda
        getenforce   # Enforcing

[ ] 12. Firewall kuralları sadece gerekli IP'lere ve portlara izin veriyor
        firewall-cmd --list-all   # Her node'da

[ ] 13. OOM koruması doğrulandı
        for svc in etcd patroni; do
          pid=$(systemctl show $svc -p MainPID | cut -d= -f2)
          echo "$svc: $(cat /proc/$pid/oom_score_adj)"
        done
        # Tümü -1000 olmalı

[ ] 14. pt-list → 1 Leader + 2 Replica streaming ✓
[ ] 15. etcd-health → 3/3 sağlıklı ✓
[ ] 16. ha-backends → pg_primary UP, pg_replicas UP ✓
[ ] 17. kl-vip → VIP aktif ✓
[ ] 18. pb-pools → cl_waiting = 0 ✓
[ ] 19. Güvenlik raporu: reports/security-report-*.html → 0 AVC ✓
[ ] 20. Sağlık raporu: reports/infra-health-*.html → tüm servisler yeşil ✓
```

---

## Ek B: Günlük Rutin Kontrol Listesi

Her sabah (sabah vardiyası başı) çalıştırılacak komutlar:

```bash
#!/bin/bash
# Günlük HA sağlık kontrolü — patroni01'de çalıştır

echo "===== $(date '+%Y-%m-%d %H:%M') HA GÜNLÜK KONTROL ====="

echo "--- KÜME DURUMU ---"
pt-list

echo "--- etcd SAĞLIK ---"
etcd-health

echo "--- HAProxy BACKEND ---"
ha-backends

echo "--- VIP ---"
kl-vip

echo "--- DİSK KULLANIMI ---"
infra-disk

echo "--- SERVİS DURUMLARI ---"
infra-services

echo "--- OOM KONTROL (son 24 saat) ---"
infra-oom-check

echo "--- REPLIKASYON DURUMU ---"
pg-repl-status

echo "--- KRİTİK SİSTEM MESAJLARI (son 24 saat) ---"
journalctl --since "24 hours ago" -p crit..emerg --no-pager | tail -20
```

Beklenen sağlıklı çıktı:
```
[ ] 1. pt-list       → 1 Leader (running) + 2 Replica (streaming), aynı TL, Lag=0
[ ] 2. etcd-health   → 3/3 sağlıklı
[ ] 3. ha-backends   → pg_primary UP, pg_replicas UP (en az 2 UP)
[ ] 4. kl-vip        → 10.253.10.56 haproxy01 veya haproxy02'de
[ ] 5. infra-disk    → /var/lib/pgsql, /var/lib/pgwal < %80 dolu
[ ] 6. infra-services → etcd, patroni, haproxy, keepalived, pgbouncer tümü active
[ ] 7. infra-oom-check → "OOM kill yok"
[ ] 8. pg-repl-status  → Replica'lar streaming, lag < 10MB
[ ] 9. Kritik mesaj    → Çıktı boş (mesaj yoksa sağlıklı)
```

Anomali bulunursa ilgili `*-diagnose` alias'ını çalıştırın:
- Patroni sorunu → `pt-diagnose`
- etcd sorunu → `etcd-diagnose`
- HAProxy sorunu → `ha-diagnose`
- VIP sorunu → `kl-diagnose`
- PgBouncer sorunu → `pb-diagnose`

---

## Ek D: Performans Ayarı

### D.1 PostgreSQL Parametre Optimizasyonu

Patroni DCS üzerinden tüm küme parametre değişiklikleri tek komutla uygulanır:

```bash
pt-edit-config
```

```yaml
bootstrap:
  dcs:
    postgresql:
      parameters:
        # ── Bellek ────────────────────────────────────────────────────
        shared_buffers:             '1GB'     # RAM'in ~%25'i
        effective_cache_size:       '3GB'     # RAM'in ~%75'i (tahmini OS önbelleği)
        work_mem:                   '16MB'    # max_connections × work_mem < RAM × 0.25
        maintenance_work_mem:       '256MB'   # VACUUM, CREATE INDEX, REINDEX için
        huge_pages:                 'try'     # Büyük sayfalar (HugeTLB — performans)

        # ── WAL ───────────────────────────────────────────────────────
        wal_buffers:                '64MB'
        wal_compression:            'lz4'     # PG 15+: lz4 / zstd / pglz / off
        max_wal_size:               '2GB'
        min_wal_size:               '512MB'
        checkpoint_completion_target: 0.9

        # ── I/O ───────────────────────────────────────────────────────
        random_page_cost:           1.1       # SSD için (HDD: 4.0)
        effective_io_concurrency:   200       # SSD için (HDD: 2)
        io_method:                  'io_uring' # PG 18: io_uring / worker / sync

        # ── Bağlantı ──────────────────────────────────────────────────
        max_connections:            200
        idle_in_transaction_session_timeout: '10min'  # Zombi oturumları öldür
        lock_timeout:               '5s'

        # ── Parallelism ───────────────────────────────────────────────
        max_parallel_workers:             4
        max_parallel_workers_per_gather:  2
        max_worker_processes:             8

        # ── Planner ───────────────────────────────────────────────────
        default_statistics_target:  100
        from_collapse_limit:        8
        join_collapse_limit:        8

        # ── Logging ───────────────────────────────────────────────────
        log_min_duration_statement:   500     # 500ms üstü sorguları logla
        log_checkpoints:              'on'
        log_lock_waits:               'on'
        log_temp_files:               0       # Tüm temp dosyaları logla
        log_autovacuum_min_duration:  250     # 250ms üstü autovacuum logla
        deadlock_timeout:             '1s'
```

```bash
# Değişiklik sonrası — hangi parametreler restart bekliyor?
pt-list   # "Pending restart" kolonu

# Reload yeterli olanlar (çoğu parametre)
patronictl -c /etc/patroni/patroni.yml reload pg-cluster

# Restart gerektirenler (shared_buffers, huge_pages, max_connections vb.)
patronictl -c /etc/patroni/patroni.yml restart pg-cluster --scheduled now
```

### D.2 HAProxy Performans Ayarı

```haproxy
global
    maxconn 100000                  # Toplam bağlantı üst sınırı
    nbthread 4                      # auto_tune: CPU × 0.25 veya belirli değer
    cpu-map auto:1/1-4 0-3         # Thread → CPU çekirdek eşlemesi

defaults
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout queue   10s             # Bağlantı kuyruğu timeout

backend pg_primary
    balance leastconn               # En az bağlantılıya yönlendir
    timeout check 3s
    default-server inter 3s fall 3 rise 2
```

```bash
# Mevcut bağlantı sayısını görüntüle
echo "show info" | socat stdio /var/run/haproxy/admin.sock | \
  grep -E "CurrConns|MaxConn|Uptime"

# Thread başına yük
echo "show info" | socat stdio /var/run/haproxy/admin.sock | grep Thread
```

### D.3 PgBouncer Boyutlandırma

```
Temel formül:
  default_pool_size = pg_max_connections / (veritabanı × kullanıcı)

Örnek: 200 PG bağlantısı, 5 kullanıcı, 2 veritabanı:
  default_pool_size = 200 / (5 × 2) = 20

max_client_conn = uygulama_thread_sayısı × 1.5-2
  500 thread → max_client_conn = 750-1000
```

```ini
pool_mode = transaction       # transaction modu önerilir
max_client_conn = 1000
default_pool_size = 20
reserve_pool_size = 5
reserve_pool_timeout = 3
```

```bash
# Pool doluluğunu izle (cl_waiting > 0 = pool sıkıştı)
psql -h /var/run/pgbouncer -p 6432 -U pgbouncer pgbouncer -c "SHOW POOLS;"
```

### D.4 Yavaş Sorgu Analizi

```sql
-- pg_stat_statements extension kur (bir kez, Primary'de)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- pg_stat_statements'ı etkinleştir (patronictl edit-config)
-- shared_preload_libraries: 'pg_stat_statements'
-- pg_stat_statements.max = 10000
-- pg_stat_statements.track = all

-- En çok toplam süre harcayan 10 sorgu
SELECT
  round(total_exec_time::numeric, 2)  AS total_ms,
  calls,
  round(mean_exec_time::numeric, 2)   AS mean_ms,
  round((100 * total_exec_time / sum(total_exec_time) OVER ())::numeric, 2) AS pct,
  left(query, 120)                    AS query
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 10;

-- En yavaş ortalama süreli sorgular
SELECT calls, round(mean_exec_time::numeric, 2) AS mean_ms,
       stddev_exec_time::int AS stddev_ms, left(query, 120)
FROM pg_stat_statements
WHERE calls > 10
ORDER BY mean_exec_time DESC
LIMIT 10;

-- En çok çağrılan sorgular
SELECT calls, round(mean_exec_time::numeric, 2) AS mean_ms, left(query, 120)
FROM pg_stat_statements
ORDER BY calls DESC
LIMIT 10;

-- I/O baskısı olan sorgular (shared_blks_read yüksek)
SELECT shared_blks_read, shared_blks_hit,
       round(shared_blks_hit::numeric/(shared_blks_hit+shared_blks_read+1)*100,1) AS hit_pct,
       left(query, 120)
FROM pg_stat_statements
WHERE shared_blks_read > 1000
ORDER BY shared_blks_read DESC
LIMIT 10;

-- İstatistikleri sıfırla (analiz tamamlandıktan sonra)
SELECT pg_stat_statements_reset();
```

### D.5 Index Analizi

```sql
-- Kullanılmayan indexler (idx_scan = 0)
SELECT schemaname, tablename, indexname,
       pg_size_pretty(pg_relation_size(schemaname||'.'||indexname::text)) AS size
FROM pg_stat_user_indexes
WHERE idx_scan = 0
  AND indexname NOT LIKE '%pkey%'
  AND indexname NOT LIKE '%uniq%'
ORDER BY pg_relation_size(schemaname||'.'||indexname::text) DESC;

-- Büyük indexler
SELECT schemaname, tablename, indexname,
       pg_size_pretty(pg_relation_size(schemaname||'.'||indexname::text)) AS index_size,
       idx_scan
FROM pg_stat_user_indexes
ORDER BY pg_relation_size(schemaname||'.'||indexname::text) DESC
LIMIT 20;

-- Eksik index adayları (sıralı tarama > index taraması)
SELECT schemaname, tablename,
       seq_scan, seq_tup_read,
       idx_scan,
       CASE WHEN seq_scan > 0
            THEN round(seq_tup_read::numeric / seq_scan, 0)
            ELSE 0
       END AS avg_seq_reads
FROM pg_stat_user_tables
WHERE seq_scan > 100
  AND seq_tup_read / GREATEST(seq_scan, 1) > 1000
ORDER BY seq_tup_read DESC
LIMIT 20;

-- Önbellek hit oranı (>0.99 olması lazım)
SELECT
  sum(heap_blks_hit)::float / NULLIF(sum(heap_blks_hit) + sum(heap_blks_read), 0) AS cache_hit_ratio
FROM pg_statio_user_tables;

-- Düşükse shared_buffers artır veya pg_prewarm ile tabloyu önbelleğe al
CREATE EXTENSION IF NOT EXISTS pg_prewarm;
SELECT pg_prewarm('public.my_large_table');
```

### D.6 Checkpoint ve WAL Analizi

```sql
-- Checkpoint istatistikleri
SELECT checkpoints_timed, checkpoints_req,
       checkpoint_write_time / 1000 AS write_sec,
       checkpoint_sync_time / 1000  AS sync_sec,
       buffers_checkpoint, buffers_clean, buffers_backend,
       stats_reset
FROM pg_stat_bgwriter;

-- Yüksek buffers_backend_fsync → I/O darboğazı işareti
-- Yüksek checkpoints_req → max_wal_size artır veya checkpoint_completion_target artır

-- WAL üretim hızı
SELECT pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0'::pg_lsn)) AS total_wal;

-- WAL istatistikleri (PG 14+)
SELECT wal_records, wal_fpi,
       pg_size_pretty(wal_bytes::bigint)  AS wal_bytes,
       wal_write, wal_sync,
       round(wal_write_time::numeric, 2)  AS write_ms,
       round(wal_sync_time::numeric, 2)   AS sync_ms
FROM pg_stat_wal;
```
