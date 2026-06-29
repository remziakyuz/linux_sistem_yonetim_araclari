# PATRONI HA KÜMESİ — VERİTABANI YÖNETİCİSİ EL KİTABI

**Sürüm:** v1.1 (2026-06-28)
**Kapsam:** PostgreSQL 18 · Patroni · HA Küme · Performans · Güvenlik · PG18 Yeni Özellikler · İç Mimari · Kapasite Planlama

---

## İçindekiler

1. [Ortam ve Bağlantı](#1-ortam-ve-bağlantı)
2. [PostgreSQL 18 Yeni Özellikler](#2-postgresql-18-yeni-özellikler)
3. [Küme Yönetimi (Patroni Gözünden)](#3-küme-yönetimi-patroni-gözünden)
4. [Replikasyon Yönetimi](#4-replikasyon-yönetimi)
5. [Veritabanı Nesneleri](#5-veritabanı-nesneleri)
6. [Performans ve Tuning](#6-performans-ve-tuning)
7. [Sorgu Optimizasyonu](#7-sorgu-optimizasyonu)
8. [Vacuum ve Autovacuum](#8-vacuum-ve-autovacuum)
9. [WAL ve Checkpoint](#9-wal-ve-checkpoint)
10. [Yedekleme ve Kurtarma](#10-yedekleme-ve-kurtarma)
11. [Kullanıcı ve Rol Yönetimi](#11-kullanıcı-ve-rol-yönetimi)
12. [pg_stat Görünümleri](#12-pg_stat-görünümleri)
13. [Uzantı Yönetimi](#13-uzantı-yönetimi)
14. [Büyük Tablo ve Şema Operasyonları](#14-büyük-tablo-ve-şema-operasyonları)
15. [pgBouncer ve Bağlantı Havuzu](#15-pgbouncer-ve-bağlantı-havuzu)
16. [Aksaklık Giderme](#16-aksaklık-giderme)
17. [pgbench ile Performans Testi](#17-pgbench-ile-performans-testi)
18. [Bakım Takvimi](#18-bakım-takvimi)
19. [SQL Şablonları Hızlı Başvuru](#19-sql-şablonları-hızlı-başvuru)
20. [PostgreSQL İç Mimarisi](#20-postgresql-iç-mimarisi)
21. [Bağlantı Yönetimi — İleri Seviye](#21-bağlantı-yönetimi--ileri-seviye)
22. [Row Level Security (RLS)](#22-row-level-security-rls)
23. [Büyük Versiyon Yükseltme](#23-büyük-versiyon-yükseltme-major-version-upgrade)
24. [Kapasite Planlama](#24-kapasite-planlama)
25. [I/O Tuning](#25-io-tuning)
26. [Yüksek Performanslı Cluster Tasarımı](#26-yüksek-performanslı-cluster-tasarımı)
27. [Prometheus ile İzleme](#27-prometheus-ile-i̇zleme)
28. [Güvenlik (DBA Perspektifi)](#28-güvenlik-dba-perspektifi)
29. [pg_waldump ile WAL Analizi](#29-pg_waldump-ile-wal-analizi)
30. [Paralel Sorgu ve JIT — Detaylı](#30-paralel-sorgu-ve-jit--detaylı)
- [Ek A: Performans Tuning Hızlı Referans](#ek-a-performans-tuning-hızlı-referans-yaml)
- [Ek B: Tanılama Sorguları Hızlı Başvuru](#ek-b-tanılama-sorguları-hızlı-başvuru)

---

## 1. Ortam ve Bağlantı

### 1.1 Bağlantı Noktaları

| Bağlantı | Host | Port | Açıklama |
|----------|------|------|----------|
| **Uygulama yazma** | 10.253.10.56 (VIP) | 6432 | PgBouncer → Primary |
| **Uygulama okuma** | 10.253.10.56 (VIP) | 6433 | PgBouncer → Replica'lar |
| **DBA doğrudan** | 10.253.10.51 | 5432 | Patroni Primary (patroni01) |
| **DBA doğrudan** | 10.253.10.52 | 5432 | Patroni (patroni02) |
| **DBA doğrudan** | 10.253.10.53 | 5432 | Patroni (patroni03) |

```bash
# Bağlantı örnekleri
psql -h 10.253.10.56 -p 6432 -U postgres -d mydb          # PgBouncer yazma
psql -h 10.253.10.56 -p 6433 -U readonly_user -d mydb     # PgBouncer okuma
psql -h 10.253.10.51 -p 5432 -U postgres -d mydb          # Doğrudan primary

# Admin alias'ları (patroni node'larında)
pg-primary    # Primary'ye psql
pg-replica    # Replica'ya psql
```

### 1.2 Bağlantı Parametreleri (psql)

```bash
# .pgpass — passwordless erişim
echo "10.253.10.56:6432:*:postgres:SuParola" >> ~/.pgpass
chmod 0600 ~/.pgpass

# Bağlantı dizisi (connection string)
psql "host=10.253.10.56 port=6432 dbname=mydb user=appuser sslmode=prefer"

# pgBouncer transaction mode limitasyonları:
# - SET, LISTEN, NOTIFY, PREPARE, COPY — session mode gerektirir
# - prepared statements: server_reset_query_always=1 ile dikkatli kullan
```

### 1.3 Temel Durum Sorguları

```sql
-- PG sürümü
SELECT version();

-- Hangi sunucu? (Primary mı Replica mı?)
SELECT pg_is_in_recovery(),
       inet_server_addr(),
       current_timestamp;

-- Aktif bağlantılar
SELECT count(*), state, datname
FROM pg_stat_activity
GROUP BY state, datname
ORDER BY count DESC;

-- Küme başlangıç zamanı
SELECT pg_postmaster_start_time();
```

---

## 2. PostgreSQL 18 Yeni Özellikler

### 2.1 io_uring — Linux Async I/O

```sql
SHOW io_method;   -- io_uring | worker | sync
```

**io_uring** (default, kernel 5.1+, RHEL 9 uyumlu):
- Geleneksel `pread/pwrite` syscall overhead'ini ortadan kaldırır
- Özellikle yoğun I/O iş yüklerinde (%20-40) throughput artışı
- `pg_stat_io` ile ölçülür

```sql
-- io_uring etkisini izle
SELECT backend_type, object, context,
       reads, writes, extends,
       read_time::bigint AS read_ms,
       write_time::bigint AS write_ms
FROM pg_stat_io
WHERE reads + writes > 0
ORDER BY reads + writes DESC
LIMIT 20;
```

Sorun yaşanırsa:
```sql
-- Geçici kapatma (parametre kapatmaz, önerilmez)
-- Kalıcı: vars.yml → pg_io_method: "worker"
SHOW io_method;
```

### 2.2 WAL Sıkıştırma — lz4

```sql
SHOW wal_compression;   -- lz4 (varsayılan)
```

**lz4** avantajları:
- `pglz`'ye göre 3-5× hızlı sıkıştırma, 2× hızlı açma
- WAL trafiğini %20-60 azaltır (workload'a bağlı)
- CPU maliyeti düşük

```sql
-- WAL boyutu izleme
SELECT wal_records, wal_fpi, wal_bytes,
       wal_fpi_bytes,
       round(wal_fpi_bytes::numeric / wal_bytes * 100, 2) AS fpi_pct,
       stats_reset
FROM pg_stat_wal;

-- FPI (Full Page Image) oranı > %30 ise:
--   - checkpoint_completion_target artır
--   - wal_log_hints: on durumunda pg_basebackup önerisi
```

Sıkıştırma algoritmaları karşılaştırması:
| Algoritma | Hız | Oran | Önerilen Kullanım |
|-----------|-----|------|-------------------|
| `lz4` | Çok hızlı | İyi | Varsayılan, OLTP |
| `pglz` | Yavaş | Orta | Eski sistemler |
| `zstd` | Hızlı | En iyi | Büyük FPI, yavaş ağ |
| `off` | En hızlı | Yok | NVMe + yüksek bant genişliği |

### 2.3 summarize_wal — Artımlı Yedekleme

```sql
SHOW summarize_wal;  -- off (varsayılan)
```

`summarize_wal = on` iken PG 18, her WAL dosyası için özet üretir.
Bu özetler artımlı `pg_basebackup` için gereklidir.

```bash
# Artımlı yedekleme için etkinleştir
# inventory/group_vars/all/vars.yml:
#   pg_summarize_wal: "on"
ansible-playbook playbooks/patroni-infra-kur.yml --tags patroni

# Artımlı yedek (manifest gerektirir)
pg_basebackup -h 10.253.10.52 -p 5432 -U replicator \
  --incremental=<manifest-dosyası> \
  -D /backup/pg-incr-$(date +%F) -Ft --checkpoint=fast
```

### 2.4 allow_alter_system

```sql
SHOW allow_alter_system;  -- on (varsayılan)
```

`off` yapılırsa `ALTER SYSTEM SET ...` ve `ALTER SYSTEM RESET ...` komutları engellenir.
Patroni kümesinde `ALTER SYSTEM` yerine `patronictl edit-config` tercih edin.

```bash
# Patroni kümesinde DCS'ten parametre değişikliği (önerilen yol)
pt-edit-config

# ALTER SYSTEM ise sadece o node'u etkiler — kümeyi bozabilir!
```

### 2.5 Geliştirilmiş pg_stat_io (PG 18)

```sql
-- Tüm I/O metrikleri
SELECT backend_type, object, context, reads, writes, extends,
       hit, evictions, reuses,
       read_time::bigint || 'ms' AS read_time,
       write_time::bigint || 'ms' AS write_time
FROM pg_stat_io
ORDER BY reads + writes DESC;

-- Buffer cache miss oranı
SELECT sum(reads)::float / nullif(sum(reads + hit), 0) AS cache_miss_ratio
FROM pg_stat_io WHERE context = 'normal';

-- Tablo seviyesi I/O
SELECT schemaname, relname,
       heap_blks_read, heap_blks_hit,
       round(heap_blks_hit::numeric * 100 /
             nullif(heap_blks_hit + heap_blks_read, 0), 2) AS hit_pct
FROM pg_statio_user_tables
ORDER BY heap_blks_read DESC
LIMIT 20;
```

### 2.6 Recovery Prefetch (PG 14+, PG 18'de Varsayılan `on`)

```sql
SHOW recovery_prefetch;  -- on (replica'larda)

-- Prefetch istatistikleri (Replica'da)
SELECT * FROM pg_stat_recovery_prefetch;
```

Yüksek `prefetch_skipped` varsa `wal_receiver_buffer_size` artırın.

---

## 3. Küme Yönetimi (Patroni Gözünden)

### 3.1 Küme Durumu

```bash
# Alias (patroni node'larında)
pt-list

# Detaylı JSON çıktı
patronictl -c /etc/patroni/patroni.yml list --output=json

# REST API üzerinden
curl -s http://10.253.10.51:8008/patroni | python3 -m json.tool
```

### 3.2 Patroni DCS Konfigürasyonu

```bash
pt-config        # Mevcut DCS konfigürasyonu
pt-edit-config   # DCS konfigürasyonunu düzenle
```

PostgreSQL parametrelerini `pt-edit-config` ile değiştirin:

```yaml
bootstrap:
  dcs:
    postgresql:
      parameters:
        shared_buffers: "2GB"         # Restart gerektirir
        work_mem: "16MB"              # Reload yeterli
        wal_compression: "zstd"       # Reload yeterli
        io_method: "worker"           # io_uring sorun yaşanırsa
        checkpoint_timeout: "20min"   # Reload yeterli
        log_min_duration_statement: 500  # Reload yeterli
```

```bash
# Reload (restart gerektirmeyen parametreler)
pt-reload

# Restart (shared_buffers, max_connections vb.)
# Önce pt-list → "Pending restart" olan node'ları gör
patronictl -c /etc/patroni/patroni.yml restart pg-cluster --scheduled now
```

### 3.3 Patroni History

```bash
pt-history   # Tüm switchover/failover/restart geçmişi

# Manuel:
patronictl -c /etc/patroni/patroni.yml history pg-cluster
```

### 3.4 Synchronous Mod

```bash
pt-edit-config
```

```yaml
bootstrap:
  dcs:
    synchronous_mode: false      # true → veri kaybına karşı garantili failover
    synchronous_mode_strict: false  # true → sync replica yoksa yaz kabul etme
```

**Dikkat:** `synchronous_mode: true` yazma performansını etkiler.
OLTP için genellikle `false` yeterlidir; kritik finansal uygulamalar için `true`.

---

## 4. Replikasyon Yönetimi

### 4.1 Replikasyon Durumu

```sql
-- Primary'de — replikasyon gecikmesi
SELECT client_addr,
       state,
       pg_size_pretty(sent_lsn - replay_lsn) AS lag_bytes,
       pg_size_pretty(sent_lsn - flush_lsn) AS flush_lag,
       sync_state,
       write_lag, flush_lag, replay_lag
FROM pg_stat_replication
ORDER BY replay_lsn DESC;

-- Replica'da — gecikme süresi
SELECT now() - pg_last_xact_replay_timestamp() AS replication_delay,
       pg_is_in_recovery(),
       pg_last_wal_receive_lsn(),
       pg_last_wal_replay_lsn();
```

```bash
# Alias
pg-repl-status    # Primary'de
```

### 4.2 Replikasyon Slotları

```sql
-- Mevcut slotlar
SELECT slot_name, plugin, slot_type,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_wal,
       active, catalog_xmin
FROM pg_replication_slots;

-- Aktif olmayan slot varsa WAL birikmesi riski!
-- Güvenli temizleme:
SELECT pg_drop_replication_slot('eski_slot_adi');
```

**Uyarı:** Pasif slotlar WAL birikmesine → disk dolmasına → küme çöküşüne yol açar.
`maximum_lag_on_failover` (Patroni) ile slot davranışı yönetilir.

### 4.3 Replikasyon Kullanıcısı

```sql
-- replicator kullanıcısı Patroni tarafından oluşturulur
SELECT usename, userepl, usebypassrls
FROM pg_user
WHERE usename = 'replicator';

-- Bağlantı testi
PGPASSWORD=<repl_password> /usr/pgsql-18/bin/psql \
  -h 10.255.255.52 -p 5432 -U replicator \
  -c "IDENTIFY_SYSTEM;" replication=database
```

### 4.4 Timeline Takibi

```sql
-- Mevcut timeline (Primary ve replica'larda)
SELECT timeline_id FROM pg_control_checkpoint();

-- Timeline geçmişi
PGPASSWORD=<repl_pass> /usr/pgsql-18/bin/psql \
  -h 10.255.255.51 -p 5432 -U replicator replication=on \
  -c "TIMELINE_HISTORY 2;"
```

---

## 5. Veritabanı Nesneleri

### 5.1 Temel DDL

```sql
-- Veritabanı oluştur
CREATE DATABASE mydb
  ENCODING = 'UTF8'
  LC_COLLATE = 'tr_TR.UTF-8'
  LC_CTYPE = 'tr_TR.UTF-8'
  TEMPLATE = template0;

-- Şema
CREATE SCHEMA myschema AUTHORIZATION myuser;

-- Tablo
CREATE TABLE orders (
    id            bigserial PRIMARY KEY,
    customer_id   bigint NOT NULL,
    order_date    timestamptz NOT NULL DEFAULT now(),
    total_amount  numeric(12,2) NOT NULL,
    status        text NOT NULL DEFAULT 'pending'
) PARTITION BY RANGE (order_date);

-- Aylık partition (PG 18: gen_random_uuid() için pgcrypto gerekmez)
CREATE TABLE orders_2026_06
  PARTITION OF orders
  FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
```

### 5.2 Index Yönetimi

```sql
-- B-Tree (varsayılan)
CREATE INDEX CONCURRENTLY idx_orders_customer
  ON orders(customer_id, order_date DESC)
  WHERE status != 'cancelled';

-- GIN (tam metin, jsonb)
CREATE INDEX CONCURRENTLY idx_products_search
  ON products USING gin(to_tsvector('turkish', description));

-- BRIN (sıralı büyük tablolar)
CREATE INDEX idx_events_ts ON events USING brin(created_at)
  WITH (pages_per_range = 128);

-- Index kullanım istatistikleri
SELECT schemaname, tablename, indexname,
       idx_scan, idx_tup_read, idx_tup_fetch,
       pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC
LIMIT 20;

-- Kullanılmayan index'ler (son istatistik sıfırlamasından itibaren)
SELECT schemaname, tablename, indexname,
       pg_size_pretty(pg_relation_size(indexrelid)) AS wasted_size
FROM pg_stat_user_indexes
WHERE idx_scan = 0
  AND indexrelid NOT IN (
    SELECT conindid FROM pg_constraint WHERE contype IN ('p', 'u')
  )
ORDER BY pg_relation_size(indexrelid) DESC;
```

### 5.3 Tablo Boyutu ve Şişme

```sql
-- Tablo boyutları
SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS total,
       pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS table,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)
                      - pg_relation_size(schemaname||'.'||tablename)) AS indexes
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog','information_schema')
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 20;

-- Dead tuple (şişme) raporu
SELECT schemaname, relname,
       n_live_tup, n_dead_tup,
       round(n_dead_tup::numeric * 100 / nullif(n_live_tup + n_dead_tup, 0), 2) AS dead_pct,
       last_autovacuum, last_autoanalyze
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC
LIMIT 20;
```

```bash
# Alias
pg-bloat
```

---

## 6. Performans ve Tuning

> **auto_tune — Parametreler Otomatik Hesaplanır**
>
> Kurulum sırasında `auto_tune` rolü çalışarak sunucunun gerçek RAM ve vCPU sayısını okur,
> aşağıdaki parametrelerin büyük çoğunluğunu **otomatik** olarak belirler.
> `group_vars/all/vars.yml` içindeki değerler sadece `auto_tune_enabled: false` iken geçerlidir (FALLBACK).
>
> Hesaplanan değerleri görmek için:
> ```bash
> ansible-playbook playbooks/patroni-infra-kur.yml --tags auto_tune --check
> ```
> Kurulum raporlarının (`reports/patroni-kurulum-*.txt`) sonundaki **AUTO-TUNE RAPORU** bölümü
> her parametre için formülü ve gerekçeyi içerir.

### 6.1 Temel Yapılandırma (auto_tune ile hesaplanır)

| Parametre | Formül | Örnek 256GB/32vCPU | Açıklama |
|-----------|--------|-------------------|----------|
| `shared_buffers` | RAM × 0.25 | 64GB | PostgreSQL buffer pool |
| `effective_cache_size` | RAM × 0.75 | 192GB | OS + PG toplam cache tahmini |
| `work_mem` | sb÷(maxconn×4), max 256MB | 81MB | Sıralama/hash başına bellek |
| `maintenance_work_mem` | min(2GB, RAM×0.05) | 2GB | VACUUM, CREATE INDEX, CLUSTER |
| `max_worker_processes` | vCPU | 32 | Arka plan worker havuzu |
| `max_parallel_workers` | max(2, vCPU/2) | 16 | Paralel query worker'ları |
| `autovacuum_max_workers` | max(3, min(8, vCPU/4)) | 8 | Paralel autovacuum |
| `io_method` | sabit | io_uring | Linux async I/O (PG 18) |
| `wal_compression` | sabit | lz4 | WAL sıkıştırma (PG 18) |
| `random_page_cost` | sabit | 1.0 | NVMe optimize |
| `effective_io_concurrency` | sabit | 1000 | NVMe optimize |
| `huge_pages` | sabit | on | Üretim: hugepages etkin |
| `jit` | sabit | on | JIT derleme |

### 6.2 Parametreleri Güncelleme

```bash
# 1. DCS üzerinden (Patroni ile — önerilen)
pt-edit-config

# 2. Değişikliğin etkisini kontrol et
pt-list    # Pending restart var mı?

# 3a. Reload yeterli ise
pt-reload

# 3b. Restart gerekiyorsa
patronictl -c /etc/patroni/patroni.yml restart pg-cluster --scheduled now

# YANLŞ: ALTER SYSTEM (sadece o node'u etkiler!)
# ALTER SYSTEM SET shared_buffers = '2GB';
```

### 6.3 work_mem Optimizasyonu

```sql
-- Büyük sıralamalar için oturum bazlı artır
SET work_mem = '64MB';

-- Hangi sorgular disk'e taşıyor?
SELECT query, temp_blks_read, temp_blks_written
FROM pg_stat_statements
WHERE temp_blks_read + temp_blks_written > 1000
ORDER BY temp_blks_read + temp_blks_written DESC
LIMIT 10;
```

**work_mem × max_connections × 2-4 = Maksimum RAM kullanımı.**
4 GB RAM, 200 bağlantı → work_mem = 5-8MB (dikkatli olun).

### 6.4 Büyük İşlemler İçin Geçici Ayarlar

```sql
-- Maintenance işlemi (INDEX, VACUUM, CLUSTER)
BEGIN;
SET LOCAL maintenance_work_mem = '1GB';
VACUUM FULL my_big_table;
COMMIT;

-- Büyük sıralama
SET work_mem = '256MB';
SELECT * FROM big_table ORDER BY big_column;
RESET work_mem;
```

### 6.5 JIT Kontrolü

```sql
SHOW jit;                    -- on (varsayılan)
SHOW jit_above_cost;         -- 100000
SHOW jit_inline_above_cost;  -- 500000

-- JIT'in devreye girdiğini gör
EXPLAIN ANALYZE SELECT sum(amount) FROM orders WHERE status = 'completed';
-- "JIT: ... Functions: ... Options: Inlining true, Optimization true"

-- OLTP sorgularda JIT kapalı olsun (kısa sorgular için overhead)
SET jit = off;
-- veya DCS'ten: jit_above_cost: 100000000
```

---

## 7. Sorgu Optimizasyonu

### 7.1 EXPLAIN ANALYZE

```sql
-- Detaylı analiz
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT, TIMING)
SELECT c.name, count(*) AS order_count, sum(o.total_amount)
FROM customers c
JOIN orders o ON c.id = o.customer_id
WHERE o.order_date >= NOW() - INTERVAL '30 days'
GROUP BY c.name;

-- JSON formatı (online araçlar için)
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT ...;

-- PG 18: pg_stat_io ile I/O detayı
-- pg_stat_reset_shared('io') sonrası sorgu çalıştır
SELECT pg_stat_reset_shared('io');
-- ... sorguyu çalıştır ...
SELECT backend_type, object, reads, writes, read_time
FROM pg_stat_io WHERE reads > 0;
```

**EXPLAIN ANALYZE Okuma İpuçları:**

| Gösterge | Sorun | Çözüm |
|----------|-------|-------|
| Seq Scan (büyük tablo) | Index yok / kullanılmıyor | Index ekle, stats güncelle |
| `rows=1000 actual rows=500000` | İstatistik bayat | ANALYZE çalıştır |
| `Buffers: read=5000000` | Cache miss yüksek | shared_buffers artır |
| `Sort Method: external merge Disk:` | work_mem yetersiz | work_mem artır |
| Hash: `batches=8` | Hash dışa taştı | work_mem artır |
| `Nested Loop (outer=100K)` | join order yanlış | enable_nestloop=off dene |

### 7.2 pg_stat_statements

```sql
-- Uzantı durumu
SELECT * FROM pg_extension WHERE extname = 'pg_stat_statements';

-- En yavaş sorgular (toplam süre)
SELECT calls, round(total_exec_time::numeric, 2) AS total_ms,
       round(mean_exec_time::numeric, 2) AS avg_ms,
       round(stddev_exec_time::numeric, 2) AS std_ms,
       rows,
       regexp_replace(query, '\s+', ' ', 'g') AS short_query
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 20;

-- En fazla I/O yapan sorgular
SELECT calls,
       shared_blks_read + local_blks_read AS total_reads,
       temp_blks_read + temp_blks_written AS temp_io,
       regexp_replace(query, '\s+', ' ', 'g') AS short_query
FROM pg_stat_statements
ORDER BY shared_blks_read DESC
LIMIT 10;

-- İstatistikleri sıfırla (yeni ölçüm için)
SELECT pg_stat_statements_reset();
```

### 7.3 Gerçek Zamanlı Ağır Sorgular

```sql
-- Anlık uzun sorgular (>5 saniye)
SELECT pid, datname, usename, client_addr,
       now() - query_start AS duration,
       wait_event_type, wait_event,
       state,
       left(query, 100) AS short_query
FROM pg_stat_activity
WHERE now() - query_start > interval '5 seconds'
  AND state != 'idle'
  AND query NOT ILIKE '%pg_stat_activity%'
ORDER BY duration DESC;
```

```bash
# Alias
pg-slow-queries
```

### 7.4 Partition Pruning (PG 18)

```sql
-- Partition pruning etkin mi?
SHOW enable_partition_pruning;  -- on

-- Partition'ın kullanıldığını doğrula
EXPLAIN SELECT * FROM orders
WHERE order_date BETWEEN '2026-06-01' AND '2026-06-30';
-- "Partitions selected: orders_2026_06" görünmeli

-- Parallel partition scan
SHOW enable_partitionwise_join;       -- on
SHOW enable_partitionwise_aggregate;  -- on

-- Yeni partition otomatik oluşturma (cron veya trigger ile)
CREATE TABLE orders_2026_07
  PARTITION OF orders
  FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
```

---

## 8. Vacuum ve Autovacuum

### 8.1 Autovacuum Yapılandırması (vars.yml'den)

| Parametre | Değer | Açıklama |
|-----------|-------|----------|
| `autovacuum_max_workers` | 3 | Eş zamanlı worker sayısı |
| `autovacuum_vacuum_cost_delay` | 2ms | Worker'ın I/O throttle gecikmesi |
| `autovacuum_vacuum_cost_limit` | 400 | Throttle eşiği (varsayılan 200) |
| `autovacuum_vacuum_scale_factor` | 0.05 | %5 dead tuple'da tetikle |
| `autovacuum_analyze_scale_factor` | 0.02 | %2 değişimde ANALYZE |
| `autovacuum_vacuum_insert_scale_factor` | 0.05 | Insert-heavy tablo için |
| `log_autovacuum_min_duration` | 1000ms | 1+ saniye süren vacuum'u logla |

### 8.2 Autovacuum İzleme

```sql
-- Hangi tablolar autovacuum bekliyor?
SELECT schemaname, relname,
       n_dead_tup,
       n_live_tup,
       round(n_dead_tup::numeric * 100 / nullif(n_live_tup + n_dead_tup, 0), 2) AS dead_pct,
       last_autovacuum,
       last_autoanalyze,
       autovacuum_count,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||relname)) AS size
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC
LIMIT 20;

-- Aktif autovacuum worker'ları
SELECT pid, datname, relid::regclass AS table,
       phase, heap_blks_total, heap_blks_scanned,
       dead_tuple_percent
FROM pg_stat_progress_vacuum
WHERE datname IS NOT NULL;
```

### 8.3 Manuel Vacuum

```sql
-- Normal vacuum (dead tuple'ları temizle)
VACUUM VERBOSE my_table;

-- Analyze (istatistik güncelle)
ANALYZE VERBOSE my_table;

-- Her ikisi birden
VACUUM ANALYZE my_table;

-- Full vacuum (disk alanını OS'e iade — tablo LOCK alır!)
-- Dikkat: Üretimde dikkatli kullanın
VACUUM FULL VERBOSE my_table;

-- Freeze (transaction ID wraparound önleme)
VACUUM FREEZE my_table;

-- Tüm veritabanı
VACUUMDB -U postgres -z -a   # Tüm DB'ler, analyze dahil
VACUUMDB -U postgres -z mydb
```

### 8.4 Tablo Bazlı Autovacuum Override

```sql
-- Sık değişen büyük tablolar için agresif ayar
ALTER TABLE orders SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.005,
    autovacuum_vacuum_cost_delay = 0,
    autovacuum_vacuum_cost_limit = 1000
);

-- Statik referans tablolar için azalt
ALTER TABLE countries SET (
    autovacuum_enabled = false   -- Neredeyse hiç değişmiyorsa
);
```

### 8.5 Transaction ID Wraparound

```sql
-- Kritik durum izleme
SELECT datname,
       age(datfrozenxid) AS xid_age,
       pg_size_pretty(pg_database_size(datname)) AS size
FROM pg_database
ORDER BY age(datfrozenxid) DESC;

-- Tablo seviyesi XID yaşı
SELECT schemaname, relname,
       age(relfrozenxid) AS xid_age
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_toast','information_schema')
ORDER BY age(relfrozenxid) DESC
LIMIT 10;

-- Uyarı eşikleri:
-- age > 100,000,000: autovacuum agresif moda geçer
-- age > 1,600,000,000: PostgreSQL emergency shutdown!
-- age > 200,000,000: acil müdahale gerekli
```

```bash
# Alias
pg-txid-age
```

---

## 9. WAL ve Checkpoint

### 9.1 WAL İstatistikleri

```sql
-- WAL üretim hızı
SELECT wal_records, wal_fpi,
       pg_size_pretty(wal_bytes) AS wal_size,
       wal_buffers_full,
       wal_write, wal_sync,
       round(wal_write_time::numeric / nullif(wal_write, 0), 2) AS avg_write_ms,
       round(wal_sync_time::numeric / nullif(wal_sync, 0), 2) AS avg_sync_ms,
       stats_reset
FROM pg_stat_wal;

-- Anlık WAL konumu
SELECT pg_current_wal_lsn(),
       pg_current_wal_insert_lsn(),
       pg_walfile_name(pg_current_wal_lsn());
```

```bash
# Alias
pg-wal-info
```

### 9.2 Checkpoint İstatistikleri

```sql
SELECT checkpoints_timed, checkpoints_req,
       round(checkpoint_write_time / 1000) AS write_sec,
       round(checkpoint_sync_time / 1000) AS sync_sec,
       buffers_checkpoint, buffers_clean, maxwritten_clean,
       buffers_backend,
       pg_size_pretty(buffers_checkpoint * 8192::bigint) AS checkpoint_data,
       stats_reset
FROM pg_stat_bgwriter;
```

```bash
# Alias
pg-checkpoint-stats
```

**İdeal değerler:**
- `checkpoints_req / (checkpoints_timed + checkpoints_req) < 0.1` → zorunlu checkpoint az
- `buffers_backend = 0` → arka plan temizleme yeterli
- `maxwritten_clean = 0` → bgwriter yetişiyor

**Sorun varsa:**
```bash
pt-edit-config
# checkpoint_timeout: "20min"      (varsayılan 15min)
# checkpoint_completion_target: "0.9"
# max_wal_size: "8GB"             (büyük workload için)
# bgwriter_lru_maxpages: 200      (varsayılan 100)
```

### 9.3 WAL Boyut Yönetimi

```bash
# WAL dizini boyutu
du -sh /var/lib/pgwal/pg_wal/
ls /var/lib/pgwal/pg_wal/ | wc -l   # Dosya sayısı

# Maksimum WAL boyutu (DCS'ten):
# max_wal_size: "4GB"  → checkpoint sıkışırsa WAL bu boyutu aşabilir

# Arşiv modu kontrolü
# (bu cluster arşivleme kullanmıyorsa wal_keep_size önemli)
```

---

## 10. Yedekleme ve Kurtarma

### 10.1 pg_basebackup

```bash
# Fiziksel full backup (Replica'dan almak Primary'ye yük bindirmez)
pg_basebackup \
  -h 10.255.255.52 -p 5432 -U replicator \
  -D /backup/pgbase/$(date +%F) \
  -Ft -Xs -P -z --checkpoint=fast \
  --label="manual-$(date +%Y%m%d)"

# WAL dosyaları dahil
ls /backup/pgbase/$(date +%F)/

# Doğrulama
pg_restore --list /backup/pgbase/$(date +%F)/base.tar.gz | head
```

### 10.2 Mantıksal Yedekleme (pg_dump)

```bash
# Tek veritabanı — custom format (önerilen)
pg_dump -h 10.253.10.56 -p 6432 -U postgres -d mydb \
  -Fc -Z 6 -f /backup/logical/mydb-$(date +%F-%H%M).dump

# Tüm veritabanları
pg_dumpall -h 10.253.10.56 -p 6432 -U postgres \
  -f /backup/logical/all-$(date +%F).sql.gz --compress=6

# Sadece şema
pg_dump -h 10.253.10.56 -p 6432 -U postgres -d mydb \
  -Fp --schema-only -f /backup/logical/mydb-schema-$(date +%F).sql

# Geri yükleme
pg_restore -h 10.253.10.56 -p 5432 -U postgres -d mydb \
  -Fc -j 4 --no-owner --no-privileges \
  /backup/logical/mydb-2026-06-28.dump
```

### 10.3 pgBackRest (PITR)

```bash
# Full yedek
pgbackrest --stanza=pg-cluster backup --type=full

# Artımlı
pgbackrest --stanza=pg-cluster backup --type=incr

# Differansiyel
pgbackrest --stanza=pg-cluster backup --type=diff

# Yedek listesi
pgbackrest --stanza=pg-cluster info

# En son noktaya kurtarma
pgbackrest --stanza=pg-cluster restore

# Belirli zamana kurtarma (PITR)
pgbackrest --stanza=pg-cluster restore \
  --target="2026-06-28 14:30:00" \
  --target-action=promote \
  --target-timeline=current
```

### 10.4 Veritabanı Replikasyonu ile Kopyalama

```sql
-- Subscription based (logical replication) — büyük migrasyon için
-- Kaynak (source):
CREATE PUBLICATION my_pub FOR ALL TABLES;

-- Hedef (target — farklı küme):
CREATE SUBSCRIPTION my_sub
  CONNECTION 'host=10.253.10.51 port=5432 user=replicator dbname=mydb'
  PUBLICATION my_pub;

-- Durum
SELECT subname, pid, received_lsn, latest_end_lsn
FROM pg_stat_subscription;
```

---

## 11. Kullanıcı ve Rol Yönetimi

### 11.1 Temel Roller

| Kullanıcı | Rol | Amaç |
|-----------|-----|------|
| `postgres` | Superuser | DBA yönetim, Patroni |
| `replicator` | REPLICATION | Streaming replikasyon |
| `appuser` | LOGIN | Uygulama read/write |
| `readonly_user` | LOGIN | Read-only sorgular |
| `monitoring` | LOGIN | PCP, pg_stat_* okuma |

### 11.2 Kullanıcı Oluşturma

```sql
-- Uygulama kullanıcısı
CREATE ROLE appuser WITH
    LOGIN
    PASSWORD 'GuvenliParola!'
    NOSUPERUSER NOCREATEDB NOCREATEROLE
    CONNECTION LIMIT 50
    VALID UNTIL '2027-01-01';

-- Read-only kullanıcısı
CREATE ROLE readonly_user WITH LOGIN PASSWORD 'GuvenliParola!';
GRANT CONNECT ON DATABASE mydb TO readonly_user;
GRANT USAGE ON SCHEMA public TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO readonly_user;

-- Monitoring kullanıcısı (PCP için)
CREATE ROLE monitoring WITH LOGIN PASSWORD 'MonParola';
GRANT pg_monitor TO monitoring;

-- Parola değişikliği (scram-sha-256)
ALTER ROLE appuser PASSWORD 'YeniGuvenliParola!';
```

### 11.3 Yetki Yönetimi

```sql
-- Şema yetkileri
GRANT USAGE, CREATE ON SCHEMA myschema TO appuser;

-- Tablo yetkileri
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA myschema TO appuser;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA myschema TO appuser;

-- Gelecekte oluşturulacak nesneler
ALTER DEFAULT PRIVILEGES FOR ROLE appuser IN SCHEMA myschema
    GRANT SELECT ON TABLES TO readonly_user;

-- Yetki denetimi
SELECT grantee, privilege_type, table_name
FROM information_schema.table_privileges
WHERE grantee = 'appuser'
ORDER BY table_name;

-- Rol listesi
\du+                    -- psql
SELECT usename, usesuper, userepl, usebypassrls
FROM pg_user ORDER BY usename;
```

### 11.4 pg_hba.conf (Patroni ile)

Patroni kümesinde `pg_hba.conf` doğrudan düzenlenmez — Patroni DCS'ten yönetir:

```bash
pt-edit-config
```

```yaml
bootstrap:
  pg_hba:
    - local   all         postgres                  peer
    - local   all         all                       scram-sha-256
    - host    all         all         10.253.10.0/24  scram-sha-256
    - host    replication replicator  10.255.255.0/24 scram-sha-256
    - host    all         monitoring  127.0.0.1/32    scram-sha-256
```

```bash
pt-reload   # pg_hba değişiklikleri reload yeterli
```

---

## 12. pg_stat Görünümleri

### 12.1 pg_stat_activity

```sql
-- Aktif bağlantılar gruplandırılmış
SELECT state, count(*), datname,
       max(now() - query_start) AS longest_wait
FROM pg_stat_activity
WHERE pid != pg_backend_pid()
GROUP BY state, datname
ORDER BY count DESC;

-- Bekleyen (lock) sorgular
SELECT pid, wait_event_type, wait_event,
       datname, usename, client_addr,
       now() - query_start AS duration,
       left(query, 100) AS short_query
FROM pg_stat_activity
WHERE wait_event IS NOT NULL
  AND state != 'idle'
ORDER BY duration DESC;

-- Boş oturumlar (bağlı ama idle)
SELECT pid, usename, datname, client_addr,
       now() - state_change AS idle_time,
       application_name
FROM pg_stat_activity
WHERE state = 'idle'
  AND now() - state_change > interval '10 minutes'
ORDER BY idle_time DESC;

-- Sorunlu sorguyu sonlandır
SELECT pg_cancel_backend(pid);    -- Sorguyu iptal (SIGINT)
SELECT pg_terminate_backend(pid); -- Bağlantıyı kes (SIGTERM)
```

### 12.2 pg_stat_user_tables

```sql
-- Tablo aktivitesi
SELECT schemaname, relname,
       seq_scan, seq_tup_read,
       idx_scan, idx_tup_fetch,
       n_tup_ins, n_tup_upd, n_tup_del,
       n_live_tup, n_dead_tup,
       last_vacuum, last_autovacuum,
       last_analyze, last_autoanalyze
FROM pg_stat_user_tables
ORDER BY seq_scan DESC
LIMIT 20;
```

### 12.3 pg_stat_bgwriter

```sql
-- Checkpoint ve bgwriter etkinliği (bkz. §9.2)
SELECT * FROM pg_stat_bgwriter;
```

### 12.4 pg_stat_database

```sql
-- Veritabanı genel istatistikleri
SELECT datname,
       numbackends AS connections,
       xact_commit, xact_rollback,
       round(xact_rollback::numeric * 100 /
             nullif(xact_commit + xact_rollback, 0), 2) AS rollback_pct,
       blks_read, blks_hit,
       round(blks_hit::numeric * 100 / nullif(blks_hit + blks_read, 0), 2) AS cache_hit_pct,
       temp_files, pg_size_pretty(temp_bytes) AS temp_bytes,
       deadlocks,
       stats_reset
FROM pg_stat_database
WHERE datname NOT IN ('template0','template1')
ORDER BY numbackends DESC;
```

### 12.5 pg_stat_io (PG 16+, PG 18'de Genişletilmiş)

```sql
-- Tüm I/O metrikleri
SELECT backend_type, object, context,
       reads, writes, extends, hits,
       evictions, reuses,
       read_time::bigint || ' ms' AS read_ms,
       write_time::bigint || ' ms' AS write_ms
FROM pg_stat_io
WHERE reads + writes + hits > 0
ORDER BY reads + writes DESC
LIMIT 20;
```

---

## 13. Uzantı Yönetimi

### 13.1 pg_stat_statements

```sql
-- Kurulu mu?
SELECT * FROM pg_extension WHERE extname = 'pg_stat_statements';

-- Kur (postgres superuser ile)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- shared_preload_libraries'de olmalı (DCS'te)
-- inventory/group_vars/all/vars.yml:
-- pg_shared_preload_libraries: "pg_stat_statements"

-- Yapılandırma
SHOW pg_stat_statements.max;           -- 10000
SHOW pg_stat_statements.track;         -- all
SHOW pg_stat_statements.track_io_timing; -- (pg_track_io_timing ile birlikte)
```

### 13.2 Önerilen Uzantılar

```sql
-- Tam metin arama (Türkçe)
CREATE EXTENSION IF NOT EXISTS pg_trgm;     -- Trigram benzerlik
CREATE EXTENSION IF NOT EXISTS unaccent;    -- Türkçe karakter normalize

-- Şifreleme
CREATE EXTENSION IF NOT EXISTS pgcrypto;    -- UUID gen, hash

-- JSON schemavalidation
CREATE EXTENSION IF NOT EXISTS pg_jsonschema;

-- Partman (otomatik partition yönetimi)
CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;

-- PostGIS (coğrafi veri)
-- dnf install -y postgis33_18
CREATE EXTENSION IF NOT EXISTS postgis;
```

### 13.3 Uzantı Güncelleme

```sql
-- Mevcut uzantı sürümleri
SELECT extname, extversion
FROM pg_extension
ORDER BY extname;

-- Güncelleme
ALTER EXTENSION pg_stat_statements UPDATE;
ALTER EXTENSION postgis UPDATE TO '3.5';

-- Mevcut sürümler
SELECT name, default_version, installed_version
FROM pg_available_extension_versions
WHERE name = 'postgis';
```

---

## 14. Büyük Tablo ve Şema Operasyonları

### 14.1 Online DDL (CONCURRENT)

```sql
-- Index'i kilitlemeden oluştur
CREATE INDEX CONCURRENTLY idx_orders_status ON orders(status);

-- Constraint ekle (önce doldur sonra validate)
ALTER TABLE orders ADD CONSTRAINT chk_amount
    CHECK (total_amount >= 0) NOT VALID;   -- Mevcut satırları kontrol etme
-- Bakım aralığında:
ALTER TABLE orders VALIDATE CONSTRAINT chk_amount;  -- Yavaş, kilitlemeden

-- Sütun ekle (nullable — anlık)
ALTER TABLE orders ADD COLUMN notes text;

-- Sütun ekle (NOT NULL ile default — PG 11+ hızlı)
ALTER TABLE orders ADD COLUMN created_by text NOT NULL DEFAULT 'system';
```

### 14.2 Tablo Yeniden Yazma (VACUUM FULL / CLUSTER)

```sql
-- VACUUM FULL: tüm alanı geri al, tablo LOCK alır
-- Production'da pgstattuple ile önce ölçün
CREATE EXTENSION IF NOT EXISTS pgstattuple;
SELECT * FROM pgstattuple('orders');  -- dead_tuple_percent > 20 ise gerekli

-- Düşük trafikte (gece 02:00-04:00)
VACUUM FULL VERBOSE orders;

-- CLUSTER: index sırasına göre yeniden yaz (tablo LOCK alır)
CLUSTER orders USING idx_orders_customer;

-- pg_repack (LOCK almadan — üretim önerisi)
-- dnf install -y pg_repack_18
pg_repack -h 10.253.10.56 -p 5432 -U postgres -d mydb -t orders
```

### 14.3 Partition Bakımı

```sql
-- Yeni ay partition'ı ekle (ay değişmeden önce)
CREATE TABLE orders_2026_08
    PARTITION OF orders
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');

-- Eski partition'ı ayır ve arşivle
ALTER TABLE orders DETACH PARTITION orders_2024_01 CONCURRENTLY;
-- orders_2024_01 artık bağımsız tablo
-- pg_dump ile arşivle, sonra drop:
DROP TABLE orders_2024_01;

-- Partition listesi
SELECT parent.relname, child.relname,
       pg_size_pretty(pg_relation_size(child.oid)) AS size
FROM pg_inherits
JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
JOIN pg_class child ON pg_inherits.inhrelid = child.oid
WHERE parent.relname = 'orders'
ORDER BY child.relname;
```

---

## 15. pgBouncer ve Bağlantı Havuzu

### 15.1 Bağlantı Modu Seçimi

| Mod | Açıklama | PgBouncer Ayarı | Kullanım |
|-----|----------|-----------------|----------|
| Session | Bağlantı süresi = oturum | `pool_mode=session` | LISTEN/NOTIFY, prepared stmt |
| Transaction | Bağlantı = transaction süresi | `pool_mode=transaction` | OLTP uygulamalar (varsayılan) |
| Statement | Bağlantı = sorgu süresi | `pool_mode=statement` | Simple okuma sorguları |

### 15.2 Transaction Mode Kısıtlamaları

Transaction modunda **ÇALIŞMAYAN** özellikler:
```sql
SET search_path = myschema;     -- ✗ Çalışmaz (session state)
LISTEN my_channel;              -- ✗ Çalışmaz
PREPARE stmt AS SELECT ...;     -- ✗ Çalışmaz (yönetilmeli)
BEGIN; ... COMMIT;              -- ✓ Çalışır
SAVEPOINT sp1;                  -- ✓ Çalışır (transaction içinde)
```

**Çözüm:** Session mod gerektiren özellikler için doğrudan PostgreSQL bağlantısı kullanın (port 5432).

### 15.3 Pool Boyutu Optimizasyonu

```sql
-- PgBouncer admin (alias: pb-admin)
psql -h /var/run/pgbouncer -p 6432 -U pgbouncer pgbouncer

SHOW POOLS;
-- cl_active: Aktif istemciler
-- cl_waiting: Bekleyen (pool_size yetersiz!)
-- sv_active: Aktif PG bağlantıları
-- sv_idle: Hazır PG bağlantıları

SHOW STATS;
-- avg_query_time: Ortalama sorgu süresi
-- avg_wait_time: Pool bekleme süresi
```

`cl_waiting > 0` ise `pool_size` artırın:
```ini
# /etc/pgbouncer/pgbouncer.ini
[databases]
mydb = host=10.253.10.56 port=5432 pool_size=30
```

### 15.4 PgBouncer Logları

```bash
journalctl -u pgbouncer -f

# Bağlantı pool tükenmesi
# "ERROR pooler error: no more connections allowed (max_client_conn)"
# Çözüm: max_client_conn artır

# Kullanıcı auth hatası
# "ERROR auth failed: user appuser"
# Çözüm: userlist.txt'de kullanıcı hash'i güncelle
```

---

## 16. Aksaklık Giderme

### 16.1 Sık Karşılaşılan Hatalar

| Hata | Neden | Çözüm |
|------|-------|-------|
| `FATAL: role "appuser" does not exist` | Kullanıcı yok | CREATE ROLE |
| `FATAL: password authentication failed` | Yanlış parola | ALTER ROLE ... PASSWORD |
| `ERROR: deadlock detected` | Çapraz lock | İşlem sırası düzenle |
| `ERROR: canceling statement due to conflict with recovery` | Standby query vs WAL | `hot_standby_feedback=on` |
| `ERROR: out of shared memory` | max_locks_per_transaction | max_locks artır |
| `FATAL: all connection slots are in use` | max_connections doldu | PgBouncer pool_size düşür |
| `ERROR: could not write to file "pg_wal/...": No space left` | WAL disk doldu | Disk temizle, max_wal_size azalt |
| `ERROR: io_uring not supported` | Kernel/SELinux | `io_method=worker` yap |

### 16.2 Lock Analizi

```sql
-- Kilitler (ağaç görünümü)
SELECT blocked.pid AS blocked_pid,
       blocked.query AS blocked_query,
       blocking.pid AS blocking_pid,
       blocking.query AS blocking_query,
       now() - blocked.query_start AS wait_time
FROM pg_catalog.pg_locks bl
JOIN pg_catalog.pg_stat_activity blocked ON bl.pid = blocked.pid
JOIN pg_catalog.pg_locks l2
    ON bl.transactionid = l2.transactionid AND bl.pid != l2.pid
JOIN pg_catalog.pg_stat_activity blocking ON l2.pid = blocking.pid
WHERE NOT bl.granted
ORDER BY wait_time DESC;

-- Lock türleri
SELECT pid, mode, locktype, relation::regclass AS table_name,
       granted, waitstart
FROM pg_locks
WHERE NOT granted
  AND locktype = 'relation';

-- Bloklayan transaction'ı sonlandır
SELECT pg_terminate_backend(blocking_pid);
```

```bash
# Alias
pg-locks
```

### 16.3 Replica'da Query Conflict

```sql
-- Replica'da uzun sorgular WAL replay'i geciktiriyor
-- Semptom: "canceling statement due to conflict with recovery"

-- Çözüm 1: hot_standby_feedback (Primary'ye geri bildir)
-- inventory/group_vars/all/vars.yml:
-- pg_hot_standby_feedback: "on"   # Zaten on

-- Çözüm 2: max_standby_streaming_delay artır
-- pg_max_standby_streaming_delay: "60s"   # Varsayılan 30s

-- Çözüm 3: Replica'ya özgü query_conflict_action
-- DCS üzerinden:
-- recovery_min_apply_delay = '5s'  -- delay replay to allow queries to complete
```

### 16.4 io_uring Sorun Giderme

```bash
# PG 18 io_uring log kontrol
journalctl -u patroni | grep -i "io_uring"

# Kernel audit log
ausearch -m AVC -ts recent | grep io_uring

# SELinux io_uring kısıtlaması kontrol
setsebool -P domain_can_use_io_uring 1

# Geçici test (io_uring kapalı)
psql -U postgres -c "SET io_method = 'worker';"   # Session seviyesi
# DCS üzerinden kalıcı:
pt-edit-config    # parameters: io_method: "worker"
```

### 16.5 Yüksek Gecikme Analizi

```sql
-- pg_stat_statements ile gecikme analizi
SELECT query,
       calls,
       round(mean_exec_time::numeric, 2) AS avg_ms,
       round(stddev_exec_time::numeric, 2) AS std_ms,
       round(max_exec_time::numeric, 2) AS max_ms,
       rows / calls AS rows_per_call
FROM pg_stat_statements
WHERE calls > 100
  AND mean_exec_time > 100
ORDER BY mean_exec_time DESC
LIMIT 20;

-- wait events analizi
SELECT wait_event_type, wait_event, count(*)
FROM pg_stat_activity
WHERE state = 'active'
GROUP BY wait_event_type, wait_event
ORDER BY count DESC;
```

---

## 17. pgbench ile Performans Testi

### 17.1 Otomatik Test (Ansible)

```bash
ansible-playbook playbooks/patroni-infra-kur.yml --tags test
ls -lt reports/pgbench-*.txt | head -1
```

### 17.2 Manuel pgbench

```bash
# pgbench kurulumu
dnf install -y postgresql18   # pgbench dahil

# Test veritabanı hazırla (scale=10 → ~1.5M satır)
pgbench -h 10.253.10.56 -p 6432 -U postgres -i -s 10 pgbenchdb

# Temel test (read-write)
pgbench -h 10.253.10.56 -p 6432 -U postgres \
  -c 20 -j 4 -T 60 -P 5 pgbenchdb

# Read-only test (Replica üzerinden)
pgbench -h 10.253.10.56 -p 6433 -U postgres \
  -c 50 -j 8 -T 60 -S pgbenchdb   # -S = SELECT only

# Büyük ölçek test
pgbench -h 10.253.10.56 -p 6432 -U postgres \
  -c 100 -j 16 -T 300 -P 10 pgbenchdb 2>&1 | tee /tmp/pgbench-$(date +%F).txt
```

### 17.3 pgbench Çıktı Analizi

```
latency average = 15.3 ms     # Ortalama gecikme (< 10ms OLTP için iyi)
initial connection time = 3.5 ms
tps = 1307.2                  # TPS (transactions/second)
```

**Karşılaştırma kriterleri:**
| Metrik | İyi | Orta | Kötü |
|--------|-----|------|------|
| TPS (20 istemci, scale=10) | > 2000 | 500-2000 | < 500 |
| Ortalama gecikme | < 10ms | 10-50ms | > 50ms |
| Maksimum gecikme | < 200ms | 200ms-1s | > 1s |

### 17.4 io_uring vs worker Karşılaştırma

```bash
# io_uring ile
pgbench -h 10.253.10.56 -p 6432 -U postgres -c 50 -j 8 -T 120 pgbenchdb
# io_method=io_uring → TPS kaydını al

# io_uring kapat (DCS üzerinden pt-edit-config → io_method: worker)
# patronictl restart
pgbench -h 10.253.10.56 -p 6432 -U postgres -c 50 -j 8 -T 120 pgbenchdb
# io_method=worker → TPS kaydını al
# Fark: io_uring genellikle %10-40 daha yüksek TPS
```

---

## 18. Bakım Takvimi

### Günlük (Otomatik)

- autovacuum, autovacuum analyze (PostgreSQL yönetir)
- etcd snapshot (cron, 04:00)
- Log rotasyonu (logrotate)

### Haftalık (DBA)

```bash
# Küme genel sağlığı
infra-services && pt-list && etcd-health

# Yavaş sorgu raporu
psql -U postgres -c "
SELECT calls, round(mean_exec_time::numeric,2) avg_ms,
       left(query,80) FROM pg_stat_statements
ORDER BY total_exec_time DESC LIMIT 20;" | tee reports/weekly-slow-$(date +%F).txt

# İstatistik güncelle
VACUUMDB -U postgres -a -z --analyze-only

# Transaction ID yaşı kontrol
pg-txid-age

# Disk doluluk
infra-disk
```

### Aylık (DBA)

```bash
# Tam sağlık raporu
ansible-playbook playbooks/patroni-infra-kur.yml --tags health

# etcd defrag
ETCDCTL_API=3 etcdctl --endpoints=http://10.255.255.51:2379 defrag --cluster

# pgbench performans testi
ansible-playbook playbooks/patroni-infra-kur.yml --tags test

# Şişmiş tablo kontrolü (dead_pct > 10 olanlar)
psql -U postgres -d mydb -c "
SELECT relname, n_dead_tup,
       round(n_dead_tup::numeric*100/nullif(n_live_tup+n_dead_tup,0),2) AS dead_pct
FROM pg_stat_user_tables WHERE n_dead_tup > 1000
ORDER BY dead_pct DESC;"

# Kullanılmayan index'ler
psql -U postgres -d mydb -c "
SELECT indexname, pg_size_pretty(pg_relation_size(indexrelid))
FROM pg_stat_user_indexes WHERE idx_scan=0
ORDER BY pg_relation_size(indexrelid) DESC;"
```

### Yıllık (DBA)

```bash
# pg_upgrade (major sürüm geçişi — ayrı prosedür)
# SSL sertifika yenileme (aktifse)
# Kullanıcı parola süre dolumu kontrol
psql -U postgres -c "SELECT usename, valuntil FROM pg_user WHERE valuntil < NOW() + interval '30 days';"
```

---

## 19. SQL Şablonları Hızlı Başvuru

### Buffer Cache Hit Oranı

```sql
SELECT round(sum(heap_blks_hit)::numeric * 100 /
             sum(heap_blks_hit + heap_blks_read), 4) AS cache_hit_pct
FROM pg_statio_user_tables;
-- Hedef: > %99
```

```bash
# Alias
pg-cache-hit
```

### Tablo Boyutları

```sql
SELECT schemaname||'.'||tablename AS table,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS total,
       pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS table_only
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

### Bağlantı Dağılımı

```sql
SELECT datname, usename, client_addr, state, count(*)
FROM pg_stat_activity
GROUP BY datname, usename, client_addr, state
ORDER BY count DESC;
```

```bash
# Alias
pg-connections
```

### Replikasyon Gecikmesi

```sql
-- Primary'de
SELECT client_addr,
       pg_size_pretty(sent_lsn - replay_lsn) AS lag_bytes,
       now() - reply_time AS last_reply_age,
       sync_state
FROM pg_stat_replication;
```

### WAL Üretim Hızı

```sql
SELECT round(wal_bytes / extract(epoch FROM (now() - stats_reset)) / 1024 / 1024, 2) AS wal_mb_per_sec
FROM pg_stat_wal;
```

```bash
# Alias
pg-wal-info
```

### pg_stat_io Özet (PG 18)

```sql
SELECT backend_type,
       sum(reads) AS total_reads,
       sum(writes) AS total_writes,
       sum(hits) AS buffer_hits,
       round(sum(read_time)::numeric, 2) AS read_ms
FROM pg_stat_io
GROUP BY backend_type
ORDER BY total_reads + total_writes DESC;
```

### Bloat Analizi

```sql
SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size,
       round(n_dead_tup::numeric * 100 / nullif(n_live_tup + n_dead_tup, 0), 2) AS dead_pct,
       n_live_tup, n_dead_tup
FROM pg_stat_user_tables
WHERE n_dead_tup > 5000
  OR round(n_dead_tup::numeric * 100 / nullif(n_live_tup + n_dead_tup, 0), 2) > 5
ORDER BY dead_pct DESC;
```

```bash
# Alias
pg-bloat
```

### Aktif Kilitler

```sql
SELECT blocked.pid AS blocked,
       blocking.pid AS blocking,
       blocked.usename,
       left(blocked.query, 80) AS blocked_query,
       left(blocking.query, 80) AS blocking_query,
       now() - blocked.query_start AS wait_time
FROM pg_stat_activity blocked
JOIN pg_stat_activity blocking
    ON blocking.pid = ANY(pg_blocking_pids(blocked.pid))
ORDER BY wait_time DESC;
```

```bash
# Alias
pg-locks
```

### PG 18 io_uring Etki Analizi

```sql
-- io_uring ile I/O profili
SELECT backend_type, object, context,
       reads, writes, hits,
       round(read_time::numeric / nullif(reads, 0), 3) AS avg_read_ms,
       round(write_time::numeric / nullif(writes, 0), 3) AS avg_write_ms
FROM pg_stat_io
WHERE reads + writes > 100
ORDER BY reads + writes DESC
LIMIT 15;
```

---

## 20. PostgreSQL İç Mimarisi

DBA olarak PostgreSQL'in nasıl çalıştığını anlamak sorunları tanımlamak ve
performans kararları vermek için kritiktir.

### 20.1 Süreç Modeli

PostgreSQL multi-process mimarisi kullanır (thread değil). Her bağlantı için
ayrı bir backend süreci oluşturulur.

```
postmaster (PID 1 — ana süreç)
├── background writer (bgwriter)    → dirty buffer'ları diske yazar
├── checkpointer                    → checkpoint işlemini yönetir
├── walwriter                       → WAL buffer'ı diske yazar
├── autovacuum launcher             → autovacuum worker'larını başlatır
│   ├── autovacuum worker
│   └── autovacuum worker
├── walsummarizer (PG 17+/18)       → WAL özet üretimi (artımlı yedek)
├── wal sender (Primary'de)         → Replica'lara WAL akışı gönderir
├── wal receiver (Replica'da)       → Primary'den WAL alır, uygular
├── logical replication launcher    → Mantıksal replikasyon worker'ları
└── backend (her bağlantı için ayrı süreç)
```

```bash
# Çalışan süreçleri gör
ps aux | grep postgres | grep -v grep

# Patroni süreç ağacı
systemctl status patroni
```

### 20.2 Bellek Yapısı

```
┌─────────────────────── SHARED MEMORY (tüm süreçler erişir) ────────────────┐
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Shared Buffer Pool          ← shared_buffers (disk bloklarını önbellekler) │
│  └───────────────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  WAL Buffers                 ← wal_buffers (WAL yazmadan önce tampon)      │
│  └───────────────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Lock Table + Clog + ...     ← transaction durumları, kilit bilgileri      │
│  └───────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘

PER-BACKEND (her bağlantı kendi ayrı belleğini kullanır):
┌────────────────────────────────────────────────────────────────────────────┐
│  work_mem              → ORDER BY, GROUP BY, hash join, merge join           │
│  maintenance_work_mem  → VACUUM, REINDEX, CREATE INDEX, ALTER TABLE          │
│  temp_buffers          → Geçici tablolar (SET temp_buffers = '64MB')         │
└────────────────────────────────────────────────────────────────────────────┘

OS KERNEL (PG'nin görünür etmediği ama kullandığı):
┌────────────────────────────────────────────────────────────────────────────┐
│  effective_cache_size  → Planlayıcıya verilen ipucu (shared_buffers + OS page cache) │
│  (Bu değer PG'nin gerçekten kullandığı değil, planlayıcıya söylediği tahmin)         │
└────────────────────────────────────────────────────────────────────────────┘
```

**Kural:** `shared_buffers + (max_connections × work_mem × 4) < Toplam RAM × 0.80`

### 20.3 MVCC (Multi-Version Concurrency Control)

Yazarlar okuyucuları, okuyucular yazarları bloklamaz.

```sql
-- Her satırın gizli MVCC alanları
SELECT ctid,       -- Fiziksel konum (blok, offset)
       xmin,       -- Bu satırı yaratan transaction ID
       xmax,       -- Silen/güncelleyen transaction ID (0=aktif)
       cmin, cmax, -- Command ID'ler
       * FROM my_table LIMIT 5;

-- Dead tuple (MVCC artıkları) durumu
SELECT relname,
       n_live_tup,
       n_dead_tup,
       round(n_dead_tup * 100.0 / nullif(n_live_tup + n_dead_tup, 0), 2) AS dead_pct,
       last_autovacuum,
       last_autoanalyze
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC
LIMIT 20;
-- dead_pct > 10 → VACUUM gerekebilir
-- VACUUM dead tuple'ları temizler; VACUUM FULL disk alanını geri kazandırır ama table lock alır
```

### 20.4 WAL Mimarisi

```
Yazma akışı:
Backend → WAL Buffer ──(walwriter)──→ WAL Dosyaları ──(bgwriter/checkpoint)──→ Veri Dosyaları
                                      /var/lib/pgwal/pg_wal/
                                      000000010000000000000001 (her segment 16MB)
                                                 │
                                                 ▼
                                         WAL Sender ──→ Replica WAL Receiver
```

```sql
-- WAL üretim hızı (toplam)
SELECT pg_size_pretty(wal_bytes) AS total_wal,
       round(wal_bytes / extract(epoch FROM (now() - stats_reset)) / 1024 / 1024, 2) AS mb_per_sec
FROM pg_stat_wal;

-- Segment sayısı
SELECT count(*) AS wal_segments,
       pg_size_pretty(count(*) * 16 * 1024 * 1024) AS total_size
FROM pg_ls_waldir();

-- Anlık WAL konumu
SELECT pg_current_wal_lsn(),
       pg_walfile_name(pg_current_wal_lsn()) AS current_segment;
```

### 20.5 Shared Buffer Pool ve Cache İzleme

```sql
-- pg_buffercache kurulumu (bir kez)
CREATE EXTENSION IF NOT EXISTS pg_buffercache;

-- Hangi tablolar buffer pool'da var?
SELECT c.relname,
       count(*) AS buffers,
       pg_size_pretty(count(*) * 8192::bigint) AS size_in_cache,
       round(count(*) * 8192.0 / nullif(pg_relation_size(c.oid), 0) * 100, 1) AS pct_cached
FROM pg_buffercache b
JOIN pg_class c ON b.relfilenode = pg_relation_filenode(c.oid)
WHERE c.relkind IN ('r', 'i')   -- tablo veya index
GROUP BY c.oid, c.relname
ORDER BY buffers DESC
LIMIT 20;

-- Toplam buffer kullanımı
SELECT pg_size_pretty(count(*) * 8192::bigint) AS used_buffer,
       round(count(*) * 100.0 / (
         SELECT setting::bigint FROM pg_settings WHERE name = 'shared_buffers'
       ), 2) AS pct_used
FROM pg_buffercache
WHERE relfilenode IS NOT NULL;

-- Buffer cache kullanım özeti (dirty vs clean)
SELECT CASE usagecount
         WHEN 0 THEN 'unused'
         WHEN 1 THEN 'low'
         WHEN 2 THEN 'medium'
         WHEN 3 THEN 'hot'
         ELSE 'very hot'
       END AS usage_class,
       isdirty,
       count(*) AS buffers
FROM pg_buffercache
GROUP BY usagecount, isdirty
ORDER BY usagecount;
```

**İpucu:** `pct_cached = 100` olan tablolar tamamen bellekte — iyi. `0`'a yakın olan tablolar için shared_buffers artırmak veya hot veriyi küçültmek gerekebilir.

### 20.6 TOAST (Büyük Nesne Depolama)

TOAST (The Oversized-Attribute Storage Technique), 8KB blok sınırını aşan değerleri ayrı bir tabloya taşır.

```sql
-- TOAST depolama stratejileri:
-- PLAIN    → sıkıştırma/taşıma yok (küçük sabit uzunluklu tipler: int, float)
-- EXTENDED → sıkıştır + gerekirse taşı (varsayılan, text/jsonb için)
-- EXTERNAL → sıkıştırma yok, doğrudan taşı (regex gibi erişimde hızlı)
-- MAIN     → önce sıkıştır, zorunluysa taşı

-- Sütun TOAST stratejisini değiştir
ALTER TABLE documents ALTER COLUMN content SET STORAGE EXTENDED;
ALTER TABLE events ALTER COLUMN raw_payload SET STORAGE EXTERNAL;  -- Regex kullanılacaksa

-- Hangi tablonun TOAST tablosu büyük?
SELECT c.relname AS table_name,
       pg_size_pretty(pg_relation_size(c.reltoastrelid)) AS toast_size,
       pg_size_pretty(pg_relation_size(c.oid)) AS table_size
FROM pg_class c
WHERE c.relkind = 'r'
  AND c.reltoastrelid > 0
  AND pg_relation_size(c.reltoastrelid) > 0
ORDER BY pg_relation_size(c.reltoastrelid) DESC
LIMIT 10;

-- Mevcut TOAST stratejilerini gör
SELECT attname, attstorage
FROM pg_attribute
WHERE attrelid = 'documents'::regclass
  AND attnum > 0;
-- p=PLAIN, e=EXTENDED, x=EXTERNAL, m=MAIN
```

### 20.7 Tablespace Yönetimi

```sql
-- Tablespace oluştur (farklı disk veya dizin için)
CREATE TABLESPACE fast_nvme LOCATION '/mnt/nvme/postgresql';
CREATE TABLESPACE archive LOCATION '/mnt/hdd/postgresql';

-- Tablespace listesi
SELECT spcname,
       pg_size_pretty(pg_tablespace_size(spcname)) AS size,
       pg_tablespace_location(oid) AS location
FROM pg_tablespace
WHERE spcname NOT IN ('pg_default', 'pg_global');

-- Tabloyu farklı tablespace'e taşı (tablo lock alır)
ALTER TABLE large_table SET TABLESPACE fast_nvme;

-- Index'i farklı tablespace'e koy (CONCURRENT — lock almaz)
CREATE INDEX CONCURRENTLY idx_orders_date
    ON orders(created_at)
    TABLESPACE fast_nvme;

-- Mevcut index'i taşı
ALTER INDEX idx_orders_date SET TABLESPACE fast_nvme;

-- Veritabanının varsayılan tablespace'ini değiştir
ALTER DATABASE mydb SET TABLESPACE fast_nvme;

-- Tablespace'deki nesneler
SELECT relname, relkind, pg_size_pretty(pg_relation_size(oid))
FROM pg_class
WHERE reltablespace = (SELECT oid FROM pg_tablespace WHERE spcname = 'fast_nvme');
```

---

## 21. Bağlantı Yönetimi — İleri Seviye

### 21.1 max_connections Formülü

```
Formül (PgBouncer olmadan):
  max_connections = (RAM_GB × 1000 / work_mem_MB) × 0.25

Örnekler:
  4 GB  RAM, work_mem=16MB  → (4×1000/16) × 0.25 = 62   → 100-150 kullan
  8 GB  RAM, work_mem=16MB  → (8×1000/16) × 0.25 = 125  → 150-200 kullan
  16 GB RAM, work_mem=16MB  → (16×1000/16) × 0.25 = 250 → 200-300 kullan
  32 GB RAM, work_mem=16MB  → (32×1000/16) × 0.25 = 500 → 300-500 kullan

PgBouncer ile (önerilen):
  PostgreSQL max_connections → 100-200 (düşük tutun)
  PgBouncer max_client_conn → 1000-5000 (uygulama ihtiyacına göre)
  PgBouncer default_pool_size → max_pg_conn / (db_sayısı × user_sayısı)
```

```sql
-- Bağlantı limitine yaklaşıyor mu?
SELECT
  count(*) AS current,
  (SELECT setting::int FROM pg_settings WHERE name='max_connections') AS max_conn,
  (SELECT setting::int FROM pg_settings WHERE name='superuser_reserved_connections') AS reserved,
  round(count(*) * 100.0 /
        (SELECT setting::int FROM pg_settings WHERE name='max_connections'), 2) AS pct
FROM pg_stat_activity;

-- Kullanıcı başına bağlantı
SELECT usename, count(*), max(now()-query_start) AS longest
FROM pg_stat_activity
WHERE pid != pg_backend_pid()
GROUP BY usename
ORDER BY count DESC;
```

### 21.2 Idle In Transaction — En Tehlikeli Durum

`idle in transaction` bağlantılar:
- Tablo lock'larını tutar → VACUUM, DDL, autovacuum engellenir
- Replikasyon slotlarını doldurabilir
- WAL birikmesine neden olur

```sql
-- Tehlikeli idle in transaction bağlantıları
SELECT pid, usename, datname,
       now() - xact_start AS txn_age,
       wait_event_type, wait_event,
       left(query, 100) AS last_query
FROM pg_stat_activity
WHERE state = 'idle in transaction'
ORDER BY txn_age DESC;

-- 5 dakikadan uzun idle in transaction'ları öldür
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle in transaction'
  AND now() - xact_start > interval '5 minutes';
```

```bash
# Otomatik temizleme (DCS üzerinden)
pt-edit-config
# parameters: idle_in_transaction_session_timeout: '5min'
pt-reload
```

### 21.3 PgBouncer Boyutlandırma Formülü

```ini
# Formül:
# max_client_conn = Uygulamanın açabileceği maksimum bağlantı
# default_pool_size = PostgreSQL max_connections / (veritabanı_sayısı × kullanıcı_sayısı)

# Örnek: 200 PG bağlantısı, 5 uygulama kullanıcısı, 2 veritabanı:
default_pool_size = 20    # 200 / (5 × 2) = 20
max_client_conn = 1000    # Uygulamanın açabileceği toplam bağlantı
reserve_pool_size = 5     # Spike için rezerv (pool_size'a ek)
reserve_pool_timeout = 3  # Rezerv havuza geçiş süresi (saniye)

# Pool mod seçimi:
# transaction → OLTP uygulamalar için (varsayılan)
# session     → LISTEN/NOTIFY, prepared statement, SET kullanan uygulamalar
# statement   → Çok basit okuma sorguları (üretimde nadiren uygun)
pool_mode = transaction
```

```sql
-- cl_waiting > 0 ise pool yetersiz → default_pool_size artır
-- sv_idle çok fazlaysa pool aşırı büyük → azalt
psql -h /var/run/pgbouncer -p 6432 -U pgbouncer pgbouncer -c "SHOW POOLS;"
```

---

## 22. Row Level Security (RLS)

### 22.1 Temel RLS Yapılandırması

```sql
-- Tablo bazlı satır güvenliği etkinleştir
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;  -- Sahip de politikaya tabi olsun

-- Her kullanıcı sadece kendi siparişlerini görsün
CREATE POLICY orders_user_isolation ON orders
    FOR ALL
    TO app_role
    USING (user_id = current_setting('app.current_user_id')::int);

-- Yöneticiler her şeyi görsün
CREATE POLICY orders_admin_all ON orders
    FOR ALL
    TO admin_role
    USING (true);

-- Sadece okuma için politika
CREATE POLICY orders_readonly ON orders
    FOR SELECT
    TO readonly_role
    USING (status != 'deleted');

-- Politikaları listele
SELECT policyname, roles, cmd, qual, with_check
FROM pg_policies
WHERE tablename = 'orders';

-- Test (başka kullanıcı olarak)
SET ROLE app_user;
SET app.current_user_id = '42';
SELECT * FROM orders;  -- Sadece user_id=42 satırları gelir
RESET ROLE;
RESET app.current_user_id;
```

### 22.2 Performans Etkileri

RLS, her sorguya WHERE koşulu ekler. Büyük tablolarda index'lerin RLS koşullarını kapsadığından emin olun:

```sql
-- RLS politikası koşuluna index ekle
CREATE INDEX idx_orders_user_id ON orders(user_id)
    WHERE status != 'deleted';

-- EXPLAIN ile politika etkisini gör
EXPLAIN SELECT * FROM orders;
-- "Filter: (user_id = (current_setting('app.current_user_id'))::integer)"
```

---

## 23. Büyük Versiyon Yükseltme (Major Version Upgrade)

### 23.1 pg_upgrade ile Yükseltme

Örnek: PostgreSQL 16'dan 18'e yükseltme. Tüm veri kopyalanmadan yerinde dönüştürülür.

```bash
# 1. Hazırlık — YENİ sürüm kurulumu (mevcut sürümü kaldırma)
dnf install -y postgresql18-server postgresql18

# 2. Yeni PostgreSQL'i başlatma (Patroni dışı — sadece upgrade için)
/usr/pgsql-18/bin/postgresql-18-setup initdb
# Geçici initdb — sonra silinecek

# 3. Patroni kümesini durdur (TÜM NODE'LARDA)
for node in patroni01 patroni02 patroni03; do
  ssh $node "systemctl stop patroni"
done

# 4. Upgrade sadece Primary node'da yapılır
# Primary node'da (bu örnekte patroni01):
su -s /bin/bash postgres -c "
  /usr/pgsql-18/bin/pg_upgrade \
    -b /usr/pgsql-16/bin \
    -B /usr/pgsql-18/bin \
    -d /var/lib/pgsql/16/data \
    -D /var/lib/pgsql/18/data \
    --link          # Hard link ile hızlı (geri dönüş için --clone tercih edilir)
    -o '-c config_file=/etc/patroni/pg16.conf' \
    -O '-c config_file=/etc/patroni/pg18.conf'
"

# 5. pg_upgrade kontrol (gerçek işlemden önce)
/usr/pgsql-18/bin/pg_upgrade \
  -b /usr/pgsql-16/bin -B /usr/pgsql-18/bin \
  -d /var/lib/pgsql/16/data -D /var/lib/pgsql/18/data \
  --check   # Sadece uyumluluk kontrolü — değişiklik yapmaz

# 6. Patroni yapılandırmasını güncelle
# /etc/patroni/patroni.yml → data_dir, bin_dir, pg versiyonu güncelle

# 7. Primary node'da Patroni başlat
systemctl start patroni
pt-list   # Leader olmasını bekle

# 8. Replica'ları yeniden klon
# pg_upgrade sonrası replica'lar uyumsuz olur — reinit şart
for node in patroni02 patroni03; do
  ssh $node "rm -rf /var/lib/pgsql/16/data/* /var/lib/pgwal/*"
  ssh $node "systemctl start patroni"   # Patroni otomatik klon yapacak
done
pt-list   # streaming olmasını bekle

# 9. Yükseltme sonrası istatistik güncelleme (önerilen)
/usr/pgsql-18/bin/vacuumdb -U postgres -a --analyze-in-stages

# 10. Eski sürümü kaldır (doğrulama sonrası)
# dnf remove -y postgresql16-server postgresql16
```

**Dikkat:** `--link` modu hızlıdır ama upgrade başarısız olursa 16'ya geri dönülemez.
Güvenli geri dönüş için `--clone` (CoW filesystem) veya snapshot kullanın.

### 23.2 pg_upgrade Uyumluluk Kontrolü

```bash
# Önceden kontrol et
/usr/pgsql-18/bin/pg_upgrade \
  -b /usr/pgsql-16/bin -B /usr/pgsql-18/bin \
  -d /var/lib/pgsql/16/data -D /var/lib/pgsql/18/data \
  --check 2>&1 | tee /tmp/pg_upgrade_check.log

# Sorun çıkarabilecek şeyler:
# - Kullanıcı tanımlı data type'lar
# - reg* tipler (regproc, regclass vb.) tablo sütunlarında kullanılmışsa
# - Contrib paketlerin yeni sürümde de kurulu olması gerekir
```

---

## 24. Kapasite Planlama

### 24.1 Büyüme Tahmini

```sql
-- Veritabanı boyut artış hızı (pg_stat_database — stats_reset'ten itibaren)
SELECT datname,
       pg_size_pretty(pg_database_size(datname)) AS current_size,
       pg_size_pretty(
         pg_database_size(datname) /
         extract(epoch FROM (now() - stats_reset)) * 86400 * 30
       ) AS est_monthly_growth,
       stats_reset
FROM pg_stat_database
WHERE datname NOT IN ('template0','template1','postgres')
ORDER BY pg_database_size(datname) DESC;

-- Tablo başına büyüme trendi (son N gün için monitoring gerekir)
-- pgstattuple ile tablo şişme durumu
CREATE EXTENSION IF NOT EXISTS pgstattuple;
SELECT tablename,
       (pgstattuple(tablename)).approx_free_percent AS free_pct,
       (pgstattuple(tablename)).approx_bloat_size AS bloat_bytes
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY bloat_bytes DESC
LIMIT 10;
```

### 24.2 Disk Kapasitesi

```bash
# PostgreSQL veri büyüklüğü
du -sh /var/lib/pgsql/18/data/base/

# WAL disk kullanımı
du -sh /var/lib/pgwal/pg_wal/
ls /var/lib/pgwal/pg_wal/ | wc -l   # Dosya sayısı × 16MB = kullanım

# /var/lib/pgsql doluluk oranı
df -h /var/lib/pgsql /var/lib/pgwal

# Projeksiyon: WAL MB/saat × 24 = günlük WAL
# max_wal_size genellikle anlık pik; ortalama WAL ≈ wal_bytes / saat_sayısı
```

```sql
-- Disk kullanım raporu (DB, tablo, index)
SELECT 'DATABASE' AS type, datname AS name,
       pg_size_pretty(pg_database_size(datname)) AS size
FROM pg_database
WHERE datname NOT IN ('template0','template1')
UNION ALL
SELECT 'TABLE', schemaname||'.'||tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY type, name;
```

### 24.3 Bağlantı Kapasitesi

```sql
-- Günlük pik bağlantı trendi (monitoring yoksa pg_stat_database'den tahmin)
SELECT datname,
       numbackends AS now,
       (SELECT setting::int FROM pg_settings WHERE name='max_connections') AS max,
       round(numbackends * 100.0 /
             (SELECT setting::int FROM pg_settings WHERE name='max_connections'), 2) AS pct
FROM pg_stat_database
WHERE datname NOT IN ('template0','template1','postgres')
ORDER BY numbackends DESC;
```

### 24.4 Transaction ID Wraparound Planlaması

```sql
-- Mevcut XID yaşı ve tahmini kritik süre
SELECT datname,
       age(datfrozenxid) AS xid_age,
       2147483647 - age(datfrozenxid) AS xids_remaining,
       round((2147483647 - age(datfrozenxid)) /
             (SELECT xact_commit + xact_rollback FROM pg_stat_database
              WHERE datname = d.datname) / 86400) AS est_days_to_critical
FROM pg_database d
ORDER BY age(datfrozenxid) DESC;

-- Güvenli eşikler:
-- xid_age > 200,000,000   → Acil VACUUM FREEZE gerekli
-- xid_age > 1,500,000,000 → PostgreSQL shutdown riski!
-- Günlük XID tüketimi ≈ TPS × 86400 → wraparound tarihini hesapla
```

### 24.5 Kapasite Büyütme Kararları

| Kaynak | Eşik | Aksiyon |
|--------|------|---------|
| CPU | Sürekli > %80 | vCPU artır veya sorgu optimize et |
| RAM | Free < 10% | RAM artır; shared_buffers artmaz çünkü OS cache yeterli olmayabilir |
| Disk (PGDATA) | > %75 dolu | Yeni disk ekle veya eski partition'ları arşivle |
| Disk (WAL) | > %60 dolu | max_wal_size azalt veya WAL diski büyüt |
| bağlantı | pct > 80% | PgBouncer pool_size artır; PG max_conn artırma tercihi son çare |
| XID Age | > 100M | autovacuum aggressive tune, VACUUM FREEZE çalıştır |
| Replikasyon Lag | > 100MB | Cluster ağı kontrol; Replica I/O kapasitesi yetersiz olabilir |

---

## 25. I/O Tuning

### 25.1 Disk Tipi Tespiti ve Scheduler

```bash
# Disk tipi: 0=SSD/NVMe, 1=HDD
cat /sys/block/vdb/queue/rotational
cat /sys/block/vdc/queue/rotational

# I/O scheduler görüntüle
cat /sys/block/vdb/queue/scheduler
# [none] mq-deadline kyber bfq
# SSD/NVMe için 'none' veya 'mq-deadline' tercih edilir

# I/O scheduler değiştir (geçici)
echo "none" > /sys/block/vdb/queue/scheduler

# Kalıcı (udev rule)
cat > /etc/udev/rules.d/60-scheduler.rules << 'EOF'
ACTION=="add|change", KERNEL=="vdb", ATTR{queue/scheduler}="none"
ACTION=="add|change", KERNEL=="vdc", ATTR{queue/scheduler}="none"
EOF
udevadm control --reload-rules

# PGDATA ve WAL disk I/O istatistikleri (gerçek zamanlı)
iostat -x vdb vdc 1 10

# PostgreSQL süreç bazında I/O
iotop -oP -p $(pgrep -d, -f postgres)
```

### 25.2 PostgreSQL I/O Parametreleri

```yaml
# pt-edit-config ile DCS'ten değiştir
postgresql:
  parameters:
    # SSD/NVMe için
    random_page_cost: 1.1          # HDD: 4.0; SSD: 1.0-1.5; NVMe: 1.0-1.1
    effective_io_concurrency: 200  # HDD: 2; SSD: 200; NVMe: 500-1000
    maintenance_io_concurrency: 100

    # bgwriter (dirty buffer yazma agresifliği)
    bgwriter_lru_maxpages: 200     # Varsayılan: 100; her round max yazılacak sayfa
    bgwriter_delay: '50ms'         # Varsayılan: 200ms; azaltmak bgwriter'ı aktif tutar
    bgwriter_lru_multiplier: 4.0   # Önden yazma katsayısı

    # Checkpoint I/O yayılımı
    checkpoint_completion_target: 0.9  # I/O spike'ını önlemek için yay

    # Paralel I/O (maintenance işlemleri)
    max_parallel_maintenance_workers: 4   # CREATE INDEX CONCURRENTLY için
```

### 25.3 I/O Performansı İzleme

```sql
-- Tablolar arası I/O dağılımı
SELECT relname,
       heap_blks_read,
       heap_blks_hit,
       round(heap_blks_hit * 100.0 / nullif(heap_blks_hit + heap_blks_read, 0), 2) AS hit_pct,
       idx_blks_read,
       idx_blks_hit,
       toast_blks_read
FROM pg_statio_user_tables
ORDER BY heap_blks_read + idx_blks_read DESC
LIMIT 20;

-- En fazla disk okuma yapan tablolar (cache miss)
SELECT relname,
       pg_size_pretty(heap_blks_read * 8192) AS disk_read_total
FROM pg_statio_user_tables
ORDER BY heap_blks_read DESC
LIMIT 10;

-- pg_stat_io (PG 16+) — detaylı I/O
SELECT backend_type, object, context,
       reads, read_time::bigint AS read_ms,
       writes, write_time::bigint AS write_ms,
       evictions, hits
FROM pg_stat_io
WHERE reads + writes > 100
ORDER BY read_time + write_time DESC
LIMIT 20;
```

```bash
# Disk gecikme analizi (iostat)
# await > 10ms ise bottleneck; %util sürekli 100 ise I/O doymuş
iostat -x vdb 1 30 | awk '/^vdb/{print $0; if ($10+0 > 5) print "!!! YÜKSEK GECIKME: " $10 "ms"}'
```

### 25.4 Tablespace ile I/O Dağıtımı

```sql
-- Farklı diskler için tablespace
CREATE TABLESPACE fast_nvme LOCATION '/mnt/nvme/postgresql';
CREATE TABLESPACE slow_archive LOCATION '/mnt/hdd/postgresql';

-- Sık erişilen (hot) tabloları hızlı diske taşı (table lock alır)
ALTER TABLE orders SET TABLESPACE fast_nvme;

-- Index'leri ayrı diske (CONCURRENT — lock almaz)
CREATE INDEX CONCURRENTLY idx_orders_user ON orders(user_id)
    TABLESPACE fast_nvme;

-- Bu küme zaten WAL için ayrı disk kullanıyor (vdc → /var/lib/pgwal)
```

---

## 26. Yüksek Performanslı Cluster Tasarımı

### 26.1 Okuma Ölçekleme (Read Scaling)

```
Trafik dağıtımı bu kümede:
  Yazma   → VIP:6432 → PgBouncer → Primary (patroni01 veya mevcut leader)
  Okuma   → VIP:6433 → PgBouncer (round-robin) → Replica'lar (patroni02, patroni03)

Kapasite:
  1 Primary + 2 Replica = 2× okuma kapasitesi
  Yazma kapasitesi sabit kalır (sadece Primary yazar)
```

```sql
-- Bağlantının Primary mı Replica mı olduğunu kontrol et
SELECT pg_is_in_recovery();   -- true = Replica (read-only)

-- Replica'ya bağlan (libpq bağlantı string)
-- psql "host=10.253.10.56 port=6433 target_session_attrs=standby"
-- JDBC: targetServerType=preferSlave
```

### 26.2 Hot Standby Parametreleri

```yaml
postgresql:
  parameters:
    hot_standby: 'on'
    max_standby_streaming_delay: '30s'
    max_standby_archive_delay: '30s'
    hot_standby_feedback: 'on'          # Replica aktif sorgularını Primary'ye bildirir
    wal_receiver_timeout: '60s'
    wal_receiver_status_interval: '10s'
```

### 26.3 Zaman Gecikmeli Replica (Felaket Kurtarma Penceresi)

```yaml
# Belirli bir replica için (recovery_min_apply_delay)
postgresql:
  parameters:
    recovery_min_apply_delay: '1h'   # 1 saat gecikmeli WAL uygulama
# Bu replica 1 saat öncesinin verisini gösterir
# Yanlışlıkla silinen veriyi geri almak için 1 saatlik pencere
```

### 26.4 Analitik İçin Ayrı Cluster (Mantıksal Replikasyon)

```sql
-- Kaynak (Primary) — wal_level = logical gerekli
-- pt-edit-config → parameters: wal_level: 'logical'  (restart gerektirir)

CREATE PUBLICATION olap_pub
    FOR TABLE orders, customers, products;

-- Hedef (OLAP cluster — ayrı PostgreSQL instance):
CREATE SUBSCRIPTION olap_sub
    CONNECTION 'host=10.253.10.51 port=5432 user=replicator password=xxx dbname=mydb'
    PUBLICATION olap_pub;

-- Durum
SELECT subname, pid, received_lsn, latest_end_lsn
FROM pg_stat_subscription;
```

### 26.5 NUMA Farkındalığı (Büyük Sunucular)

```bash
# NUMA topolojisi
numactl --hardware

# PostgreSQL NUMA node'a bağla
numactl --cpunodebind=0 --membind=0 -- \
    su -c "patroni /etc/patroni/patroni.yml" postgres

# NUMA istatistikleri
numastat -p $(pgrep -f 'patroni')
```

### 26.6 Performans SLA Metrikleri

```sql
-- P95/P99 sorgu gecikme tahmini
SELECT
    percentile_disc(0.95) WITHIN GROUP (ORDER BY mean_exec_time) AS p95_ms,
    percentile_disc(0.99) WITHIN GROUP (ORDER BY mean_exec_time) AS p99_ms
FROM pg_stat_statements
WHERE calls > 10;

-- Ortalama sorgu süresi
SELECT round(avg(total_exec_time / calls)::numeric, 2) AS avg_query_ms
FROM pg_stat_statements
WHERE calls > 100;
```

**SLA Hedef Eşikleri:**

| Metrik | İyi | Orta | Kötü |
|--------|-----|------|------|
| TPS (OLTP) | > 5000 | 1000-5000 | < 1000 |
| Ortalama gecikme | < 5ms | 5-50ms | > 50ms |
| P99 gecikme | < 100ms | 100ms-1s | > 1s |
| Replikasyon lag | < 10MB | 10-100MB | > 100MB |
| Buffer hit oranı | > 99% | 95-99% | < 95% |

---

## 27. Prometheus ile İzleme

### 27.1 Kritik Metrikler Referansı

| Metrik | Sorgulama Yeri | Alarm Eşiği |
|--------|----------------|-------------|
| Replikasyon lag | pg_stat_replication | > 100MB veya > 60s |
| Buffer hit oranı | pg_statio_user_tables | < 0.95 |
| Aktif bağlantı / max | pg_stat_activity | > %80 |
| Deadlock sayısı | pg_stat_database.deadlocks | > 0/dakika |
| Temp dosya boyutu | pg_stat_database.temp_bytes | > 1GB/saat |
| Transaction ID yaşı | age(datfrozenxid) | > 1.5 milyar |
| Disk doluluk | OS df | > %80 |

### 27.2 İzleme Sorguları — Dashboard Paneli

```sql
-- Anlık sağlık özeti
SELECT
    (SELECT count(*) FROM pg_stat_activity WHERE state = 'active') AS active_queries,
    (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction') AS idle_in_txn,
    (SELECT count(*) FROM pg_stat_activity WHERE wait_event IS NOT NULL) AS waiting,
    (SELECT round(sum(heap_blks_hit)::numeric / nullif(sum(heap_blks_hit + heap_blks_read), 0) * 100, 2) FROM pg_statio_user_tables) AS cache_hit_pct,
    (SELECT max(pg_size_pretty(sent_lsn - replay_lsn)) FROM pg_stat_replication) AS max_repl_lag,
    (SELECT pg_size_pretty(pg_database_size(current_database()))) AS db_size,
    (SELECT max(age(datfrozenxid)) FROM pg_database) AS max_txn_age;

-- Kilit bekleme ağacı
SELECT
    blocked.pid,
    blocked.usename,
    blocked.query AS blocked_query,
    blocking.pid AS blocking_pid,
    blocking.query AS blocking_query,
    now() - blocked.query_start AS blocked_duration
FROM pg_stat_activity blocked
JOIN pg_stat_activity blocking
    ON blocking.pid = ANY(pg_blocking_pids(blocked.pid))
ORDER BY blocked_duration DESC;
```

### 27.3 postgres_exporter ile Prometheus

```bash
# postgres_exporter env dosyası
cat > /etc/postgres_exporter.env << 'EOF'
DATA_SOURCE_NAME="postgresql://monitoring:MonParola@localhost:5432/postgres?sslmode=disable"
EOF

# Systemd servisi
cat > /etc/systemd/system/postgres_exporter.service << 'EOF'
[Unit]
Description=PostgreSQL Prometheus Exporter
After=network.target

[Service]
EnvironmentFile=/etc/postgres_exporter.env
ExecStart=/usr/local/bin/postgres_exporter \
  --web.listen-address=:9187 \
  --log.level=info
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now postgres_exporter
```

```yaml
# /etc/prometheus/rules/postgresql.yml
groups:
  - name: postgresql
    rules:
      - alert: PostgreSQLReplicationLag
        expr: pg_replication_lag > 100000000
        for: 5m
        annotations:
          summary: "Replica lag > 100MB"

      - alert: PostgreSQLHighConnections
        expr: sum(pg_stat_activity_count) / pg_settings_max_connections > 0.8
        for: 2m
        annotations:
          summary: "Bağlantı sayısı %80 eşiğini aştı"

      - alert: PostgreSQLLowCacheHit
        expr: pg_stat_database_blks_hit_ratio < 0.95
        for: 5m
        annotations:
          summary: "Buffer cache hit oranı %95 altına düştü"

      - alert: PostgreSQLXIDNearExhaustion
        expr: pg_database_wraparound_age > 1500000000
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Transaction ID tükenmek üzere — ACİL VACUUM gerekli"

      - alert: PostgreSQLDeadlockDetected
        expr: increase(pg_stat_database_deadlocks_total[5m]) > 0
        for: 0m
        annotations:
          summary: "Deadlock tespit edildi: {{ $labels.datname }}"

      - alert: PostgreSQLTempFilesHigh
        expr: pg_stat_database_temp_bytes > 1073741824
        for: 5m
        annotations:
          summary: "Geçici dosya kullanımı 1GB'yi aştı — work_mem artır"

      - alert: PostgreSQLDiskFull
        expr: node_filesystem_avail_bytes{mountpoint="/var/lib/pgsql"} /
              node_filesystem_size_bytes{mountpoint="/var/lib/pgsql"} < 0.20
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "PGDATA diski %80 dolu"
```

---

## 28. Güvenlik (DBA Perspektifi)

### 28.1 En Az Yetki İlkesi

```sql
-- Varsayılan yetkiyi PUBLIC'ten kaldır
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE mydb FROM PUBLIC;

-- Uygulama kullanıcısı: Sadece kendi şeması
CREATE USER app WITH PASSWORD 'GuvenliP@r0la!' NOSUPERUSER;
GRANT CONNECT ON DATABASE mydb TO app;
GRANT USAGE, CREATE ON SCHEMA app_schema TO app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app_schema TO app;
GRANT USAGE, UPDATE ON ALL SEQUENCES IN SCHEMA app_schema TO app;
ALTER DEFAULT PRIVILEGES IN SCHEMA app_schema
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app;

-- DBA rolü: Yetkili ama SUPERUSER değil
CREATE ROLE dba_role NOLOGIN;
GRANT CONNECT ON DATABASE mydb TO dba_role;
GRANT ALL PRIVILEGES ON SCHEMA public TO dba_role;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO dba_role;
CREATE USER dba_user WITH PASSWORD 'GuvenliP@r0la!' NOSUPERUSER;
GRANT dba_role TO dba_user;

-- Monitoring: pg_monitor
CREATE USER monitoring WITH PASSWORD 'MonParola!';
GRANT pg_monitor TO monitoring;
GRANT CONNECT ON DATABASE mydb TO monitoring;
```

### 28.2 pgAudit ile Denetim Kaydı

```yaml
# pt-edit-config ile etkinleştir
postgresql:
  parameters:
    shared_preload_libraries: 'pg_stat_statements, pgaudit'
    pgaudit.log: 'DDL, WRITE'
    pgaudit.log_catalog: 'off'
    pgaudit.log_parameter: 'on'
    pgaudit.log_relation: 'on'
    log_connections: 'on'
    log_disconnections: 'on'
```

```sql
-- pgaudit kurulumu (bir kez)
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Belirli rol için tüm aktiviteyi denetle
ALTER USER sensitive_user SET pgaudit.log = 'ALL';

-- Audit loglarını gör
-- journalctl -u patroni | grep AUDIT | tail -50
```

### 28.3 Veri Şifreleme (pgcrypto)

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Simetrik şifreleme (AES)
INSERT INTO sensitive_data(national_id, name)
VALUES (pgp_sym_encrypt('12345678901', 'gizli-anahtar-256bit'), 'Ad Soyad');

-- Çözme
SELECT pgp_sym_decrypt(national_id::bytea, 'gizli-anahtar-256bit') AS national_id
FROM sensitive_data WHERE id = 1;

-- Güvenli parola saklama (bcrypt)
INSERT INTO users(email, password_hash)
VALUES ('user@example.com', crypt('kullanici_parolasi', gen_salt('bf', 12)));

-- Parola doğrulama
SELECT EXISTS(
    SELECT 1 FROM users
    WHERE email = 'user@example.com'
      AND password_hash = crypt('kullanici_parolasi', password_hash)
) AS valid_login;
```

### 28.4 Parola Politikası ve Süresi

```sql
-- Parola süresi
ALTER USER app VALID UNTIL '2027-12-31';

-- Süresi yaklaşan parolaları kontrol et
SELECT usename, valuntil,
       valuntil - now() AS time_remaining
FROM pg_user
WHERE valuntil IS NOT NULL
  AND valuntil < now() + interval '30 days'
ORDER BY valuntil;
```

---

## 29. pg_waldump ile WAL Analizi

### 29.1 WAL Segmentini Okuma

```bash
# WAL segmentini oku — işlem tipi istatistikleri
/usr/pgsql-16/bin/pg_waldump \
    /var/lib/pgwal/pg_wal/000000010000000000000001 \
    --stats=record

# Belirli LSN aralığı
/usr/pgsql-16/bin/pg_waldump \
    --start=0/1000000 \
    --end=0/2000000 \
    /var/lib/pgwal/pg_wal/

# Belirli ilişkinin WAL kayıtları
# OID bul:
psql -U postgres -c "SELECT oid FROM pg_class WHERE relname='orders';"
/usr/pgsql-16/bin/pg_waldump \
    --relation=16384/16385 \
    /var/lib/pgwal/pg_wal/000000010000000000000001
```

### 29.2 WAL Boyut Analizi

```sql
-- WAL dizinindeki segment sayısı
SELECT count(*) AS segments,
       pg_size_pretty(count(*) * 16 * 1024 * 1024) AS total_size,
       min(name) AS oldest,
       max(name) AS newest
FROM pg_ls_waldir();

-- WAL üretim hızı (MB/saat)
SELECT round(wal_bytes / extract(epoch FROM (now() - stats_reset)) / 1024 / 1024 * 3600, 2) AS wal_mb_per_hour
FROM pg_stat_wal;

-- En fazla WAL üreten tablolar
SELECT relname,
       n_tup_ins + n_tup_upd + n_tup_del AS total_changes,
       n_tup_upd AS updates,
       n_tup_del AS deletes
FROM pg_stat_user_tables
ORDER BY total_changes DESC
LIMIT 10;
```

### 29.3 WAL ile İlgili Sorunlar

```bash
# WAL disk doldu (KRİTİK)
df -h /var/lib/pgwal

# Hangi slotlar WAL tutuyor?
psql -U postgres -c "
SELECT slot_name,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_wal,
       active
FROM pg_replication_slots
ORDER BY pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) DESC;"

# Pasif slotu sil (replica bağlı değilse)
psql -U postgres -c "SELECT pg_drop_replication_slot('slot_name');"
```

---

## 30. Paralel Sorgu ve JIT — Detaylı

### 30.1 Paralel Sorgu Yapılandırması

```yaml
postgresql:
  parameters:
    max_parallel_workers: 8
    max_parallel_workers_per_gather: 4
    max_parallel_maintenance_workers: 4
    min_parallel_table_scan_size: '8MB'
    min_parallel_index_scan_size: '512kB'
    parallel_tuple_cost: 0.1
    parallel_setup_cost: 1000
```

```sql
-- Paralel sorgu testi
SET max_parallel_workers_per_gather = 4;
EXPLAIN (ANALYZE, BUFFERS)
SELECT count(*) FROM large_table WHERE amount > 100;
-- "Gather" node görünmeli

-- Paraleli zorla (test için)
SET parallel_tuple_cost = 0;
SET parallel_setup_cost = 0;
SET min_parallel_table_scan_size = 0;
EXPLAIN SELECT count(*) FROM large_table;

-- Paraleli kapat (sorun giderme)
SET max_parallel_workers_per_gather = 0;
```

### 30.2 JIT Compilation — Detaylı

```sql
-- JIT durumu
SHOW jit;                       -- on
SHOW jit_above_cost;            -- 100000
SHOW jit_inline_above_cost;     -- 500000

-- JIT kullanımını gör
EXPLAIN (ANALYZE, VERBOSE)
SELECT sum(amount) FROM orders WHERE user_id > 0;
-- "JIT: Functions: 3, Inlining: true, Optimization: true" görünmeli

-- OLTP sorgular için kapat (overhead)
SET jit = off;
-- Analitik için açık tut (toplama, sıralama, hash join hızlanır)
```

### 30.3 Paralel Sorgu Sorunları

```sql
-- Fonksiyon paralel güvenliğini kontrol et
SELECT proname, proparallel
FROM pg_proc
WHERE proname = 'my_function';
-- 's'=safe, 'r'=restricted, 'u'=unsafe

-- PARALLEL SAFE yap (güvenli olduğundan emin olun!)
ALTER FUNCTION my_function() PARALLEL SAFE;
```

---

## Ek A: Performans Tuning Hızlı Referans (YAML)

```yaml
# patronictl edit-config ile DCS üzerinden uygulayın

# ── 16GB RAM, 8 vCPU (bu kümenin yaklaşık profili) ──────────────────
shared_buffers: '4GB'
effective_cache_size: '12GB'
work_mem: '16MB'
maintenance_work_mem: '512MB'
max_connections: 200
max_parallel_workers: 8
max_parallel_workers_per_gather: 4
autovacuum_max_workers: 5

# ── 32GB RAM, 16 vCPU ───────────────────────────────────────────────
# shared_buffers: '8GB'
# effective_cache_size: '24GB'
# work_mem: '32MB'
# maintenance_work_mem: '1GB'
# max_connections: 300

# ── 64GB RAM, 32 vCPU ───────────────────────────────────────────────
# shared_buffers: '16GB'
# effective_cache_size: '48GB'
# work_mem: '64MB'
# maintenance_work_mem: '2GB'
# max_connections: 200   # PgBouncer ile daha az tut
# huge_pages: 'on'

# ── WAL ve Checkpoint ────────────────────────────────────────────────
min_wal_size: '512MB'
max_wal_size: '4GB'
checkpoint_timeout: '15min'
checkpoint_completion_target: 0.9
wal_compression: 'lz4'
wal_level: 'replica'
wal_buffers: '64MB'

# ── I/O (SSD/NVMe için) ─────────────────────────────────────────────
random_page_cost: 1.1
effective_io_concurrency: 200
maintenance_io_concurrency: 100
bgwriter_lru_maxpages: 200
bgwriter_delay: '50ms'

# ── Bağlantı ────────────────────────────────────────────────────────
superuser_reserved_connections: 3
idle_in_transaction_session_timeout: '5min'
statement_timeout: '0'
lock_timeout: '0'

# ── Autovacuum ──────────────────────────────────────────────────────
autovacuum_naptime: '30s'
autovacuum_vacuum_scale_factor: 0.02
autovacuum_analyze_scale_factor: 0.01
autovacuum_vacuum_cost_delay: '2ms'
autovacuum_vacuum_cost_limit: 400
autovacuum_freeze_max_age: 200000000

# ── Planlayıcı ──────────────────────────────────────────────────────
default_statistics_target: 100
jit: 'on'
jit_above_cost: 100000

# ── Logging ─────────────────────────────────────────────────────────
log_min_duration_statement: 500
log_checkpoints: 'on'
log_lock_waits: 'on'
log_temp_files: 0
log_autovacuum_min_duration: 250
log_deadlocks: 'on'
shared_preload_libraries: 'pg_stat_statements, pgaudit'
pg_stat_statements.max: 10000
pg_stat_statements.track: 'all'
```

---

## Ek B: Tanılama Sorguları Hızlı Başvuru

```sql
-- ================================================================
-- PostgreSQL Tanılama — Hızlı Başvuru  v1.0  2026-06-28
-- Kullanım: psql -U postgres -d mydb -f /home/postgres/tanilama.sql
-- ================================================================

\echo '=== BAĞLANTI DURUMU ==='
SELECT state, count(*), datname, usename
FROM pg_stat_activity
WHERE pid != pg_backend_pid()
GROUP BY state, datname, usename
ORDER BY count DESC;

\echo ''
\echo '=== BEKLEYEN KILITLER ==='
SELECT blocked.pid AS blocked_pid,
       blocked.usename,
       left(blocked.query, 60) AS blocked_query,
       blocking.pid AS blocking_pid,
       left(blocking.query, 60) AS blocking_query,
       now() - blocked.query_start AS wait_time
FROM pg_stat_activity blocked
JOIN pg_stat_activity blocking
    ON blocking.pid = ANY(pg_blocking_pids(blocked.pid))
ORDER BY wait_time DESC;

\echo ''
\echo '=== CACHE HIT ORANI ==='
SELECT round(sum(heap_blks_hit)::numeric /
             nullif(sum(heap_blks_hit + heap_blks_read), 0) * 100, 2) AS cache_hit_pct
FROM pg_statio_user_tables;

\echo ''
\echo '=== EN BÜYÜK TABLOLAR (TOP 10) ==='
SELECT relname,
       pg_size_pretty(pg_total_relation_size(relid)) AS total,
       n_live_tup AS live_rows, n_dead_tup AS dead_rows
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC LIMIT 10;

\echo ''
\echo '=== TRANSACTION ID YAŞI (WRAPAROUND RISKI) ==='
SELECT datname,
       age(datfrozenxid) AS xid_age,
       2147483647 - age(datfrozenxid) AS xids_remaining,
       CASE WHEN age(datfrozenxid) > 1500000000 THEN 'KRİTİK!'
            WHEN age(datfrozenxid) > 200000000  THEN 'UYARI'
            ELSE 'OK' END AS durum
FROM pg_database ORDER BY age(datfrozenxid) DESC;

\echo ''
\echo '=== AUTOVACUUM BEKLEYEN TABLOLAR ==='
SELECT schemaname || '.' || relname AS tablo,
       n_dead_tup AS dead_rows,
       round(n_dead_tup * 100.0 / nullif(n_live_tup + n_dead_tup, 0), 2) AS dead_pct,
       last_autovacuum, last_autoanalyze
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC LIMIT 15;

\echo ''
\echo '=== REPLIKASYON DURUMU ==='
SELECT client_addr, state,
       pg_size_pretty(sent_lsn - replay_lsn) AS lag_bytes,
       write_lag, flush_lag, replay_lag, sync_state
FROM pg_stat_replication;

\echo ''
\echo '=== EN YAVAŞ SORGULAR ==='
SELECT calls,
       round(mean_exec_time::numeric, 2) AS avg_ms,
       round(max_exec_time::numeric, 2) AS max_ms,
       left(query, 80) AS sorgu
FROM pg_stat_statements
WHERE calls > 10
ORDER BY mean_exec_time DESC LIMIT 15;

\echo ''
\echo '=== KULLANILMAYAN INDEXLER ==='
SELECT schemaname || '.' || tablename AS tablo,
       indexname AS index_adi,
       pg_size_pretty(pg_relation_size(indexrelid)) AS boyut
FROM pg_stat_user_indexes
WHERE idx_scan = 0
  AND indexrelid NOT IN (
      SELECT conindid FROM pg_constraint WHERE contype IN ('p', 'u')
  )
ORDER BY pg_relation_size(indexrelid) DESC LIMIT 10;

\echo ''
\echo '=== WAL DURUM ==='
SELECT pg_size_pretty(wal_bytes) AS total_wal,
       round(wal_bytes / extract(epoch FROM (now() - stats_reset)) / 1024 / 1024, 2) AS mb_per_sec,
       stats_reset
FROM pg_stat_wal;
```

---

*Bu el kitabı Patroni HA kümesindeki PostgreSQL ortamına özgüdür.*
*Parametreler değiştirirken `patronictl edit-config` kullanın; `postgresql.conf`'u doğrudan düzenlemeyin.*

*Sürüm: v1.2 — 2026-06-28*
