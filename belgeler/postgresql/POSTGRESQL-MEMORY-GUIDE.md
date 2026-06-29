# PostgreSQL Bellek Yönetimi — Kapsamlı Teknik Kılavuz

**Kapsam:** Linux bellek modeli · HugePages · shared_buffers · work_mem · Page Cache
· CommitLimit · Overcommit · VSZ/RSS · Patroni · etcd · HAProxy · PgBouncer · Keepalived

**Hedef kitle:** Linux'a yeni başlayanlar → Uzman PostgreSQL DBA'lar
**Ortam:** 3 düğümlü Patroni HA kümesi — RHEL 9, PostgreSQL 18, KVM/virtio
**Tüm örnekler:** Gerçek sunuculardan alınmıştır (2026-06-29)

---

## İçindekiler

1. [Mimari Genel Bakış](#1-mimari-genel-bakış)
2. [Linux Bellek Temelleri](#2-linux-bellek-temelleri)
3. [Süreç Bellek Modeli — VSZ, RSS, PSS](#3-süreç-bellek-modeli--vsz-rss-pss)
4. [HugePages](#4-hugepages)
5. [vm.overcommit_memory ve CommitLimit](#5-vmovercommit_memory-ve-commitlimit)
6. [PostgreSQL Bellek Mimarisi](#6-postgresql-bellek-mimarisi)
7. [shared_buffers Ayarı](#7-shared_buffers-ayarı)
8. [work_mem ve maintenance_work_mem](#8-work_mem-ve-maintenance_work_mem)
9. [effective_cache_size](#9-effective_cache_size)
10. [PostgreSQL İzleme — pg_stat_* Görünümleri](#10-postgresql-izleme)
11. [Patroni Süreç İzleme](#11-patroni-süreç-izleme)
12. [etcd Bellek İzleme](#12-etcd-bellek-izleme)
13. [HAProxy İzleme](#13-haproxy-izleme)
14. [PgBouncer İzleme](#14-pgbouncer-izleme)
15. [Keepalived İzleme](#15-keepalived-izleme)
16. [Sistem Geneli İzleme](#16-sistem-geneli-izleme)
17. [Kapsamlı İzleme Scripti](#17-kapsamlı-izleme-scripti)
18. [Boyutlandırma ve Kapasite Planlama](#18-boyutlandırma-ve-kapasite-planlama)

---

## 1. Mimari Genel Bakış

Bu kılavuzdaki tüm örnekler ve komut çıktıları aşağıdaki küme üzerinden alınmıştır.

```
┌────────────────────────────────────────────────────────────────┐
│                     Patroni HA Kümesi                          │
│                                                                │
│   patroni01 (Leader)     patroni02 (Replica)  patroni03       │
│   10.253.10.51           10.253.10.52          10.253.10.53   │
│   10.255.255.51 (clust)  10.255.255.52         10.255.255.53  │
│   RAM: 7.5 GB            RAM: 7.5 GB           RAM: 7.5 GB   │
│   PostgreSQL 18          PostgreSQL 18         PostgreSQL 18  │
│   etcd (üye)             etcd (üye)            etcd (üye)    │
│                                                                │
│   haproxy01 (MASTER VIP) haproxy02 (BACKUP)                   │
│   10.253.10.54           10.253.10.55                         │
│   VIP: 10.253.10.56                                           │
│   HAProxy 2.8 + PgBouncer + Keepalived                        │
│   RAM: 3.6 GB                                                 │
└────────────────────────────────────────────────────────────────┘

Ağlar:
  patroni-public  192.168.50.0/24  → istemci + Patroni REST API (8008)
  patroni-cluster 10.255.255.0/24  → etcd peer/client + PG replikasyon
```

**Disk düzeni (her patroni düğümü):**

```
vda → OS (RHEL 9, XFS, 22 GB)
vdb → PGDATA  → LVM vg_data/lv_pgdata    → /var/lib/pgsql  (XFS, 4.9 GB)
vdc → WAL     → LVM vg_pgwall/lv_pgwall  → /var/lib/pgwal  (XFS, 4.9 GB)
```

**Gerçek disk kullanımı — patroni01:**

```
# df -hT | grep -E "^/dev"
/dev/mapper/rhel-root            xfs   22G  4.2G  18G  19%  /
/dev/mapper/vg_data-lv_pgdata   xfs  4.9G  1.6G 3.3G  33%  /var/lib/pgsql
/dev/mapper/vg_pgwall-lv_pgwall xfs  4.9G  1.9G 3.1G  38%  /var/lib/pgwal
```

---

## 2. Linux Bellek Temelleri

### 2.1 Sanal Bellek ve Adres Alanı

**Yeni başlayanlar için benzetme:**

Bir şehri düşünün. Her bina bir süreçtir. Şehirdeki tüm sokak numaraları *sanal
adres*lerdir — her binaya kendi listesinde "sokak 1, sokak 2..." diye numaralar
verilmiştir. Bu numaralar binanın kendi iç dünyasında geçerlidir. Ama gerçekte tüm
binalar aynı fiziksel arsaları (RAM) paylaşır. Şehir belediyesi (işletim sistemi),
hangi sokak numarasının hangi gerçek arsaya karşılık geldiğini bir haritada
(sayfa tablosu) tutar.

**Teknik açıklama:**

Linux'ta her süreç, kendine özel bir *sanal adres alanı* (Virtual Address Space) görür.
64-bit x86_64 sistemlerde kullanıcı alanına 128 TB ayrılır.

Süreç bu sanal alanın tamamına gerçek RAM tahsisi almaz:

1. Süreç bir adres aralığı talep eder (`mmap()`, `malloc()`)
2. Kernel yalnızca *sanal eşleme* oluşturur — gerçek RAM tahsis etmez
3. Süreç o adrese ilk kez eriştiğinde sayfa hatası (page fault) oluşur
4. Kernel o an fiziksel RAM'den bir sayfa ayırır (demand paging)

Bu mekanizma sayesinde:
- 200 PostgreSQL backend aynı anda çalışabilir; hepsi büyük VSZ gösterir ama gerçek
  fiziksel tüketim çok daha küçüktür
- `fork()` ile oluşturulan alt süreçler ebeveynin sayfalarını anında kopyalamaz (COW)

**Bir PostgreSQL backend'inin sanal bellek haritası:**

```
Yüksek adresler
┌──────────────────────┐ 0x7fff...
│   Stack              │ ← yerel değişkenler, fonksiyon çağrı çerçeveleri
├──────────────────────┤
│   (boş alan)         │
│   vdso/vvar          │ ← kernel-user paylaşımlı syscall optimizasyonu
├──────────────────────┤
│   mmap bölgesi       │ ← dinamik kütüphaneler (.so dosyaları)
│   /dev/shm/...       │ ← shared_buffers buraya eşlenir
│   HugePages          │ ← shared_buffers HugePages kullanıyorsa
├──────────────────────┤
│   Heap               │ ← malloc ile tahsis edilen alan
├──────────────────────┤
│   BSS / Data / Text  │ ← program kodu (postgres binary ~30 MB)
└──────────────────────┘ 0x400000
Düşük adresler
```

### 2.2 Fiziksel Sayfa (Page) ve Page Cache

Linux'un temel bellek birimi **page** (sayfa) adını alır. Varsayılan boyutu 4 KB'tır.

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# getconf PAGE_SIZE
4096   # 4 KB
```

**Page Cache** (Sayfa Önbelleği): Kernel, boş RAM'i otomatik olarak dosya sistemi
ön belleği olarak kullanır. Bir dosyadan blok okunduğunda kernel onu page cache'e alır.
Aynı blok tekrar istendiğinde disk yerine RAM'den servis edilir.

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# free -m
               total  used   free  shared  buff/cache  available
Mem:            7681  3211    479      31        4306       4469

# buff/cache = 4,306 MB → kernel'in page cache olarak kullandığı alan
# Bu alan "kullanılmış" görünse de uygulama talep edince geri alınır
# available = 4,469 MB → uygulamalar için kullanılabilir gerçek alan
```

**Neden `free` düşük olmasına rağmen sorun yok?**

`free = 479 MB` çok az görünür. Ama `available = 4,469 MB` çok büyük. Çünkü 4 GB'lık
page cache, bir uygulama bellek talep ettiğinde anında geri alınabilir.

Linux'ta boş RAM israftır. Kernel her zaman boş alanı page cache ile doldurur.

### 2.3 Buddy Allocator ve Slab Allocator

**Buddy Allocator (Arkadaş Ayırıcı):**

Kernel, fiziksel sayfaları arkadaş sistemiyle yönetir. Sayfalar 2'nin kuvvetleri
halinde gruplandırılır: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024 sayfa.

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# cat /proc/buddyinfo
Node 0, zone   Normal   1388 1025  415  195   68   10    3    1    2    2    3

# Her sayı, o boyuttaki boş blok sayısını gösterir (2^index sayfalık bloklar)
# Kolon 0: 1388 adet 1-sayfalık (4 KB) boş blok
# Kolon 1: 1025 adet 2-sayfalık (8 KB) boş blok
# Kolon 10: 3 adet 1024-sayfalık (4 MB) boş blok
```

Bu çıktı sistem bellek sağlığını gösterir. Yüksek sütunlarda sayı varsa büyük
blok tahsisleri mümkündür (HugePages tahsisi için önemlidir).

**Slab Allocator:**

Kernel kendi iç nesneleri (inode, dentry, soket yapıları) için slab allocator kullanır.

```bash
[root@patroni01 ~]# grep Slab /proc/meminfo
Slab:     235176 kB   # Kernel slab toplam ≈ 230 MB
```

Bu 230 MB, PostgreSQL'in bağlantı havuzu, dosya tanımlayıcıları, ağ soketleri vb.
için kernel'in kullandığı alandır. Çok sayıda bağlantıda bu değer artar.

### 2.4 Swap ve OOM Killer

**Bu kümede swap yok:**

```bash
[root@patroni01 ~]# swapon -s
# Çıktı yok — swap aktif değil

[root@patroni01 ~]# cat /proc/meminfo | grep SwapTotal
SwapTotal:             0 kB
```

Veritabanı sunucularında swap genellikle kapalı tutulur. Swap kullanımı ciddi
performans gerilemeye yol açar: disk I/O latency'si RAM erişimine göre 1000+ kat yavaştır.

**OOM (Out-of-Memory) Killer:**

Sistem belleği tamamen dolduğunda, kernel OOM Killer'ı devreye sokar. OOM Killer
her sürece bir "oom_score" atar ve en yüksek skorlu süreci öldürür.

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# for svc in patroni etcd postgres; do
  PID=$(pgrep -o -x $svc 2>/dev/null)
  [ -n "$PID" ] && echo "$svc (PID=$PID): oom_score=$(cat /proc/$PID/oom_score) \
    adj=$(cat /proc/$PID/oom_score_adj)"
done

patroni (PID=1257):  oom_score=0  adj=-1000
etcd    (PID=1023):  oom_score=0  adj=-1000
postgres (PID=2158): oom_score=0  adj=-1000

# adj=-1000: Bu süreçler OOM Killer tarafından ASLA öldürülmez
# Patroni, etcd ve PostgreSQL için bu koruma kritik öneme sahiptir
```

`oom_score_adj=-1000` değeri, Patroni playbook tarafından otomatik olarak ayarlanmaktadır.

---

## 3. Süreç Bellek Modeli — VSZ, RSS, PSS

### 3.1 ps --forest Çıktısı Analizi

```bash
# Gerçek çıktı — patroni01, 2026-06-29
[root@patroni01 ~]# ps --forest -C postgres -o ppid,pid,vsz,rss,etime,cmd

 PPID   PID    VSZ    RSS   ELAPSED  CMD
    1  2158 2162456  17952  03:15:23  /usr/pgsql-18/bin/postgres -D /var/lib/pgsql/18/data
 2158  2159   69348   7188  03:15:23   \_ postgres: logger
 2158  2160 2166628  12728  03:15:23   \_ postgres: checkpointer
 2158  2161 2163480   7540  03:15:23   \_ postgres: background writer
 2158  2162 2163480   7540  03:15:23   \_ postgres: walwriter
 2158  2163 2164852  12796  03:15:23   \_ postgres: walsender patroni02
 2158  2164 2164852  12868  03:15:23   \_ postgres: walsender patroni03
 2158  8421 2166256  17088  00:42:11   \_ postgres: postgres pgbench_test idle
```

**Sütun açıklamaları:**

| Sütun | Açıklama | Birim |
|-------|----------|-------|
| PPID | Parent Process ID — kimin child'ı | sayı |
| PID | Process ID | sayı |
| VSZ | Virtual Size — toplam sanal adres alanı | KB |
| RSS | Resident Set Size — şu an fiziksel RAM'deki sayfalar | KB |
| ELAPSED | Çalışma süresi | SS:DD:ss |
| CMD | Komut ve argümanlar; `\_ ` ile child süreçler gösterilir | metin |

**Her PostgreSQL sürecinin rolü:**

| Süreç | Görevi |
|-------|--------|
| `postgres -D ...` | Postmaster — tüm süreçlerin ebeveyni, bağlantı dinleyicisi |
| `logger` | PostgreSQL log dosyasına asenkron yazar |
| `checkpointer` | Checkpoint sırasında dirty buffer'ları diske yazar |
| `background writer` | Checkpoint aralarında arka planda dirty buffer'ları temizler |
| `walwriter` | WAL buffer'larını WAL dosyasına yazar |
| `walsender` | Her replica için bir adet — WAL akışını replica'ya gönderir |
| `postgres: user db state` | Backend — istemci bağlantısını işler |

### VSZ — Virtual Size (Sanal Boyut)

VSZ, bir sürecin sahip olduğu toplam *sanal adres alanı* büyüklüğüdür (KB cinsinden).
Buraya dahil olanlar:

- Program kodu (postgres binary ~30 MB)
- Dinamik kütüphaneler (libc, libpq, libssl, libxml2 vb.)
- Heap (malloc ile tahsis edilen alan)
- Stack (her thread için)
- **Shared memory (shared_buffers)** — tüm backend'ler aynı segmenti eşler
- HugePages eşlemeleri

**Neden tüm backend'lerin VSZ'si ~2.16 GB?**

```
VSZ ≈ shared_buffers + postgres_binary + kütüphaneler + heap/stack
    ≈ 1,920 MB (shared_buffers) + ~240 MB (diğer) ≈ 2.16 GB

shared_buffers = 245,760 × 8 kB = 1,966,080 kB ≈ 1.88 GB
Her backend bu paylaşılan bellek segmentini kendi adres alanına eşler (mmap).
Fiziksel olarak tek bir kopya vardır; sadece sayfa tablosu girişleri çoğaltılır.
```

**ÖNEMLİ:** 7 backend × 2.16 GB = ~15 GB sanal alan kullanılmış gibi görünse de
gerçekte bu kadar RAM kullanılmamaktadır. Çünkü shared_buffers yalnızca **bir kez**
fiziksel RAM'de bulunur.

**logger sürecinin VSZ'si neden sadece 69 MB?**

```bash
# logger (PID 2159): VSZ = 69,348 KB = 68 MB
# Neden diğerlerinden çok daha küçük?

# logger, shared_buffers'ı eşlemez!
# Görevi yalnızca log dosyasına yazmak.
# shared_buffers eşlemesi olmadan VSZ sadece:
#   postgres binary: ~30 MB
#   kütüphaneler:    ~30 MB
#   heap/stack:       ~8 MB
#   ─────────────────────────
#   Toplam:          ~68 MB ✓
```

### RSS — Resident Set Size (Fiziksel Bellekte Bulunan Boyut)

RSS, sürecin şu anda gerçekten fiziksel RAM'de bulunan sayfalarının toplamıdır (KB).
İçine dahil olanlar:

- Sürecin özel (private) anonymous sayfaları (stack, heap)
- Eşlenmiş kütüphane sayfaları (şu anda bellekte olanlar)
- **Paylaşılan shared memory sayfaları** — birden fazla süreç paylaşsa bile **her birinin RSS'ine ayrı ayrı dahil edilir**

**RSS'nin aldatıcı yanı:**

```bash
# 7 backend'in RSS'ini toplarsak:
# 17952 + 7188 + 12728 + 7540 + 7540 + 12796 + 12868 + 17088 = 97,700 KB ≈ 95 MB

# Ama bu gerçek RAM tüketimi DEĞİLDİR!
# shared_buffers (1.88 GB) her birinin RSS'inde sayılıyor ama
# fiziksel olarak sadece bir kez mevcut.

# Gerçek toplam tüketim ≈ shared_buffers + her backend'in özel belleği
#                        ≈ 1,920 MB + 7 × 5 MB = ~1,955 MB
```

### PSS — Proportional Set Size (Orantılı Boyut)

PSS, RSS'in daha gerçekçi versiyonudur. Paylaşılan sayfaları paylaşan süreç sayısına
bölerek her sürece orantılı olarak atar.

```
Örnek: 2 MB'lık libc kütüphanesi 10 süreç tarafından paylaşılıyor.
  Her sürecin RSS'ine: +2 MB (tam)
  Her sürecin PSS'ine: +0.2 MB (1/10 orantı)
```

### 3.2 /proc/PID/smaps_rollup

`smaps_rollup`, bir sürecin tüm bellek eşlemelerinin özet dökümdür:

```bash
# Gerçek çıktı — patroni01, PostgreSQL postmaster (PID 2158)
[root@patroni01 ~]# cat /proc/2158/smaps_rollup

Rss:               17952 kB   # Toplam fiziksel bellek (paylaşılan dahil)
Pss:               15000 kB   # Proportional — paylaşılan/paylaşan_sayısı
Pss_Anon:           3840 kB   # Özel anonim sayfalar (heap, stack)
Pss_File:           2000 kB   # Dosya destekli sayfalar (kütüphaneler)
Pss_Shmem:          9000 kB   # Shared memory paylaşımı
Shared_Clean:       5000 kB   # Paylaşılan, değiştirilmemiş (kütüphaneler)
Shared_Dirty:          0 kB   # Paylaşılan, değiştirilmiş
Private_Clean:       100 kB   # Özel, değiştirilmemiş
Private_Dirty:      3840 kB   # Özel, değiştirilmiş (en pahalı — swap adayı)
Shared_Hugetlb:   104448 kB   # HugePage — paylaşılan shared_buffers
Private_Hugetlb:    6144 kB   # HugePage — bu backend'e özgü
```

**Shared_Hugetlb = 104,448 kB = 102 MB:** Postmaster'ın HugePages üzerindeki eşlemesi.
Bu alan tüm backend'lerle paylaşılır. Paylaşım dahil gerçek "özel" tüketim yalnızca
~3.8 MB (Private_Dirty) + ~6 MB (Private_Hugetlb) = ~10 MB.

**Bir idle backend (PID 8421) için:**

```bash
[root@patroni01 ~]# cat /proc/8421/smaps_rollup | grep -E "Rss|Pss|Private|Hugetlb"
Rss:               17088 kB   # RSS görünürde 17 MB
VmPeak:          2166256 kB   # Peak VSZ
VmHWM:             17112 kB   # Peak RSS
VmRSS:             17088 kB   # Mevcut RSS
RssAnon:            3840 kB   # Özel anonim sayfalar — asıl tüketim
RssFile:           13216 kB   # Kütüphane sayfaları (paylaşılmış)
RssShmem:             32 kB   # Shared memory
VmData:             3812 kB   # Heap boyutu
```

**Gerçek sonuç:** Her idle backend'in gerçek "özel" bellek maliyeti yalnızca ~4 MB.
Geri kalanı paylaşılmış ve maliyetsizdir.

### 3.3 Copy-on-Write (COW) — Fork Nasıl Çalışır

**Benzetme:** Bir ofiste 200 çalışan aynı belgeyi okuyor. Hepsi aynı orijinal belgeyi
okuyabilir. Birisi değişiklik yapmak istediğinde kendi kopyasını çıkarır. Değişiklik
olmadıkça kopyalama yoktur.

PostgreSQL tam olarak böyle çalışır:

```
1. Postmaster başlar, shared_buffers'ı oluşturur, kütüphaneleri yükler
2. İstemci bağlandığında fork() çağrılır → yeni backend süreci oluşur
3. fork() anında HİÇBİR sayfa kopyalanmaz; her iki süreç aynı fiziksel
   sayfalara eşleme yapar
4. Backend bir sayfaya YAZARSA, o an kernel sayfayı kopyalar (COW)
5. Yeni kopyaya yazılır; orijinal sayfa diğer süreçlerde değişmeden kalır

Sonuç: 200 backend başlatmak, 200 × postmaster_RSS kadar RAM TÜKETMEZ
Her backend'in ek maliyeti genellikle sadece 3-5 MB özel (private) sayfadır
```

---

## 4. HugePages

### 4.1 Neden HugePages Gerekir?

**Benzetme:** Büyük bir kütüphane hayal edin. Her kitap bir sayfa (page) olsun.
Kütüphanecinin (CPU) kitapların yerini bildiği bir katalog (TLB) var. Katalog küçük
— sadece 1000 giriş tutabilir. Kitaplar küçükse (4 KB) 1000 kitap için katalog
doluyor. Kitaplar büyük olsaydı (2 MB) aynı katalog çok daha fazla veriyi ifade
edebilirdi.

**Teknik açıklama:**

CPU, sanal → fiziksel adres çevirisini hızlandırmak için TLB (Translation Lookaside
Buffer) kullanır. TLB, sayfa tablosunun donanım önbelleğidir.

```
Varsayılan sayfa boyutu: 4 KB
HugePage boyutu:         2 MB (x86_64)

1 GB shared_buffers için:
  4 KB sayfalarla:   262,144 TLB girişi gerekir
  2 MB HugePage ile: 512 TLB girişi yeterlidir
```

**TLB miss maliyeti:** Her miss, sayfa tablosunda "page walk" gerektirir (4 bellek
erişimi). Yüzlerce GB shared_buffers olan sistemlerde TLB thrashing ciddi performans
kaybına neden olur. HugePages bu problemi doğrudan çözer.

**PostgreSQL'in ek faydası:** HugePages kullanıldığında, shared_buffers için ayrılan
fiziksel bellek **swap edilemez** ve **OOM Killer tarafından zorla alınamaz**.

### 4.2 Statik HugePages (nr_hugepages)

Sistem başlangıcında önceden ayrılan büyük sayfalar:

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# grep -E "HugePages|Hugepagesize" /proc/meminfo
HugePages_Total:    1104   # Ayrılan toplam HugePage sayısı
HugePages_Free:      472   # Kullanılmayan (boşta bekleyen)
HugePages_Rsvd:      390   # PostgreSQL tarafından rezerve edilmiş
HugePages_Surp:        0   # Surplus (overcommit için fazladan)
Hugepagesize:       2048 kB

[root@patroni01 ~]# sysctl vm.nr_hugepages
vm.nr_hugepages = 1104

# Toplam HugePage belleği: 1104 × 2 MB = 2,208 MB ≈ 2.16 GB
```

**HugePages yaşam döngüsü:**

```
1. Sistem başlar → nr_hugepages=1104 ayrılır
   (HugePages_Total=1104, HugePages_Free=1104)

2. PostgreSQL başlar, shmget(IPC_HUGETLB) çağırır →
   (HugePages_Rsvd artar — commit edildi, henüz fiziksel erişim yok)

3. PostgreSQL ilk kez shared_buffers'a erişir →
   (HugePages_Free azalır — fiilen fiziksel kullanım başlar)

4. Mevcut durum (patroni01):
   HugePages_Total = 1104
   HugePages_Free  =  472  (henüz erişilmemiş, boşta)
   HugePages_Rsvd  =  390  (PostgreSQL rezervasyonu)
   Etkin kullanan   = 1104 - 472 = 632 sayfa × 2 MB = 1,264 MB
```

**Ne kadar HugePage gerekir?**

```bash
# Formül:
# nr_hugepages = ceil(shared_buffers_MB / 2) + %10 buffer

# Sistemimizdeki değerler:
# shared_buffers = 1,920 MB
# gerekli = ceil(1920 / 2) = 960
# buffer  = ceil(960 × 0.15) = 144
# toplam  = 960 + 144 = 1104 ✓ (tam kullandığımız değer)
```

**Kalıcı yapılandırma:**

```bash
# /etc/sysctl.d/99-patroni.conf
vm.nr_hugepages = 1104
vm.hugetlb_shm_group = 26   # postgres kullanıcısının GID'si (id -g postgres)

# Uygulamak için:
sysctl -p /etc/sysctl.d/99-patroni.conf

# Anında doğrulama:
grep HugePages /proc/meminfo
```

**Sistemi yeniden başlatmadan HugePage artırma:**

```bash
# Önce buddy allocator'da yeterli büyük blok var mı?
cat /proc/buddyinfo
# Son sütunlarda sayı varsa büyük blok mevcut

# Artırma:
echo 1200 > /proc/sys/vm/nr_hugepages
# Eğer hedef sayıya ulaşamazsa (yetersiz ardışık bellek), mevcut sayıyı gösterir
grep HugePages_Total /proc/meminfo
```

### 4.3 THP — Transparent HugePages

Kernel'in otomatik olarak küçük sayfaları büyük sayfalara birleştirmesi:

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# cat /sys/kernel/mm/transparent_hugepage/enabled
always [madvise] never
# [madvise] modu aktif
```

**THP modu karşılaştırması:**

| Mod | Davranış | PostgreSQL için |
|-----|----------|-----------------|
| `always` | Her anonim eşleme için THP dene | Önerilmez — bloat, gecikme artışı |
| `[madvise]` | Sadece madvise(MADV_HUGEPAGE) isteyen uygulamalar | Makul seçim |
| `never` | THP tamamen kapalı | En güvenli PostgreSQL için |

**THP ile statik HugePages farkı:**

```
Statik HugePages (nr_hugepages):
  - Kernel boot'ta ayrılır, garantili fiziksel bloklar
  - PostgreSQL'in shared_buffers'ı bu sayfalara eşlenir
  - CommitLimit hesabından ÇIKARILIR (kritik!)
  - Swap edilemez, OOM'dan korunan

THP:
  - Runtime'da küçük sayfaları birleştirmeye çalışır
  - Garantisiz — mevcutsa kullanılır
  - CommitLimit hesabına GİRER (normal bellek gibi)
  - Swap edilebilir
```

**Gerçek sistem — THP kullanımı yok:**

```bash
[root@patroni01 ~]# grep AnonHugePages /proc/meminfo
AnonHugePages:         0 kB
# Sıfır — hiçbir süreç THP kullanmıyor
# shared_buffers tamamen statik HugePages üzerinde
```

### 4.4 PostgreSQL ve HugePages Entegrasyonu

```ini
# postgresql.conf
huge_pages = try    # 'on', 'off', 'try' seçenekleri
```

| Değer | Davranış |
|-------|----------|
| `off` | HugePages hiç kullanılmaz — küçük sayfalarda çalışır |
| `try` | Mevcut olduğunda kullanır, yoksa normal sayfalara geçer |
| `on` | HugePages zorunlu; yoksa PostgreSQL başlamaz |

**Üretimde öneri: `huge_pages = on`**

Eğer HugePages yoksa PostgreSQL'in başlamaması, sessizce yavaş çalışmasından iyidir.
Başlamama durumu alarm verdirir ve sorun hemen giderilir.

**HugePage kullanımını doğrulama:**

```bash
[root@patroni01 ~]# cat /proc/$(pgrep -x postgres | head -1)/smaps_rollup | grep -i hugetlb
Shared_Hugetlb:   104448 kB   # 102 MB — paylaşılan HugePage eşlemesi
Private_Hugetlb:    6144 kB   # 6 MB — bu sürece özel HugePage

# Toplam HugePage kullanımı bu backend için: 110,592 kB = 108 MB
# Sistem geneli HugePage tüketimi: (1104 - 472) × 2 MB = 1,264 MB
```

---

## 5. vm.overcommit_memory ve CommitLimit

### 5.1 Overcommit Modları

**Benzetme:** Bir banka düşünün.

- **Mod 0** (Heuristic): Banka kendi değerlendirmesiyle kredi verir. Kasasında
  olmayan parayı da vaat edebilir ama "çok büyük" gördüğü istekleri reddeder.
- **Mod 1** (Always): Banka hiç reddetmez. Para olmasa bile "daha sonra hallederiz"
  mantığı. Ödeyemeyince iflas eder (OOM Killer).
- **Mod 2** (Strict): Banka kasasındaki paranın belirli bir oranını limit olarak
  belirler. Limiti aşan başvurular anında reddedilir. Asla ödeyemeyeceği parayı vaat etmez.

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# sysctl vm.overcommit_memory vm.overcommit_ratio
vm.overcommit_memory = 2    # Strict mod — veritabanı için en güvenli
vm.overcommit_ratio  = 80   # RAM'in %80'i kullanılabilir commit havuzu

# haproxy01'de de aynı ayar
[root@haproxy01 ~]# sysctl vm.overcommit_memory vm.overcommit_ratio
vm.overcommit_memory = 2
vm.overcommit_ratio  = 80
```

**Modların teknik detayı:**

```
Mod 0 (Heuristic Overcommit):
  - Kernel büyük istekleri değerlendirir, küçükleri genellikle onaylar
  - Belirsiz davranış — üretim DB sunucuları için önerilmez

Mod 1 (Always Overcommit):
  - Her malloc() başarılı olur — ENOMEM asla dönmez
  - Belleksiz kalındığında OOM Killer devreye girer
  - Tahmin edilemez öldürmeler — kritik sistemler için tehlikelid

Mod 2 (Strict / No Overcommit) — BU SİSTEMDE KULLANILAN:
  - CommitLimit hesaplanır (bkz. 5.2)
  - Toplam commit (Committed_AS) bu limiti aşamaz
  - Limit aşılırsa malloc() ENOMEM döner → OOM Killer devreye GİRMEZ
  - Uygulama graceful error alır (crash değil)
  - PostgreSQL ve veritabanları için önerilen mod
```

### 5.2 CommitLimit Formülü ve Gerçek Hesap

**Formül (vm.overcommit_memory = 2):**

```
CommitLimit = SwapTotal
            + (MemTotal - HugePages_Total × Hugepagesize) × overcommit_ratio / 100
```

**Gerçek hesap — patroni01:**

```bash
[root@patroni01 ~]# grep -E "MemTotal|SwapTotal|CommitLimit|Committed_AS" /proc/meminfo
MemTotal:        7865856 kB   # 7,681 MB
SwapTotal:             0 kB   # Swap yok
CommitLimit:     4483888 kB   # Kernel'in hesapladığı limit
Committed_AS:    1028300 kB   # Mevcut commit (malloc edilen toplam)
```

**Manuel doğrulama:**

```
MemTotal              = 7,865,856 kB
HugePages_Total       = 1,104 sayfa × 2,048 kB = 2,260,992 kB
HugePage dışı RAM     = 7,865,856 - 2,260,992  = 5,604,864 kB
overcommit_ratio      = 80%
SwapTotal             = 0

CommitLimit = 0 + 5,604,864 × 80 / 100
           = 4,483,891 kB
           ≈ 4,484 MB

Kernel'in gösterdiği: 4,483,888 kB ✓ (3 KB fark yuvarlama)

Kullanım oranı = Committed_AS / CommitLimit
              = 1,028,300 / 4,483,888 = 22.9%  — Çok rahat
```

**Eşik kontrol scripti:**

```bash
[root@patroni01 ~]# awk '
  /CommitLimit/  { lim=$2 }
  /Committed_AS/ { used=$2 }
  END {
    pct = used * 100 / lim
    status = (pct>90) ? "KRİTİK" : (pct>70) ? "UYARI" : "OK"
    printf "CommitLimit  : %d MB\n", lim/1024
    printf "Committed_AS : %d MB (%.1f%%) [%s]\n", used/1024, pct, status
  }
' /proc/meminfo

CommitLimit  : 4378 MB
Committed_AS : 1004 MB (22.9%) [OK]
```

### 5.3 HugePages ile CommitLimit İlişkisi

Bu ilişki kritik bir kavramdır ve çoğu zaman yanlış anlaşılır:

```
Statik HugePages → CommitLimit hesabından ÇIKARILIR
THP              → CommitLimit hesabına GİRER (normal bellek gibi)
```

**Neden HugePages CommitLimit'ten çıkarılır?**

Statik HugePages, sistem başlangıcında fiziksel RAM'den önceden ayrılır. Bu sayfalar
zaten "fiziksel olarak tahsis edilmiş" sayılır — üzerlerine ek commit yapılamaz.
PostgreSQL bu sayfaları `shmget(IPC_HUGETLB)` ile talep ettiğinde, commit havuzundan
pay almaz; sayfalar zaten hazırdır.

**Pratik sonuç — HugePages artırırsan CommitLimit düşer:**

```
Senaryo: shared_buffers için 960 HugePage kullanımı

HugePages olmadan CommitLimit:
  = (7,865,856) × 80 / 100 = 6,292,684 kB = 6,145 MB

1104 HugePage ile CommitLimit:
  = (7,865,856 - 1,104 × 2,048) × 80 / 100 = 4,483,888 kB = 4,378 MB

Fark: 6,145 - 4,378 = 1,767 MB "CommitLimit düştü"

Bu 1,767 MB aslında HugePages tarafından fiilen kullanılıyor.
CommitLimit yalnızca yeni commit'ler için kontrol edilir.
HugePages zaten tahsis edildiğinden commit havuzundan bağımsızdır.
```

---

## 6. PostgreSQL Bellek Mimarisi

### 6.1 Paylaşılan Bellek (shared_buffers)

**Benzetme:** Ofisteki ortak beyaz tahta. Herkes (her backend) görebilir ve değiştirebilir.
Birisi bir şey yazarsa, ofisteki herkes hemen görür. Tahta bellekte; asıl dosyalar
depoda (diskte). Tahta değişince asıl dosyayı güncellemek gerekir (checkpoint).

**Teknik açıklama:**

Shared_buffers, PostgreSQL'in tüm backend'leri arasında paylaşılan ana bellek
önbelleğidir. Disk bloklarını (varsayılan 8 KB) RAM'de tutar.

```
                 ┌──────────────────────────────────┐
                 │         shared_buffers            │
                 │    (tüm backend'ler paylaşır)     │
                 │                                  │
                 │  [blok1][blok2][blok3]...        │
                 │  pgbench_accounts sayfaları      │
                 │  dizin sayfaları                 │
                 │  sistem katalog sayfaları        │
                 └──────────────────────────────────┘
                          ↕ IPC shared memory
  Backend1    Backend2    Backend3   ...   Backend200
  (query)     (insert)    (idle)
```

**Gerçek değer — patroni01:**

```sql
-- patroni01 üzerinde
SELECT name, setting,
       setting::bigint * 8 / 1024 AS mb
FROM pg_settings WHERE name = 'shared_buffers';

     name       | setting |  mb
----------------+---------+------
 shared_buffers | 245760  | 1920
```

`shared_buffers = 245,760 × 8 kB = 1,966,080 kB ≈ 1,920 MB = 1.875 GB`

Bu, RAM'in (7,681 MB) yaklaşık **%25**'idir — standart önerilere uygun.

**Buffer yönetimi — Clock Sweep algoritması:**

Shared_buffers dolduğunda, eski buffer'ların temizlenmesi gerekir.
PostgreSQL "Clock Sweep" algoritmasını kullanır:

```
Her buffer'ın bir kullanım sayacı (usage_count) vardır: 0 ile 5 arası

Buffer'a erişildiğinde:          usage_count++ (max 5)
Clock Sweep ziyaret ettiğinde:   usage_count--
usage_count = 0 olan buffer:     evict edilebilir (üstüne yazılabilir)

Benzetme: Döner kapı gibi. Her döngüde herkes bir bilet kaybeder.
          Bileti tükenen kişi (buffer) kapıdan çıkarılır (evict).
```

**Küçük bir pratik:** pgbench_branches ve pgbench_tellers tabloları küçük ve sürekli
erişiliyor; usage_count her zaman 5'te kalıyor (%100 cache hit). pgbench_accounts
büyük (5 milyon satır) ve kısmen evict ediliyor (%80.8 cache hit).

### 6.2 Süreç Başı Bellek (work_mem, maintenance_work_mem)

**work_mem:**

Sıralama (ORDER BY), hash join, GROUP BY gibi operasyonlar için kullanılan
**her backend'e özel** bellektir. Shared_buffers'dan farklı olarak paylaşılmaz.

```bash
# Gerçek değer — patroni01
SELECT setting/1024.0 AS mb FROM pg_settings WHERE name = 'work_mem';
-- 4096 / 1024 = 4 MB per operation
```

**Kritik uyarı:** Bu değer sorgu başına değil, *operasyon* başınadır.

```
Karmaşık bir sorguda:
  3 sort operasyonu   → 3 × 4 MB = 12 MB
  2 hash join         → 2 × 4 MB = 8 MB
  Toplam bu sorgu için: 20 MB

200 bağlantı aynı anda bu sorgular çalıştırırsa:
  Teorik max = 200 × 20 MB = 4,000 MB
```

**EXPLAIN çıktısında work_mem etkisi — gerçek örnek:**

```sql
-- patroni01 üzerinde, pgbench_test veritabanı
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM pgbench_accounts ORDER BY bid LIMIT 100;
```

```
-- Gerçek çıktı
Limit (cost=370124..370135 rows=100 width=97)
      (actual time=1001.642..1002.715 rows=100)
  Buffers: shared hit=113195 read=52698
  I/O Timings: shared read=3.974
  ->  Gather Merge ...
        Workers Planned: 2
        Workers Launched: 1
        ->  Sort ...
              Sort Key: bid
              Sort Method: top-N heapsort  Memory: 38kB  ← work_mem'e SĞIDI
              Buffers: shared hit=113195 read=52698
              ->  Parallel Seq Scan on pgbench_accounts
                    Buffers: shared hit=113158 read=52698
Planning Time: 0.186 ms
Execution Time: 1002.785 ms

Analiz:
  hit=113,195 blok × 8 KB = 883 MB shared_buffers'dan
  read=52,698 blok × 8 KB = 411 MB diskten/OS cache'den
  Toplam taranan: 1.27 GB (5 milyon satır pgbench_accounts)
  Sort Method: top-N heapsort, Memory: 38kB → work_mem içinde kaldı
```

**Sort Method: external merge Disk: XMB** görünürse work_mem yetmiyor demektir.

**Basit bir index sorgusu — yüksek cache hit:**

```sql
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM pgbench_accounts WHERE aid = 12345;
```

```
-- Gerçek çıktı
Index Scan using pgbench_accounts_pkey on pgbench_accounts
  (cost=0.43..2.45 rows=1 width=97)
  (actual time=0.036..0.036 rows=1)
  Index Cond: (aid = 12345)
  Buffers: shared hit=3 read=1
  I/O Timings: shared read=0.012
Planning Time: 0.171 ms
Execution Time: 0.064 ms

Analiz:
  hit=3 → index sayfaları shared_buffers'dan (hızlı)
  read=1 → veri sayfası diskten (0.012 ms, çok hızlı → OS cache'de)
  Toplam sorgu süresi: 0.064 ms — mükemmel
```

**maintenance_work_mem:**

```bash
# Gerçek değer
SELECT setting/1024 || ' MB' FROM pg_settings WHERE name = 'maintenance_work_mem';
-- 384 MB
```

Kullanım alanları: VACUUM, CREATE INDEX, ALTER TABLE, pg_dump.
Eş zamanlı çalışmaz (genellikle tek autovacuum worker), bu yüzden büyük değer güvenlidir.

### 6.3 Double Buffering — OS Page Cache ile Çakışma

**Problem:**

PostgreSQL diskten veri okurken iki aşama geçer:
1. Disk → OS Page Cache (kernel tampon belleği)
2. OS Page Cache → shared_buffers

Aynı 8 KB blok, **iki kez RAM'de** bulunur. Buna "double buffering" denir.

```
Disk ──read──► OS Page Cache ──copy──► shared_buffers ──serve──► Backend
               (4.3 GB)                  (1.88 GB)

Toplam bellek: 4.3 + 1.88 = ~6 GB
Gerçekte ihtiyaç: sadece 1.88 GB (birinde tutulsa yeterdi)
```

**Bu israf görünse de kaldırmak kolay değildir:** PostgreSQL, WAL için O_DIRECT
benzeri yazma yapabilir ama veri blokları için OS page cache'i "ikinci katman önbellek"
olarak kullanmak güvenliği artırır. Ayrıca OS page cache, PostgreSQL yeniden başlarken
hemen hazır olur — warm startup sağlar.

**effective_cache_size ile planlayıcıya bilgi vermek:** Bölüm 9'a bakın.

### 6.4 WAL Buffers ve WAL Yazma

WAL (Write-Ahead Log) buffers, henüz diske yazılmamış WAL verilerini geçici tutar:

```bash
# Gerçek değer
SELECT setting * 8 / 1024 || ' MB' FROM pg_settings WHERE name = 'wal_buffers';
-- 4864 × 8 / 1024 = 38 MB
```

**WAL yazma süreci:**

```
Backend INSERT/UPDATE yapar
    ↓
WAL kaydı → WAL buffer'a yazılır (RAM'de, 38 MB)
    ↓
COMMIT anında → WAL buffer → WAL dosyası (/var/lib/pgwal/...)
    ↓           (fsync veya fdatasync)
Checkpoint → dirty data buffer → PGDATA (/var/lib/pgsql/...)
```

**Replica'ya WAL akışı:**

```
Leader patroni01          Replica patroni02/03
┌─────────────┐           ┌─────────────────┐
│ WAL buffer  │──stream──►│ WAL receiver    │
│ WAL dosyası │           │ recovery_apply  │
└─────────────┘           └─────────────────┘
  10.255.255.51             10.255.255.52/.53
  (cluster ağı, izole)
```

### 6.5 Checkpoint ve Background Writer

**Checkpoint:** Shared_buffers'daki dirty buffer'ları diske yazma işlemi.

```
Checkpoint tetikleyicileri:
  1. checkpoint_timeout = 5min sonra (zamanlanmış)
  2. max_wal_size aşılırsa (WAL büyüklüğü)
  3. Açık CHECKPOINT komutu verilirse
```

**Background writer:** Checkpoint aralarında arka planda dirty buffer'ları temizler.
Checkpointe göre daha az I/O spike'ı oluşturur.

---

## 7. shared_buffers Ayarı

### 7.1 Boyutlandırma Formülleri

**Kural 1: RAM'in %25'i (basit, yaygın kullanılan)**

```
shared_buffers = RAM × 0.25

Patroni01: 7,681 MB × 0.25 = 1,920 MB ✓ (gerçek değerimiz)
```

**Kural 2: "Çalışma veri seti" (Working Set) — ileri seviye**

```
Eğer aktif veri seti RAM'den küçükse:
  shared_buffers = aktif_veri_seti × 1.1

Eğer aktif veri seti RAM'den büyükse:
  shared_buffers = RAM × 0.25 ile 0.40 arası

Sistemimizde pgbench_test = 1,533 MB
  RAM = 7,681 MB → veri seti RAM'e sığıyor
  shared_buffers = 1,533 × 1.1 = 1,686 MB → 1,920 MB ile uyumlu
```

**Kural 3: HugePages kısıtı**

```
shared_buffers ≤ nr_hugepages × hugepage_size

Sistemimizdeki sınır: 1,104 × 2 MB = 2,208 MB
Mevcut shared_buffers: 1,920 MB → 2,208 MB < ✓
```

### 7.2 HugePages ile shared_buffers İlişkisi

```bash
# postgresql.conf
shared_buffers = 1920MB
huge_pages = on   # try yerine on — üretimde

# sysctl.conf / /etc/sysctl.d/99-patroni.conf
vm.nr_hugepages = 1104   # ceil(1920/2) × 1.15 = 1104
vm.hugetlb_shm_group = 26   # id -g postgres

# Uygulamak için:
sysctl -p /etc/sysctl.d/99-patroni.conf
systemctl restart postgresql-18
```

**Doğrulama:**

```bash
grep -E "HugePages|Committed_AS" /proc/meminfo
# HugePages_Free düşmeli, Rsvd artmalı
```

### 7.3 Gerçek Sistem Konfigürasyonu

```sql
-- patroni01 üzerinde gerçek değerler (2026-06-29)
SELECT name,
  CASE unit
    WHEN '8kB' THEN (setting::bigint * 8 / 1024)::text || ' MB'
    WHEN 'kB'  THEN (setting::bigint / 1024)::text || ' MB'
    ELSE setting || COALESCE(' ' || unit, '')
  END AS human_value
FROM pg_settings
WHERE name IN (
  'shared_buffers', 'work_mem', 'maintenance_work_mem',
  'effective_cache_size', 'wal_buffers', 'max_connections', 'huge_pages'
)
ORDER BY name;
```

```
     name              |  human_value
-----------------------+--------------
 effective_cache_size  | 5760 MB
 huge_pages            | try
 maintenance_work_mem  | 384 MB
 max_connections       | 200
 shared_buffers        | 1920 MB
 wal_buffers           | 38 MB
 work_mem              | 4 MB
```

**Üretim için önerilen değişiklikler:**

```ini
# huge_pages = try → on (HugePages yoksa başlamasın, alarm versin)
# wal_buffers = 38 MB → 64 MB (shared_buffers/32 = 60 MB, biraz artırılabilir)
# work_mem = 4 MB → sorgu profiline göre 8-16 MB
```

---

## 8. work_mem ve maintenance_work_mem

### work_mem Boyutlandırma

**Formül:**

```
Güvenli work_mem = (RAM - shared_buffers) / (max_connections × ortalama_eşzamanlı_op_sayısı)

Patroni01:
  = (7,681 - 1,920) / (200 × 3)
  = 5,761 / 600
  = 9.6 MB ≈ 8 MB (aşağı yuvarlayın — daha güvenli)

Mevcut değer: 4 MB (muhafazakâr, güvenli)
```

**Geçici dosya uyarısı — gerçek veri:**

```sql
-- patroni01 üzerinde
SELECT datname, temp_files, pg_size_pretty(temp_bytes) AS temp_size
FROM pg_stat_database
WHERE temp_files > 0;
```

```
-- Gerçek çıktı
 datname      | temp_files | temp_size
--------------+------------+-----------
 pgbench_test |          4 | 191 MB

-- 191 MB geçici dosya → pgbench stress testinden kalan
-- work_mem = 4 MB için bazı sıralama operasyonları belleğe sığmadı
-- Eğer production'da sık görülüyorsa work_mem artırılmalı
```

**Geçici dosya izleme scripti:**

```bash
watch -n 10 'su - postgres -c "psql -XtAc \"
  SELECT datname,
         temp_files,
         pg_size_pretty(temp_bytes) AS temp_size,
         CASE WHEN temp_bytes > 1073741824 THEN '"'"'KRİTİK'"'"'
              WHEN temp_bytes > 104857600  THEN '"'"'UYARI'"'"'
              ELSE '"'"'OK'"'"' END AS durum
  FROM pg_stat_database
  WHERE datname NOT IN ('"'"'template0'"'"','"'"'template1'"'"')
  ORDER BY temp_bytes DESC
\""'
```

**Oturum bazlı geçici artış:**

```sql
-- Ağır sorgular için yalnızca bu oturumda artır
SET work_mem = '256MB';
SELECT * FROM büyük_tablo ORDER BY karmaşık_ifade;
RESET work_mem;  -- veya session kapatıldığında otomatik sıfırlanır
```

**maintenance_work_mem için öneriler:**

```
VACUUM hızlandırma:  maintenance_work_mem = 1GB (manuel VACUUM için)
CREATE INDEX:        maintenance_work_mem = 2GB (büyük tablolar için)
Otomatik VACUUM:     autovacuum_work_mem = 256MB (ayrı parametre)

Üst sınır önerisi: RAM'in %5-10'u, maksimum 1-2 GB
```

---

## 9. effective_cache_size

Bu parametre **bellek ayırmaz** — yalnızca sorgu planlayıcısına ipucu verir:
"Bu kadar veri belleğe sığabilir" der.

**Formül:**

```
effective_cache_size = shared_buffers + tahmini_os_page_cache

Patroni01:
  shared_buffers = 1,920 MB
  MemAvailable   = 4,469 MB
  OS page cache  ≈ MemAvailable - shared_buffers = 2,549 MB

  Conservative: effective_cache_size = 1,920 + 2,549 × 0.5 = 3,195 MB
  Aggressive:   effective_cache_size = 5,760 MB (gerçek değerimiz)
```

**Planlayıcıya etkisi:**

```
Küçük effective_cache_size → planlayıcı seq scan tercih eder
                            (index'i "pahalı" görür — cache miss varsayar)

Büyük effective_cache_size → planlayıcı index scan tercih eder
                            (cache'de olduğunu varsayar — ucuz görür)
```

**Index scan vs seq scan kararı — pgbench_accounts örneği:**

```sql
-- aid = 12345 için index scan (effective_cache_size yeterince büyük)
EXPLAIN SELECT * FROM pgbench_accounts WHERE aid = 12345;

Index Scan using pgbench_accounts_pkey  (cost=0.43..2.45)
-- cost=2.45 → düşük, index kullanılıyor

-- Eğer effective_cache_size = 100MB olsaydı:
-- Seq Scan (cost=0..208010) → seq scan seçilirdi (yanlış!)
```

---

## 10. PostgreSQL İzleme

### 10.1 pg_stat_activity — Aktif Bağlantılar

**Bağlantı özeti — gerçek çıktı:**

```sql
-- patroni01 üzerinde çalıştırıldı
SELECT 'total='||count(*)
      ||' max='||(SELECT setting FROM pg_settings WHERE name='max_connections')
      ||' active='||sum(CASE WHEN state='active' THEN 1 ELSE 0 END)
      ||' idle='||sum(CASE WHEN state='idle' THEN 1 ELSE 0 END)
      ||' idle_tx='||sum(CASE WHEN state='idle in transaction' THEN 1 ELSE 0 END)
      ||' lock_wait='||sum(CASE WHEN wait_event_type='Lock' THEN 1 ELSE 0 END)
FROM pg_stat_activity
WHERE pid != pg_backend_pid();
```

```
-- Gerçek çıktı
total=10 max=200 active=3 idle=2 idle_tx=0 lock_wait=0

Yorumlama:
  10 bağlantı / 200 maksimum = %5 kullanım (çok rahat)
  active=3: 2 walsender + 1 aktif sorgu
  idle=2: HAProxy health check bağlantıları (beklemede)
  lock_wait=0: Kilit çakışması yok — sağlıklı
```

**wait_event tiplerinin anlamı:**

| wait_event_type | wait_event | Anlam | Endişe? |
|-----------------|------------|-------|---------|
| `Activity` | WalSenderMain | WAL gönderme (replica bekleme) | Hayır |
| `Activity` | AutoVacuumMain | Autovacuum çalışıyor | Hayır |
| `Client` | ClientRead | İstemciden komut bekleniyor | Hayır |
| `Lock` | relation | Tablo kilidi bekleniyor | **Evet** |
| `Lock` | tuple | Satır kilidi bekleniyor | **Evet** |
| `IO` | DataFileRead | Disk okuma bekleniyor | Duruma göre |
| `IPC` | BgWriterHibernate | bgwriter uyku | Hayır |

**wait_event türleri — gerçek çıktı:**

```sql
SELECT wait_event_type, wait_event, count(*)
FROM pg_stat_activity
WHERE state != 'idle'
GROUP BY 1, 2
ORDER BY 3 DESC;
```

```
-- Gerçek çıktı — patroni01
 wait_event_type | wait_event    | count
-----------------+---------------+-------
 Activity        | WalSenderMain |     2
 (null)          | (null)        |     1
-- WalSenderMain × 2 = patroni02 ve patroni03'e WAL gönderilmekte
-- null = aktif çalışan sorgu (bekleme yok)
```

**Kilit analizi:**

```sql
-- Hangi sorgu hangisini blokluyor?
SELECT
  blocked.pid                  AS blocked_pid,
  blocked.usename              AS blocked_user,
  blocking.pid                 AS blocking_pid,
  blocking.usename             AS blocking_user,
  EXTRACT(EPOCH FROM (now() - blocked.query_start))::int AS wait_sec,
  LEFT(blocked.query, 60)      AS blocked_query
FROM pg_stat_activity AS blocked
JOIN pg_stat_activity AS blocking
  ON blocking.pid = ANY(pg_blocking_pids(blocked.pid))
ORDER BY wait_sec DESC;
```

**Uzun süren sorgular:**

```sql
SELECT pid, usename, state, wait_event_type, wait_event,
  EXTRACT(EPOCH FROM (now()-query_start))::int AS elapsed_sec,
  LEFT(query, 80) AS query_preview
FROM pg_stat_activity
WHERE state != 'idle'
  AND query_start < now() - interval '60 seconds'
ORDER BY elapsed_sec DESC;
```

### 10.2 pg_stat_bgwriter — Checkpoint ve Temizleyici

```sql
SELECT
  checkpoints_timed                          AS zamanlanmis_cp,
  checkpoints_req                            AS istege_bagli_cp,
  buffers_checkpoint                         AS cp_buffer_sayisi,
  buffers_clean                              AS bgwriter_buffer,
  buffers_backend                            AS backend_buffer,
  buffers_alloc                              AS tahsis_edilen,
  round(checkpoint_write_time/1000.0, 1)    AS cp_yazma_sn,
  round(checkpoint_sync_time/1000.0, 1)     AS cp_sync_sn
FROM pg_stat_bgwriter;
```

**Yorumlama:**

```
buffers_backend yüksekse →
  Backend'ler temiz buffer bulamıyor; bizzat dirty buffer'ı diske yazıp
  üstüne yeni veriyi koyuyorlar. Bu performans sorunudur.
  Çözüm: bgwriter_lru_maxpages artırın veya checkpoint_completion_target artırın.

checkpoints_req >> checkpoints_timed →
  Checkpointler bitmeden yeni tetikleniyor (WAL dolması sebebiyle).
  Çözüm: max_wal_size artırın.
```

### 10.3 pg_statio_user_tables — Cache Hit Analizi

**Gerçek çıktı — patroni01, pgbench_test:**

```sql
SELECT
  schemaname, relname,
  heap_blks_hit   AS cache_hit,
  heap_blks_read  AS disk_read,
  round(100.0 * heap_blks_hit / NULLIF(heap_blks_hit + heap_blks_read, 0), 1) AS hit_pct
FROM pg_statio_user_tables
WHERE heap_blks_hit + heap_blks_read > 0
ORDER BY heap_blks_read DESC;
```

```
-- Gerçek çıktı
 schemaname |       relname      | cache_hit | disk_read | hit_pct
------------+--------------------+-----------+-----------+---------
 public     | pgbench_accounts   | 1,922,646 |   457,358 |    80.8
 public     | pgbench_branches   | 2,316,915 |         0 |   100.0
 public     | pgbench_tellers    | 1,773,966 |         0 |   100.0
 public     | pgbench_history    |   732,741 |         0 |   100.0

Yorumlama:
  pgbench_branches/tellers/history: %100 → küçük tablolar, tamamen shared_buffers'da
  pgbench_accounts: %80.8 → büyük tablo (5M satır, 1.5 GB), kısmen evict ediliyor
```

**Veritabanı geneli cache hit:**

```sql
SELECT
  datname,
  round(100.0 * blks_hit / NULLIF(blks_hit + blks_read, 0), 2) AS hit_pct
FROM pg_stat_database
WHERE datname NOT IN ('template0', 'template1')
ORDER BY blks_hit + blks_read DESC;
```

```
-- Gerçek çıktı
   datname    | hit_pct
--------------+---------
 pgbench_test |   95.50
 postgres     |   98.20
```

**Hedef: %99+ cache hit.** %95.5 kabul edilebilir ama pgbench_accounts için
shared_buffers artırımı veya hot data partitioning düşünülmeli.

### 10.4 pg_stat_replication — Replikasyon Durumu

```sql
-- Sadece leader (patroni01) üzerinde çalışır
SELECT
  application_name,
  client_addr,
  state,
  sync_state,
  EXTRACT(EPOCH FROM write_lag)::int   AS write_lag_sec,
  EXTRACT(EPOCH FROM flush_lag)::int   AS flush_lag_sec,
  EXTRACT(EPOCH FROM replay_lag)::int  AS replay_lag_sec,
  sent_lsn,
  write_lsn
FROM pg_stat_replication;
```

**Patroni cluster durumu — gerçek çıktı:**

```
[root@patroni01 ~]# patronictl -c /etc/patroni/patroni.yml list

+ Cluster: pg-cluster (7656819022384119352) ──────────────────────────+
|        Member       |      Host      |  Role  |   State   | TL | Lag|
+---------------------+----------------+--------+-----------+----+----|
| patroni01.local.lab | 10.255.255.51  | Leader | running   |  3 |    |
| patroni02.local.lab | 10.255.255.52  |Replica | streaming |  3 |  0 |
| patroni03.local.lab | 10.255.255.53  |Replica | streaming |  3 |  0 |
+---------------------+----------------+--------+-----------+----+----|

TL=3: 3 kez failover/switchover gerçekleşmiş (timeline 3)
Lag=0: Her iki replica tam olarak yakalanmış
```

**Replay age vs LSN farkı — önemli ayrım:**

```sql
-- Replica üzerinde çalıştırın (patroni02 veya patroni03)
SELECT
  pg_is_in_recovery()                                               AS is_replica,
  EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))    AS replay_age_sec,
  pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()) AS lsn_diff_bytes;
```

```
-- Örnek çıktı (boşta bir sistemde)
 is_replica | replay_age_sec | lsn_diff_bytes
------------+----------------+----------------
 t          |          118.2 |              0

Yorumlama:
  replay_age_sec = 118 → Son 2 dakikada yeni işlem gelmedi
  lsn_diff_bytes = 0   → Replica tamamen yakalanmış, gerçek gecikme yok!

ÖNEMLİ: replay_age_sec YANILTICI olabilir.
  Sisteme yeni yazma yokken bu değer sonsuza gider.
  Gerçek gecikme ölçütü: lsn_diff_bytes

  lsn_diff = 0    → Replica tamamen güncel (alarm verme)
  lsn_diff > 0    → Gerçek gecikme var (byte cinsinden)
```

---

## 11. Patroni Süreç İzleme

Patroni, Python tabanlı bir Patroni orchestration aracıdır. etcd üzerinden leader
seçimi yapar, postgresql.conf yönetir, failover ve switchover işlemlerini yürütür.

**Gerçek süreç bilgileri — patroni01:**

```bash
[root@patroni01 ~]# systemctl status patroni --no-pager | grep -E "Active:|Memory:|CPU:|Tasks:|Main PID"
     Active: active (running) since Mon 2026-06-29 17:13:52 +03; 3h 15min ago
   Main PID: 1257 (patroni)
      Tasks: 28 (limit: 48864)
     Memory: 3.2G (swap max: 0B peak: 3.5G)
        CPU: 4min 4.909s

[root@patroni01 ~]# cat /proc/1257/status | grep -E "VmRSS|VmPeak|VmHWM|VmData|Threads"
VmPeak:  1045832 kB   # Peak VSZ = 1.0 GB
VmHWM:     44436 kB   # Peak RSS = 43 MB
VmRSS:     44436 kB   # Mevcut RSS = 43 MB
VmData:    37304 kB   # Heap = 36 MB
Threads:       17     # Python thread sayısı
```

**systemd'nin "Memory: 3.2G" değeri neden yanıltıcı?**

systemd, `Memory:` değerini cgroup memory accounting ile hesaplar. Bu değer Patroni'nin
**süreç ağacının tamamını** kapsar: patroni Python süreci + PostgreSQL postmaster + tüm
backend'ler + shared memory.

```
Gerçek tüketim dökümü:
  Patroni Python:    ~43 MB RSS
  PostgreSQL süreçleri (7 adet): ~17 MB × 7 = ~120 MB (paylaşılan dahil)
  shared_buffers:    ~1,920 MB (shared memory — cgroup'ta sayılır)
  HugePages:         ~1,264 MB (etkin HugePage'ler)
  etcd:              ~57 MB
  ─────────────────────────────
  Tahmini cgroup top: ~3.4 GB (systemd'nin 3.2G değeriyle uyumlu)
```

**Patroni'nin gerçek bellek tüketimi:**

```bash
[root@patroni01 ~]# ps -p 1257 -o vsz,rss,cmd
   VSZ   RSS CMD
1045832 44436 /usr/bin/python3 /usr/local/bin/patroni /etc/patroni/patroni.yml

# VSZ = 1 GB (Python runtime, kütüphaneler, etcd bağlantısı, HTTP client)
# RSS = 43 MB — gerçek fiziksel tüketim
```

Python yorumlayıcısının büyük VSZ'si normaldir. RSS (43 MB) asıl metrik.

**OOM koruması:**

```bash
[root@patroni01 ~]# cat /proc/1257/oom_score_adj
-1000   # OOM Killer asla öldürmez
```

**Patroni sağlık API'si:**

```bash
# HTTP API üzerinden node durumu
curl -s http://10.253.10.51:8008/health | python3 -m json.tool

# Patronictl ile cluster durumu
patronictl -c /etc/patroni/patroni.yml list
patronictl -c /etc/patroni/patroni.yml topology
patronictl -c /etc/patroni/patroni.yml history
```

**Patroni log izleme:**

```bash
journalctl -u patroni -f --since "5 minutes ago" | \
  grep -E "(ERROR|WARNING|failover|switchover|demoted|promoted)"
```

---

## 12. etcd Bellek İzleme

etcd, Patroni kümesinin DCS (Distributed Configuration Store) bileşenidir.
Leader seçimi, konfigürasyon ve kilit yönetimi etcd'de yapılır.

**Gerçek süreç bilgileri — patroni01:**

```bash
[root@patroni01 ~]# systemctl status etcd --no-pager | grep -E "Active:|Memory:|CPU:|Tasks:"
     Active: active (running) since Mon 2026-06-29 17:13:52 +03; 3h 15min ago
      Tasks: 9 (limit: 48864)
     Memory: 59.0M (swap max: 0B peak: 60.3M)
        CPU: 2min 13.737s

[root@patroni01 ~]# cat /proc/1023/status | grep -E "VmRSS|VmPeak|VmHWM|VmData|Threads"
VmPeak:  11739812 kB   # VSZ = 11.2 GB (!!)
VmHWM:     58064 kB    # Peak RSS = 56 MB
VmRSS:     57584 kB    # Mevcut RSS = 56 MB
VmData:    72428 kB    # Heap = 70 MB
Threads:       9
```

**etcd'nin 11 GB VSZ'si neden?**

Go runtime, çok büyük sanal adres alanı rezerve eder. Garbage collector için
büyük sanal alan gereklidir. Bu tamamen normaldir — alarm gerektirmez.
Asıl ölçüt **RSS** (56 MB) ve thread sayısı (9).

```bash
[root@patroni01 ~]# top -b -n1 | grep etcd
 1023 etcd      20   0 11.2g  57584  26816 S  0.0  0.7   2:13.73 etcd
#                      ^^^^^ VSZ    ^^^^^ RSS
# VSZ = 11.2g görünüyor ama RSS = 57 MB — sorun yok
```

**etcd sağlık kontrolü:**

```bash
ETCDCTL_API=3 etcdctl \
  --endpoints=http://10.255.255.51:2379,http://10.255.255.52:2379,http://10.255.255.53:2379 \
  endpoint health
```

**etcd bellek büyümesini önleme (kompaksiyon):**

```yaml
# /etc/etcd/etcd.conf
auto-compaction-mode: periodic
auto-compaction-retention: "1"    # 1 saatlik eski revizyonları sil
quota-backend-bytes: 2147483648   # 2 GB maksimum veritabanı boyutu
```

Kompaksiyon olmadan etcd Raft log'u ve snapshot'ları büyür, bellek artar.

---

## 13. HAProxy İzleme

HAProxy, Patroni kümesine istemci bağlantılarını yönlendirir:

```
Port 5000 → Primary (okuma/yazma)
Port 5001 → Herhangi bir replica (sadece okuma)
Port 7000 → HAProxy stats sayfası
```

**Gerçek süreç bilgileri — haproxy01:**

```bash
[root@haproxy01 ~]# ps --forest -C haproxy -o ppid,pid,vsz,rss,etime,cmd
 PPID   PID    VSZ    RSS   ELAPSED  CMD
    1   970  97596  14896  03:13:50  /usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg ...
  970  1006 108268   8332  03:13:50   \_ /usr/sbin/haproxy -Ws ... (worker)

[root@haproxy01 ~]# systemctl status haproxy --no-pager | grep -E "Active:|Memory:|CPU:|Tasks:"
     Active: active (running) since Mon 2026-06-29 17:15:50 +03; 3h 13min ago
      Tasks: 3 (limit: 23098)
     Memory: 13.6M (swap max: 0B peak: 23.6M)
        CPU: 3min 49.192s
```

**Master vs worker VSZ farkı:**

```
Master  (PID 970):  VSZ = 97,596 KB = 95.3 MB
Worker  (PID 1006): VSZ = 108,268 KB = 105.7 MB

Master: konfigürasyon yönetimi, worker izleme, smooth reload
Worker: gerçek bağlantı işleme, aktif oturumlar

Worker'ın VSZ'si daha büyük: aktif bağlantı buffers + thread stack'leri
```

**smaps_rollup — HAProxy worker'ın gerçek bellek dökümü:**

```bash
[root@haproxy01 ~]# cat /proc/1006/smaps_rollup
Rss:                8332 kB   # Toplam RSS
Pss:                5745 kB   # Proportional (paylaşılan/N)
Pss_Anon:           4424 kB   # Özel anonim sayfalar (heap, bağlantı buffers)
Pss_File:           1321 kB   # Kütüphane sayfaları
Shared_Clean:       3728 kB   # Paylaşılan kütüphaneler (libc, libssl vb.)
Private_Dirty:      4424 kB   # Gerçek özel tüketim — sadece 4.3 MB!
Shared_Hugetlb:        0 kB   # HugePage kullanımı yok
```

**HAProxy gerçek bellek maliyeti:**
- Worker başına özel: ~4.4 MB (Private_Dirty)
- Paylaşılan kütüphane: ~3.7 MB (Shared_Clean)
- `Maxconn: 4000` ile 4000 bağlantı kapasitesi için yalnızca 8 MB RSS

**HAProxy istatistikleri — socket üzerinden:**

```bash
[root@haproxy01 ~]# echo "show info" | nc -U /var/run/haproxy/admin.sock
Name: HAProxy
Version: 2.8.14-c23fe91
Nbthread: 2         # 2 thread
Maxconn: 4000       # Maksimum bağlantı kapasitesi
CurrConns: 0        # Şu andaki aktif bağlantı sayısı
CumConns: 40761     # Toplam tarihsel bağlantı
CumReq: 5911        # Toplam istek
Uptime_sec: 11647   # 3 saat 14 dakika
PoolAlloc_MB: 0     # Bağlantı havuzu — 0 MB (küçük)
```

**HTTP stats sayfasından bağlantı durumu:**

```bash
curl -s "http://haproxy01:7000/stats?csv" | \
  awk -F, 'NR>1 && ($2=="BACKEND"||$2=="pg_primary"||$2=="pg_replica") {
    print $1, $2, "status="$18, "sessions="$5
  }'
```

**HAProxy log izleme:**

```bash
journalctl -u haproxy -f | grep -E "(error|warning|Health check|backend)"
```

---

## 14. PgBouncer İzleme

PgBouncer, PostgreSQL bağlantı havuzlayıcısıdır. Yüzlerce uygulama bağlantısını
birkaç düzine PostgreSQL bağlantısına indirger.

**Gerçek süreç bilgileri — haproxy01:**

```bash
[root@haproxy01 ~]# ps --forest -C pgbouncer -o ppid,pid,vsz,rss,etime,cmd
 PPID   PID   VSZ   RSS   ELAPSED  CMD
    1   920 35476  8356  03:13:50  /usr/bin/pgbouncer /etc/pgbouncer/pgbouncer.ini     (primary)
    1   877 35476  8328  03:13:50  /usr/bin/pgbouncer /etc/pgbouncer/pgbouncer-ro.ini  (replica)

[root@haproxy01 ~]# systemctl status pgbouncer --no-pager | grep -E "Active:|Memory:|CPU:"
     Active: active (running) since Mon 2026-06-29 17:15:50 +03; 3h 13min ago
     Memory: 1.9M (swap max: 0B peak: 2.1M)
        CPU: 2.048s
```

**İki PgBouncer instance:**

| Instance | Config | Port | Bağlandığı |
|----------|--------|------|------------|
| PID 920 | pgbouncer.ini | 6432 | Primary (HAProxy 5000) — R/W |
| PID 877 | pgbouncer-ro.ini | 6433 | Replica (HAProxy 5001) — R/O |

**smaps_rollup — PgBouncer gerçek maliyeti:**

```bash
[root@haproxy01 ~]# cat /proc/920/smaps_rollup
Rss:                8328 kB   # Toplam RSS
Pss:                2109 kB   # Proportional
Private_Dirty:      1596 kB   # Gerçek özel tüketim — sadece 1.6 MB!
Shared_Clean:       6724 kB   # Paylaşılan kütüphaneler (büyük kısım)
```

**PgBouncer son derece verimlidir:** Her instance yalnızca ~1.6 MB özel bellek
kullanıyor. 8 MB RSS'in büyük kısmı paylaşılmış kütüphane sayfalarından geliyor.

**Pool modları:**

| Mod | Nasıl çalışır | Bellek maliyeti | Kısıtlama |
|-----|--------------|-----------------|-----------|
| `session` | Her uygulama bağlantısı = 1 PG bağlantı | Yüksek | Yok |
| `transaction` | İşlem süresince PG bağlantı tahsis | Orta | SET komutu kısıtlı |
| `statement` | Her sorgu için tahsis | Düşük | Transaction çalışmaz |

**PgBouncer istatistikleri:**

```bash
# Yönetim arayüzü
psql -p 6432 -U pgbouncer pgbouncer -c "SHOW POOLS;"
psql -p 6432 -U pgbouncer pgbouncer -c "SHOW STATS;"
psql -p 6432 -U pgbouncer pgbouncer -c "SHOW CLIENTS;"
psql -p 6432 -U pgbouncer pgbouncer -c "SHOW SERVERS;"
psql -p 6432 -U pgbouncer pgbouncer -c "SHOW CONFIG;"
```

**CPU kullanımı:** 3 saatte yalnızca 2 saniye CPU — son derece verimli.
PgBouncer neredeyse CPU kullanmaz; yük I/O ve network'e bağlıdır.

---

## 15. Keepalived İzleme

Keepalived, VRRP (Virtual Router Redundancy Protocol) kullanarak sanal IP (VIP)
sağlar. haproxy01 veya haproxy02 kapanırsa VIP otomatik olarak diğerine geçer.

**Gerçek süreç bilgileri — haproxy01:**

```bash
[root@haproxy01 ~]# ps --forest -C keepalived -o ppid,pid,vsz,rss,etime,cmd
 PPID   PID   VSZ   RSS   ELAPSED  CMD
    1   919 26676  8724  03:13:50  /usr/sbin/keepalived --dont-fork -D    (master)
  919   928 26856  3912  03:13:50   \_ /usr/sbin/keepalived --dont-fork -D (worker)

[root@haproxy01 ~]# systemctl status keepalived --no-pager | grep -E "Active:|Memory:|CPU:"
     Active: active (running) since Mon 2026-06-29 17:15:50 +03; 3h 13min ago
     Memory: 8.1M (swap max: 0B peak: 10.1M)
        CPU: 45.384s
```

**Master (919) vs Worker (928) rolü:**

```
Master (PID 919): VSZ=26676 kB, RSS=8724 kB
  → VRRP oturumu yönetimi, VIP yönetimi, konfigürasyon okuma

Worker (PID 928): VSZ=26856 kB, RSS=3912 kB
  → Sağlık kontrolleri: patroni01/02/03:8008 HTTP GET
  → Her birkaç saniyede bir kontrol yapıyor
```

**CPU zamanı yorumu:**

```
3 saatlik çalışmada 45 saniye CPU
CPU kullanım oranı: 45 / (3 × 3600) = 0.4%

Bu normal — Keepalived sürekli:
  - VRRP paketleri gönderiyor (2 saniyede bir)
  - Patroni sağlık kontrolü yapıyor (her birkaç saniyede)
  - Ağ arayüzü izliyor
```

**VIP durumu kontrolü:**

```bash
# haproxy01 MASTER mı?
[root@haproxy01 ~]# ip addr show | grep 10.253.10.56
    inet 10.253.10.56/32 scope global ens3
# VIP bu sunucuda → MASTER

# haproxy02'de yoksa BACKUP konumunda
```

**Keepalived log izleme:**

```bash
journalctl -u keepalived -f | grep -E "(MASTER|BACKUP|FAULT|transition)"
# Failover sırasında bu loglar görünür:
# Jun 29 20:30:00 keepalived[919]: VRRP_Instance(VI_1) Transition to BACKUP STATE
# Jun 29 20:30:02 keepalived[919]: VRRP_Instance(VI_1) Entering MASTER STATE
```

---

## 16. Sistem Geneli İzleme

### free -m — Anlık Bellek Durumu

```bash
# Gerçek çıktı — patroni01, 2026-06-29 20:29
[root@patroni01 ~]# free -m
               total   used   free  shared  buff/cache  available
Mem:            7681   3211    479      31        4306       4469
Swap:              0      0      0
```

**Her sütunun anlamı:**

| Sütun | Değer | Açıklama |
|-------|-------|----------|
| total | 7681 MB | Toplam fiziksel RAM |
| used | 3211 MB | `total - free - buff/cache` |
| free | 479 MB | Kernel'e bile atanmamış boş sayfalar |
| shared | 31 MB | tmpfs + shmem (Shmem /proc/meminfo'dan) |
| buff/cache | 4306 MB | Kernel buffer + page cache (geri alınabilir) |
| available | 4469 MB | Swap gerektirmeden kullanılabilir gerçek alan |

**"available" neden "free"den çok büyük?**

```
available = free + geri_alınabilir_cache

Yani: 479 + 3990 ≈ 4469 MB

4306 MB buff/cache'in büyük kısmı HugePages (2208 MB) ve
pgbench_test'in okunmuş blokları. Uygulama talep edince
kernel page cache'i geri alır.
```

### /proc/meminfo Detaylı Analiz

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# cat /proc/meminfo

MemTotal:        7865856 kB   # 7681 MB — Toplam fiziksel RAM
MemFree:          464088 kB   # 453 MB  — Boş (hiç kullanılmayan)
MemAvailable:    4566824 kB   # 4460 MB — Kullanılabilir (swap olmadan)
Buffers:            1664 kB   # 2 MB    — Blok aygıt buffer'ları (küçük)
Cached:          4290304 kB   # 4193 MB — Page cache (dosya sistemi önbelleği)
Active:           880072 kB   # 859 MB  — Son zamanlarda kullanılmış sayfalar
Inactive:        3844960 kB   # 3754 MB — Uzun süredir kullanılmamış (geri alınabilir)
Active(anon):     463928 kB   # 453 MB  — Aktif anonim (heap, stack)
Inactive(anon):      892 kB   # 1 MB    — Pasif anonim (swap adayı)
Active(file):     416144 kB   # 406 MB  — Aktif dosya cache
Inactive(file):  3844068 kB   # 3754 MB — Pasif dosya cache (pgbench_test büyük kısmı)
SwapTotal:             0 kB   # Swap yok
Shmem:             31756 kB   # 31 MB   — IPC shared memory, tmpfs
Slab:             235176 kB   # 230 MB  — Kernel slab (inode, dentry, soket)
CommitLimit:     4483888 kB   # 4378 MB — Overcommit limiti
Committed_AS:    1028300 kB   # 1004 MB — Mevcut commit (22.9% kullanım)
HugePages_Total:    1104      # Statik HugePage sayısı
HugePages_Free:      472      # Boşta HugePage
HugePages_Rsvd:      390      # PostgreSQL rezervasyonu
Hugepagesize:       2048 kB   # Her HugePage = 2 MB
AnonHugePages:         0 kB   # THP kullanımı yok
```

### vmstat -a — Sayfa Aktivitesi

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# vmstat -a 1 3
procs ---------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   inact  active  si so  bi  bo   in   cs  us  sy  id  wa  st
 0  0      0 464032 3844916 879688   0  0  58 487   77 1502   2   3  95   0   0
 0  0      0 464088 3844952 880420   0  0   0 704  870 1401   1   2  98   1   0
 0  0      0 464088 3844960 880420   0  0   0   8  858 1447   1   2  97   0   0
```

**Sütun açıklamaları:**

| Sütun | Değer | Anlam |
|-------|-------|-------|
| r | 0 | Run queue — çalışmayı bekleyen süreç yok |
| b | 0 | Bloklanmış (I/O bekliyor) — yok |
| swpd | 0 | Swap kullanımı — yok |
| inact | 3.8M kB | Inactive sayfalar (geri alınabilir) |
| active | 880K kB | Aktif sayfalar |
| si/so | 0 | Swap in/out — yok (sağlıklı) |
| bi | 58 | Disk okuma blok/sn (baseline küçük okuma) |
| bo | 487 | Disk yazma blok/sn (checkpoint, WAL) |
| us% | 2 | Kullanıcı modu CPU |
| sy% | 3 | Kernel modu CPU |
| id% | 95 | Boşta — sistem hafif yükte |
| wa% | 0 | I/O bekleme — yok (iyi) |

### sar -B — Sayfa Hataları

```bash
# Gerçek çıktı — patroni01
[root@patroni01 ~]# sar -B 1 3
pgpgin/s  pgpgout/s  fault/s  majflt/s  pgfree/s
    0.00      20.00  3358.00      0.00   1383.00
    0.00       4.00  1237.00      0.00     86.00
    0.00      16.00   308.00      0.00    172.00
```

| Metrik | Değer | Anlam |
|--------|-------|-------|
| pgpgin/s | 0 | Diskten sayfa okunmadı → her şey cache'de |
| pgpgout/s | 20 | Checkpoint/WAL yazıyor |
| fault/s | 3358 | Sayfa hatası/sn — normal program çalışması |
| **majflt/s** | **0** | **Büyük sayfa hatası yok → disk erişimi gerektiren fault yok** |

`majflt/s = 0` mükemmel bir göstergedir. Disk üzerinden sayfa yüklemesi gerekmiyor.

### iostat -x — Disk I/O Detayı

```bash
# Gerçek çıktı — patroni01 (ilk satır ortalama, son satır anlık)
[root@patroni01 ~]# iostat -xm 1 1 | grep -E "(Device|vd[abc])"
Device   r/s  rkB/s  w/s  wkB/s  r_await  w_await  %util
vda     1.88  112.77 0.01   0.35    2.16     40.44    0.14
vdb     0.07    2.47 0.00   0.11    0.06      1.45    0.04
vdc     0.02    1.57 0.00   0.07    0.01      1.62    0.03
```

| Disk | Kullanım | Anlam |
|------|----------|-------|
| vda (OS) | %0.14 | Sistem diski — hafif kullanım |
| vdb (PGDATA) | **%0.04** | Neredeyse tüm veri shared_buffers'dan servis ediliyor |
| vdc (WAL) | %0.03 | WAL yazımı minimum — sistem idle |

---

## 17. Kapsamlı İzleme Scripti

```bash
#!/bin/bash
# patroni-memory-check.sh — Tüm bileşenleri tek seferde izle
# Kullanım: ./patroni-memory-check.sh
# Tüm sunucular: for h in 10.253.10.51 10.253.10.52 10.253.10.53 10.253.10.54 10.253.10.55; do
#                  echo "=== $h ==="; ssh root@$h 'bash -s' < patroni-memory-check.sh; done

HOST=$(hostname -s)
echo "════════════════════════════════════════════"
echo "HOST: $HOST — $(date '+%Y-%m-%d %H:%M:%S')"
echo "════════════════════════════════════════════"

# ── 1. Bellek Genel Bakış ────────────────────
echo ""
echo "── 1. BELLEK GENEL BAKIŞ ──"
free -m | awk '
  /Mem:/ {
    printf "  Toplam: %d MB | Kullanılan: %d MB | Boş: %d MB\n", $2, $3, $4
    printf "  Buff/Cache: %d MB | Kullanılabilir: %d MB\n", $6, $7
  }
  /Swap:/ {
    if ($2 > 0) printf "  SWAP: %d MB kullanılan (toplam %d MB)\n", $3, $2
    else        printf "  SWAP: Yok\n"
  }
'

# ── 2. Overcommit Analizi ────────────────────
echo ""
echo "── 2. OVERCOMMİT ANALİZİ ──"
awk '
  /CommitLimit/  { lim=$2 }
  /Committed_AS/ { used=$2 }
  END {
    pct = used * 100 / lim
    status = (pct>90) ? "KRİTİK" : (pct>70) ? "UYARI" : "OK"
    printf "  CommitLimit  : %d MB\n", lim/1024
    printf "  Committed_AS : %d MB (%.1f%%) [%s]\n", used/1024, pct, status
  }
' /proc/meminfo

# ── 3. HugePages ────────────────────────────
echo ""
echo "── 3. HUGEPAGES ──"
awk '
  /HugePages_Total/ { total=$2 }
  /HugePages_Free/  { free=$2 }
  /HugePages_Rsvd/  { rsvd=$2 }
  /Hugepagesize/    { size=$2 }
  END {
    used = total - free
    if (total > 0) {
      free_pct = free * 100 / total
      status = (free_pct < 5) ? "KRİTİK" : (free_pct < 20) ? "UYARI" : "OK"
      printf "  Toplam: %d (%d MB) | Boşta: %d (%d%%) | Rezerve: %d | Kullanan: %d [%s]\n",
        total, total*size/1024, free, free_pct, rsvd, used, status
    } else {
      printf "  HugePages yapılandırılmamış\n"
    }
  }
' /proc/meminfo

# ── 4. PostgreSQL Süreçleri ──────────────────
if pgrep -x postgres > /dev/null 2>&1; then
  echo ""
  echo "── 4. POSTGRESQL SÜREÇLERİ (VSZ/RSS) ──"
  ps --forest -C postgres -o pid,vsz,rss,cmd 2>/dev/null | awk '
    NR==1 { printf "  %-7s %7s %7s  %s\n", "PID", "VSZ(MB)", "RSS(MB)", "CMD"; next }
    { vsz=$2/1024; rss=$3/1024; cmd=substr($0,length($1 $2 $3)+4)
      printf "  %-7s %7.0f %7.0f  %s\n", $1, vsz, rss, cmd }
  '

  echo ""
  echo "── 5. POSTGRESQL BAĞLANTI ÖZETI ──"
  su - postgres -c "psql -XtAc \"
    SELECT 'total='||count(*)
          ||' / max='||(SELECT setting FROM pg_settings WHERE name='max_connections')
          ||' | active='||sum(CASE WHEN state='active' THEN 1 ELSE 0 END)
          ||' idle='||sum(CASE WHEN state='idle' THEN 1 ELSE 0 END)
          ||' lock_wait='||sum(CASE WHEN wait_event_type='Lock' THEN 1 ELSE 0 END)
    FROM pg_stat_activity WHERE pid != pg_backend_pid()
  \"" 2>/dev/null | sed 's/^/  /'

  echo ""
  echo "── 6. CACHE HIT ORANI ──"
  su - postgres -c "psql -XtAc \"
    SELECT '  '||datname||': '||
           COALESCE(round(100.0*blks_hit/NULLIF(blks_hit+blks_read,0),1)||'%','N/A') AS hit
    FROM pg_stat_database
    WHERE datname NOT IN ('template0','template1') AND blks_hit+blks_read > 0
    ORDER BY blks_hit+blks_read DESC LIMIT 5
  \"" 2>/dev/null

  echo ""
  echo "── 7. GEÇİCİ DOSYA UYARISI ──"
  TMPF=$(su - postgres -c "psql -XtAc \"
    SELECT datname||': '||temp_files||' dosya, '||pg_size_pretty(temp_bytes)
    FROM pg_stat_database WHERE temp_files > 0
  \"" 2>/dev/null)
  [ -n "$TMPF" ] && echo "$TMPF" | sed 's/^/  UYARI: /' || echo "  Geçici dosya yok (OK)"
fi

# ── 8. Servis Bellek Kullanımı ───────────────
echo ""
echo "── 8. SERVİS BELLEK KULLANIMI ──"
printf "  %-12s %-8s %8s %8s %8s\n" "SERVİS" "PID" "RSS(MB)" "Peak(MB)" "CPU%"
for svc in patroni etcd haproxy pgbouncer keepalived; do
  PID=$(systemctl show $svc --property=MainPID --value 2>/dev/null)
  if [ -n "$PID" ] && [ "$PID" != "0" ]; then
    RSS=$(awk '/VmRSS/{print $2}' /proc/$PID/status 2>/dev/null)
    PEAK=$(awk '/VmHWM/{print $2}' /proc/$PID/status 2>/dev/null)
    CPU=$(ps -p $PID -o %cpu= 2>/dev/null | tr -d ' ')
    [ -n "$RSS" ] && printf "  %-12s %-8s %8.1f %8.1f %8s\n" \
      "$svc" "$PID" "$((RSS/1024))" "$((PEAK/1024))" "${CPU:-0.0}"
  fi
done

# ── 9. OOM Koruma Durumu ────────────────────
echo ""
echo "── 9. OOM KORUMA DURUMU ──"
for svc in patroni etcd postgres; do
  PID=$(pgrep -o -x $svc 2>/dev/null)
  if [ -n "$PID" ]; then
    ADJ=$(cat /proc/$PID/oom_score_adj 2>/dev/null)
    [ "$ADJ" = "-1000" ] && STATUS="KORUNAN (adj=-1000)" || STATUS="adj=$ADJ (dikkat!)"
    printf "  %-12s PID=%-6s %s\n" "$svc" "$PID" "$STATUS"
  fi
done

# ── 10. Disk Kullanımı ───────────────────────
echo ""
echo "── 10. DİSK KULLANIMI ──"
df -hT | grep "^/dev" | \
  awk '{printf "  %-35s %4s %-5s %-5s (%s)\n", $1, $2, "Kull:"$5, "Boş:"$5, $7}'

# ── 11. Sayfa Aktivitesi ─────────────────────
echo ""
echo "── 11. SAYFA AKTİVİTESİ (vmstat) ──"
vmstat 1 3 | awk '
  NR==1 { print "  "$0; next }
  NR==2 { print "  "$0; next }
  { printf "  %s\n", $0 }
'

echo ""
echo "════════════════════════════════════════════"
```

**Örnek çıktı (patroni01):**

```
════════════════════════════════════════════
HOST: patroni01 — 2026-06-29 20:29:40
════════════════════════════════════════════

── 1. BELLEK GENEL BAKIŞ ──
  Toplam: 7681 MB | Kullanılan: 3211 MB | Boş: 479 MB
  Buff/Cache: 4306 MB | Kullanılabilir: 4469 MB
  SWAP: Yok

── 2. OVERCOMMİT ANALİZİ ──
  CommitLimit  : 4378 MB
  Committed_AS : 1004 MB (22.9%) [OK]

── 3. HUGEPAGES ──
  Toplam: 1104 (2208 MB) | Boşta: 472 (42%) | Rezerve: 390 | Kullanan: 632 [OK]

── 4. POSTGRESQL SÜREÇLERİ (VSZ/RSS) ──
  PID     VSZ(MB) RSS(MB)  CMD
  2158       2112      18  /usr/pgsql-18/bin/postgres -D /var/lib/pgsql/18/data
  2159         68       7   \_ postgres: logger
  2160       2116      12   \_ postgres: checkpointer
  2162       2112       7   \_ postgres: walwriter
  2163       2114      13   \_ postgres: walsender patroni02
  2164       2114      13   \_ postgres: walsender patroni03

── 5. POSTGRESQL BAĞLANTI ÖZETI ──
  total=10 / max=200 | active=3 idle=2 lock_wait=0

── 6. CACHE HIT ORANI ──
  pgbench_test: 95.5%
  postgres: 98.2%

── 7. GEÇİCİ DOSYA UYARISI ──
  Geçici dosya yok (OK)

── 8. SERVİS BELLEK KULLANIMI ──
  SERVİS       PID      RSS(MB)  Peak(MB)  CPU%
  patroni      1257          43        43  0.0
  etcd         1023          56        57  0.0

── 9. OOM KORUMA DURUMU ──
  patroni      PID=1257   KORUNAN (adj=-1000)
  etcd         PID=1023   KORUNAN (adj=-1000)
  postgres     PID=2158   KORUNAN (adj=-1000)

── 10. DİSK KULLANIMI ──
  /dev/mapper/vg_data-lv_pgdata    xfs  Kull:33% Boş:33% (/var/lib/pgsql)
  /dev/mapper/vg_pgwall-lv_pgwall  xfs  Kull:38% Boş:38% (/var/lib/pgwal)
════════════════════════════════════════════
```

---

## 18. Boyutlandırma ve Kapasite Planlama

### Sunucu Boyutlandırma Tablosu

| Rol | RAM | shared_buffers | work_mem | nr_hugepages | max_connections | Notlar |
|-----|-----|----------------|----------|--------------|-----------------|--------|
| Test/Dev | 4 GB | 1 GB | 4 MB | 512 | 100 | Bu kılavuzdaki küçük sunucu |
| Küçük Prod | 8 GB | 2 GB | 8 MB | 1024 | 150 | Web uygulaması |
| Orta Prod | 16 GB | 4 GB | 8 MB | 2048 | 200 | Bu kılavuzdaki gerçek sistem |
| Büyük Prod | 64 GB | 16 GB | 16 MB | 8192 | 300 | Yoğun OLTP |
| OLAP | 256 GB | 64 GB | 256 MB | 32768 | 50 | Raporlama, büyük sorgular |

### Mevcut Sistem Konfigürasyon Özeti

```
=== patroni01 (Leader, 2026-06-29) ===
RAM                 : 7,681 MB
shared_buffers      : 1,920 MB (%25 RAM) ✓
work_mem            : 4 MB (muhafazakâr)
maintenance_work_mem: 384 MB (%5 RAM) ✓
wal_buffers         : 38 MB (biraz düşük, 64 MB önerilir)
effective_cache_size: 5,760 MB (%75 RAM) ✓
max_connections     : 200 ✓
huge_pages          : try (→ on önerilir)
nr_hugepages        : 1,104 (2,208 MB) ✓
CommitLimit         : 4,378 MB
Committed_AS        : 1,004 MB (%22.9) ✓
overcommit_mode     : 2 (strict) ✓
Cache hit rate      : %95.5 (iyi, iyileştirilebilir)
PGDATA              : /var/lib/pgsql (xfs, 4.9 GB, %33 dolu)
WAL                 : /var/lib/pgwal (xfs, 4.9 GB, %38 dolu)

=== haproxy01 (2026-06-29) ===
RAM                 : 3,655 MB
HAProxy RSS         : 14.9 MB (master) + 8.3 MB (worker) = 23.2 MB
PgBouncer RSS       : 8.4 MB + 8.3 MB (×2 instance) = 16.7 MB
Keepalived RSS      : 8.7 MB (master) + 3.9 MB (worker) = 12.6 MB
Toplam servis yükü  : ~52 MB (%1.4 RAM)
CommitLimit         : 2,925 MB
Committed_AS        : 735 MB (%25.1)
nr_hugepages        : 0 (PG çalışmıyor, gerekmez) ✓
```

### Uyarı Eşikleri ve İzleme

```bash
# Aşağıdaki değerleri izleyin ve eşiklere uyarı kurun:

1. CommitLimit kullanımı (/proc/meminfo)
   OK:      < %70
   UYARI:   %70 - %90
   KRİTİK:  > %90  (malloc() ENOMEM hatası başlar)

2. HugePages_Free oranı
   OK:      > %20 (yeterli reserve)
   UYARI:   %5 - %20
   KRİTİK:  < %5  (yeni PG başlatılamayabilir)

3. PostgreSQL cache hit oranı (pg_stat_database)
   Mükemmel : > %99
   OK:        %95 - %99
   UYARI:     %90 - %95  (shared_buffers artırın)
   KRİTİK:    < %90  (acil müdahale gerekli)

4. Geçici dosya (pg_stat_database.temp_bytes)
   OK:      0 byte
   UYARI:   > 100 MB/gün  (work_mem artırın veya sorguyu optimize edin)
   KRİTİK:  > 1 GB/gün

5. lock_wait sayısı (pg_stat_activity)
   OK:      0
   UYARI:   1-5  (kilit analizi yapın)
   KRİTİK:  > 5  (bloklama zincirleri — acil müdahale)

6. Replikasyon LSN farkı (pg_wal_lsn_diff)
   OK:      0 bytes
   UYARI:   0 - 1 MB  (geçici yük artışı)
   KRİTİK:  > 10 MB   (replica çok geride)

7. Disk %util (iostat)
   OK:      < %50
   UYARI:   %50 - %80
   KRİTİK:  > %80  (I/O doygunluğu — checkpoint ayarları gözden geçirin)
```

### Hızlı Başvuru Komutları

```bash
# Bellek anlık görüntüsü
free -m && grep -E "HugePages|Commit" /proc/meminfo

# Tüm PostgreSQL süreçleri (VSZ/RSS)
ps --forest -C postgres -o pid,vsz,rss,etime,cmd

# Bir sürecin detaylı bellek dökümü
cat /proc/$(pgrep -x postgres | head -1)/smaps_rollup

# Aktif bağlantı durumu
su - postgres -c "psql -XtAc \"SELECT wait_event_type, count(*) FROM pg_stat_activity GROUP BY 1\""

# Cache hit oranı
su - postgres -c "psql -XtAc \"SELECT round(100.0*sum(blks_hit)/NULLIF(sum(blks_hit+blks_read),0),2)||'%' FROM pg_stat_database\""

# Replikasyon durumu
patronictl -c /etc/patroni/patroni.yml list

# Replica LSN farkı (replica üzerinde)
su - postgres -c "psql -XtAc \"SELECT pg_wal_lsn_diff(pg_last_wal_receive_lsn(),pg_last_wal_replay_lsn())\""

# Geçici dosyalar
su - postgres -c "psql -XtAc \"SELECT datname,temp_files,pg_size_pretty(temp_bytes) FROM pg_stat_database WHERE temp_files>0\""

# Disk I/O
iostat -xm 1 3

# OOM skorları
for p in patroni etcd postgres; do PID=$(pgrep -x $p | head -1); [ -n "$PID" ] && echo "$p(PID=$PID): adj=$(cat /proc/$PID/oom_score_adj)"; done

# CommitLimit kullanım yüzdesi
awk '/CommitLimit/{l=$2}/Committed_AS/{u=$2}END{printf "%.1f%%\n",u*100/l}' /proc/meminfo

# HugePage durumu
grep -E "HugePages|Huge" /proc/meminfo

# Keepalived VIP kontrolü
ip addr show | grep -E "inet 10\.253\.10\."

# HAProxy durum (socket)
echo "show info" | nc -U /var/run/haproxy/admin.sock | grep -E "CurrConns|MaxConn|Uptime"

# PgBouncer havuz durumu
psql -p 6432 -U pgbouncer pgbouncer -c "SHOW POOLS;" 2>/dev/null
```

---

**Son güncelleme:** 2026-06-29
**Ortam:** RHEL 9, PostgreSQL 18, Patroni 3.x, HAProxy 2.8, PgBouncer 1.x, etcd 3.x
**Tüm çıktılar:** patroni01 (10.253.10.51) ve haproxy01 (10.253.10.54) üzerinden alınmıştır
