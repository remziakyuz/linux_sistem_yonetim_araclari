# iSCSI Target Sunucu Yönetim Scripti — v0.94

> **Desteklenen dağıtımlar:** Oracle Linux · Red Hat Enterprise Linux (RHEL) · Rocky Linux · AlmaLinux · CentOS Stream · Fedora

Tek dosya Bash scripti ile iSCSI target sunucu kurulumu, dinamik yönetimi, cluster optimizasyonu ve aktif bağlantı izleme.

---

## İçindekiler

- [Özellikler](#özellikler)
- [Gereksinimler](#gereksinimler)
- [Hızlı Başlangıç](#hızlı-başlangıç)
- [Menü Yapısı](#menü-yapısı)
- [Yapılandırmayı Güncelleme](#yapılandırmayı-güncelleme)
- [Aktif Bağlantı İzleme](#aktif-bağlantı-i̇zleme)
- [Cluster Desteği](#cluster-desteği)
- [Cluster Kurulum Akışı](#cluster-kurulum-akışı)
- [Dosya ve Dizin Yapısı](#dosya-ve-dizin-yapısı)
- [Konfigürasyon Referansı](#konfigürasyon-referansı)
- [Sorun Giderme](#sorun-giderme)
- [Sürüm Geçmişi](#sürüm-geçmişi)

---

## Özellikler

### Temel Özellikler

| Özellik | Açıklama |
|---|---|
| Çoklu dağıtım desteği | `dnf`/`yum` otomatik tespiti |
| Tam interaktif menü | SSH üzerinden güvenli; her giriş onay adımlı |
| LUN yönetimi | LVM LV oluştur, ekle, sil, initiator'a bağla |
| Initiator yönetimi | IQN ekle/sil, ACL uygula |
| Portal yönetimi | Birden fazla IP:port, anlık değişiklik |
| CHAP kimlik doğrulama | Kullanıcı adı + parola, min 12 karakter |
| Konfigürasyon kalıcılığı | `/etc/iscsi-manager/config.sh` — reboot sonrası otomatik yükleme |
| Otomatik yedekleme | targetcli her değişiklik öncesi JSON yedeği alır |
| Dry-run modu | `--dry-run` ile değişiklik yapmadan önizleme |
| Log dosyası | `/var/log/iscsi-manager.log` zaman damgalı |
| Firewall + SELinux | `firewall-cmd` ve `semanage`/`chcon` otomatik |

### Yapılandırma Güncelleme (v0.94)

| Özellik | Açıklama |
|---|---|
| **Yapılandırılmış sistem koruması** | Sihirbaz, çalışan kurulumda yeniden başlamaz; mevcut yapılandırma özeti gösterilir |
| **Yapılandırmayı sıfırla** | Çift onaylı (yazılı `SIFIRLA`), aktif session uyarılı, otomatik yedekli güvenli temizleme |
| **Tam yapılandırma güncelleme** | Target IQN, portal, CHAP, cluster ayarları sistemi bozmadan güncellenir |
| Tam idempotent uygulama | configfs'den mevcut değerler okunur; yalnızca farklı olanlar uygulanır |
| Backstore isim çözümleme | `config.sh`'daki isim ile `targetcli`'deki isim farklıysa device path üzerinden doğru backstore otomatik bulunur |
| Mevcut yapılandırma tespiti | `config.sh` yoksa targetcli'deki aktif yapılandırmayı otomatik algılar ve içe aktarır |
| Aktif bağlantı listesi | Bağlı client'ları `targetcli sessions` + TCP bağlantıları ile anlık listele |
| Mevcut LUN'a client ekle | Yeni initiator IQN'i tanımla, seçtiğin LUN'lara erişim ver |
| Client'ı tamamen sil | ACL + tüm LUN mapped bağlantıları tek adımda kaldır |
| LUN'dan erişim kaldır | Belirli bir LUN için sadece o client'ın mapped bağlantısını kes |
| Yeni LUN ekle | Kurulmuş sisteme ek LVM LV + backstore + LUN tanımla |

### Cluster Özellikleri (v0.80'den)

| Özellik | Açıklama |
|---|---|
| SCSI Persistent Reservations | `emulate_pr=1` — STONITH/fencing için **zorunlu** |
| Compare And Write | `emulate_caw=1` — GFS2/OCFS2 atomik yazma için **zorunlu** |
| Third Party Copy | `emulate_3pc=1` — XCOPY ile CPU kullanmadan veri kopyası |
| UNMAP / WRITE SAME | `emulate_tpu=1`, `emulate_tpws=1` — thin provisioning desteği |
| PR Session izolasyonu | `enforce_pr_isids=1` — node'lar arası PR anahtarı karışmaz |
| ALUA port group | Simetrik (round-robin) veya asimetrik (active-standby) MPIO |
| Kernel ağ optimizasyonu | 16 MB TCP buffer, keepalive, vm.swappiness sysctl |
| I/O scheduler otomasyonu | Disk tipine göre `mq-deadline`/`none` + kalıcı udev kuralı |
| SCSI PR doğrulama | `sg_persist` ile test anahtarı kayıt/silme testi |
| Multipath config üreteci | Cluster node'lara kopyalanacak `/etc/multipath.conf` |
| 5 sayfalık kurulum kılavuzu | Mimari · Target · Node · GFS2/OCFS2 · STONITH |

---

## Gereksinimler

### Target Sunucu

- RHEL tabanlı dağıtım (yukarıdaki liste)
- `root` yetkisi (`sudo`)
- Aşağıdaki paketler eksikse script otomatik kurar:
  - `targetcli` `lvm2` `device-mapper` `firewalld`
  - Cluster için: `sg3_utils` `device-mapper-multipath` + seçilen FS araçları

### Cluster Node'ları (initiator makineler)

- `iscsi-initiator-utils`
- `device-mapper-multipath`
- `sg3_utils`
- Seçilen cluster FS: `gfs2-utils`, `ocfs2-tools` veya `lvm2-lockd`

### Ağ

- iSCSI storage ağı ve cluster heartbeat ağı **ayrı NIC** üzerinde olmalı
- Jumbo frame (MTU 9000) önerilir — switch desteği gerekli
- Her LUN için en az 2 farklı ağ yolu (MPIO)

---

## Hızlı Başlangıç

```bash
# Script'i çalıştır (root gerekli)
sudo bash iscsi-manager.sh

# Değişiklik yapmadan önizleme
sudo bash iscsi-manager.sh --dry-run
```

### Mevcut Sistemde İlk Çalıştırma

`config.sh` dosyası yoksa script, targetcli'deki aktif yapılandırmayı otomatik tespit eder ve içe aktarmayı teklif eder:

```
══ MEVCUT YAPILANDIRMA TESPİT EDİLDİ ══
[INFO ] targetcli'de aktif bir yapılandırma bulundu.
  Target IQN : iqn.2025-01.com.sirket:storage01
  Portal      : 172.16.166.248:3260
  Portal      : 172.16.216.248:3260
  LUN0       : /dev/vg_data01/lv_ha_shared01 (100G)
  LUN1       : /dev/vg_data01/lv_ha_shared02 (200G)
  Initiator   : iqn.1994-05.lab.local:clstr01
  Initiator   : iqn.1994-05.lab.local:clstr02
  Cluster     : Aktif (PR etkin)

Bu yapılandırma içe aktarılsın mı? [E/h]:
```

Onaylandığında ayarlar `/etc/iscsi-manager/config.sh` dosyasına kaydedilir ve artık menü üzerinden yönetilebilir.

### Yeni Kurulum (Sihirbaz)

```
Ana Menü → 1. Tam Kurulum Sihirbazı
```

Sihirbaz adımları:

1. **Target IQN** — `iqn.2025-01.com.sirket:storage01`
2. **Portal IP'leri** — iSCSI NIC'lerinin IP'leri (birden fazla olabilir)
3. **LUN tanımları** — VG/LV adı ve boyutu (örn: `vg_data/lv_shared01`, `200G`)
4. **Initiator IQN'leri** — Client makinelerin initiator IQN'leri
5. **CHAP** — Kimlik doğrulama (isteğe bağlı)
6. **Cluster modu** — GFS2/OCFS2/lvmlockd seçimi, ALUA modu, digest

---

## Menü Yapısı

```
Ana Menü
├── 1. Tam Kurulum Sihirbazı
│   └── (yapılandırılmış sistemde mevcut yapılandırmayı gösterir, yeniden kurulumu engeller)
├── 2. Sistem Durumu
├── 3. LUN / Backstore Yönetimi
│   ├── Listele
│   ├── Ekle
│   ├── LUN → Initiator Bağla
│   └── Kaldır
├── 4. Initiator Yönetimi
│   ├── Listele
│   ├── Ekle
│   └── Sil
├── 5. Cluster Yönetimi
│   ├── Cluster Modunu Etkinleştir
│   ├── ALUA Port Group Modu Seç
│   ├── Cluster Dosya Sistemi Seç
│   ├── iSCSI Digest Modu Seç
│   ├── Multipath Konfigürasyon Üret
│   ├── SCSI PR Doğrulama
│   ├── Cluster Durumu Göster
│   └── Cluster Kurulum Kılavuzu (5 sayfa)
├── 6. Portal Yönetimi
├── 7. CHAP Kimlik Doğrulama
├── 8. Yapılandırmayı Güncelle  ★
│   ├── Aktif Bağlantıları Listele
│   ├── Mevcut LUN'a Yeni Client Ekle
│   ├── Bağlı Client Sil / LUN Erişimini Kaldır
│   ├── Yeni LUN Ekle
│   └── Tam Yapılandırma Güncelleme  ★ YENİ
│       ├── Target IQN değiştir
│       ├── Portal IP/port güncelle
│       ├── CHAP ayarlarını güncelle
│       ├── Cluster modu / FS / ALUA / Digest güncelle
│       └── Yapılandırmayı tekrar uygula (idempotent)
├── 9. Tüm Yapılandırmayı Uygula (idempotent)
├── 10. Yapılandırmayı Sıfırla  ⚠ YENİ
├── 11. Firewall ve SELinux Güncelle
├── 12. Client Bağlantı Bilgisi
└── 13. Çıkış
```

---

## Yapılandırılmış Sistem Koruması

Sistem zaten kurulu ve çalışıyorsa (config.sh dolu **ve** targetcli'de target var), `1. Tam Kurulum Sihirbazı` seçildiğinde yeniden kurulum **başlatılmaz**. Bunun yerine mevcut yapılandırma özeti gösterilir ve kullanıcıya yapılabilecekler açıklanır:

```
  ⚠  Sistem zaten yapılandırılmıştır.

  Mevcut Yapılandırma:
    Target IQN  : iqn.2025-01.com.sirket:storage01
    Portal      : 172.16.166.248:3260
    Portal      : 172.16.216.248:3260
    LUN0        : /dev/vg_data01/lv_ha_shared01 (100G)
    LUN1        : /dev/vg_data01/lv_ha_shared02 (200G)
    LUN2        : /dev/vg_data01/lv_ha_shared03 (50G)
    Initiator   : iqn.1994-05.lab.local:clstr01
    Initiator   : iqn.1994-05.lab.local:clstr02
    Cluster     : Evet (gfs2 / symmetric)
    CHAP        : Devre Dışı

  Yapılabilecekler:
    • 8. Yapılandırmayı Güncelle     – Mevcut sistemi günceller (LUN/client ekle/sil)
    • 9. Tüm Yapılandırmayı Uygula   – config.sh'ı targetcli'ye yansıtır (idempotent)
    • 10. Yapılandırmayı Sıfırla     – Sistemi temizler, sıfırdan başlamak için
```

Sıfırdan kurulum yapılmak isteniyorsa önce `10. Yapılandırmayı Sıfırla` ile sistem temizlenir, sonra sihirbaz yeniden çalıştırılır.

---

## Yapılandırmayı Sıfırla (Güvenli Sıfırlama)

`Ana Menü → 10. Yapılandırmayı Sıfırla` ile çalışan bir sistemin tüm targetcli yapılandırması güvenli şekilde temizlenir.

**Güvenlik adımları:**

1. **Yapılacakların özeti gösterilir** — silinecek ve korunacak öğeler net şekilde listelenir
2. **İlk onay** — `e/h` sorusu
3. **Aktif session uyarısı** — bağlı client varsa sayısı gösterilir, ek onay istenir
4. **İkinci onay** — kullanıcı `SIFIRLA` kelimesini açıkça yazmalıdır
5. **Otomatik yedekleme** — targetcli JSON yedeği + config.sh yedeği `/etc/iscsi-manager/backups/` altına alınır
6. **Sıralı temizlik** — target sil → backstore'lar sil → saveconfig → servis yeniden başlat → config.sh kaldır

**Korunan öğeler:**

- LVM Logical Volume'ları (`lv_*`) — **veriler korunur**
- Volume Group'lar
- Önceki tüm yedekler
- Kernel/sysctl parametreleri ve udev kuralları

**Geri alma:** Sıfırlama sonrası hata durumunda son yedekten geri yüklenebilir:

```bash
targetcli restoreconfig /etc/iscsi-manager/backups/<son_yedek>.json
```

---

## Yapılandırmayı Güncelleme

`Ana Menü → 8. Yapılandırmayı Güncelle` altındaki seçenekler, kurulmuş ve çalışan bir sistemi yeniden kurulum yapmadan günceller.

> **Not:** Script ilk çalıştırıldığında `config.sh` yoksa targetcli'deki mevcut yapılandırmayı otomatik algılar ve içe aktarır. Bu sayede daha önce manuel veya farklı araçlarla kurulmuş sistemler de menü üzerinden yönetilebilir hale gelir.

### Mevcut LUN'a Yeni Client Ekle

Yeni bir makineyi sisteme bağlamak için kullanılır:

1. Yeni client'ta initiator IQN'ini öğrenin:
   ```bash
   cat /etc/iscsi/initiatorname.iscsi
   ```
2. Menüden `2. Mevcut LUN'a Yeni Client Ekle` seçin.
3. IQN'i girin. İstediğiniz LUN numaralarını boşlukla ayırarak yazın (boş bırakırsanız tüm LUN'lara erişim verilir).
4. Onaylayın — ACL ve mapped_lun otomatik oluşturulur, targetcli kaydedilir.

### Bağlı Client Sil

Bir client'ı sistemden kaldırmak için iki seçenek sunulur:

- **Yalnızca belirli bir LUN'dan kaldır:** ACL korunur, sadece o LUN'a ait `mapped_lun` silinir.
- **Client'ı tamamen sil:** ACL ve tüm mapped bağlantılar kaldırılır, `ALLOWED_INITIATORS` listesinden de silinir.

Her iki işlem öncesinde otomatik yedek alınır.

### Yeni LUN Ekle

Çalışan sisteme yeni bir LVM LV + backstore + LUN ekler. Hedef target aktifse ekledikten sonra "şimdi uygulanşın mı?" sorusu sorulur; onaylanırsa mevcut initiator'ların ACL'lerine yeni LUN otomatik mapped edilir. Cluster modu aktifse PR+CAW+ALUA attribute'ları da uygulanır.

---

## Aktif Bağlantı İzleme

`Ana Menü → 8 → 1. Aktif Bağlantıları Listele` ile erişilir.

İki katmanlı bilgi sunar:

| Kaynak | Ne Gösterir |
|---|---|
| `targetcli sessions` | Aktif sessionlar: alias (hostname), session ID, durum (LOGGED_IN vb.) |
| `ss -tn state established` | Aktif TCP bağlantıları: target tarafındaki ve client tarafındaki IP:port adresleri |

Ek olarak configfs üzerinden session sayısı doğrulanır.

---

## Cluster Desteği

### Neden Cluster Modu Gerekli?

Birden fazla sunucunun aynı iSCSI LUN'a eş zamanlı okuma/yazma yapabilmesi için standart yapılandırma yeterli değildir:

```
Sorun 1 — Split-brain
  İki node ağ bağlantısını kaybeder; her ikisi de
  "aktif node benim" sanarak aynı bloklara yazar → VERİ BOZULUR

Sorun 2 — Atomik yazma garantisi yok
  GFS2/OCFS2 metadata güncellemesi için Compare And Write (CAW) gerekir.
  Yoksa cluster FS tutarsızlaşır → DOSYA SİSTEMİ BOZULUR

Çözüm: SCSI Persistent Reservations (PR) + STONITH
  Node'lar birbirini PR mekanizmasıyla fence eder.
  Sorunlu node diskten kesilir → split-brain önlenir
```

### Cluster SCSI Attribute'ları

`Cluster Yönetimi → Cluster Modunu Etkinleştir` her LUN'a şunları otomatik uygular:

| targetcli Attribute | Değer | Kritiklik | Açıklama |
|---|---|---|---|
| `emulate_pr` | `1` | 🔴 ZORUNLU | SCSI-3 Persistent Reservations — `fence_scsi` bunun üzerinde çalışır |
| `emulate_caw` | `1` | 🔴 ZORUNLU | Compare And Write — GFS2/OCFS2/lvmlockd atomik operasyonları için |
| `emulate_rest_reord` | `0` | 🔴 ZORUNLU | I/O yeniden sıralamayı kapatır; write ordering garantisi |
| `emulate_write_cache` | `0` | 🔴 ZORUNLU | Write-through — önbellek kaynaklı tutarsızlığı önler |
| `emulate_3pc` | `1` | 🟡 ÖNERİLEN | Third Party Copy (XCOPY) — CPU kullanmadan sunucu-sunucu veri kopyası |
| `emulate_tpu` | `1` | 🟡 ÖNERİLEN | UNMAP — cluster FS silinmiş blokları bildirir |
| `emulate_tpws` | `1` | 🟡 ÖNERİLEN | WRITE SAME with UNMAP — thin provisioning awareness |
| `enforce_pr_isids` | `1` | 🟡 ÖNERİLEN | PR session izolasyonu — node'lar birbirinin anahtarını ezemez |
| `emulate_fua_write` | `1` | 🟡 ÖNERİLEN | Force Unit Access — metadata yazmalarında önbellek atlanır |

### iSCSI TPG Parametreleri (Cluster Modu)

| Parametre | Değer | Açıklama |
|---|---|---|
| `MaxBurstLength` | 16.776.192 (16 MB) | Maksimum veri burst boyutu |
| `FirstBurstLength` | 262.144 (256 KB) | İlk paketteki maksimum veri |
| `InitialR2T` | `No` | R2T beklemeden hemen veri gönder |
| `ImmediateData` | `Yes` | İlk PDU ile veri taşı |
| `MaxConnections` | `1` | Session başına bağlantı |
| `login_timeout` | `15 sn` | Bağlantı kurma zaman aşımı |

### ALUA Port Group

**Simetrik ALUA** (varsayılan): tüm portaller eşit önceliktedir, MPIO round-robin yapar.

**Asimetrik ALUA**: Portal 1 birincil (Active/Optimized), diğerleri yedektir. Portal 1 kesildiğinde MPIO otomatik geçer.

| Mod | Ne zaman kullan? |
|---|---|
| **Simetrik** | Tüm portaller aynı hız ve gecikmedeyse — önerilen |
| **Asimetrik** | Portaller farklı bant genişliğindeyse (10GbE + 1GbE yedek) |

### Kernel ve I/O Optimizasyonları

Cluster modu etkinleştirildiğinde otomatik uygulanır:

`/etc/sysctl.d/99-iscsi-cluster.conf`:
```ini
net.core.rmem_max             = 16777216
net.core.wmem_max             = 16777216
net.ipv4.tcp_rmem             = 4096 4194304 16777216
net.ipv4.tcp_wmem             = 4096 4194304 16777216
net.ipv4.tcp_keepalive_time   = 10
net.ipv4.tcp_keepalive_intvl  = 10
net.ipv4.tcp_keepalive_probes = 6
vm.swappiness                 = 10
vm.dirty_ratio                = 5
```

I/O Scheduler: disk tipine göre otomatik seçim + kalıcı udev kuralı.

| Disk Tipi | Scheduler |
|---|---|
| NVMe | `none` |
| SSD | `mq-deadline` |
| HDD | `mq-deadline` |

---

## Cluster Kurulum Akışı

### Adım 1 — Target Kurulumu

```
Ana Menü → Tam Kurulum Sihirbazı → Cluster modunu etkinleştir
```

### Adım 2 — SCSI PR Doğrulama

```
Ana Menü → Cluster Yönetimi → SCSI PR Doğrulama
```

### Adım 3 — Multipath Config Üret ve Dağıt

```
Ana Menü → Cluster Yönetimi → Multipath Konfigürasyon Üret
```

Her cluster node'a kopyalayın:
```bash
scp /etc/iscsi-manager/multipath.conf.generated root@<NODE_IP>:/etc/multipath.conf
```

### Adım 4 — Her Node'da Initiator Kurulumu

```bash
dnf install iscsi-initiator-utils device-mapper-multipath sg3_utils

# Her node için FARKLI IQN kullanın
echo 'InitiatorName=iqn.2025-01.com.sirket:node1' > /etc/iscsi/initiatorname.iscsi

systemctl enable --now iscsid

# Discovery (tüm portallardan)
iscsiadm -m discovery -t st -p <PORTAL_IP>:3260

# Login (tüm portallardan — MPIO için zorunlu)
iscsiadm -m node -T <TARGET_IQN> -p <PORTAL_1_IP>:3260 --login
iscsiadm -m node -T <TARGET_IQN> -p <PORTAL_2_IP>:3260 --login

systemctl enable --now multipathd
multipath -ll   # Her LUN için 2 yol görünmeli
```

### Adım 5 — Cluster FS Kurulumu (GFS2 örneği)

```bash
dnf install dlm corosync pacemaker pcs gfs2-utils

pcs cluster setup --name mycluster node1 node2
pcs cluster start --all && pcs cluster enable --all

pcs resource create dlm systemd:dlm clone clone-max=2 clone-node-max=1

# STONITH (SCSI PR tabanlı — ZORUNLU)
pcs stonith create myFence fence_scsi \
    devices=/dev/mapper/mpathX \
    pcmk_host_map="node1:1;node2:2" \
    pcmk_reboot_action=off

pcs property set stonith-enabled=true
pcs property set no-quorum-policy=freeze

# GFS2 formatla (YALNIZCA BİR NODE'DA — tek seferlik)
mkfs.gfs2 -p lock_dlm -t mycluster:myvol -j 2 /dev/mapper/mpathX

# Tüm node'larda mount et
mount -t gfs2 /dev/mapper/mpathX /mnt/shared
# /etc/fstab: /dev/mapper/mpathX  /mnt/shared  gfs2  defaults,_netdev  0 0
```

### Adım 6 — Doğrulama

```bash
pcs status
sg_persist --in --read-keys /dev/mapper/mpathX   # Her node bir anahtar görmeli
iscsiadm -m session                               # Her node 2 session olmalı
multipath -ll
```

---

## Dosya ve Dizin Yapısı

```
/etc/iscsi-manager/
├── config.sh                            # Kalıcı konfigürasyon (reboot'ta yüklenir)
├── backups/
│   ├── targetcli_YYYYMMDD_HHMMSS.json  # targetcli otomatik yedekleri
│   └── lvm.conf.YYYYMMDDHHMMSS.bak     # LVM konfigürasyon yedeği
└── multipath.conf.generated            # Cluster node'lar için multipath konfigürasyonu

/var/log/iscsi-manager.log              # Tüm işlem logları (zaman damgalı)

/etc/sysctl.d/99-iscsi-cluster.conf    # Kernel ağ parametreleri (cluster modu)

/etc/udev/rules.d/99-iscsi-scheduler.rules   # I/O scheduler kalıcı udev kuralları
```

---

## Konfigürasyon Referansı

`/etc/iscsi-manager/config.sh` dosyası tüm ayarları saklar. Script menüsü üzerinden değiştirilmeli; doğrudan düzenlenmesi **önerilmez**.

```bash
ISCSI_TARGET_IQN="iqn.2025-01.com.sirket:storage01"
ISCSI_PORTAL_PORT="3260"
CHAP_ENABLED=false
CHAP_USERNAME=""
CHAP_PASSWORD=""

# Cluster ayarları
CLUSTER_MODE=true
CLUSTER_FS_TYPE="gfs2"           # gfs2 | ocfs2 | lvmlockd | raw
CLUSTER_DIGEST="None"             # None | CRC32C
CLUSTER_ALUA_MODE="symmetric"    # symmetric | asymmetric
ISCSI_MAX_BURST=16776192          # 16 MB
ISCSI_FIRST_BURST=262144          # 256 KB
ISCSI_MAX_R2T=1
ISCSI_LOGIN_TIMEOUT=15

ISCSI_PORTAL_IPS=(
  "192.168.100.10"
  "192.168.100.11"
)
LUN_DEFINITIONS=(
  "vg_data/lv_shared01:0:200G"
  "vg_data/lv_shared02:1:500G"
)
ALLOWED_INITIATORS=(
  "iqn.2025-01.com.sirket:node1"
  "iqn.2025-01.com.sirket:node2"
)
```

### LUN Tanım Formatı

```
"<VolumeGroup>/<LogicalVolume>:<LUN_Numarası>:<Boyut>"

Örnekler:
  "vg_data/lv_db_shared:0:500G"
  "vg_nvme/lv_app_logs:1:100G"
```

---

## Sorun Giderme

### targetcli attribute hatası

```
Error: no such attribute 'emulate_pr'
```

Kernel veya targetcli sürümü bu attribute'ı desteklemiyor.

```bash
uname -r          # Kernel (PR için Linux 4.10+ gerekli)
targetcli version
dnf update targetcli python3-rtslib
```

---

### SCSI PR testi başarısız

```
sg_persist: PR register failed
```

`emulate_pr=1` uygulanmamış veya LUN yeniden oluşturuldu.

```bash
targetcli ls /backstores/block/<bs_name>
# Ana Menü → Cluster Yönetimi → Cluster Modunu Etkinleştir
```

---

### Multipath yol sayısı eksik

```bash
# Tüm portallardan discovery yenile
iscsiadm -m discovery -t st -p <PORTAL_2_IP>:3260

# İkinci portala login
iscsiadm -m node -T <TARGET_IQN> -p <PORTAL_2_IP>:3260 --login

multipathd reconfigure
multipath -ll
```

---

### Aktif bağlantı listesi boş geliyor

```bash
# targetcli sessions komutu eski sürümlerde yoktur
targetcli sessions

# configfs erişimini kontrol et
ls /sys/kernel/config/target/iscsi/

# target servisi çalışıyor mu?
systemctl status target

# Port dinleniyor mu?
ss -tlnp | grep 3260
```

---

### GFS2 mount başarısız: `DLM not running`

```bash
pcs status              # DLM kaynağının Started olduğunu kontrol et
systemctl status corosync
dlm_tool status

pcs cluster stop --all
pcs cluster start --all
```

---

### STONITH devre dışı uyarısı

Bu uyarıyı **görmezden gelmeyin** — STONITH olmadan cluster güvenli değildir.

```bash
dnf install fence-agents-scsi

pcs stonith create myFence fence_scsi \
    devices=/dev/mapper/mpathX \
    pcmk_host_map="node1:1;node2:2"

pcs property set stonith-enabled=true
```

---

### Log dosyası

```bash
tail -f /var/log/iscsi-manager.log
```

---

## Güvenlik Notları

- CHAP parolası minimum 12 karakter olmalı; cluster ortamında **mutual CHAP** önerilir.
- iSCSI storage trafiği ayrı bir VLAN/segment üzerinde olmalı.
- `ALLOWED_INITIATORS` listesi boş bırakılmamalı — boş liste tüm initiator'lara erişim açar.
- targetcli yedekleri hassas konfigürasyon içerebilir; dosya izinlerini koruyun:

```bash
chmod 600 /etc/iscsi-manager/config.sh
chmod 700 /etc/iscsi-manager/backups/
```

---

## Sürüm Geçmişi

| Sürüm | Değişiklikler |
|---|---|
| **v0.94** | **Yapılandırılmış sistem koruması:** Sihirbaz, mevcut çalışan kurulumu algılar ve yeniden kurulumu engeller — yapılacakları gösterir. **Yapılandırmayı Sıfırla** menüsü: çift onaylı (yazılı `SIFIRLA`), aktif session uyarılı, otomatik yedekli güvenli sıfırlama. **Tam Yapılandırma Güncelleme** alt menüsü: Target IQN, portal, CHAP, cluster ayarlarını çalışan sistemi bozmadan güncelleme. |
| **v0.93** | Tam idempotent yapılandırma: configfs'den mevcut değerler okunarak sadece farklı olanlar uygulanır. Backstore isim çözümleme. `emulate_ua_intlck_ctrl` ve `nopin_*` parametreleri kaldırıldı. I/O scheduler disk tekrarı düzeltildi. Pipe bloğu içindeki log çıktıları sorunu çözüldü. |
| **v0.91** | Mevcut targetcli yapılandırmasını otomatik tespit ve içe aktarma (`detect_existing_config`). Aktif session listesi düzeltildi. Ana menü seçim sayısı hatası düzeltildi (13→12). |
| **v0.90** | Yapılandırma güncelleme menüsü: mevcut LUN'a client ekle, client sil, LUN'dan erişim kaldır, yeni LUN ekle. Boş dizi cleanup bug'ı düzeltildi. |
| **v0.85** | Cluster modu: SCSI PR, CAW, ALUA, kernel/I/O optimizasyon, multipath config üreteci, 5 sayfalık kılavuz |
| **v0.80** | Çoklu dağıtım desteği, tam interaktif menü, konfigürasyon kalıcılığı, CHAP, otomatik yedekleme, dry-run modu |
| **v0.60** | Fedora odaklı, sabit tanımlı temel kurulum scripti |
