#!/bin/bash
# =============================================================================
# FreeIPA - Linux Sistem Yöneticisi Sudo Kurulum Scripti
# =============================================================================
# AÇIKLAMA  : Bu script FreeIPA üzerinde linux-sysadmin rolü için
#             sudo komutları, komut grupları ve sudo kuralları oluşturur.
#
# ÖN KOŞULLAR:
#   - IPA client kurulu ve domain'e üye bir sunucu
#   - Geçerli Kerberos admin bileti (kinit admin)
#   - ipa-admintools paketi kurulu
#
# KULLANIM  :
#   $ kinit admin
#   $ bash freeipa_sysadmin_sudo_setup.sh
#
# OLUŞTURULAN GRUPLAR:
#   01. sysadmin_service_mgmt      - Servis Yönetimi
#   02. sysadmin_disk_mgmt         - Disk ve Volume Yönetimi
#   03. sysadmin_filesystem_mgmt   - Dosya Sistemi Yönetimi
#   04. sysadmin_network_mgmt      - Network Yönetimi
#   05. sysadmin_cpu_process_mgmt  - İşlemci ve Process Yönetimi
#   06. sysadmin_log_analysis      - Log Analizi
#   07. sysadmin_app_analysis      - Uygulama Analizi (Memory/Library/Profiling)
#   08. sysadmin_system_config     - Sistem Yapılandırma ve Güncelleme
#   09. sysadmin_disk_encryption   - Disk Şifreleme
#   10. sysadmin_hardware_mgmt     - Donanım Yönetimi
#   11. sysadmin_user_mgmt         - Kullanıcı Yönetimi
#   12. sysadmin_security_analysis - Güvenlik Analizi
#   13. sysadmin_backup_recovery   - Yedekleme ve Kurtarma
#   14. sysadmin_virt_container    - Sanallaştırma ve Konteyner
#
# SUDO KURALI: rule_linux_sysadmin
#   - Tüm gruplara ALL hosts üzerinde erişim
#   - Root shell geçişi (su - / bash / sh) kesinlikle YOK
# =============================================================================

set -euo pipefail

# --------------------------------------------------------------------------- #
#  Renkli çıktı yardımcıları
# --------------------------------------------------------------------------- #
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[+]${NC} $*"; }
info()    { echo -e "${BLUE}[i]${NC} $*"; }
section() { echo -e "\n${CYAN}${BOLD}>>> $* ${NC}"; echo "$(printf '=%.0s' {1..60})"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[x]${NC} $*" >&2; }
ok()      { echo -e "${GREEN}[OK]${NC} $*"; }

# --------------------------------------------------------------------------- #
#  IPA yardımcı fonksiyonları
# --------------------------------------------------------------------------- #

# Sudo komutu ekle: ipa_cmd <isim> <aciklama>
ipa_cmd() {
    local name="$1" desc="$2"
    if ipa sudocmd-show "$name" &>/dev/null; then
        warn "Var (atlandı): $name"
    else
        ipa sudocmd-add "$name" --desc="$desc" 2>/dev/null \
            && log "Komut eklendi: [$name] | $desc" \
            || err "Eklenemedi  : $name"
    fi
}

# Komut grubu oluştur: ipa_grp <isim> <aciklama>
ipa_grp() {
    local name="$1" desc="$2"
    if ipa sudocmdgroup-show "$name" &>/dev/null; then
        warn "Grup var (atlandı): $name"
    else
        ipa sudocmdgroup-add "$name" --desc="$desc" 2>/dev/null \
            && log "Grup oluşturuldu: $name" \
            || err "Grup oluşturulamadı: $name"
    fi
}

# Sudo kuralı oluştur
ipa_rule() {
    local name="$1" desc="$2"
    if ipa sudorule-show "$name" &>/dev/null; then
        warn "Kural var (atlandı): $name"
    else
        ipa sudorule-add "$name" --desc="$desc" 2>/dev/null \
            && log "Kural oluşturuldu: $name" \
            || err "Kural oluşturulamadı: $name"
    fi
}

# Gruba komut üyesi ekle
add_members() {
    local grp="$1"; shift
    info "Gruba üye ekleniyor: $grp"
    for cmd in "$@"; do
        ipa sudocmdgroup-add-member "$grp" --sudocmds="$cmd" &>/dev/null \
            && log "  OK $grp <- $cmd" \
            || warn "  ~  Zaten üye veya hata: $cmd"
    done
}

# --------------------------------------------------------------------------- #
#  Ön kontrol
# --------------------------------------------------------------------------- #
echo ""
echo -e "${BOLD}${CYAN}"
echo "=================================================================="
echo "     FreeIPA Linux Sysadmin Sudo Kurulum Scripti"
echo "=================================================================="
echo -e "${NC}"

# -----------------------------------------------------------------------
# KRB5CCNAME tespiti
# klist -l ciktisinda cache adi 2. sutunda olabilir, principal 1. sutunda.
# En guvenilir yontem: KRB5CCNAME sifirla, klist ile "Ticket cache:" oku.
# -----------------------------------------------------------------------

# Onceki KRB5CCNAME varsa sifirla - klist sistem varsayilanini kullansin
unset KRB5CCNAME 2>/dev/null || true

# klist ciktisindaki "Ticket cache: KCM:1639200003:2685" satirini oku
DETECTED=$(klist 2>/dev/null | awk '/^Ticket cache:/{print $3; exit}')

if [[ -n "$DETECTED" ]]; then
    export KRB5CCNAME="$DETECTED"
    info "KRB5CCNAME tespit edildi: $KRB5CCNAME"
else
    err "Kerberos ticket cache bulunamadi."
    err "Lutfen once 'kinit admin' calistirin."
    info "Mevcut klist ciktisi:"
    klist 2>&1 | sed 's/^/  /' || true
    exit 1
fi

# Ticket gecerliligi
if ! klist -s 2>/dev/null; then
    err "Gecerli Kerberos bileti bulunamadi."
    err "Lutfen once 'kinit admin' calistirin."
    info "Cache durumu:"
    klist 2>&1 | sed 's/^/  /' || true
    exit 1
fi

ok "Kerberos bileti gecerli."
info "Principal : $(klist 2>/dev/null | awk '/Default principal:/{print $3}')"
info "Cache     : $KRB5CCNAME"

if ! ipa ping &>/dev/null; then
    warn "ipa ping basarisiz - IPA sunucusuna erisim sorunu olabilir."
fi

ok "IPA oturumu aktif. Kurulum baslatiliyor..."



# =============================================================================
#  BÖLÜM 1 - SERVİS YÖNETİMİ
#  Grup: sysadmin_service_mgmt
# =============================================================================
section "BÖLÜM 1 - SERVİS YÖNETİMİ KOMUTLARI"

ipa_cmd "/usr/bin/systemctl"          "Systemd servis yönetimi: start/stop/restart/enable/disable/status/mask/daemon-reload"
ipa_cmd "/usr/sbin/service"           "SysV init uyumlu servis yönetim komutu (eski dağıtımlar için)"
ipa_cmd "/usr/bin/journalctl"         "Systemd journal log okuyucu: birim/zaman/öncelik/kernel filtreleme"
ipa_cmd "/usr/bin/systemd-analyze"    "Systemd başlangıç süresi ve bağımlılık grafiği (blame/critical-chain)"
ipa_cmd "/usr/bin/systemd-cgls"       "Systemd cgroup hiyerarşisini ağaç görünümünde listeleme"
ipa_cmd "/usr/bin/systemd-cgtop"      "Cgroup kaynak kullanımını anlık izleme (top benzeri)"
ipa_cmd "/usr/bin/timedatectl"        "Sistem saat/zaman dilimi/NTP eşitleme durumu yönetimi"
ipa_cmd "/usr/bin/chronyc"            "Chrony NTP istemci: tracking/sources/makestep komutları"
ipa_cmd "/usr/sbin/ntpdate"           "NTP sunucusundan anlık saat senkronizasyonu"
ipa_cmd "/usr/sbin/chkconfig"         "SysV runlevel servis başlangıç durumu yönetimi (RHEL/CentOS)"
ipa_cmd "/usr/bin/loginctl"           "Systemd-logind oturum ve kullanıcı oturumu yönetimi"


# =============================================================================
#  BÖLÜM 2 - DİSK VE VOLUME YÖNETİMİ
#  Grup: sysadmin_disk_mgmt
# =============================================================================
section "BÖLÜM 2 - DİSK VE VOLUME YÖNETİMİ KOMUTLARI"

# Disk bölümlendirme
ipa_cmd "/usr/sbin/fdisk"             "MBR disk bölüm tablosu oluşturma ve düzenleme"
ipa_cmd "/usr/sbin/gdisk"             "GPT disk bölüm tablosu oluşturma ve düzenleme"
ipa_cmd "/usr/sbin/cgdisk"            "GPT bölümlendirme interaktif TUI arayüzü"
ipa_cmd "/usr/sbin/parted"            "Gelişmiş disk bölümlendirme: MBR+GPT, resize, hizalama"
ipa_cmd "/usr/sbin/partprobe"         "Kernel'e disk bölüm tablosu değişikliğini bildirme"
ipa_cmd "/usr/sbin/sfdisk"            "Script dostu disk bölümlendirme (otomasyon/yedekleme)"

# Disk bilgisi ve izleme
ipa_cmd "/usr/bin/lsblk"              "Blok aygıtları ağaç yapısında listeleme (UUID/FS/mount)"
ipa_cmd "/usr/sbin/blkid"             "Blok aygıt UUID, TYPE ve LABEL bilgisi sorgulama"
ipa_cmd "/usr/bin/df"                 "Bağlı dosya sistemlerinin disk kullanım istatistikleri"
ipa_cmd "/usr/bin/du"                 "Dizin ve dosya disk tüketim analizi"
ipa_cmd "/usr/sbin/hdparm"            "SATA/IDE disk parametre okuma ve hız testi (-tT)"
ipa_cmd "/usr/sbin/sdparm"            "SCSI/SAS disk parametre okuma ve yönetimi"
ipa_cmd "/usr/sbin/smartctl"          "Disk SMART sağlık testi, kısa/uzun test başlatma, log okuma"
ipa_cmd "/usr/bin/iostat"             "Disk I/O ve CPU kullanım istatistikleri (sysstat paketi)"
ipa_cmd "/usr/bin/iotop"              "Process bazında anlık disk I/O aktivitesi izleme"
ipa_cmd "/usr/bin/fio"                "Disk okuma/yazma performans kıyaslama ve benchmark aracı"
ipa_cmd "/usr/bin/ioping"             "Disk I/O gecikme (latency) ölçüm aracı"

# LVM yönetimi
ipa_cmd "/usr/sbin/pvcreate"          "LVM: Fiziksel birim (PV) oluşturma"
ipa_cmd "/usr/sbin/pvdisplay"         "LVM: Fiziksel birim detaylı bilgisi görüntüleme"
ipa_cmd "/usr/sbin/pvremove"          "LVM: Fiziksel birimi LVM sisteminden kaldırma"
ipa_cmd "/usr/sbin/pvmove"            "LVM: Fiziksel birimler arası extent veri taşıma"
ipa_cmd "/usr/sbin/pvresize"          "LVM: Fiziksel birimi yeniden boyutlandırma"
ipa_cmd "/usr/sbin/pvs"               "LVM: Fiziksel birim özet listesi"
ipa_cmd "/usr/sbin/pvscan"            "LVM: Sistemdeki fiziksel birimleri tarama"
ipa_cmd "/usr/sbin/vgcreate"          "LVM: Birim grubu (VG) oluşturma"
ipa_cmd "/usr/sbin/vgdisplay"         "LVM: Birim grubu detaylı bilgisi görüntüleme"
ipa_cmd "/usr/sbin/vgextend"          "LVM: Birim grubuna yeni PV ekleme"
ipa_cmd "/usr/sbin/vgreduce"          "LVM: Birim grubundan PV çıkarma"
ipa_cmd "/usr/sbin/vgremove"          "LVM: Birim grubunu tamamen silme"
ipa_cmd "/usr/sbin/vgrename"          "LVM: Birim grubunu yeniden adlandırma"
ipa_cmd "/usr/sbin/vgs"               "LVM: Birim grubu özet listesi"
ipa_cmd "/usr/sbin/vgscan"            "LVM: Sistemdeki birim gruplarını tarama"
ipa_cmd "/usr/sbin/vgchange"          "LVM: Birim grubu özellik değişikliği (activate/deactivate)"
ipa_cmd "/usr/sbin/lvcreate"          "LVM: Mantıksal birim (LV) oluşturma"
ipa_cmd "/usr/sbin/lvdisplay"         "LVM: Mantıksal birim detaylı bilgisi görüntüleme"
ipa_cmd "/usr/sbin/lvextend"          "LVM: Mantıksal birimi büyütme"
ipa_cmd "/usr/sbin/lvreduce"          "LVM: Mantıksal birimi küçültme (veri kaybı riski var)"
ipa_cmd "/usr/sbin/lvremove"          "LVM: Mantıksal birimi silme"
ipa_cmd "/usr/sbin/lvrename"          "LVM: Mantıksal birimi yeniden adlandırma"
ipa_cmd "/usr/sbin/lvresize"          "LVM: Mantıksal birimi büyütme veya küçültme"
ipa_cmd "/usr/sbin/lvs"               "LVM: Mantıksal birim özet listesi"
ipa_cmd "/usr/sbin/lvscan"            "LVM: Sistemdeki mantıksal birimleri tarama"
ipa_cmd "/usr/sbin/lvchange"          "LVM: Mantıksal birim özellik değişikliği (activate/permissions)"
ipa_cmd "/usr/sbin/lvconvert"         "LVM: LV türü dönüştürme (thin/mirror/cache/snapshot)"
ipa_cmd "/usr/sbin/lvm"               "LVM: Genel yönetim arayüzü (tüm lvm alt komutları)"

# Stratis ve RAID
ipa_cmd "/usr/bin/stratis"            "Stratis: Modern depolama katmanı (pool/filesystem/blockdev) yönetimi"
ipa_cmd "/usr/sbin/mdadm"             "Linux yazılım RAID (md): oluşturma/yönetme/izleme/onarım"


# =============================================================================
#  BÖLÜM 3 - DOSYA SİSTEMİ YÖNETİMİ
#  Grup: sysadmin_filesystem_mgmt
# =============================================================================
section "BÖLÜM 3 - DOSYA SİSTEMİ YÖNETİMİ KOMUTLARI"

ipa_cmd "/usr/sbin/mkfs"              "Genel dosya sistemi biçimlendirme"
ipa_cmd "/usr/sbin/mkfs.ext4"         "EXT4 dosya sistemi oluşturma"
ipa_cmd "/usr/sbin/mkfs.ext3"         "EXT3 dosya sistemi oluşturma"
ipa_cmd "/usr/sbin/mkfs.xfs"          "XFS dosya sistemi oluşturma"
ipa_cmd "/usr/sbin/mkfs.btrfs"        "Btrfs dosya sistemi oluşturma"
ipa_cmd "/usr/sbin/mkfs.vfat"         "FAT32 dosya sistemi oluşturma (USB/EFI bölümü için)"
ipa_cmd "/usr/sbin/mkfs.ntfs"         "NTFS dosya sistemi oluşturma"
ipa_cmd "/usr/sbin/mkswap"            "Swap alanı oluşturma"
ipa_cmd "/usr/sbin/swapon"            "Swap alanını/dosyasını etkinleştirme"
ipa_cmd "/usr/sbin/swapoff"           "Swap alanını devre dışı bırakma"
ipa_cmd "/usr/bin/mount"              "Dosya sistemi bağlama (--bind, -o options desteği)"
ipa_cmd "/usr/bin/umount"             "Dosya sistemi bağlantısını güvenli kesme"
ipa_cmd "/usr/sbin/tune2fs"           "EXT2/3/4 parametreleri: label, UUID, reserved-blocks, fsck-interval"
ipa_cmd "/usr/sbin/dumpe2fs"          "EXT2/3/4 süper blok ve grup tanımlayıcı bilgilerini dump etme"
ipa_cmd "/usr/sbin/debugfs"           "EXT dosya sistemi düşük seviye debug ve veri kurtarma"
ipa_cmd "/usr/sbin/e2fsck"            "EXT2/3/4 dosya sistemi denetimi ve otomatik onarım"
ipa_cmd "/usr/sbin/fsck"              "Genel dosya sistemi denetim aracı"
ipa_cmd "/usr/sbin/xfs_repair"        "XFS dosya sistemi onarım aracı"
ipa_cmd "/usr/sbin/xfs_info"          "Bağlı XFS dosya sistemi geometri bilgisi görüntüleme"
ipa_cmd "/usr/sbin/xfs_admin"         "XFS dosya sistemi parametrelerini değiştirme (label, UUID)"
ipa_cmd "/usr/sbin/xfs_db"            "XFS debug aracı: inode/blok/superblock inceleme"
ipa_cmd "/usr/sbin/xfs_freeze"        "XFS dosya sistemini dondurma/çözme (canlı snapshot için)"
ipa_cmd "/usr/sbin/resize2fs"         "EXT2/3/4 dosya sistemini canlı büyütme/küçültme"
ipa_cmd "/usr/sbin/xfs_growfs"        "XFS dosya sistemini canlı büyütme"
ipa_cmd "/usr/sbin/btrfs"             "Btrfs: subvolume/snapshot/quota/balance/scrub/device yönetimi"
ipa_cmd "/usr/bin/findmnt"            "Bağlı dosya sistemlerini hiyerarşik listeleme"
ipa_cmd "/usr/bin/lsattr"             "EXT dosya sistemi genişletilmiş özelliklerini listeleme"
ipa_cmd "/usr/bin/chattr"             "EXT dosya sistemi özelliklerini ayarlama (immutable, append-only)"
ipa_cmd "/usr/bin/setfacl"            "POSIX ACL erişim kontrol listesi ayarlama"
ipa_cmd "/usr/bin/getfacl"            "POSIX ACL erişim kontrol listesi görüntüleme"
ipa_cmd "/usr/bin/chown"              "Dosya/dizin sahipliği ve grubu değiştirme"
ipa_cmd "/usr/bin/chmod"              "Dosya/dizin erişim izinlerini değiştirme"
ipa_cmd "/usr/bin/cp"                 "Dosya/dizin kopyalama (-a: archive modu, -p: izin koru)"
ipa_cmd "/usr/bin/mv"                 "Dosya/dizin taşıma veya yeniden adlandırma"
ipa_cmd "/usr/bin/rm"                 "Dosya/dizin silme (-rf: rekürsif silme)"
ipa_cmd "/usr/bin/mkdir"              "Dizin ve alt dizin yapısı oluşturma (-p)"
ipa_cmd "/usr/bin/rsync"              "Hızlı artımlı dosya/dizin eşitleme ve yedekleme"
ipa_cmd "/usr/bin/tar"                "Arşiv oluşturma/çıkarma (gzip/bzip2/xz sıkıştırma destekli)"
ipa_cmd "/usr/bin/dd"                 "Ham veri kopyalama: disk imaj alma/yazma, benchmark"
ipa_cmd "/usr/bin/truncate"           "Dosya boyutunu belirtilen değere ayarlama"
ipa_cmd "/usr/bin/fallocate"          "Disk bloklarını önceden ayırma (swap dosyası, büyük dosya)"
ipa_cmd "/usr/sbin/quotacheck"        "Dosya sistemi disk kota veritabanı denetimi"
ipa_cmd "/usr/sbin/quotaon"           "Dosya sistemi disk kotasını etkinleştirme"
ipa_cmd "/usr/sbin/quotaoff"          "Dosya sistemi disk kotasını devre dışı bırakma"
ipa_cmd "/usr/sbin/edquota"           "Kullanıcı/grup disk kota soft/hard limitlerini düzenleme"
ipa_cmd "/usr/sbin/repquota"          "Disk kota kullanım raporunu görüntüleme"


# =============================================================================
#  BÖLÜM 4 - NETWORK YÖNETİMİ
#  Grup: sysadmin_network_mgmt
# =============================================================================
section "BÖLÜM 4 - NETWORK YÖNETİMİ KOMUTLARI"

# Arayüz ve adres yönetimi
ipa_cmd "/usr/sbin/ip"                "Linux IP: addr/link/route/rule/neigh/netns tam yönetimi"
ipa_cmd "/usr/sbin/ifconfig"          "Network arayüz yapılandırması (eski, net-tools paketi)"
ipa_cmd "/usr/sbin/iwconfig"          "Kablosuz network arayüz yapılandırması"
ipa_cmd "/usr/sbin/iwlist"            "Kablosuz ağları tarama ve bant bilgisi listeleme"
ipa_cmd "/usr/bin/nmcli"              "NetworkManager: bağlantı/aygıt/wifi/profil tam yönetimi"
ipa_cmd "/usr/bin/nmtui"              "NetworkManager metin tabanlı etkileşimli yapılandırma arayüzü"
ipa_cmd "/usr/sbin/dhclient"          "DHCP istemci: IP adresi alma/yenileme/bırakma"
ipa_cmd "/usr/sbin/ethtool"           "Ethernet NIC: hız/duplex/offload/ring-buffer/istatistik yönetimi"
ipa_cmd "/usr/sbin/mii-tool"          "NIC MII bağlantı durumu ve hız/duplex görüntüleme"
ipa_cmd "/usr/sbin/ifenslave"         "NIC bonding (LACP/active-backup) arayüz yönetimi"
ipa_cmd "/usr/sbin/brctl"             "Ethernet bridge oluşturma ve STP yönetimi"
ipa_cmd "/usr/sbin/bridge"            "Gelişmiş bridge ve VLAN yönetimi (ip bridge alternatifi)"

# Güvenlik duvarı
ipa_cmd "/usr/sbin/iptables"          "IPv4 paket filtreleme: ACCEPT/DROP/REJECT/LOG/MASQUERADE kuralları"
ipa_cmd "/usr/sbin/iptables-save"     "Aktif iptables kurallarını dosyaya kaydetme"
ipa_cmd "/usr/sbin/iptables-restore"  "Kaydedilmiş iptables kurallarını yükleme"
ipa_cmd "/usr/sbin/ip6tables"         "IPv6 paket filtreleme kuralları yönetimi"
ipa_cmd "/usr/sbin/nft"               "nftables: modern Linux güvenlik duvarı kural yönetimi"
ipa_cmd "/usr/bin/firewall-cmd"       "Firewalld: zone/service/port/rich-rule/masquerade yönetimi"

# Paket analizi ve diagnostik
ipa_cmd "/usr/sbin/tcpdump"           "Network paket yakalama: protocol/host/port filtre desteği"
ipa_cmd "/usr/bin/tshark"             "Wireshark komut satırı: detaylı protocol dissection analizi"
ipa_cmd "/usr/bin/nmap"               "Network keşif: port/OS/servis/güvenlik açığı taraması"
ipa_cmd "/usr/bin/ncat"               "Nmap Netcat: TCP/UDP/SSL bağlantı testi ve port dinleme"
ipa_cmd "/usr/bin/nc"                 "Netcat: TCP/UDP port testi ve basit veri aktarımı"
ipa_cmd "/usr/bin/socat"              "Çift yönlü veri köprüsü: TCP/UDP/UNIX/TLS socket relay"
ipa_cmd "/usr/bin/netstat"            "Network bağlantı, route tablosu ve soket istatistikleri"
ipa_cmd "/usr/bin/ss"                 "Soket istatistikleri: TCP durumu/process/buffer/timer bilgisi"
ipa_cmd "/usr/sbin/route"             "IP yönlendirme tablosu görüntüleme ve yönetimi (eski)"
ipa_cmd "/usr/sbin/arp"               "ARP tablosu görüntüleme ve statik ARP girişi yönetimi"
ipa_cmd "/usr/sbin/arping"            "ARP isteği ile host keşfi ve MAC adresi tespiti"
ipa_cmd "/usr/bin/ping"               "ICMP echo isteği ile bağlantı ve gecikme testi"
ipa_cmd "/usr/bin/ping6"              "IPv6 ICMP echo bağlantı ve gecikme testi"
ipa_cmd "/usr/bin/traceroute"         "Paket rotasını ve her hop gecikmesini izleme"
ipa_cmd "/usr/bin/tracepath"          "Path MTU keşfi ile paket yolunu izleme"
ipa_cmd "/usr/bin/mtr"                "Kombinasyonlu traceroute+ping gerçek zamanlı ağ diagnostiği"
ipa_cmd "/usr/bin/iperf3"             "TCP/UDP ağ bant genişliği ve throughput ölçümü"

# DNS ve ad çözümleme
ipa_cmd "/usr/bin/dig"                "DNS sorgusu: A/MX/NS/SOA/TXT/AAAA/ANY kayıt analizi"
ipa_cmd "/usr/bin/nslookup"           "DNS sorgulama ve ters DNS çözümleme"
ipa_cmd "/usr/bin/host"               "DNS kayıt sorgulama ve ters DNS kontrolü"
ipa_cmd "/usr/bin/whois"              "Domain ve IP WHOIS kayıt sorgulama"
ipa_cmd "/usr/sbin/nscd"              "Name Service Cache Daemon yeniden başlatma ve önbellek temizleme"

# İndirme ve aktarım
ipa_cmd "/usr/bin/curl"               "HTTP/HTTPS/FTP veri transferi, REST API testi, header analizi"
ipa_cmd "/usr/bin/wget"               "HTTP/FTP dosya indirme, site mirroring desteği"
ipa_cmd "/usr/bin/scp"                "SSH üzerinden güvenli dosya kopyalama"
ipa_cmd "/usr/bin/sftp"               "SSH üzerinden güvenli dosya transfer protokolü istemcisi"

# Sistem network parametreleri
ipa_cmd "/usr/sbin/sysctl"            "Kernel parametrelerini okuma/yazma: net.ipv4.*/vm.*/kernel.*"


# =============================================================================
#  BÖLÜM 5 - İŞLEMCİ VE PROCESS YÖNETİMİ
#  Grup: sysadmin_cpu_process_mgmt
# =============================================================================
section "BÖLÜM 5 - İŞLEMCİ VE PROCESS YÖNETİMİ KOMUTLARI"

# Process izleme
ipa_cmd "/usr/bin/top"                "Anlık CPU/Memory/Process kaynak kullanımı etkileşimli izleme"
ipa_cmd "/usr/bin/htop"               "Gelişmiş etkileşimli process yöneticisi (tree/filter/sort)"
ipa_cmd "/usr/bin/atop"               "CPU/Memory/Disk/Net kaynaklarını process bazında izleme ve kayıt"
ipa_cmd "/usr/bin/btop"               "Modern kaynak izleme aracı (grafiksel terminal UI)"
ipa_cmd "/usr/bin/glances"            "Web arayüzlü kapsamlı sistem izleme aracı"
ipa_cmd "/usr/bin/ps"                 "Anlık process listesi: -aux, -ef, --forest, -o format"
ipa_cmd "/usr/bin/pstree"             "Process hiyerarşisini ağaç görünümünde gösterme"
ipa_cmd "/usr/bin/pidstat"            "Process bazında CPU/Memory/IO/context-switch istatistikleri"

# Process kontrol
ipa_cmd "/usr/bin/kill"               "PID'e sinyal gönderme: SIGTERM/SIGKILL/SIGHUP/SIGUSR1/SIGUSR2"
ipa_cmd "/usr/bin/killall"            "İsme göre tüm eşleşen processleri sonlandırma"
ipa_cmd "/usr/bin/pkill"              "Pattern/user/group kriterine göre process sonlandırma"
ipa_cmd "/usr/bin/pgrep"              "Kritere göre PID arama ve listeleme"
ipa_cmd "/usr/bin/nice"               "Belirtilen nice önceliği (-20..+19) ile process başlatma"
ipa_cmd "/usr/bin/renice"             "Çalışan process nice önceliğini dinamik olarak değiştirme"

# CPU afinite ve zamanlayıcı
ipa_cmd "/usr/bin/taskset"            "Process CPU afinitesi: belirli çekirdeklere sabitleme/okuma"
ipa_cmd "/usr/bin/chrt"               "Gerçek zamanlı zamanlama politikası: FIFO/RR/BATCH/IDLE"
ipa_cmd "/usr/bin/ionice"             "Process I/O zamanlama sınıfı: idle/best-effort/realtime"
ipa_cmd "/usr/bin/numactl"            "NUMA node CPU ve bellek afinite politikası atama"
ipa_cmd "/usr/bin/numastat"           "NUMA istatistikleri: node başına bellek erişim dağılımı"

# CPU bilgisi ve performans
ipa_cmd "/usr/bin/lscpu"              "CPU mimari: core/thread/cache/NUMA/frequency/flag bilgisi"
ipa_cmd "/usr/bin/mpstat"             "CPU core başına kullanım istatistikleri (sysstat paketi)"
ipa_cmd "/usr/bin/vmstat"             "Sanal bellek, CPU, I/O, bağlam değiştirme istatistikleri"
ipa_cmd "/usr/bin/sar"                "Geçmiş sistem aktivite raporu: CPU/memory/io/network analizi"
ipa_cmd "/usr/bin/nproc"              "Kullanılabilir logical CPU sayısını gösterme"
ipa_cmd "/usr/bin/cpupower"           "CPU frekans ölçeklendirme ve güç durumu yönetimi"
ipa_cmd "/usr/sbin/tuned-adm"         "Sistem performans profili: throughput/latency/powersave/balanced"
ipa_cmd "/usr/bin/stress-ng"          "CPU/Memory/I/O/Network stres ve kararlılık testi"
ipa_cmd "/usr/bin/sysbench"           "CPU/Memory/Disk/Database kıyaslama ve benchmark aracı"

# Cgroup ve kaynak limitleri
ipa_cmd "/usr/bin/cgset"              "Cgroup parametrelerini ayarlama (cpu.shares, memory.limit_in_bytes)"
ipa_cmd "/usr/bin/cgget"              "Cgroup parametrelerini okuma"
ipa_cmd "/usr/bin/cgcreate"           "Cgroup hiyerarşisi oluşturma"
ipa_cmd "/usr/bin/cgdelete"           "Cgroup hiyerarşisi silme"
ipa_cmd "/usr/bin/prlimit"            "Process kaynak limitlerini görüntüleme/değiştirme (ulimit gibi)"


# =============================================================================
#  BÖLÜM 6 - LOG ANALİZİ
#  Grup: sysadmin_log_analysis
# =============================================================================
section "BÖLÜM 6 - LOG ANALİZİ KOMUTLARI"

ipa_cmd "/usr/bin/journalctl"         "Journal: -u servis -p öncelik --since --until --follow filtreleri"
ipa_cmd "/usr/bin/tail"               "Dosya sonunu okuma (-f: canlı log takibi, -n: satır sayısı)"
ipa_cmd "/usr/bin/head"               "Dosya başını belirtilen satır sayısı kadar okuma"
ipa_cmd "/usr/bin/grep"               "Metin arama: -i/-r/-l/-n/-A/-B/-C context ve renk desteği"
ipa_cmd "/usr/bin/egrep"              "Genişletilmiş regex ile çoklu kalıp arama"
ipa_cmd "/usr/bin/zgrep"              "Sıkıştırılmış (.gz) log dosyalarında regex arama"
ipa_cmd "/usr/bin/zcat"               "Gzip sıkıştırılmış log dosyasını açmadan okuma"
ipa_cmd "/usr/bin/bzcat"              "bzip2 sıkıştırılmış log dosyasını açmadan okuma"
ipa_cmd "/usr/bin/xzcat"              "xz sıkıştırılmış log dosyasını açmadan okuma"
ipa_cmd "/usr/bin/awk"                "Log analiz programlama dili: sütun ayırma, toplama, koşullu işlem"
ipa_cmd "/usr/bin/sed"                "Akış düzenleyici: log dönüştürme, arama-değiştirme, filtreleme"
ipa_cmd "/usr/bin/cut"                "Sütun/karakter tabanlı veri kesme ve ayırma"
ipa_cmd "/usr/bin/sort"               "Log satırlarını sıralama (-k: alan, -n: sayısal, -r: ters, -u: teksizsiz)"
ipa_cmd "/usr/bin/uniq"               "Tekrarlanan satırları kaldırma (-c: frekans sayımı)"
ipa_cmd "/usr/bin/wc"                 "Satır/kelime/byte sayımı (hata frekansı tespiti için)"
ipa_cmd "/usr/bin/less"               "Büyük log dosyalarını sayfalı okuma (arama ve navigation desteği)"
ipa_cmd "/usr/bin/more"               "Log dosyasını sayfa sayfa görüntüleme"
ipa_cmd "/usr/bin/cat"                "Dosya içeriği görüntüleme ve birleştirme"
ipa_cmd "/usr/bin/tac"                "Dosya satırlarını ters sırada (sondan başa) görüntüleme"
ipa_cmd "/usr/bin/nl"                 "Satır numarası ekleyerek dosya görüntüleme"
ipa_cmd "/usr/bin/dmesg"              "Kernel ring buffer: donanım hataları, sürücü mesajları, boot logları"
ipa_cmd "/usr/bin/last"               "Kullanıcı oturum geçmişi (/var/log/wtmp analizi)"
ipa_cmd "/usr/bin/lastlog"            "Her kullanıcının son başarılı giriş zaman ve konum bilgisi"
ipa_cmd "/usr/bin/lastb"              "Başarısız SSH/login denemeleri (/var/log/btmp analizi)"
ipa_cmd "/usr/bin/who"                "Aktif oturumları ve giriş zaman/terminal bilgisi"
ipa_cmd "/usr/bin/w"                  "Aktif kullanıcılar ve yürüttükleri komut/kaynak kullanımı"
ipa_cmd "/usr/sbin/ausearch"          "Audit log arama: kullanıcı/dosya/sistem çağrısı/zaman filtresi"
ipa_cmd "/usr/sbin/aureport"          "Audit olay özet raporu: giriş/dosya/exec/avc istatistikleri"
ipa_cmd "/usr/sbin/auditctl"          "Audit kural yönetimi: dosya izleme, sistem çağrısı kaydı"
ipa_cmd "/usr/bin/logwatch"           "Günlük log özet raporu otomatik üretimi"
ipa_cmd "/usr/bin/multitail"          "Birden fazla log dosyasını eş zamanlı renk kodlu takip"
ipa_cmd "/usr/bin/lnav"               "Log dosyaları için terminal tabanlı gezgin ve analiz aracı"
ipa_cmd "/usr/sbin/logrotate"         "Log döndürme kurallarını manuel uygulama ve test etme"


# =============================================================================
#  BÖLÜM 7 - UYGULAMA ANALİZİ
#  (Kaynak kullanımı, Library, RAM, Memory Leak, Profiling)
#  Grup: sysadmin_app_analysis
# =============================================================================
section "BÖLÜM 7 - UYGULAMA ANALİZİ KOMUTLARI"

# Library ve bağımlılık analizi
ipa_cmd "/usr/bin/ldd"                "Uygulamanın dinamik kütüphane (shared library) bağımlılıklarını listeleme"
ipa_cmd "/usr/sbin/ldconfig"          "Dinamik kütüphane önbelleğini yenileme (/etc/ld.so.cache güncelleme)"
ipa_cmd "/usr/bin/ltrace"             "Uygulama kütüphane çağrılarını (libc/özel lib) gerçek zamanlı izleme"
ipa_cmd "/usr/bin/strace"             "Sistem çağrılarını izleme: açık dosyalar, network, sinyal, hata debug"
ipa_cmd "/usr/bin/pmap"               "Process bellek haritası: kütüphane, heap, stack, anonim segment boyutları"
ipa_cmd "/usr/bin/lsof"               "Açık dosya/soket/kütüphane/pipe listesi (process bazında)"
ipa_cmd "/usr/bin/objdump"            "ELF binary disassemble, section analizi ve debug bilgisi"
ipa_cmd "/usr/bin/nm"                 "Binary/kütüphane sembol tablosu: fonksiyon ve değişken isimleri"
ipa_cmd "/usr/bin/readelf"            "ELF başlık, section, program header, dinamik bağlantı bilgisi"
ipa_cmd "/usr/bin/strings"            "Binary dosyasındaki okunabilir metin dizilerini çıkarma"
ipa_cmd "/usr/bin/file"               "Dosya türü tespiti: ELF/shared-lib/script/encoding/magic byte"
ipa_cmd "/usr/bin/eu-stack"           "Elfutils: çalışan process stack trace görüntüleme (gdb alternatifi)"
ipa_cmd "/usr/bin/eu-nm"              "Elfutils: gelişmiş sembol tablosu analizi"
ipa_cmd "/usr/bin/eu-objdump"         "Elfutils: gelişmiş binary disassemble ve annotation"

# Memory analizi ve leak tespiti
ipa_cmd "/usr/bin/valgrind"           "Memory leak, invalid read/write, use-after-free, double-free tespiti"
ipa_cmd "/usr/bin/ms_print"           "Valgrind Massif heap profiler çıktısını okunabilir raporlama"
ipa_cmd "/usr/bin/smem"               "Paylaşımlı bellek dahil gerçek RSS/PSS/USS kullanım analizi"
ipa_cmd "/usr/bin/memusage"           "Uygulama heap/stack bellek kullanım profili oluşturma"
ipa_cmd "/usr/bin/heaptrack"          "Heap bellek ayırma takibi ve memory leak analizi"
ipa_cmd "/usr/bin/heaptrack_print"    "Heaptrack sonuçlarını analiz ve raporlama"
ipa_cmd "/usr/bin/mtrace"             "GNU C kütüphanesi malloc/free çağrı izleme (leak tespiti)"

# Performans profiling
ipa_cmd "/usr/bin/perf"               "Linux perf: CPU sayaçları, cache miss, branch misprediction analizi"
ipa_cmd "/usr/bin/gprof"              "GNU profiler: fonksiyon çağrı grafiği ve süre dağılımı analizi"
ipa_cmd "/usr/bin/gdb"                "GNU Debugger: canlı process debug, core dump analizi, backtrace"
ipa_cmd "/usr/bin/addr2line"          "Bellek adresini kaynak kod dosyası/satır numarasına çevirme"
ipa_cmd "/usr/bin/stap"               "SystemTap: dinamik kernel/userspace profiling script çalıştırma"
ipa_cmd "/usr/bin/bpftrace"           "eBPF tabanlı dinamik izleme: latency histogramı, flame graph, trace"
ipa_cmd "/usr/bin/flamegraph.pl"      "Perf/stack verilerinden interaktif SVG flame graph oluşturma"

# BCC eBPF araçları
ipa_cmd "/usr/share/bcc/tools/execsnoop"    "BCC: Yeni başlatılan processleri gerçek zamanlı izleme"
ipa_cmd "/usr/share/bcc/tools/opensnoop"    "BCC: Açılan dosyaları gerçek zamanlı izleme (hangi process hangisini açıyor)"
ipa_cmd "/usr/share/bcc/tools/biolatency"   "BCC: Blok I/O gecikme dağılımı histogramı"
ipa_cmd "/usr/share/bcc/tools/tcpconnect"   "BCC: Aktif TCP bağlantılarını gerçek zamanlı izleme"
ipa_cmd "/usr/share/bcc/tools/tcpaccept"    "BCC: Kabul edilen TCP bağlantılarını izleme"
ipa_cmd "/usr/share/bcc/tools/runqlat"      "BCC: CPU çalıştırma kuyruğu gecikme histogramı (scheduler latency)"
ipa_cmd "/usr/share/bcc/tools/profile"      "BCC: CPU profiling - stack trace örnekleme ve hot path analizi"
ipa_cmd "/usr/share/bcc/tools/memleak"      "BCC: Kernel ve userspace memory leak gerçek zamanlı tespiti"
ipa_cmd "/usr/share/bcc/tools/funccount"    "BCC: Kernel/userspace fonksiyon çağrı frekansı sayma"
ipa_cmd "/usr/share/bcc/tools/funclatency"  "BCC: Fonksiyon çağrı gecikme dağılımı analizi"
ipa_cmd "/usr/share/bcc/tools/cachestat"    "BCC: Dosya sistemi buffer cache hit/miss istatistikleri"
ipa_cmd "/usr/share/bcc/tools/cpudist"      "BCC: Process CPU kullanım süresi dağılım histogramı"


# =============================================================================
#  BÖLÜM 8 - SİSTEM YAPILANDIRMA VE GÜNCELLEME
#  Grup: sysadmin_system_config
# =============================================================================
section "BÖLÜM 8 - SİSTEM YAPILANDIRMA VE GÜNCELLEME KOMUTLARI"

# Paket yönetimi
ipa_cmd "/usr/bin/dnf"                "RHEL/CentOS/Fedora: paket kurma/kaldırma/güncelleme/history"
ipa_cmd "/usr/bin/yum"                "Eski RHEL/CentOS paket yöneticisi (RHEL7 ve öncesi)"
ipa_cmd "/usr/bin/rpm"                "RPM: paket kurma/kaldırma/sorgulama/doğrulama (-Va integrity)"
ipa_cmd "/usr/bin/apt"                "Debian/Ubuntu: paket kurma/kaldırma/güncelleme"
ipa_cmd "/usr/bin/apt-get"            "Debian/Ubuntu gelişmiş paket kurulum ve bağımlılık yöneticisi"
ipa_cmd "/usr/bin/apt-cache"          "Debian/Ubuntu paket önbelleği arama ve bilgi sorgulama"
ipa_cmd "/usr/bin/dpkg"               "Debian düşük seviye: paket kurma/kaldırma/sorgulama/reconfigure"
ipa_cmd "/usr/bin/snap"               "Snap evrensel paket yöneticisi"
ipa_cmd "/usr/bin/flatpak"            "Flatpak sandbox paket yöneticisi"
ipa_cmd "/usr/sbin/update-alternatives" "Alternatif uygulama sürüm seçimi ve sembolik link yönetimi"

# Sistem yapılandırma
ipa_cmd "/usr/bin/hostnamectl"        "Sistem hostname: static/transient/pretty isim ayarlama"
ipa_cmd "/usr/bin/localectl"          "Sistem locale ve konsol klavye düzeni ayarları"
ipa_cmd "/usr/bin/crontab"            "Zamanlanmış görev (cron job) oluşturma, listeleme ve silme"
ipa_cmd "/usr/bin/at"                 "Tek seferlik zamanlı komut çalıştırma"
ipa_cmd "/usr/sbin/anacron"           "Kaçırılan periyodik görevleri güvenli çalıştırma"
ipa_cmd "/usr/bin/tee"                "Pipe çıktısını hem ekrana hem dosyaya yazma (/proc/sys/* için)"

# SELinux yönetimi
ipa_cmd "/usr/sbin/semanage"          "SELinux: port/fcontext/user/boolean politika kalıcı yönetimi"
ipa_cmd "/usr/sbin/setenforce"        "SELinux çalışma modunu Enforcing/Permissive olarak ayarlama"
ipa_cmd "/usr/sbin/setsebool"         "SELinux boolean değerini açma/kapama (-P: kalıcı)"
ipa_cmd "/usr/sbin/restorecon"        "Dosya/dizin SELinux güvenlik bağlamını varsayılana döndürme"
ipa_cmd "/usr/bin/chcon"              "Dosya SELinux bağlamını geçici olarak değiştirme"
ipa_cmd "/usr/sbin/getenforce"        "Mevcut SELinux çalışma modunu görüntüleme"
ipa_cmd "/usr/bin/sestatus"           "SELinux durum, politika adı ve boolean değerlerini görüntüleme"
ipa_cmd "/usr/bin/audit2allow"        "SELinux red (AVC denied) loglarından politika modülü oluşturma"

# AppArmor yönetimi
ipa_cmd "/usr/bin/aa-status"          "AppArmor profil yükleme ve çalışma durumunu görüntüleme"
ipa_cmd "/usr/sbin/aa-enforce"        "AppArmor profilini enforcing moda alma"
ipa_cmd "/usr/sbin/aa-complain"       "AppArmor profilini complain (yalnızca log) moda alma"

# Önyükleyici yönetimi
ipa_cmd "/usr/sbin/grubby"            "GRUB: varsayılan kernel, kernel argümanı ekleme/kaldırma"
ipa_cmd "/usr/sbin/grub2-mkconfig"    "GRUB2: yapılandırma dosyasını yeniden oluşturma"
ipa_cmd "/usr/sbin/update-grub"       "Debian/Ubuntu: GRUB yapılandırmasını güncelleme"
ipa_cmd "/usr/sbin/dracut"            "initramfs imajı oluşturma (yeni kernel/modül/sürücü eklenince)"
ipa_cmd "/usr/sbin/mkinitrd"          "Initial ramdisk imajı oluşturma (eski RHEL/CentOS)"

# Sistem yeniden başlatma
ipa_cmd "/usr/sbin/reboot"            "Sistemi yeniden başlatma"
ipa_cmd "/usr/sbin/shutdown"          "Sistemi zamanla kapatma veya yeniden başlatma"
ipa_cmd "/usr/sbin/halt"              "Sistemi durdurma"
ipa_cmd "/usr/sbin/poweroff"          "Sistemi güvenli kapatma ve güç kesme"

# Kimlik doğrulama yapılandırması
ipa_cmd "/usr/bin/authselect"         "Kimlik doğrulama profili seçme (RHEL8+): sssd/winbind/nis"
ipa_cmd "/usr/sbin/authconfig"        "Kimlik doğrulama ve LDAP ayarları yapılandırması (RHEL7)"
ipa_cmd "/usr/sbin/sss_cache"         "SSSD önbelleğini geçersiz kılma (kullanıcı/grup değişikliği sonrası)"


# =============================================================================
#  BÖLÜM 9 - DİSK ŞİFRELEME
#  Grup: sysadmin_disk_encryption
# =============================================================================
section "BÖLÜM 9 - DİSK ŞİFRELEME KOMUTLARI"

ipa_cmd "/usr/sbin/cryptsetup"        "LUKS: şifreli birim oluşturma/açma/kapatma/başlık dump"
ipa_cmd "/usr/sbin/cryptsetup-reencrypt" "LUKS: canlı şifre algoritması ve anahtar yenileme"
ipa_cmd "/usr/bin/clevis"             "Clevis: LUKS otomatik kilit açma (Tang/TPM2 politikası)"
ipa_cmd "/usr/bin/clevis-luks-bind"   "LUKS birimi Clevis politikasına (Tang/TPM2) bağlama"
ipa_cmd "/usr/bin/clevis-luks-unbind" "LUKS birimini Clevis politikasından kaldırma"
ipa_cmd "/usr/sbin/veritysetup"       "dm-verity: blok aygıt bütünlük doğrulama kurulumu ve kontrolü"
ipa_cmd "/usr/bin/gpg"                "GPG: anahtar oluşturma, dosya şifreleme/imzalama, anahtar deposu"
ipa_cmd "/usr/bin/gpg2"               "GPG2: OpenPGP gelişmiş şifreleme ve anahtar yönetimi"
ipa_cmd "/usr/bin/openssl"            "OpenSSL: sertifika/anahtar üretimi, şifreleme, hash, SSL test"
ipa_cmd "/usr/bin/mokutil"            "UEFI Secure Boot MOK anahtar kayıt, listeleme ve silme"


# =============================================================================
#  BÖLÜM 10 - DONANIM YÖNETİMİ
#  Grup: sysadmin_hardware_mgmt
# =============================================================================
section "BÖLÜM 10 - DONANIM YÖNETİMİ KOMUTLARI"

# Donanım bilgisi
ipa_cmd "/usr/sbin/lshw"              "Kapsamlı donanım envanteri: CPU/RAM/disk/PCI/USB/ağ detayı"
ipa_cmd "/usr/bin/lspci"              "PCI aygıt listesi: VGA/NIC/storage controller/kernel sürücü"
ipa_cmd "/usr/bin/lsusb"              "USB aygıt listesi ve device descriptor bilgisi"
ipa_cmd "/usr/bin/lsscsi"             "SCSI/SAS/SATA disk ve tape aygıtlarını listeleme"
ipa_cmd "/usr/bin/dmidecode"          "DMI/SMBIOS: BIOS/anakart/RAM/CPU/seri numarası bilgisi"
ipa_cmd "/usr/bin/hwinfo"             "Kapsamlı donanım tespiti ve atanan sürücü bilgisi"
ipa_cmd "/usr/bin/inxi"               "Sistem/donanım özet bilgisi (kolay okunur, renkli format)"

# Kernel modülleri
ipa_cmd "/usr/sbin/modprobe"          "Kernel modülünü bağımlılıkları ile birlikte akıllıca yükleme"
ipa_cmd "/usr/sbin/modinfo"           "Kernel modülü: yazar, sürüm, parametre ve bağımlılık bilgisi"
ipa_cmd "/usr/sbin/lsmod"             "Yüklü kernel modüllerini ve kullanım sayısını listeleme"
ipa_cmd "/usr/sbin/rmmod"             "Kernel modülünü bellekten kaldırma"
ipa_cmd "/usr/sbin/insmod"            "Kernel modülünü doğrudan yükleme (modprobe tercih edilmeli)"
ipa_cmd "/usr/sbin/depmod"            "Kernel modülü bağımlılık haritasını yenileme"

# Sensörler ve sıcaklık
ipa_cmd "/usr/bin/sensors"            "Donanım sensörleri: CPU/GPU sıcaklık, fan hızı, voltaj değerleri"
ipa_cmd "/usr/sbin/sensors-detect"    "Sisteme bağlı donanım sensörlerini otomatik algılama"
ipa_cmd "/usr/bin/ipmitool"           "IPMI/BMC: uzaktan güç/fan/sensör/SEL event log yönetimi"
ipa_cmd "/usr/bin/ipmi-sensors"       "FreeIPMI: IPMI sensör değerlerini listeleme ve eşik kontrolü"
ipa_cmd "/usr/bin/rasdaemon"          "RAS donanım hata izleme: ECC bellek ve MCE hataları"
ipa_cmd "/usr/bin/mcelog"             "Machine Check Exception CPU/memory donanım hata kayıt analizi"

# Aygıt yönetimi
ipa_cmd "/usr/sbin/udevadm"           "udev: kural tetikleme/test etme/yenileme, aygıt özellik sorgulama"
ipa_cmd "/usr/bin/fwupdmgr"           "LVFS: UEFI ve donanım firmware güncelleme yöneticisi"
ipa_cmd "/usr/sbin/i2cdetect"         "I2C veri yolu üzerindeki aygıtları tarama"
ipa_cmd "/usr/sbin/i2cget"            "I2C aygıtından register değeri okuma"
ipa_cmd "/usr/sbin/i2cset"            "I2C aygıtına register değeri yazma"


# =============================================================================
#  BÖLÜM 11 - KULLANICI YÖNETİMİ
#  Grup: sysadmin_user_mgmt
# =============================================================================
section "BÖLÜM 11 - KULLANICI YÖNETİMİ KOMUTLARI"

ipa_cmd "/usr/sbin/useradd"           "Yeni yerel kullanıcı: UID/GID/home/shell/gecos/expire ayarlama"
ipa_cmd "/usr/sbin/usermod"           "Mevcut kullanıcı: grup/shell/home/lock/expire/comment değiştirme"
ipa_cmd "/usr/sbin/userdel"           "Kullanıcı hesabını silme (-r: home ve mail dizini ile birlikte)"
ipa_cmd "/usr/sbin/groupadd"          "Yeni yerel grup oluşturma (GID belirterek)"
ipa_cmd "/usr/sbin/groupmod"          "Grup adı veya GID değiştirme"
ipa_cmd "/usr/sbin/groupdel"          "Yerel grubu silme"
ipa_cmd "/usr/sbin/gpasswd"           "Grup şifresi ve üyelik ekleme/kaldırma yönetimi"
ipa_cmd "/usr/bin/passwd"             "Kullanıcı şifresi değiştirme, kilitleme (-l) ve açma (-u)"
ipa_cmd "/usr/sbin/chpasswd"          "Toplu kullanıcı şifresi güncelleme (stdin veya dosyadan okuma)"
ipa_cmd "/usr/bin/chage"              "Şifre yaşlandırma: min/max gün, uyarı, etkisizleştirme tarihi"
ipa_cmd "/usr/bin/faillock"           "Başarısız giriş sayacı görüntüleme ve kilitli hesap açma"
ipa_cmd "/usr/sbin/pwck"              "/etc/passwd ve /etc/shadow dosyası bütünlük doğrulaması"
ipa_cmd "/usr/sbin/grpck"             "/etc/group dosyası tutarlılık ve bütünlük denetimi"
ipa_cmd "/usr/sbin/pwconv"            "Shadow password sistemine geçiş"
ipa_cmd "/usr/sbin/pwunconv"          "Shadow password sisteminden çıkış"
ipa_cmd "/usr/bin/id"                 "Kullanıcı UID/GID ve tüm grup üyeliklerini görüntüleme"
ipa_cmd "/usr/bin/groups"             "Kullanıcının üye olduğu grupları listeleme"
ipa_cmd "/usr/bin/su"                 "Başka kullanıcıya geçiş yapma (root HARIÇ kullanılabilir)"
ipa_cmd "/usr/sbin/visudo"            "Sudoers dosyasını sözdizimi doğrulamalı güvenli düzenleme"
ipa_cmd "/usr/bin/sudo"               "Başka kullanıcı (genellikle root) yetkisiyle komut çalıştırma"
ipa_cmd "/usr/sbin/sssd"              "SSSD servis yönetimi (LDAP/Kerberos/IPA kimlik doğrulama)"
ipa_cmd "/usr/bin/sssctl"             "SSSD domain, kullanıcı ve cache durumu yönetimi"
ipa_cmd "/usr/bin/getent"             "NSS veritabanı sorgulama: passwd/group/hosts/shadow kayıtları"


# =============================================================================
#  BÖLÜM 12 - GÜVENLİK ANALİZİ
#  Grup: sysadmin_security_analysis
# =============================================================================
section "BÖLÜM 12 - GÜVENLİK ANALİZİ KOMUTLARI"

ipa_cmd "/usr/bin/lynis"              "Sistem güvenlik denetimi ve CIS/PCI/ISO27001 uyumluluk analizi"
ipa_cmd "/usr/bin/rkhunter"           "Rootkit, backdoor, local exploit ve şüpheli dosya tespiti"
ipa_cmd "/usr/sbin/chkrootkit"        "Rootkit, trojan ve çekirnek bırakma (worm) tespit aracı"
ipa_cmd "/usr/bin/aide"               "AIDE: dosya sistemi bütünlüğü izleme ve değişiklik tespiti"
ipa_cmd "/usr/bin/oscap"              "OpenSCAP: OVAL/XCCDF güvenlik uyumluluk taraması ve remediation"
ipa_cmd "/usr/sbin/sysdig"            "Sistem çağrısı izleme: davranışsal analiz ve güvenlik forensics"
ipa_cmd "/usr/bin/sssctl"             "SSSD kullanıcı kimlik doğrulama ve domain durum denetimi"
ipa_cmd "/usr/sbin/fail2ban-client"   "Fail2ban: brute-force engelleme kuralı ve ban durumu yönetimi"
ipa_cmd "/usr/bin/clamscan"           "ClamAV antivirüs ile dosya/dizin taraması"
ipa_cmd "/usr/bin/freshclam"          "ClamAV virüs imza veritabanını güncelleme"
ipa_cmd "/usr/bin/ss_audit"           "Açık port ve dinleyen servis güvenlik denetimi (ss ile)"
ipa_cmd "/usr/bin/nmap_audit"         "Lokal sistem güvenlik açığı ve port taraması (nmap ile)"


# =============================================================================
#  BÖLÜM 13 - YEDEKLEME VE KURTARMA
#  Grup: sysadmin_backup_recovery
# =============================================================================
section "BÖLÜM 13 - YEDEKLEME VE KURTARMA KOMUTLARI"

ipa_cmd "/usr/bin/rsync_bkp"          "Artımlı dosya/dizin yedekleme: --delete/--link-dest/--checksum"
ipa_cmd "/usr/bin/tar_bkp"            "Arşiv tabanlı yedekleme (gzip/bzip2/xz sıkıştırma)"
ipa_cmd "/usr/bin/dd_bkp"             "Ham disk/bölüm imajı yedekleme ve geri yükleme"
ipa_cmd "/usr/sbin/dump"              "EXT dosya sistemi artımlı yedekleme (level 0-9)"
ipa_cmd "/usr/sbin/restore"           "dump yedeğinden dosya veya dosya sistemi geri yükleme"
ipa_cmd "/usr/bin/xfsdump"            "XFS dosya sistemi artımlı yedekleme aracı"
ipa_cmd "/usr/bin/xfsrestore"         "xfsdump yedeğinden XFS dosya sistemi geri yükleme"
ipa_cmd "/usr/bin/borg"               "BorgBackup: deduplikasyon + şifreleme + sıkıştırma ile yedekleme"
ipa_cmd "/usr/bin/restic"             "Restic: hızlı şifreli çoklu backend (S3/B2/local) yedekleme"
ipa_cmd "/usr/bin/duplicati"          "Duplicati: şifreli bulut ve yerel yedekleme aracı"
ipa_cmd "/usr/bin/testdisk"           "Bölüm tablosu kurtarma ve silinen bölüm tespit/geri yükleme"
ipa_cmd "/usr/bin/photorec"           "Silinen/kayıp dosyaları dosya imzası ile kurtarma"
ipa_cmd "/usr/bin/extundelete"        "EXT3/EXT4 dosya sisteminde silinen dosyaları kurtarma"


# =============================================================================
#  BÖLÜM 14 - SANALLAŞTıRMA VE KONTEYNER
#  Grup: sysadmin_virt_container
# =============================================================================
section "BÖLÜM 14 - SANALLAŞTıRMA VE KONTEYNER KOMUTLARI"

ipa_cmd "/usr/bin/virsh"              "KVM/QEMU libvirt: VM başlatma/durdurma/anlık görüntü/klonlama"
ipa_cmd "/usr/bin/virt-install"       "Yeni KVM sanal makinesi oluşturma ve işletim sistemi kurma"
ipa_cmd "/usr/bin/virt-clone"         "Mevcut sanal makineyi klonlama"
ipa_cmd "/usr/bin/virt-top"           "Sanal makinelerin CPU ve Memory kullanımını anlık izleme"
ipa_cmd "/usr/bin/qemu-img"           "Sanal disk imajı: oluşturma/dönüştürme/bilgi görüntüleme/snapshot"
ipa_cmd "/usr/bin/podman"             "Rootless OCI konteyner: çalıştırma/build/compose/pod yönetimi"
ipa_cmd "/usr/bin/docker"             "Docker konteyner platformu tam yönetimi"
ipa_cmd "/usr/bin/buildah"            "OCI konteyner imajı oluşturma ve değiştirme"
ipa_cmd "/usr/bin/skopeo"             "Konteyner imajı kopyalama, inspect ve registry yönetimi"
ipa_cmd "/usr/bin/nsenter"            "Belirtilen namespace'e girerek komut çalıştırma (konteyner debug)"
ipa_cmd "/usr/bin/unshare"            "Yeni mount/network/PID/user namespace oluşturma"
ipa_cmd "/usr/bin/criu"               "CRIU: çalışan process checkpoint/restore (konteyner taşıma)"


# =============================================================================
#  KOMUT GRUPLARININ OLUŞTURULMASI
# =============================================================================
section "KOMUT GRUPLARININ OLUŞTURULMASI"

ipa_grp "sysadmin_service_mgmt"      "Servis Yönetimi: systemctl/service/journalctl/timedatectl/chronyc"
ipa_grp "sysadmin_disk_mgmt"         "Disk ve LVM Volume Yönetimi: fdisk/parted/lvm/mdadm/smartctl/fio"
ipa_grp "sysadmin_filesystem_mgmt"   "Dosya Sistemi Yönetimi: mkfs/mount/fsck/resize/quota/acl/btrfs"
ipa_grp "sysadmin_network_mgmt"      "Network Yönetimi: ip/nmcli/iptables/nft/tcpdump/nmap/dig/curl"
ipa_grp "sysadmin_cpu_process_mgmt"  "İşlemci ve Process Yönetimi: top/htop/kill/taskset/perf/cgroup"
ipa_grp "sysadmin_log_analysis"      "Log Analizi: journalctl/ausearch/tail/grep/awk/last/dmesg/logwatch"
ipa_grp "sysadmin_app_analysis"      "Uygulama Analizi: strace/ltrace/valgrind/perf/bpftrace/ldd/pmap"
ipa_grp "sysadmin_system_config"     "Sistem Yapılandırma: dnf/apt/rpm/sysctl/selinux/grub/dracut"
ipa_grp "sysadmin_disk_encryption"   "Disk Şifreleme: cryptsetup/LUKS/clevis/dm-verity/gpg/openssl"
ipa_grp "sysadmin_hardware_mgmt"     "Donanım Yönetimi: lshw/lspci/modprobe/sensors/ipmitool/udevadm"
ipa_grp "sysadmin_user_mgmt"         "Kullanıcı Yönetimi: useradd/usermod/passwd/chage/sssd/getent"
ipa_grp "sysadmin_security_analysis" "Güvenlik Analizi: lynis/rkhunter/aide/oscap/clamscan/fail2ban"
ipa_grp "sysadmin_backup_recovery"   "Yedekleme ve Kurtarma: rsync/borg/restic/dump/testdisk/photorec"
ipa_grp "sysadmin_virt_container"    "Sanallaştırma ve Konteyner: virsh/podman/docker/buildah/nsenter"


# =============================================================================
#  GRUPLARA KOMUT ÜYELİKLERİ
# =============================================================================
section "GRUPLARA KOMUT ÜYELİKLERİ EKLENİYOR"

add_members "sysadmin_service_mgmt" \
    "/usr/bin/systemctl" "/usr/sbin/service" "/usr/bin/journalctl" \
    "/usr/bin/systemd-analyze" "/usr/bin/systemd-cgls" "/usr/bin/systemd-cgtop" \
    "/usr/bin/timedatectl" "/usr/bin/chronyc" "/usr/sbin/ntpdate" \
    "/usr/sbin/chkconfig" "/usr/bin/loginctl"

add_members "sysadmin_disk_mgmt" \
    "/usr/sbin/fdisk" "/usr/sbin/gdisk" "/usr/sbin/cgdisk" "/usr/sbin/parted" \
    "/usr/sbin/partprobe" "/usr/sbin/sfdisk" \
    "/usr/bin/lsblk" "/usr/sbin/blkid" "/usr/bin/df" "/usr/bin/du" \
    "/usr/sbin/hdparm" "/usr/sbin/sdparm" "/usr/sbin/smartctl" \
    "/usr/bin/iostat" "/usr/bin/iotop" "/usr/bin/fio" "/usr/bin/ioping" \
    "/usr/sbin/pvcreate" "/usr/sbin/pvdisplay" "/usr/sbin/pvremove" \
    "/usr/sbin/pvmove" "/usr/sbin/pvresize" "/usr/sbin/pvs" "/usr/sbin/pvscan" \
    "/usr/sbin/vgcreate" "/usr/sbin/vgdisplay" "/usr/sbin/vgextend" \
    "/usr/sbin/vgreduce" "/usr/sbin/vgremove" "/usr/sbin/vgrename" \
    "/usr/sbin/vgs" "/usr/sbin/vgscan" "/usr/sbin/vgchange" \
    "/usr/sbin/lvcreate" "/usr/sbin/lvdisplay" "/usr/sbin/lvextend" \
    "/usr/sbin/lvreduce" "/usr/sbin/lvremove" "/usr/sbin/lvrename" \
    "/usr/sbin/lvresize" "/usr/sbin/lvs" "/usr/sbin/lvscan" \
    "/usr/sbin/lvchange" "/usr/sbin/lvconvert" "/usr/sbin/lvm" \
    "/usr/bin/stratis" "/usr/sbin/mdadm"

add_members "sysadmin_filesystem_mgmt" \
    "/usr/sbin/mkfs" "/usr/sbin/mkfs.ext4" "/usr/sbin/mkfs.ext3" \
    "/usr/sbin/mkfs.xfs" "/usr/sbin/mkfs.btrfs" "/usr/sbin/mkfs.vfat" \
    "/usr/sbin/mkfs.ntfs" "/usr/sbin/mkswap" "/usr/sbin/swapon" "/usr/sbin/swapoff" \
    "/usr/bin/mount" "/usr/bin/umount" \
    "/usr/sbin/tune2fs" "/usr/sbin/dumpe2fs" "/usr/sbin/debugfs" \
    "/usr/sbin/e2fsck" "/usr/sbin/fsck" \
    "/usr/sbin/xfs_repair" "/usr/sbin/xfs_info" "/usr/sbin/xfs_admin" \
    "/usr/sbin/xfs_db" "/usr/sbin/xfs_freeze" \
    "/usr/sbin/resize2fs" "/usr/sbin/xfs_growfs" "/usr/sbin/btrfs" \
    "/usr/bin/findmnt" "/usr/bin/lsattr" "/usr/bin/chattr" \
    "/usr/bin/setfacl" "/usr/bin/getfacl" \
    "/usr/bin/chown" "/usr/bin/chmod" "/usr/bin/cp" "/usr/bin/mv" \
    "/usr/bin/rm" "/usr/bin/mkdir" "/usr/bin/rsync" "/usr/bin/tar" "/usr/bin/dd" \
    "/usr/bin/truncate" "/usr/bin/fallocate" \
    "/usr/sbin/quotacheck" "/usr/sbin/quotaon" "/usr/sbin/quotaoff" \
    "/usr/sbin/edquota" "/usr/sbin/repquota"

add_members "sysadmin_network_mgmt" \
    "/usr/sbin/ip" "/usr/sbin/ifconfig" "/usr/sbin/iwconfig" "/usr/sbin/iwlist" \
    "/usr/bin/nmcli" "/usr/bin/nmtui" "/usr/sbin/dhclient" \
    "/usr/sbin/ethtool" "/usr/sbin/mii-tool" "/usr/sbin/ifenslave" \
    "/usr/sbin/brctl" "/usr/sbin/bridge" \
    "/usr/sbin/iptables" "/usr/sbin/iptables-save" "/usr/sbin/iptables-restore" \
    "/usr/sbin/ip6tables" "/usr/sbin/nft" "/usr/bin/firewall-cmd" \
    "/usr/sbin/tcpdump" "/usr/bin/tshark" "/usr/bin/nmap" \
    "/usr/bin/ncat" "/usr/bin/nc" "/usr/bin/socat" \
    "/usr/bin/netstat" "/usr/bin/ss" "/usr/sbin/route" \
    "/usr/sbin/arp" "/usr/sbin/arping" \
    "/usr/bin/ping" "/usr/bin/ping6" "/usr/bin/traceroute" \
    "/usr/bin/tracepath" "/usr/bin/mtr" "/usr/bin/iperf3" \
    "/usr/bin/dig" "/usr/bin/nslookup" "/usr/bin/host" "/usr/bin/whois" \
    "/usr/sbin/nscd" "/usr/bin/curl" "/usr/bin/wget" \
    "/usr/bin/scp" "/usr/bin/sftp" "/usr/sbin/sysctl"

add_members "sysadmin_cpu_process_mgmt" \
    "/usr/bin/top" "/usr/bin/htop" "/usr/bin/atop" "/usr/bin/btop" \
    "/usr/bin/glances" "/usr/bin/ps" "/usr/bin/pstree" "/usr/bin/pidstat" \
    "/usr/bin/kill" "/usr/bin/killall" "/usr/bin/pkill" "/usr/bin/pgrep" \
    "/usr/bin/nice" "/usr/bin/renice" \
    "/usr/bin/taskset" "/usr/bin/chrt" "/usr/bin/ionice" \
    "/usr/bin/numactl" "/usr/bin/numastat" \
    "/usr/bin/lscpu" "/usr/bin/mpstat" "/usr/bin/vmstat" "/usr/bin/sar" \
    "/usr/bin/nproc" "/usr/bin/cpupower" "/usr/sbin/tuned-adm" \
    "/usr/bin/stress-ng" "/usr/bin/sysbench" \
    "/usr/bin/cgset" "/usr/bin/cgget" "/usr/bin/cgcreate" "/usr/bin/cgdelete" \
    "/usr/bin/prlimit"

add_members "sysadmin_log_analysis" \
    "/usr/bin/journalctl" "/usr/bin/tail" "/usr/bin/head" \
    "/usr/bin/grep" "/usr/bin/egrep" "/usr/bin/zgrep" \
    "/usr/bin/zcat" "/usr/bin/bzcat" "/usr/bin/xzcat" \
    "/usr/bin/awk" "/usr/bin/sed" "/usr/bin/cut" \
    "/usr/bin/sort" "/usr/bin/uniq" "/usr/bin/wc" \
    "/usr/bin/less" "/usr/bin/more" "/usr/bin/cat" "/usr/bin/tac" "/usr/bin/nl" \
    "/usr/bin/dmesg" "/usr/bin/last" "/usr/bin/lastlog" "/usr/bin/lastb" \
    "/usr/bin/who" "/usr/bin/w" \
    "/usr/sbin/ausearch" "/usr/sbin/aureport" "/usr/sbin/auditctl" \
    "/usr/bin/logwatch" "/usr/bin/multitail" "/usr/bin/lnav" "/usr/sbin/logrotate"

add_members "sysadmin_app_analysis" \
    "/usr/bin/ldd" "/usr/sbin/ldconfig" "/usr/bin/ltrace" "/usr/bin/strace" \
    "/usr/bin/pmap" "/usr/bin/lsof" \
    "/usr/bin/objdump" "/usr/bin/nm" "/usr/bin/readelf" "/usr/bin/strings" \
    "/usr/bin/file" "/usr/bin/eu-stack" "/usr/bin/eu-nm" "/usr/bin/eu-objdump" \
    "/usr/bin/valgrind" "/usr/bin/ms_print" "/usr/bin/smem" \
    "/usr/bin/memusage" "/usr/bin/heaptrack" "/usr/bin/heaptrack_print" \
    "/usr/bin/mtrace" \
    "/usr/bin/perf" "/usr/bin/gprof" "/usr/bin/gdb" "/usr/bin/addr2line" \
    "/usr/bin/stap" "/usr/bin/bpftrace" "/usr/bin/flamegraph.pl" \
    "/usr/share/bcc/tools/execsnoop" "/usr/share/bcc/tools/opensnoop" \
    "/usr/share/bcc/tools/biolatency" "/usr/share/bcc/tools/tcpconnect" \
    "/usr/share/bcc/tools/tcpaccept" "/usr/share/bcc/tools/runqlat" \
    "/usr/share/bcc/tools/profile" "/usr/share/bcc/tools/memleak" \
    "/usr/share/bcc/tools/funccount" "/usr/share/bcc/tools/funclatency" \
    "/usr/share/bcc/tools/cachestat" "/usr/share/bcc/tools/cpudist"

add_members "sysadmin_system_config" \
    "/usr/bin/dnf" "/usr/bin/yum" "/usr/bin/rpm" \
    "/usr/bin/apt" "/usr/bin/apt-get" "/usr/bin/apt-cache" \
    "/usr/bin/dpkg" "/usr/bin/snap" "/usr/bin/flatpak" \
    "/usr/sbin/update-alternatives" \
    "/usr/bin/hostnamectl" "/usr/bin/localectl" \
    "/usr/bin/crontab" "/usr/bin/at" "/usr/sbin/anacron" "/usr/bin/tee" \
    "/usr/sbin/semanage" "/usr/sbin/setenforce" "/usr/sbin/setsebool" \
    "/usr/sbin/restorecon" "/usr/bin/chcon" "/usr/sbin/getenforce" \
    "/usr/bin/sestatus" "/usr/bin/audit2allow" \
    "/usr/bin/aa-status" "/usr/sbin/aa-enforce" "/usr/sbin/aa-complain" \
    "/usr/sbin/grubby" "/usr/sbin/grub2-mkconfig" "/usr/sbin/update-grub" \
    "/usr/sbin/dracut" "/usr/sbin/mkinitrd" \
    "/usr/sbin/reboot" "/usr/sbin/shutdown" "/usr/sbin/halt" "/usr/sbin/poweroff" \
    "/usr/bin/authselect" "/usr/sbin/authconfig" "/usr/sbin/sss_cache"

add_members "sysadmin_disk_encryption" \
    "/usr/sbin/cryptsetup" "/usr/sbin/cryptsetup-reencrypt" \
    "/usr/bin/clevis" "/usr/bin/clevis-luks-bind" "/usr/bin/clevis-luks-unbind" \
    "/usr/sbin/veritysetup" \
    "/usr/bin/gpg" "/usr/bin/gpg2" "/usr/bin/openssl" "/usr/bin/mokutil"

add_members "sysadmin_hardware_mgmt" \
    "/usr/sbin/lshw" "/usr/bin/lspci" "/usr/bin/lsusb" "/usr/bin/lsscsi" \
    "/usr/bin/dmidecode" "/usr/bin/hwinfo" "/usr/bin/inxi" \
    "/usr/sbin/modprobe" "/usr/sbin/modinfo" "/usr/sbin/lsmod" \
    "/usr/sbin/rmmod" "/usr/sbin/insmod" "/usr/sbin/depmod" \
    "/usr/bin/sensors" "/usr/sbin/sensors-detect" \
    "/usr/bin/ipmitool" "/usr/bin/ipmi-sensors" \
    "/usr/bin/rasdaemon" "/usr/bin/mcelog" \
    "/usr/sbin/udevadm" "/usr/bin/fwupdmgr" \
    "/usr/sbin/i2cdetect" "/usr/sbin/i2cget" "/usr/sbin/i2cset"

add_members "sysadmin_user_mgmt" \
    "/usr/sbin/useradd" "/usr/sbin/usermod" "/usr/sbin/userdel" \
    "/usr/sbin/groupadd" "/usr/sbin/groupmod" "/usr/sbin/groupdel" \
    "/usr/sbin/gpasswd" "/usr/bin/passwd" "/usr/sbin/chpasswd" \
    "/usr/bin/chage" "/usr/bin/faillock" \
    "/usr/sbin/pwck" "/usr/sbin/grpck" "/usr/sbin/pwconv" "/usr/sbin/pwunconv" \
    "/usr/bin/id" "/usr/bin/groups" "/usr/bin/su" \
    "/usr/sbin/visudo" "/usr/bin/sudo" \
    "/usr/sbin/sssd" "/usr/bin/sssctl" "/usr/bin/getent"

add_members "sysadmin_security_analysis" \
    "/usr/bin/lynis" "/usr/bin/rkhunter" "/usr/sbin/chkrootkit" \
    "/usr/bin/aide" "/usr/bin/oscap" "/usr/sbin/sysdig" \
    "/usr/bin/sssctl" "/usr/sbin/fail2ban-client" \
    "/usr/bin/clamscan" "/usr/bin/freshclam" \
    "/usr/bin/ss_audit" "/usr/bin/nmap_audit"

add_members "sysadmin_backup_recovery" \
    "/usr/bin/rsync_bkp" "/usr/bin/tar_bkp" "/usr/bin/dd_bkp" \
    "/usr/sbin/dump" "/usr/sbin/restore" \
    "/usr/bin/xfsdump" "/usr/bin/xfsrestore" \
    "/usr/bin/borg" "/usr/bin/restic" "/usr/bin/duplicati" \
    "/usr/bin/testdisk" "/usr/bin/photorec" "/usr/bin/extundelete"

add_members "sysadmin_virt_container" \
    "/usr/bin/virsh" "/usr/bin/virt-install" "/usr/bin/virt-clone" \
    "/usr/bin/virt-top" "/usr/bin/qemu-img" \
    "/usr/bin/podman" "/usr/bin/docker" "/usr/bin/buildah" \
    "/usr/bin/skopeo" "/usr/bin/nsenter" "/usr/bin/unshare" "/usr/bin/criu"


# =============================================================================
#  IPA KULLANICI GRUBU OLUŞTURMA
# =============================================================================
section "IPA KULLANICI GRUBU OLUŞTURMA"

if ipa group-show linux-sysadmin &>/dev/null; then
    warn "IPA grubu zaten mevcut: linux-sysadmin"
else
    ipa group-add linux-sysadmin \
        --desc="Linux Sistem Yöneticileri - Sudo ile tam yönetim yetkisi, root geçişi yasak" \
        && ok "IPA grubu oluşturuldu: linux-sysadmin" \
        || err "IPA grubu oluşturulamadı"
fi


# =============================================================================
#  ROOT GEÇİŞ DENY KOMUT GRUBU
# =============================================================================
section "ROOT GEÇİŞ ENGELİ - DENY GRUBU"

ipa_grp "sysadmin_deny_root_shells" "Root/shell geçiş komutları - KESINLIKLE ENGELLENDI"

ipa_cmd "/usr/bin/su_to_root"         "DENY: su - ile root shell geçişi engeli"
ipa_cmd "/usr/bin/bash_shell"         "DENY: sudo bash ile root shell başlatma engeli"
ipa_cmd "/usr/bin/sh_shell"           "DENY: sudo sh ile root shell başlatma engeli"
ipa_cmd "/usr/bin/zsh_shell"          "DENY: sudo zsh ile root shell başlatma engeli"
ipa_cmd "/usr/bin/fish_shell"         "DENY: sudo fish ile root shell başlatma engeli"

add_members "sysadmin_deny_root_shells" \
    "/usr/bin/su_to_root" "/usr/bin/bash_shell" \
    "/usr/bin/sh_shell" "/usr/bin/zsh_shell" "/usr/bin/fish_shell"


# =============================================================================
#  SUDO KURALLARI OLUŞTURMA
# =============================================================================
section "SUDO KURALLARI OLUŞTURMA"

ALLOW_RULE="rule_linux_sysadmin"
DENY_RULE="rule_linux_sysadmin_deny_root"

# --- ALLOW Kuralı ---
ipa_rule "$ALLOW_RULE" \
    "Linux Sistem Yöneticisi: 14 komut grubuna sudo erişimi - root shell geçişi kesinlikle yasak"

info "Allow kuralı yapılandırılıyor: $ALLOW_RULE"

ipa sudorule-add-host "$ALLOW_RULE" --hosts=ALL 2>/dev/null \
    && ok "Tüm host'lara uygulandı" || warn "Host ALL zaten ekli"

ipa sudorule-add-user "$ALLOW_RULE" --groups="linux-sysadmin" 2>/dev/null \
    && ok "linux-sysadmin grubu kurala eklendi" || warn "Grup zaten ekli"

info "Allow kuralına komut grupları ekleniyor..."
ALLOW_GROUPS=(
    "sysadmin_service_mgmt"
    "sysadmin_disk_mgmt"
    "sysadmin_filesystem_mgmt"
    "sysadmin_network_mgmt"
    "sysadmin_cpu_process_mgmt"
    "sysadmin_log_analysis"
    "sysadmin_app_analysis"
    "sysadmin_system_config"
    "sysadmin_disk_encryption"
    "sysadmin_hardware_mgmt"
    "sysadmin_user_mgmt"
    "sysadmin_security_analysis"
    "sysadmin_backup_recovery"
    "sysadmin_virt_container"
)

for grp in "${ALLOW_GROUPS[@]}"; do
    ipa sudorule-add-allow-command "$ALLOW_RULE" --sudocmdgroups="$grp" 2>/dev/null \
        && ok "  Allow: $grp -> $ALLOW_RULE" \
        || warn "  Zaten ekli: $grp"
done

# --- DENY Kuralı ---
ipa_rule "$DENY_RULE" \
    "Root shell geçişi kesinlikle engellenir: su/bash/sh/zsh ile root erişimi yok"

info "Deny kuralı yapılandırılıyor: $DENY_RULE"

ipa sudorule-add-host "$DENY_RULE" --hosts=ALL 2>/dev/null \
    && ok "Tüm host'lara uygulandı (deny)" || warn "Host ALL zaten ekli (deny)"

ipa sudorule-add-user "$DENY_RULE" --groups="linux-sysadmin" 2>/dev/null \
    && ok "linux-sysadmin grubu deny kuralına eklendi" || warn "Grup zaten ekli (deny)"

ipa sudorule-add-deny-command "$DENY_RULE" \
    --sudocmdgroups="sysadmin_deny_root_shells" 2>/dev/null \
    && ok "Root shell engeli deny kuralına eklendi" || warn "Deny komutu zaten ekli"


# =============================================================================
#  KURULUMU DOĞRULAMA
# =============================================================================
section "KURULUM DOĞRULAMA VE ÖZET"

echo ""
info "Oluşturulan sudo komut grupları:"
ALL_GROUPS=(
    "sysadmin_service_mgmt"
    "sysadmin_disk_mgmt"
    "sysadmin_filesystem_mgmt"
    "sysadmin_network_mgmt"
    "sysadmin_cpu_process_mgmt"
    "sysadmin_log_analysis"
    "sysadmin_app_analysis"
    "sysadmin_system_config"
    "sysadmin_disk_encryption"
    "sysadmin_hardware_mgmt"
    "sysadmin_user_mgmt"
    "sysadmin_security_analysis"
    "sysadmin_backup_recovery"
    "sysadmin_virt_container"
    "sysadmin_deny_root_shells"
)

GRP_OK=0; GRP_FAIL=0
for g in "${ALL_GROUPS[@]}"; do
    if ipa sudocmdgroup-show "$g" &>/dev/null; then
        # Üye sayısını al
        MEMBERS=$(ipa sudocmdgroup-show "$g" 2>/dev/null | awk -F: '/Member Sudo/{gsub(/,/,"",$0); n=NF-1; print n}' || echo "?")
        echo -e "  ${GREEN}[OK]${NC} $g"
        GRP_OK=$((GRP_OK+1))
    else
        echo -e "  ${RED}[HATA]${NC} $g - BULUNAMADI!"
        GRP_FAIL=$((GRP_FAIL+1))
    fi
done
echo ""
info "Grup özeti: ${GRP_OK} başarılı, ${GRP_FAIL} başarısız"

echo ""
info "Oluşturulan sudo kuralları:"
for rule in "rule_linux_sysadmin" "rule_linux_sysadmin_deny_root"; do
    if ipa sudorule-show "$rule" &>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} $rule"
    else
        echo -e "  ${RED}[HATA]${NC} $rule - BULUNAMADI!"
    fi
done

echo ""
info "IPA linux-sysadmin grubu:"
if ipa group-show linux-sysadmin &>/dev/null; then
    MEMBERS=$(ipa group-show linux-sysadmin 2>/dev/null | awk -F: '/Member users:/{print $2}')
    echo -e "  ${GREEN}[OK]${NC} linux-sysadmin | Üyeler:${MEMBERS:-" (henüz üye yok)"}"
else
    echo -e "  ${RED}[HATA]${NC} linux-sysadmin - BULUNAMADI!"
fi

echo ""
info "Allow kuralı komut grup bağlantıları:"
ipa sudorule-show "rule_linux_sysadmin" 2>/dev/null | grep -E "Sudo Allow|Command Groups" | sed 's/^/  /'


echo ""
echo -e "${GREEN}${BOLD}"
echo "=================================================================="
echo "             KURULUM TAMAMLANDI!"
echo "=================================================================="
echo "  Allow Kuralı   : rule_linux_sysadmin"
echo "  Deny Kuralı    : rule_linux_sysadmin_deny_root"
echo "  IPA Grubu      : linux-sysadmin"
echo "  Komut Grubu    : 14 grup + 1 deny grubu"
echo ""
echo "  Kullanici eklemek icin:"
echo "    ipa group-add-member linux-sysadmin --users=<kullanici>"
echo ""
echo "  Dogrulama icin (istemcide):"
echo "    sudo -l -U <kullanici>"
echo "    ipa sudorule-show rule_linux_sysadmin"
echo "=================================================================="
echo -e "${NC}"
