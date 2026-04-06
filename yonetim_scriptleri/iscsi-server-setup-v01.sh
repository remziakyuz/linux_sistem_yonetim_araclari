#!/bin/bash
# =============================================================================
# Fedora 43 - iSCSI Target Sunucu Yapılandırma Scripti
# Açıklama : LVM üzerinde LUN oluşturur, multi-access modda hizmete alır
#            ve tanımlı initiator'lara erişim izni verir.
# Kullanım  : sudo bash iscsi-server-setup.sh
# Versiyon  : v01
# =============================================================================

set -euo pipefail

# =============================================================================
# RENK TANIMLARI
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
log_section() { echo -e "\n${CYAN}========== $* ==========${NC}"; }

# =============================================================================
# ROOT KONTROLÜ
# =============================================================================
[[ $EUID -ne 0 ]] && log_error "Bu script root yetkisiyle çalıştırılmalıdır. (sudo)"

# =============================================================================
# KULLANICI TANIMLARI  <<<  BURADAN YAPILANDIRIN  >>>
# =============================================================================

# --- iSCSI Hedef (Target) Adı ---
# IQN formatı: iqn.YYYY-MM.domain:identifier
ISCSI_TARGET_IQN="iqn.2025-01.com.sirket:storage01"

# --- Portal IP ve Port ---
# İki ayrı ağ arayüzü üzerinden dinleme yapılır (ör: farklı NIC/VLAN)
ISCSI_PORTAL_IPS=(
    "172.16.16.248"   # 1. portal – birincil depolama ağı
    "192.168.251.248"   # 2. portal – ikincil depolama ağı / yedek yol
)
ISCSI_PORTAL_PORT="3260"

# --- LUN Tanımları ---
# Format: "VG_ADI/LV_ADI:LUN_NO:BOYUT"
# UYARI: Her LUN satırı benzersiz bir LV'ye işaret etmelidir.
#        Aynı LV iki ayrı backstore'a atanamaz (device already in use).
LUN_DEFINITIONS=(
    "vg_data01/lv_ha_shared01:0:100G"
    "vg_data01/lv_ha_shared02:1:200G"
)

# --- İzin Verilen Client InitiatorName'leri ---
# Her client'ın /etc/iscsi/initiatorname.iscsi dosyasındaki değer
ALLOWED_INITIATORS=(
    "iqn.1994-05.lab.local:clstr01"
    "iqn.1994-05.lab.local:clstr02"
)

# --- CHAP Kimlik Doğrulama (opsiyonel) ---
# CHAP kullanmak istemiyorsanız CHAP_ENABLED=false yapın
CHAP_ENABLED=false
CHAP_USERNAME="iscsi_user"
CHAP_PASSWORD="G3c3rliSifre!2025"   # En az 12 karakter

# =============================================================================
# FONKSİYONLAR
# =============================================================================

# Paket kurulum fonksiyonu
install_packages() {
    log_section "PAKET KURULUMU"

    local packages=(
        targetcli           # iSCSI target yönetim aracı (LIO kernel)
        lvm2                # LVM araçları
        device-mapper       # Device mapper
        firewalld           # Güvenlik duvarı
        policycoreutils-python-utils  # SELinux araçları
    )

    log_info "Sistem paketleri güncelleniyor..."
    dnf -y upgrade --refresh --quiet

    log_info "Gerekli paketler yükleniyor: ${packages[*]}"
    dnf -y install "${packages[@]}" --quiet

    log_ok "Tüm paketler başarıyla yüklendi."
}

# LVM LUN oluşturma fonksiyonu
create_lvm_luns() {
    log_section "LVM LUN OLUŞTURMA"

    # Duplicate LV kontrolü: aynı LV iki LUN'a atanamaz
    local -A seen_lvs
    for lun_def in "${LUN_DEFINITIONS[@]}"; do
        IFS=':' read -r vg_lv lun_no size <<< "$lun_def"
        if [[ -n "${seen_lvs[$vg_lv]+_}" ]]; then
            log_error "Konfigürasyon hatası: '$vg_lv' aynı LV iki farklı LUN'a atanmış" \
                      "(LUN ${seen_lvs[$vg_lv]} ve LUN ${lun_no}). Her LUN benzersiz bir LV'ye işaret etmelidir."
        fi
        seen_lvs[$vg_lv]=$lun_no
    done

    for lun_def in "${LUN_DEFINITIONS[@]}"; do
        IFS=':' read -r vg_lv lun_no size <<< "$lun_def"
        IFS='/' read -r vg_name lv_name <<< "$vg_lv"

        log_info "İşleniyor: VG=${vg_name} | LV=${lv_name} | LUN=${lun_no} | Boyut=${size}"

        # VG varlık kontrolü
        if ! vgs "$vg_name" &>/dev/null; then
            log_warn "Volume Group '${vg_name}' bulunamadı! Atlanıyor: ${lv_name}"
            log_warn "  → VG oluşturmak için: vgcreate ${vg_name} /dev/sdX"
            continue
        fi

        # LV daha önce oluşturulmuş mu?
        if lvs "${vg_name}/${lv_name}" &>/dev/null; then
            log_warn "Logical Volume '${vg_name}/${lv_name}' zaten mevcut. Atlanıyor."
        else
            log_info "  LV oluşturuluyor: lvcreate -L ${size} -n ${lv_name} ${vg_name}"
            lvcreate -L "${size}" -n "${lv_name}" "${vg_name}"
            log_ok "  LV başarıyla oluşturuldu: /dev/${vg_name}/${lv_name}"
        fi
    done
}

# targetcli ile iSCSI yapılandırma
configure_iscsi_target() {
    log_section "iSCSI TARGET YAPILANDIRMA"

    # targetcli toplu komut dosyası oluştur
    local tcli_script
    tcli_script=$(mktemp /tmp/targetcli_XXXXXX.conf)

    {
        # ---- Backstore'ları oluştur ----
        for lun_def in "${LUN_DEFINITIONS[@]}"; do
            IFS=':' read -r vg_lv lun_no size <<< "$lun_def"
            IFS='/' read -r vg_name lv_name <<< "$vg_lv"

            # LV yoksa atla
            [[ ! -b "/dev/${vg_name}/${lv_name}" ]] && continue

            # targetcli 2.1.x'te write_back, create parametresi değil attribute'tur.
            # Önce backstore oluşturulur, ardından ayrı komutla write_back=false atanır.
            local bs_name="${lv_name}_lun${lun_no}"
            echo "cd /backstores/block"
            echo "create dev=/dev/${vg_name}/${lv_name} name=${bs_name}"
            echo "cd /backstores/block/${bs_name}"
            echo "set attribute emulate_write_cache=0"
        done

        # ---- Target oluştur ----
        echo "cd /iscsi"
        echo "create ${ISCSI_TARGET_IQN}"

        # ---- Portal yapılandır (birden fazla IP) ----
        echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/portals"
        echo "delete 0.0.0.0 3260"
        for portal_ip in "${ISCSI_PORTAL_IPS[@]}"; do
            echo "create ${portal_ip} ${ISCSI_PORTAL_PORT}"
        done

        # ---- LUN'ları target'a bağla ----
        echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/luns"
        for lun_def in "${LUN_DEFINITIONS[@]}"; do
            IFS=':' read -r vg_lv lun_no size <<< "$lun_def"
            IFS='/' read -r vg_name lv_name <<< "$vg_lv"

            [[ ! -b "/dev/${vg_name}/${lv_name}" ]] && continue

            local bs_name="${lv_name}_lun${lun_no}"
            echo "create /backstores/block/${bs_name} lun=${lun_no}"
        done

        # ---- Multi-Access TPG Attribute'ları ----
        echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1"
        echo "set attribute demo_mode_write_protect=0"
        echo "set attribute generate_node_acls=0"
        echo "set attribute cache_dynamic_acls=0"
        echo "set parameter InitialR2T=No"
        echo "set parameter ImmediateData=Yes"

        # ---- CHAP (opsiyonel) ----
        if [[ "${CHAP_ENABLED}" == "true" ]]; then
            echo "set auth userid=${CHAP_USERNAME}"
            echo "set auth password=${CHAP_PASSWORD}"
            echo "set attribute authentication=1"
        else
            echo "set attribute authentication=0"
        fi

        # ---- İzin Verilen Initiator ACL'leri ----
        echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls"
        for initiator in "${ALLOWED_INITIATORS[@]}"; do
            echo "create ${initiator}"

            for lun_def in "${LUN_DEFINITIONS[@]}"; do
                IFS=':' read -r vg_lv lun_no size <<< "$lun_def"
                IFS='/' read -r vg_name lv_name <<< "$vg_lv"

                [[ ! -b "/dev/${vg_name}/${lv_name}" ]] && continue

                echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls/${initiator}"
                echo "create mapped_lun=${lun_no} tpg_lun_or_backstore=${lun_no}"
            done

            echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls"
        done

        # ---- Kaydet ----
        echo "cd /"
        echo "saveconfig"
        echo "exit"

    } > "$tcli_script"

    log_info "targetcli yapılandırması uygulanıyor..."
    targetcli < "$tcli_script"
    rm -f "$tcli_script"
    log_ok "iSCSI target yapılandırması tamamlandı."
}

# Multi-Write (ALUA/PR) desteği için LVM ayarı
configure_multiwrite() {
    log_section "MULTI-ACCESS (ALUA) YAPILANDIRMA"

    # LIO kernel modülü ALUA desteği zaten aktif
    # Ancak birden fazla sunucunun aynı anda yazması için backstore'da
    # "set attribute emulate_write_cache=0" (write_through) + her initiator'da
    # hem read hem write yetkisi verilmeli

    log_info "device-mapper sürümü kontrol ediliyor..."
    dmsetup version

    # LVM filter - sadece kendi cihazlarını görsün (opsiyonel güvenlik)
    # /etc/lvm/lvm.conf içinde global_filter ayarlanabilir

    log_info "LVM önbellek davranışı kontrol ediliyor..."
    lvmconfig --type current activation/use_linear_target 2>/dev/null || true

    log_ok "Multi-access modu için LIO ALUA kullanılıyor (kernel yerleşik)."
    log_info "  → Her LUN için ALUA aktif, birden fazla initiator eşzamanlı bağlanabilir."
}

# Servis etkinleştirme
enable_services() {
    log_section "SERVİS YÖNETİMİ"

    local services=("target" "firewalld")

    for svc in "${services[@]}"; do
        log_info "Etkinleştiriliyor ve başlatılıyor: ${svc}"
        systemctl enable --now "$svc"
        systemctl is-active --quiet "$svc" \
            && log_ok "  ${svc} çalışıyor." \
            || log_warn "  ${svc} başlatılamadı! 'journalctl -xe' ile kontrol edin."
    done
}

# Güvenlik duvarı yapılandırması
configure_firewall() {
    log_section "GÜVENLIK DUVARI"

    log_info "iSCSI servisi firewall'a ekleniyor (port ${ISCSI_PORTAL_PORT}/tcp)..."
    firewall-cmd --permanent --add-service=iscsi-target
    firewall-cmd --permanent --add-port="${ISCSI_PORTAL_PORT}/tcp"
    firewall-cmd --reload
    log_ok "Firewall kuralları uygulandı (${#ISCSI_PORTAL_IPS[@]} portal için)."
}

# SELinux yapılandırması
configure_selinux() {
    log_section "SELINUX YAPILANDIRMA"

    local selinux_status
    selinux_status=$(getenforce 2>/dev/null || echo "Disabled")

    if [[ "$selinux_status" == "Enforcing" || "$selinux_status" == "Permissive" ]]; then
        log_info "SELinux aktif (${selinux_status}). iSCSI context ayarlanıyor..."

        # LVM cihazlarına iSCSI erişimi için context
        for lun_def in "${LUN_DEFINITIONS[@]}"; do
            IFS=':' read -r vg_lv lun_no size <<< "$lun_def"
            IFS='/' read -r vg_name lv_name <<< "$vg_lv"

            [[ ! -b "/dev/${vg_name}/${lv_name}" ]] && continue

            log_info "  SELinux context: /dev/${vg_name}/${lv_name}"
            chcon -t tgtd_var_lib_t "/dev/${vg_name}/${lv_name}" 2>/dev/null || \
                semanage fcontext -a -t tgtd_var_lib_t "/dev/${vg_name}/${lv_name}" 2>/dev/null || \
                log_warn "  SELinux context ayarlanamadı, manuel yapılması gerekebilir."
        done

        # iSCSI Boolean
        setsebool -P iscsi_tcp_connect 1 2>/dev/null || true

        log_ok "SELinux yapılandırması tamamlandı."
    else
        log_warn "SELinux devre dışı. SELinux context adımı atlandı."
    fi
}

# Yapılandırma doğrulama
verify_configuration() {
    log_section "YAPILANDIRMA DOĞRULAMA"

    log_info "Target durumu:"
    targetcli ls /iscsi 2>/dev/null || log_warn "targetcli çıktısı alınamadı."

    echo ""
    log_info "Backstore listesi:"
    targetcli ls /backstores/block 2>/dev/null || true

    echo ""
    log_info "Açık portlar:"
    for portal_ip in "${ISCSI_PORTAL_IPS[@]}"; do
        ss -tlnp | grep "${ISCSI_PORTAL_PORT}" | grep "${portal_ip}" \
            && log_ok "  ${portal_ip}:${ISCSI_PORTAL_PORT} dinleniyor." \
            || log_warn "  ${portal_ip}:${ISCSI_PORTAL_PORT} henüz dinlenmiyor."
    done

    echo ""
    log_info "Servis durumları:"
    systemctl is-active target   && log_ok "  target.service    → aktif" || log_warn "  target.service    → inaktif"
    systemctl is-active firewalld && log_ok "  firewalld.service → aktif" || log_warn "  firewalld.service → inaktif"
}

# Özet bilgisi
print_summary() {
    log_section "KURULUM ÖZETİ"

    echo -e "${GREEN}"
    echo "  Target IQN   : ${ISCSI_TARGET_IQN}"
    echo "  Portaller    :"
    for portal_ip in "${ISCSI_PORTAL_IPS[@]}"; do
        echo "    ${portal_ip}:${ISCSI_PORTAL_PORT}"
    done
    echo "  CHAP         : $([ "${CHAP_ENABLED}" == "true" ] && echo "Aktif (${CHAP_USERNAME})" || echo "Devre Dışı")"
    echo ""
    echo "  LUN Listesi  :"
    for lun_def in "${LUN_DEFINITIONS[@]}"; do
        IFS=':' read -r vg_lv lun_no size <<< "$lun_def"
        echo "    LUN ${lun_no} → /dev/${vg_lv} (${size})"
    done
    echo ""
    echo "  İzinli Initiator'lar:"
    for initiator in "${ALLOWED_INITIATORS[@]}"; do
        echo "    - ${initiator}"
    done
    echo -e "${NC}"

    echo -e "${YELLOW}Client tarafında bağlanmak için:${NC}"
    echo "  dnf install iscsi-initiator-utils"
    for portal_ip in "${ISCSI_PORTAL_IPS[@]}"; do
        echo "  iscsiadm -m discovery -t st -p ${portal_ip}:${ISCSI_PORTAL_PORT}"
    done
    echo "  iscsiadm -m node -T ${ISCSI_TARGET_IQN} -p ${ISCSI_PORTAL_IPS[0]}:${ISCSI_PORTAL_PORT} --login"
    echo "  iscsiadm -m node -T ${ISCSI_TARGET_IQN} -p ${ISCSI_PORTAL_IPS[1]}:${ISCSI_PORTAL_PORT} --login"
    echo ""
    echo -e "${YELLOW}Multi-access not:${NC}"
    echo "  Birden fazla sunucunun aynı anda bağlanabilmesi için cluster dosya sistemi"
    echo "  (GFS2, OCFS2, CephFS vb.) kullanılması önerilir. Raw block olarak"
    echo "  paylaşımda veri bütünlüğü cluster yazılımı tarafından sağlanmalıdır."
}

# =============================================================================
# ANA AKIŞ
# =============================================================================
main() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════════════════╗"
    echo "  ║     Fedora 43 — iSCSI Target Sunucu Kurulumu      ║"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"

    install_packages
    create_lvm_luns
    configure_multiwrite
    enable_services
    configure_iscsi_target
    configure_firewall
    configure_selinux
    verify_configuration
    print_summary

    log_ok "Kurulum tamamlandı!"
}

main "$@"
