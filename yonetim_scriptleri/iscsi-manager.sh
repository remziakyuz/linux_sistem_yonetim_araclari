#!/bin/bash
# =============================================================================
#  iSCSI Target Sunucu Yönetim Scripti
#  Sürüm  : 0.94
#  Destek : Oracle Linux 8/9 · RHEL 8/9 · Rocky · AlmaLinux · Fedora · CentOS
#  Kullanım: sudo bash iscsi-manager.sh [--dry-run]
# =============================================================================

set -uo pipefail
[[ "${BASH_VERSINFO[0]}" -lt 4 ]] && { echo "Bash 4+ gerekli."; exit 1; }

# ─── Sabitler ─────────────────────────────────────────────────────────────────
readonly VERSION="0.94"
readonly CONFIG_DIR="/etc/iscsi-manager"
readonly CONFIG_FILE="${CONFIG_DIR}/config.sh"
readonly BACKUP_DIR="${CONFIG_DIR}/backups"
readonly LOG_FILE="/var/log/iscsi-manager.log"
readonly SYSCTL_FILE="/etc/sysctl.d/99-iscsi-cluster.conf"
readonly UDEV_FILE="/etc/udev/rules.d/99-iscsi-scheduler.rules"
readonly MULTIPATH_OUT="${CONFIG_DIR}/multipath.conf.generated"

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

# ─── Renkler ($'...' → gerçek ESC byte, printf %s içinde de çalışır) ─────────
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

# ─── Loglama ──────────────────────────────────────────────────────────────────
_ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_info()    { echo -e "${BLUE}[INFO ]${NC} $*"; echo "$(_ts) [INFO ] $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()      { echo -e "${GREEN}[ OK  ]${NC} $*"; echo "$(_ts) [ OK  ] $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn()    { echo -e "${YELLOW}[UYARI]${NC} $*"; echo "$(_ts) [UYARI] $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "${RED}[HATA ]${NC} $*" >&2; echo "$(_ts) [HATA ] $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_section() { echo -e "\n${CYAN}${BOLD}══ $* ══${NC}"; }
die()         { log_error "$@"; exit 1; }
# Pipe ( { ... } | _run_targetcli ) bloğu içinde kullanılacak log fonksiyonları.
# stdout targetcli'ye gider, bu yüzden log çıktısı stderr'e yönlendirilir.
_p_info()  { echo -e "${BLUE}[INFO ]${NC} $*" >&2; echo "$(_ts) [INFO ] $*" >> "$LOG_FILE" 2>/dev/null || true; }
_p_ok()    { echo -e "${GREEN}[ OK  ]${NC} $*" >&2; echo "$(_ts) [ OK  ] $*" >> "$LOG_FILE" 2>/dev/null || true; }
_p_warn()  { echo -e "${YELLOW}[UYARI]${NC} $*" >&2; echo "$(_ts) [UYARI] $*" >> "$LOG_FILE" 2>/dev/null || true; }

# ─── Menü ─────────────────────────────────────────────────────────────────────
# Kurallar:
#   1. ANSI kodu YALNIZCA printf FORMAT string'inde kullanılır.
#   2. Metin argümanları (%s) ANSI içermez → genişlik her zaman doğru ölçülür.
#   3. Genişlik ölçümü: python3 → wc -m (LC_ALL=C) → wc -c fallback zinciri.

_viswidth() {
    # UTF-8 karakter sayısı (byte değil)
    if command -v python3 &>/dev/null; then
        printf '%s' "$1" | \
            python3 -c "import sys; print(len(sys.stdin.read().rstrip('\n')))" 2>/dev/null \
            && return
    fi
    printf '%s' "$1" | LC_ALL=C wc -m 2>/dev/null || printf '%s' "$1" | wc -c
}

show_menu() {
    # Kullanım: show_menu "Başlık" "Seçenek 1" "Seçenek 2" ...
    local title="$1"; shift
    local W=56           # İç genişlik (║ dahil değil)
    local sep=""
    local j; for (( j=0; j<W; j++ )); do sep+="═"; done

    # Üst kenarlık
    printf "\n${CYAN}${BOLD}╔%s╗${NC}\n" "$sep"

    # Başlık satırı
    local tw; tw=$(_viswidth "$title")
    local tp=$(( W - 2 - tw )); (( tp < 0 )) && tp=0
    local tpad=""; for (( j=0; j<tp; j++ )); do tpad+=" "; done
    printf "${CYAN}${BOLD}║${NC}  ${BOLD}%s${NC}%s${CYAN}${BOLD}║${NC}\n" "$title" "$tpad"

    # Ayraç
    printf "${CYAN}${BOLD}╠%s╣${NC}\n" "$sep"

    # Seçenekler
    local i=1
    local opt
    for opt in "$@"; do
        local row; row=$(printf "%2d. %s" "$i" "$opt")
        local rw; rw=$(_viswidth "$row")
        local rp=$(( W - 2 - rw )); (( rp < 0 )) && rp=0
        local rpad=""; for (( j=0; j<rp; j++ )); do rpad+=" "; done
        printf "${CYAN}${BOLD}║${NC}  ${BOLD}%2d.${NC} %s%s${CYAN}${BOLD}║${NC}\n" "$i" "$opt" "$rpad"
        (( i++ ))
    done

    # Alt kenarlık
    printf "${CYAN}${BOLD}╚%s╝${NC}\n" "$sep"
}

# ─── Yardımcı etkileşim fonksiyonları ────────────────────────────────────────
# Tüm promptlar >&2 (stderr) → $() yakalama içinde ekranda görünür
# Tüm read < /dev/tty → TTY'den doğrudan okur, pipe/subshell engeli yok

press_enter() {
    printf "\n${CYAN}↵ Devam için Enter...${NC}" >&2
    read -r < /dev/tty
}

confirm() {
    # confirm "Soru?" [e|h]  → 0=evet, 1=hayır
    local prompt="${1:-Devam?}" default="${2:-e}" ans
    if [[ "$default" == "e" ]]; then
        printf "${YELLOW}%s [${BOLD}E${NC}${YELLOW}/h]: ${NC}" "$prompt" >&2
    else
        printf "${YELLOW}%s [e/${BOLD}H${NC}${YELLOW}]: ${NC}" "$prompt" >&2
    fi
    read -r ans < /dev/tty
    ans="${ans:-$default}"
    [[ "${ans,,}" =~ ^(e|evet|y|yes)$ ]]
}

read_choice() {
    # read_choice MAX → kullanıcıdan 1..MAX arası sayı al, stdout'a yaz
    local max="$1" ch
    while true; do
        printf "${BOLD}Seçim [1-%s]: ${NC}" "$max" >&2
        read -r ch < /dev/tty
        [[ "$ch" =~ ^[0-9]+$ ]] && (( ch >= 1 && ch <= max )) && break
        printf "${RED}  ✗ 1-%s arasında bir sayı girin.${NC}\n" "$max" >&2
    done
    printf '%s' "$ch"
}

input_text() {
    # input_text "Prompt" [varsayılan] [validator_fn] → stdout'a değer yazar
    local prompt="$1" default="${2:-}" validator="${3:-}" value ans
    while true; do
        if [[ -n "$default" ]]; then
            printf "${CYAN}%s${NC} [${YELLOW}%s${NC}]: " "$prompt" "$default" >&2
        else
            printf "${CYAN}%s${NC}: " "$prompt" >&2
        fi
        read -r value < /dev/tty
        value="${value:-$default}"
        if [[ -z "$value" ]]; then
            printf "${RED}  ✗ Boş bırakılamaz.${NC}\n" >&2; continue
        fi
        if [[ -n "$validator" ]] && ! "$validator" "$value" 2>/dev/null; then
            printf "${RED}  ✗ Geçersiz değer.${NC}\n" >&2; continue
        fi
        printf "${YELLOW}  → '%s' doğru mu? [E/h]: ${NC}" "$value" >&2
        read -r ans < /dev/tty
        [[ "${ans,,}" =~ ^(h|hayir|n|no)$ ]] && continue
        break
    done
    printf '%s' "$value"
}

input_password() {
    local prompt="$1" v1 v2
    while true; do
        printf "${CYAN}%s${NC}: " "$prompt" >&2
        read -r -s v1 < /dev/tty; printf "\n" >&2
        printf "${CYAN}  Tekrar${NC}: " >&2
        read -r -s v2 < /dev/tty; printf "\n" >&2
        [[ "$v1" != "$v2" ]] && { printf "${RED}  ✗ Eşleşmiyor.${NC}\n" >&2; continue; }
        (( ${#v1} >= 12 ))   || { printf "${RED}  ✗ En az 12 karakter.${NC}\n" >&2; continue; }
        break
    done
    printf '%s' "$v1"
}

# ─── Doğrulama fonksiyonları ──────────────────────────────────────────────────
validate_ip() {
    local r='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    [[ "$1" =~ $r ]] || return 1
    local IFS='.' oct
    read -ra oct <<< "$1"
    local o; for o in "${oct[@]}"; do (( o >= 0 && o <= 255 )) || return 1; done
}
validate_iqn()      { [[ "$1" =~ ^iqn\.[0-9]{4}-[0-9]{2}\.[a-zA-Z0-9._-]+(:[a-zA-Z0-9._:-]+)?$ ]]; }
validate_port()     { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
validate_lvm_size() { [[ "$1" =~ ^[0-9]+(\.[0-9]+)?[MmGgTtPp](iB|ib|B|b)?$ ]]; }
validate_vg_lv()    { [[ "$1" =~ ^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$ ]]; }
validate_nonempty() { [[ -n "$1" ]]; }

# ─── Global değişkenler ───────────────────────────────────────────────────────
ISCSI_TARGET_IQN=""
ISCSI_PORTAL_IPS=()
ISCSI_PORTAL_PORT="3260"
LUN_DEFINITIONS=()        # "vg/lv:lun_no:boyut"
ALLOWED_INITIATORS=()
CHAP_ENABLED=false
CHAP_USERNAME=""
CHAP_PASSWORD=""
PKG_MGR=""
OS_NAME=""
OS_VERSION=""

# Cluster ayarları
CLUSTER_MODE=false
CLUSTER_FS_TYPE="gfs2"
CLUSTER_DIGEST="None"
CLUSTER_ALUA_MODE="symmetric"
ISCSI_MAX_BURST=16776192
ISCSI_FIRST_BURST=262144
ISCSI_MAX_R2T=1
ISCSI_LOGIN_TIMEOUT=15
ISCSI_NOPIN_TIMEOUT=30
ISCSI_NOPIN_RESP_TIMEOUT=60

# ─── Dizin / Yapılandırma / Log ───────────────────────────────────────────────
init_dirs() {
    mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
    touch "$LOG_FILE" 2>/dev/null || true
}

save_config() {
    {
        echo "# iSCSI Manager ${VERSION} – $(_ts)"
        echo "ISCSI_TARGET_IQN=\"${ISCSI_TARGET_IQN}\""
        echo "ISCSI_PORTAL_PORT=\"${ISCSI_PORTAL_PORT}\""
        echo "CHAP_ENABLED=${CHAP_ENABLED}"
        echo "CHAP_USERNAME=\"${CHAP_USERNAME}\""
        echo "CHAP_PASSWORD=\"${CHAP_PASSWORD}\""
        echo "CLUSTER_MODE=${CLUSTER_MODE}"
        echo "CLUSTER_FS_TYPE=\"${CLUSTER_FS_TYPE}\""
        echo "CLUSTER_DIGEST=\"${CLUSTER_DIGEST}\""
        echo "CLUSTER_ALUA_MODE=\"${CLUSTER_ALUA_MODE}\""
        echo "ISCSI_MAX_BURST=${ISCSI_MAX_BURST}"
        echo "ISCSI_FIRST_BURST=${ISCSI_FIRST_BURST}"
        echo "ISCSI_MAX_R2T=${ISCSI_MAX_R2T}"
        echo "ISCSI_LOGIN_TIMEOUT=${ISCSI_LOGIN_TIMEOUT}"
        echo "ISCSI_NOPIN_TIMEOUT=${ISCSI_NOPIN_TIMEOUT}"
        echo "ISCSI_NOPIN_RESP_TIMEOUT=${ISCSI_NOPIN_RESP_TIMEOUT}"
        echo "ISCSI_PORTAL_IPS=("
        local x; for x in "${ISCSI_PORTAL_IPS[@]:-}"; do
            [[ -n "$x" ]] && echo "  \"$x\""
        done
        echo ")"
        echo "LUN_DEFINITIONS=("
        for x in "${LUN_DEFINITIONS[@]:-}"; do
            [[ -n "$x" ]] && echo "  \"$x\""
        done
        echo ")"
        echo "ALLOWED_INITIATORS=("
        for x in "${ALLOWED_INITIATORS[@]:-}"; do
            [[ -n "$x" ]] && echo "  \"$x\""
        done
        echo ")"
    } > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    log_ok "Yapılandırma kaydedildi: $CONFIG_FILE"
}

load_config() {
    [[ -f "$CONFIG_FILE" ]] || return 1
    # shellcheck source=/dev/null
    source "$CONFIG_FILE" && log_info "Yapılandırma yüklendi."
}

backup_targetcli() {
    command -v targetcli &>/dev/null || return 0
    local bak="${BACKUP_DIR}/targetcli_$(date +%Y%m%d_%H%M%S).json"
    targetcli saveconfig "$bak" &>/dev/null && log_info "targetcli yedeği: $bak" || true
}

# ─── OS Tespiti ───────────────────────────────────────────────────────────────
detect_os() {
    [[ -f /etc/os-release ]] || die "/etc/os-release bulunamadı."
    # shellcheck source=/dev/null
    source /etc/os-release
    OS_NAME="${NAME:-Bilinmeyen}"
    OS_VERSION="${VERSION_ID:-0}"
    local id="${ID:-}"
    local id_like="${ID_LIKE:-}"
    case "$id" in
        fedora|rhel|centos|ol|rocky|almalinux|centos-stream)
            command -v dnf &>/dev/null && PKG_MGR="dnf" || PKG_MGR="yum" ;;
        *)
            [[ "$id_like" =~ rhel|fedora|centos ]] || die "Desteklenmeyen dağıtım: $OS_NAME"
            command -v dnf &>/dev/null && PKG_MGR="dnf" || PKG_MGR="yum" ;;
    esac
    log_info "Sistem: $OS_NAME $OS_VERSION | Paket yöneticisi: $PKG_MGR"
    $DRY_RUN && log_warn "[DRY-RUN] Sistem değişikliği yapılmaz."
}

# ─── Paket Kurulumu ───────────────────────────────────────────────────────────
install_packages() {
    log_section "PAKET KURULUMU"
    local pkgs=(targetcli lvm2 device-mapper firewalld)
    # RHEL/OL 7 ile uyumluluk
    if [[ "$PKG_MGR" == "yum" ]] || \
       { [[ "${OS_VERSION%%.*}" -le 7 ]] 2>/dev/null; }; then
        pkgs+=(policycoreutils-python)
    else
        pkgs+=(policycoreutils-python-utils)
    fi
    if $DRY_RUN; then log_warn "[DRY-RUN] Kurulacak: ${pkgs[*]}"; return; fi
    "$PKG_MGR" -y install "${pkgs[@]}" --quiet 2>&1 | tee -a "$LOG_FILE"
    log_ok "Temel paketler kuruldu."
}

install_cluster_packages() {
    log_section "CLUSTER PAKETLERİ"
    local pkgs=(sg3_utils device-mapper-multipath)
    case "$CLUSTER_FS_TYPE" in
        gfs2)     pkgs+=(dlm corosync pacemaker pcs gfs2-utils) ;;
        ocfs2)    pkgs+=(ocfs2-tools corosync pacemaker pcs) ;;
        lvmlockd) pkgs+=(lvm2-lockd sanlock corosync pcs) ;;
    esac
    if $DRY_RUN; then log_warn "[DRY-RUN] Cluster paketleri: ${pkgs[*]}"; return; fi
    "$PKG_MGR" -y install "${pkgs[@]}" --quiet 2>&1 | tee -a "$LOG_FILE" \
        && log_ok "Cluster paketleri kuruldu." \
        || log_warn "Bazı paketler kurulamadı – depo erişimini kontrol edin."
}

# ─── targetcli Komut Çalıştırıcı ─────────────────────────────────────────────
_run_targetcli() {
    # Stdin'den targetcli komutları alır
    local tmpf; tmpf=$(mktemp /tmp/iscsi_tcli_XXXXXX.conf)
    cat > "$tmpf"
    if $DRY_RUN; then
        log_warn "[DRY-RUN] targetcli komutları:"
        cat "$tmpf"
    else
        # Zararsız "already exists" uyarılarını filtrele, gerçek hataları göster
        targetcli < "$tmpf" 2>&1 | \
            grep -v -E "already exists in configFS|already mapped to this NodeACL|This MappedLUN already|This NodeACL already|This NetworkPortal already|This Target already|Storage object .* exists$|lun for storage object .* already exists" | \
            tee -a "$LOG_FILE"
    fi
    rm -f "$tmpf"
}

# ─── Backstore İsim Çözümleme ─────────────────────────────────────────────────
_resolve_backstore_name() {
    # Bir block device için mevcut backstore adını bul; yoksa varsayılan üret.
    # $1 = /dev/vg/lv   $2 = lv adı   $3 = lun numarası   $4 = targetcli ls çıktısı
    local dev="$1" default_lv="$2" default_lno="$3" tcli_state="$4"
    local default_bs="${default_lv}_lun${default_lno}"

    if [[ -n "$tcli_state" ]]; then
        # targetcli ls çıktısında dev yolunu içeren backstore satırını bul
        # Örnek: "o- lv_ha_shared02_lun3 ... [/dev/vg_data01/lv_ha_shared03 (50.0GiB) ...]"
        local existing_bs
        existing_bs=$(echo "$tcli_state" \
            | grep -F "$dev" \
            | grep -E "write-thru|write-back|activated|deactivated" \
            | sed -n 's/.*o- \([a-zA-Z0-9_-]*\)\s.*/\1/p' \
            | head -1)
        if [[ -n "$existing_bs" ]]; then
            printf '%s' "$existing_bs"
            return
        fi
    fi
    printf '%s' "$default_bs"
}

# ─── Cluster: Backstore Attribute'ları ───────────────────────────────────────
_cluster_backstore_attrs() {
    # $1 = backstore adı
    # Çıktı (stdout): yalnızca DEĞİŞMESİ gereken targetcli komutları
    # Durum (stderr): ✓ güncel / ↻ güncelleniyor mesajları
    local bs="$1"
    local -a attr_pairs=(
        "emulate_pr:1"  "emulate_caw:1"  "emulate_3pc:1"
        "emulate_tpu:1" "emulate_tpws:1" "enforce_pr_isids:1"
        "emulate_rest_reord:0" "emulate_write_cache:0"
        "emulate_fua_write:1" "emulate_fua_read:1"
    )

    # configfs dizinini bul
    local cfg_base=""
    local d
    for d in /sys/kernel/config/target/core/iblock_*/"${bs}"; do
        [[ -d "$d" ]] && cfg_base="$d" && break
    done

    local changed=0 need_cd=true
    local pair attr val current
    for pair in "${attr_pairs[@]}"; do
        attr="${pair%%:*}"; val="${pair##*:}"
        current=""
        [[ -n "$cfg_base" && -f "${cfg_base}/attrib/${attr}" ]] && \
            current=$(cat "${cfg_base}/attrib/${attr}" 2>/dev/null)
        if [[ "$current" != "$val" ]]; then
            $need_cd && { echo "cd /backstores/block/${bs}"; need_cd=false; }
            echo "set attribute ${attr}=${val}"
            (( changed++ ))
        fi
    done

    if (( changed == 0 )); then
        _p_info "  ✓ Backstore '${bs}' attribute'ları güncel."
    else
        _p_info "  ↻ Backstore '${bs}': ${changed} attribute güncelleniyor."
    fi
}

# ─── Cluster: TPG Parametreleri ──────────────────────────────────────────────
_cluster_tpg_params() {
    # Çıktı (stdout): yalnızca DEĞİŞMESİ gereken targetcli komutları
    local tpg_base="/sys/kernel/config/target/iscsi/${ISCSI_TARGET_IQN}/tpgt_1"

    local -a params=(
        "MaxBurstLength:${ISCSI_MAX_BURST}"
        "FirstBurstLength:${ISCSI_FIRST_BURST}"
        "InitialR2T:No"
        "ImmediateData:Yes"
        "MaxOutstandingR2T:${ISCSI_MAX_R2T}"
        "MaxConnections:1"
        "HeaderDigest:${CLUSTER_DIGEST}"
        "DataDigest:${CLUSTER_DIGEST}"
    )
    local -a attrs=(
        "login_timeout:${ISCSI_LOGIN_TIMEOUT}"
        "default_erl:0"
        "demo_mode_write_protect:0"
        "generate_node_acls:0"
        "cache_dynamic_acls:0"
    )

    local need_cd=true changed=0
    local pair pname pval current

    # Parametreler (param/ dizininde)
    for pair in "${params[@]}"; do
        pname="${pair%%:*}"; pval="${pair##*:}"
        current=""
        [[ -f "${tpg_base}/param/${pname}" ]] && \
            current=$(cat "${tpg_base}/param/${pname}" 2>/dev/null)
        if [[ "$current" != "$pval" ]]; then
            $need_cd && { echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1"; need_cd=false; }
            echo "set parameter ${pname}=${pval}"
            (( changed++ ))
        fi
    done

    # Attribute'lar (attrib/ dizininde)
    for pair in "${attrs[@]}"; do
        pname="${pair%%:*}"; pval="${pair##*:}"
        current=""
        [[ -f "${tpg_base}/attrib/${pname}" ]] && \
            current=$(cat "${tpg_base}/attrib/${pname}" 2>/dev/null)
        if [[ "$current" != "$pval" ]]; then
            $need_cd && { echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1"; need_cd=false; }
            echo "set attribute ${pname}=${pval}"
            (( changed++ ))
        fi
    done

    if (( changed == 0 )); then
        _p_info "  ✓ TPG parametreleri güncel."
    else
        _p_info "  ↻ TPG: ${changed} parametre güncelleniyor."
    fi
}

# ─── LVM ─────────────────────────────────────────────────────────────────────
list_vgs() {
    echo -e "\n${BOLD}Mevcut Volume Group'lar:${NC}"
    if vgs --noheadings -o vg_name,vg_size,vg_free 2>/dev/null | grep -q .; then
        vgs --noheadings -o vg_name,vg_size,vg_free 2>/dev/null | \
            awk '{printf "  %-20s  Toplam: %-10s  Bos: %-10s\n",$1,$2,$3}'
    else
        echo "  (VG bulunamadı)"
    fi
    echo ""
}

create_single_lun() {
    log_section "YENİ LUN EKLE"
    list_vgs

    local vg_lv; vg_lv=$(input_text "VG/LV (örn: vg_data/lv_shared01)" "" validate_vg_lv)
    local vg lv
    IFS='/' read -r vg lv <<< "$vg_lv"

    # Otomatik bir sonraki LUN numarası
    local next=0 x eno
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r _ eno _ <<< "$x"
        (( eno >= next )) && next=$(( eno + 1 ))
    done
    local lun_no; lun_no=$(input_text "LUN numarası" "$next")

    # Çakışma kontrolü
    local x evl en
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r evl en _ <<< "$x"
        if [[ "$en" == "$lun_no" ]]; then
            log_error "LUN${lun_no} zaten tanımlı."; press_enter; return
        fi
        if [[ "$evl" == "$vg_lv" ]]; then
            log_error "${vg_lv} başka bir LUN'a atanmış."; press_enter; return
        fi
    done

    local size; size=$(input_text "Boyut (örn: 100G, 500G)" "" validate_lvm_size)

    echo ""
    log_info "Özet → VG/LV: $vg_lv  |  LUN: $lun_no  |  Boyut: $size"
    $CLUSTER_MODE && log_info "  Cluster modu: PR+CAW+ALUA otomatik uygulanacak."
    confirm "Oluşturulsun mu?" || { press_enter; return; }

    if $DRY_RUN; then
        log_warn "[DRY-RUN] lvcreate -L $size -n $lv $vg"
        LUN_DEFINITIONS+=("${vg_lv}:${lun_no}:${size}")
        save_config; press_enter; return
    fi

    vgs "$vg" &>/dev/null || { log_error "VG '$vg' yok."; press_enter; return; }
    if lvs "${vg}/${lv}" &>/dev/null; then
        log_warn "LV /dev/${vg_lv} zaten var – atlandı."
    else
        lvcreate -L "$size" -n "$lv" "$vg" 2>&1 | tee -a "$LOG_FILE" \
            && log_ok "LV oluşturuldu: /dev/${vg_lv}" \
            || { log_error "LV oluşturulamadı."; press_enter; return; }
    fi

    LUN_DEFINITIONS+=("${vg_lv}:${lun_no}:${size}")
    save_config

    if [[ -n "$ISCSI_TARGET_IQN" ]] && \
       targetcli ls /iscsi 2>/dev/null | grep -q "$ISCSI_TARGET_IQN"; then
        confirm "Backstore + LUN target'a şimdi eklensin mi?" && \
            _add_lun_to_target "$vg" "$lv" "$lun_no"
    fi
    log_ok "LUN${lun_no} eklendi."; press_enter
}

_add_lun_to_target() {
    local vg="$1" lv="$2" lun_no="$3"
    local dev="/dev/${vg}/${lv}"
    [[ -b "$dev" ]] || { log_error "Block device yok: $dev"; return 1; }
    backup_targetcli

    local tcli_state=""
    tcli_state=$(targetcli ls 2>/dev/null) || true
    local bs
    bs=$(_resolve_backstore_name "$dev" "$lv" "$lun_no" "$tcli_state")

    local cmds=""
    cmds=$(
    {
        # Backstore yoksa oluştur
        if ! echo "$tcli_state" | grep -qF "block/${bs}" 2>/dev/null; then
            echo "cd /backstores/block"
            echo "create dev=${dev} name=${bs}"
        fi
        # Attribute'lar — configfs-aware
        if $CLUSTER_MODE; then
            _cluster_backstore_attrs "$bs"
        else
            local cur_wc="" d2
            for d2 in /sys/kernel/config/target/core/iblock_*/"${bs}"/attrib/emulate_write_cache; do
                [[ -f "$d2" ]] && cur_wc=$(cat "$d2" 2>/dev/null) && break
            done
            [[ "$cur_wc" != "0" ]] && echo "cd /backstores/block/${bs}" && echo "set attribute emulate_write_cache=0"
        fi
        # LUN yoksa oluştur
        if ! echo "$tcli_state" | grep -qE "o- lun${lun_no}[^0-9]" 2>/dev/null; then
            echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/luns"
            echo "create /backstores/block/${bs} lun=${lun_no}"
        fi
        # Mapped LUN'lar — configfs ile kontrol
        local cfgfs_tgt="/sys/kernel/config/target/iscsi/${ISCSI_TARGET_IQN}/tpgt_1"
        local ai
        for ai in "${ALLOWED_INITIATORS[@]:-}"; do
            [[ -z "$ai" ]] && continue
            if [[ ! -d "${cfgfs_tgt}/acls/${ai}/lun_${lun_no}" ]]; then
                echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls/${ai}"
                echo "create mapped_lun=${lun_no} tpg_lun_or_backstore=${lun_no}"
            fi
        done
    } )

    if [[ -z "$cmds" ]]; then
        log_ok "LUN${lun_no} zaten güncel – değişiklik gerekmedi."
    else
        {
            echo "$cmds"
            echo "cd /"; echo "saveconfig"; echo "exit"
        } | _run_targetcli && log_ok "LUN${lun_no} target'a eklendi."
    fi
}

list_luns() {
    log_section "MEVCUT LUN'LAR"
    if [[ ${#LUN_DEFINITIONS[@]} -eq 0 ]]; then
        echo "  (Henüz LUN tanımlanmamış)"
    else
        printf "  %-6s %-30s %-10s %s\n" "LUN" "VG/LV" "Boyut" "Durum"
        printf "  %-6s %-30s %-10s %s\n" "──────" "──────────────────────────────" "──────────" "──────"
        local x vg_lv lno sz vg lv st
        for x in "${LUN_DEFINITIONS[@]:-}"; do
            [[ -z "$x" ]] && continue
            IFS=':' read -r vg_lv lno sz <<< "$x"
            IFS='/' read -r vg lv <<< "$vg_lv"
            st="${RED}yok${NC}"
            [[ -b "/dev/${vg}/${lv}" ]] && st="${GREEN}aktif${NC}"
            printf "  %-6s %-30s %-10s " "$lno" "$vg_lv" "$sz"
            echo -e "$st"
        done
    fi
    echo ""
    log_info "targetcli backstoreler:"
    targetcli ls /backstores/block 2>/dev/null || echo "  (erişim yok)"
    press_enter
}

remove_lun() {
    log_section "LUN KALDIR"
    if [[ ${#LUN_DEFINITIONS[@]} -eq 0 ]]; then
        log_warn "Silinecek LUN yok."; press_enter; return
    fi
    local i=1 x vg_lv lno sz
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv lno sz <<< "$x"
        echo "  ${i}. LUN${lno} → /dev/${vg_lv} (${sz})"
        (( i++ ))
    done
    local idx; idx=$(read_choice $(( i - 1 )))
    local to_del="${LUN_DEFINITIONS[$((idx-1))]}"
    local del_vg_lv del_lno del_vg del_lv
    IFS=':' read -r del_vg_lv del_lno _ <<< "$to_del"
    IFS='/' read -r del_vg del_lv <<< "$del_vg_lv"
    local del_bs="${del_lv}_lun${del_lno}"

    echo -e "${YELLOW}  Not: LV fiziksel olarak silinmez, sadece targetcli'den kaldırılır.${NC}"
    confirm "LUN${del_lno} (${del_vg_lv}) kaldırılsın mı?" "h" || { press_enter; return; }
    backup_targetcli

    if [[ -n "$ISCSI_TARGET_IQN" ]]; then
        {
            local ai
            for ai in "${ALLOWED_INITIATORS[@]:-}"; do
                [[ -z "$ai" ]] && continue
                echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls/${ai}"
                echo "delete mapped_lun=${del_lno}"
            done
            echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/luns"
            echo "delete lun${del_lno}"
            echo "cd /backstores/block"
            echo "delete ${del_bs}"
            echo "cd /"; echo "saveconfig"; echo "exit"
        } | _run_targetcli
    fi

    local nl=() x2
    for x2 in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x2" || "$x2" == "$to_del" ]] && continue
        nl+=("$x2")
    done
    LUN_DEFINITIONS=(); [[ ${#nl[@]} -gt 0 ]] && LUN_DEFINITIONS=("${nl[@]}")
    save_config
    log_ok "LUN${del_lno} kaldırıldı."
    press_enter
}

# ─── Initiator ────────────────────────────────────────────────────────────────
list_initiators() {
    log_section "INITIATOR'LAR"
    if [[ ${#ALLOWED_INITIATORS[@]} -eq 0 ]]; then
        echo "  (Henüz initiator tanımlanmamış)"
    else
        local i=1 ai
        for ai in "${ALLOWED_INITIATORS[@]:-}"; do
            [[ -z "$ai" ]] && continue
            echo "  ${i}. ${ai}"
            (( i++ ))
        done
    fi
    press_enter
}

add_initiator() {
    log_section "INITIATOR EKLE"
    echo -e "  ${YELLOW}Initiator IQN'ini öğrenmek için client'ta:${NC}"
    echo -e "  ${BOLD}cat /etc/iscsi/initiatorname.iscsi${NC}\n"
    local iqn; iqn=$(input_text "Initiator IQN" "" validate_iqn)
    local ai
    for ai in "${ALLOWED_INITIATORS[@]:-}"; do
        [[ "$ai" == "$iqn" ]] && { log_warn "Bu initiator zaten tanımlı."; press_enter; return; }
    done
    ALLOWED_INITIATORS+=("$iqn")
    save_config
    if [[ -n "$ISCSI_TARGET_IQN" ]] && \
       targetcli ls /iscsi 2>/dev/null | grep -q "$ISCSI_TARGET_IQN"; then
        confirm "ACL şimdi uygulansın mı?" && _apply_acl "$iqn"
    fi
    log_ok "Eklendi: ${iqn}"
    press_enter
}

_apply_acl() {
    local iqn="$1"
    backup_targetcli
    {
        echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls"
        echo "create ${iqn}"
        local x vg_lv lno vg lv
        for x in "${LUN_DEFINITIONS[@]:-}"; do
            [[ -z "$x" ]] && continue
            IFS=':' read -r vg_lv lno _ <<< "$x"
            IFS='/' read -r vg lv <<< "$vg_lv"
            [[ -b "/dev/${vg}/${lv}" ]] || continue
            echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls/${iqn}"
            echo "create mapped_lun=${lno} tpg_lun_or_backstore=${lno}"
        done
        echo "cd /"; echo "saveconfig"; echo "exit"
    } | _run_targetcli && log_ok "ACL uygulandı: ${iqn}"
}

remove_initiator() {
    log_section "INITIATOR SİL"
    if [[ ${#ALLOWED_INITIATORS[@]} -eq 0 ]]; then
        log_warn "Silinecek initiator yok."; press_enter; return
    fi
    local i=1 ai
    for ai in "${ALLOWED_INITIATORS[@]:-}"; do
        [[ -z "$ai" ]] && continue
        echo "  ${i}. ${ai}"; (( i++ ))
    done
    local idx; idx=$(read_choice $(( i - 1 )))
    local to_del="${ALLOWED_INITIATORS[$((idx-1))]}"
    confirm "${RED}${to_del}${NC} silinsin mi?" "h" || { press_enter; return; }
    backup_targetcli

    if [[ -n "$ISCSI_TARGET_IQN" ]]; then
        {
            echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls"
            echo "delete ${to_del}"
            echo "cd /"; echo "saveconfig"; echo "exit"
        } | _run_targetcli
    fi

    local nl=() ai2
    for ai2 in "${ALLOWED_INITIATORS[@]:-}"; do
        [[ -z "$ai2" || "$ai2" == "$to_del" ]] && continue
        nl+=("$ai2")
    done
    ALLOWED_INITIATORS=(); [[ ${#nl[@]} -gt 0 ]] && ALLOWED_INITIATORS=("${nl[@]}")
    save_config
    log_ok "Silindi: ${to_del}"
    press_enter
}

map_lun_to_initiator() {
    log_section "LUN → INITIATOR BAĞLA"
    if [[ ${#ALLOWED_INITIATORS[@]} -eq 0 ]]; then log_warn "Önce initiator ekleyin."; press_enter; return; fi
    if [[ ${#LUN_DEFINITIONS[@]}    -eq 0 ]]; then log_warn "Önce LUN ekleyin.";       press_enter; return; fi
    if [[ -z "$ISCSI_TARGET_IQN"         ]]; then log_warn "Target IQN tanımlanmamış."; press_enter; return; fi

    local i=1 ai
    echo -e "\n${BOLD}Initiator seçin:${NC}"
    for ai in "${ALLOWED_INITIATORS[@]:-}"; do
        [[ -z "$ai" ]] && continue; echo "  ${i}. ${ai}"; (( i++ ))
    done
    local ii; ii=$(read_choice $(( i - 1 )))
    local sel_init="${ALLOWED_INITIATORS[$((ii-1))]}"

    i=1
    echo -e "\n${BOLD}LUN seçin:${NC}"
    local x vg_lv lno sz
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv lno sz <<< "$x"
        echo "  ${i}. LUN${lno} → /dev/${vg_lv} (${sz})"; (( i++ ))
    done
    local li; li=$(read_choice $(( i - 1 )))
    IFS=':' read -r _ sel_lno _ <<< "${LUN_DEFINITIONS[$((li-1))]}"

    confirm "LUN${sel_lno} → ${sel_init} bağlansın mı?" || { press_enter; return; }
    backup_targetcli
    {
        echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls/${sel_init}"
        echo "create mapped_lun=${sel_lno} tpg_lun_or_backstore=${sel_lno}"
        echo "cd /"; echo "saveconfig"; echo "exit"
    } | _run_targetcli && log_ok "Bağlandı."
    press_enter
}

# ─── Portal / CHAP ────────────────────────────────────────────────────────────
manage_portals() {
    log_section "PORTAL YÖNETİMİ"
    echo -e "\n${BOLD}Mevcut portaller:${NC}"
    if [[ ${#ISCSI_PORTAL_IPS[@]} -eq 0 ]]; then
        echo "  (yok)"
    else
        local i=1 ip
        for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
            [[ -z "$ip" ]] && continue
            echo "  ${i}. ${ip}:${ISCSI_PORTAL_PORT}"; (( i++ ))
        done
    fi
    echo ""
    show_menu "Portal Yönetimi" "Portal Ekle" "Portal Sil" "Port Numarası Değiştir" "Geri"
    local ch; ch=$(read_choice 4)
    case "$ch" in
        1)
            local ip; ip=$(input_text "Yeni portal IP" "" validate_ip)
            local ex
            for ex in "${ISCSI_PORTAL_IPS[@]:-}"; do
                [[ "$ex" == "$ip" ]] && { log_warn "Bu IP zaten tanımlı."; press_enter; return; }
            done
            ISCSI_PORTAL_IPS+=("$ip"); save_config; log_ok "Eklendi: $ip"
            ;;
        2)
            if [[ ${#ISCSI_PORTAL_IPS[@]} -le 1 ]]; then
                log_warn "En az 1 portal gereklidir."; press_enter; return
            fi
            local i=1 ip
            for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
                [[ -z "$ip" ]] && continue; echo "  ${i}. $ip"; (( i++ ))
            done
            local idx; idx=$(read_choice $(( i - 1 )))
            local td="${ISCSI_PORTAL_IPS[$((idx-1))]}"
            confirm "$td silinsin mi?" "h" || { press_enter; return; }
            local nl=() ip2
            for ip2 in "${ISCSI_PORTAL_IPS[@]:-}"; do
                [[ -z "$ip2" || "$ip2" == "$td" ]] && continue; nl+=("$ip2")
            done
            ISCSI_PORTAL_IPS=(); [[ ${#nl[@]} -gt 0 ]] && ISCSI_PORTAL_IPS=("${nl[@]}"); save_config; log_ok "Silindi."
            ;;
        3)
            ISCSI_PORTAL_PORT=$(input_text "Yeni port numarası" "$ISCSI_PORTAL_PORT" validate_port)
            save_config; log_ok "Port: $ISCSI_PORTAL_PORT"
            ;;
        4) return ;;
    esac
    press_enter
}

manage_chap() {
    log_section "CHAP KİMLİK DOĞRULAMA"
    local st="${RED}Devre Dışı${NC}"
    $CHAP_ENABLED && st="${GREEN}Aktif (${CHAP_USERNAME})${NC}"
    echo -e "  Mevcut durum: ${st}\n"
    show_menu "CHAP" "Etkinleştir / Güncelle" "Devre Dışı Bırak" "Geri"
    local ch; ch=$(read_choice 3)
    case "$ch" in
        1)
            CHAP_USERNAME=$(input_text "Kullanıcı adı" "${CHAP_USERNAME:-iscsi_user}" validate_nonempty)
            CHAP_PASSWORD=$(input_password "Parola (min 12 karakter)")
            CHAP_ENABLED=true; save_config; log_ok "CHAP etkinleştirildi."
            ;;
        2) CHAP_ENABLED=false; save_config; log_ok "CHAP devre dışı bırakıldı." ;;
        3) return ;;
    esac
    press_enter
}

# ─── iSCSI Target Yapılandırması ──────────────────────────────────────────────
configure_iscsi_target() {
    log_section "iSCSI TARGET UYGULANIYOR"
    if [[ -z "$ISCSI_TARGET_IQN" ]]; then log_error "Target IQN tanımlanmamış!"; return 1; fi
    if [[ ${#ISCSI_PORTAL_IPS[@]} -eq 0 ]]; then log_error "Portal IP tanımlanmamış!"; return 1; fi
    backup_targetcli

    # ── Mevcut durum analizi ──
    local tcli_state=""
    local cfgfs_tgt="/sys/kernel/config/target/iscsi/${ISCSI_TARGET_IQN}/tpgt_1"
    if ! $DRY_RUN; then
        tcli_state=$(targetcli ls 2>/dev/null) || true
    fi

    local new_count=0 exist_count=0 cmd_count=0
    local cmds=""
    cmds=$(
    {
        # ── 1. Backstoreler ──
        local x vg_lv lno vg lv bs dev
        for x in "${LUN_DEFINITIONS[@]:-}"; do
            [[ -z "$x" ]] && continue
            IFS=':' read -r vg_lv lno _ <<< "$x"
            IFS='/' read -r vg lv <<< "$vg_lv"
            dev="/dev/${vg}/${lv}"
            [[ -b "$dev" ]] || { _p_warn "  $dev yok – atlandı."; continue; }

            bs=$(_resolve_backstore_name "$dev" "$lv" "$lno" "$tcli_state")

            if echo "$tcli_state" | grep -qF "block/${bs}" 2>/dev/null; then
                _p_info "  ✓ Backstore '${bs}' zaten var."
            else
                echo "cd /backstores/block"
                echo "create dev=${dev} name=${bs}"
            fi

            # Attribute'lar — configfs'den oku, farklı olanları gönder
            if $CLUSTER_MODE; then
                _cluster_backstore_attrs "$bs"
            else
                local cur_wc=""
                local d2
                for d2 in /sys/kernel/config/target/core/iblock_*/"${bs}"/attrib/emulate_write_cache; do
                    [[ -f "$d2" ]] && cur_wc=$(cat "$d2" 2>/dev/null) && break
                done
                if [[ "$cur_wc" != "0" ]]; then
                    echo "cd /backstores/block/${bs}"
                    echo "set attribute emulate_write_cache=0"
                fi
            fi
        done

        # ── 2. Target ──
        if echo "$tcli_state" | grep -qF "$ISCSI_TARGET_IQN" 2>/dev/null; then
            _p_info "  ✓ Target '${ISCSI_TARGET_IQN}' zaten var."
        else
            echo "cd /iscsi"
            echo "create ${ISCSI_TARGET_IQN}"
        fi

        # ── 3. Portaller ──
        if echo "$tcli_state" | grep -qF "0.0.0.0:3260" 2>/dev/null; then
            echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/portals"
            echo "delete 0.0.0.0 3260"
        fi
        local ip
        for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
            [[ -z "$ip" ]] && continue
            if echo "$tcli_state" | grep -qF "${ip}:${ISCSI_PORTAL_PORT}" 2>/dev/null; then
                _p_info "  ✓ Portal ${ip}:${ISCSI_PORTAL_PORT} zaten var."
            else
                echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/portals"
                echo "create ${ip} ${ISCSI_PORTAL_PORT}"
            fi
        done

        # ── 4. LUN eşlemeleri ──
        for x in "${LUN_DEFINITIONS[@]:-}"; do
            [[ -z "$x" ]] && continue
            IFS=':' read -r vg_lv lno _ <<< "$x"
            IFS='/' read -r vg lv <<< "$vg_lv"
            dev="/dev/${vg}/${lv}"
            [[ -b "$dev" ]] || continue
            bs=$(_resolve_backstore_name "$dev" "$lv" "$lno" "$tcli_state")
            if echo "$tcli_state" | grep -qE "o- lun${lno}[^0-9]" 2>/dev/null; then
                _p_info "  ✓ LUN${lno} zaten var."
            else
                echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/luns"
                echo "create /backstores/block/${bs} lun=${lno}"
            fi
        done

        # ── 5. TPG parametreleri — configfs'den oku, farklı olanları gönder ──
        if $CLUSTER_MODE; then
            _cluster_tpg_params
        else
            local -a tpg_checks=(
                "attrib:demo_mode_write_protect:0"
                "attrib:generate_node_acls:0"
                "attrib:cache_dynamic_acls:0"
                "param:InitialR2T:No"
                "param:ImmediateData:Yes"
            )
            local tpc tc_dir tc_name tc_val tc_cur need_tpg_cd=true
            for tpc in "${tpg_checks[@]}"; do
                IFS=':' read -r tc_dir tc_name tc_val <<< "$tpc"
                tc_cur=""
                [[ -f "${cfgfs_tgt}/${tc_dir}/${tc_name}" ]] && \
                    tc_cur=$(cat "${cfgfs_tgt}/${tc_dir}/${tc_name}" 2>/dev/null)
                if [[ "$tc_cur" != "$tc_val" ]]; then
                    $need_tpg_cd && { echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1"; need_tpg_cd=false; }
                    [[ "$tc_dir" == "param" ]] \
                        && echo "set parameter ${tc_name}=${tc_val}" \
                        || echo "set attribute ${tc_name}=${tc_val}"
                fi
            done
        fi

        # ── 6. CHAP ──
        local auth_cur=""
        [[ -f "${cfgfs_tgt}/attrib/authentication" ]] && \
            auth_cur=$(cat "${cfgfs_tgt}/attrib/authentication" 2>/dev/null)
        if $CHAP_ENABLED; then
            if [[ "$auth_cur" != "1" ]]; then
                echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1"
                echo "set auth userid=${CHAP_USERNAME}"
                echo "set auth password=${CHAP_PASSWORD}"
                echo "set attribute authentication=1"
            fi
        else
            if [[ "$auth_cur" != "0" && -n "$auth_cur" ]]; then
                echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1"
                echo "set attribute authentication=0"
            fi
        fi

        # ── 7. ACL + Mapped LUN'lar ──
        local ai
        for ai in "${ALLOWED_INITIATORS[@]:-}"; do
            [[ -z "$ai" ]] && continue
            local acl_cfgfs="${cfgfs_tgt}/acls/${ai}"
            if [[ -d "$acl_cfgfs" ]]; then
                _p_info "  ✓ ACL '${ai}' zaten var."
            else
                echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls"
                echo "create ${ai}"
            fi
            # Mapped LUN'lar
            for x in "${LUN_DEFINITIONS[@]:-}"; do
                [[ -z "$x" ]] && continue
                IFS=':' read -r vg_lv lno _ <<< "$x"
                IFS='/' read -r vg lv <<< "$vg_lv"
                [[ -b "/dev/${vg}/${lv}" ]] || continue
                if [[ -d "${acl_cfgfs}/lun_${lno}" ]]; then
                    _p_info "  ✓ MappedLUN${lno} → ${ai} zaten var."
                else
                    echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls/${ai}"
                    echo "create mapped_lun=${lno} tpg_lun_or_backstore=${lno}"
                fi
            done
        done
    } )

    # ── Komut varsa çalıştır, yoksa "güncel" de ──
    if [[ -z "$cmds" ]]; then
        log_ok "Yapılandırma tamamen güncel – değişiklik gerekmedi."
    else
        {
            echo "$cmds"
            echo "cd /"; echo "saveconfig"; echo "exit"
        } | _run_targetcli
        log_ok "Target yapılandırması güncellendi."
    fi
}

# ─── Cluster Optimizasyonları ─────────────────────────────────────────────────
configure_kernel_params() {
    log_section "KERNEL AĞ OPTİMİZASYONU"
    if $DRY_RUN; then
        log_warn "[DRY-RUN] Yazılacak: $SYSCTL_FILE"; return
    fi
    local new_content
    new_content=$(cat <<SYSCTL
# iSCSI Cluster Kernel Parametreleri – iscsi-manager $VERSION
net.core.rmem_max           = 16777216
net.core.wmem_max           = 16777216
net.core.rmem_default       = 4194304
net.core.wmem_default       = 4194304
net.ipv4.tcp_rmem           = 4096 4194304 16777216
net.ipv4.tcp_wmem           = 4096 4194304 16777216
net.core.netdev_max_backlog = 50000
net.core.somaxconn          = 4096
net.ipv4.tcp_timestamps     = 1
net.ipv4.tcp_sack           = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_keepalive_time   = 10
net.ipv4.tcp_keepalive_intvl  = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_fin_timeout      = 30
net.ipv4.tcp_syncookies       = 1
vm.swappiness               = 10
vm.dirty_ratio              = 5
vm.dirty_background_ratio   = 2
SYSCTL
    )
    # Aynı içerikse atla
    if [[ -f "$SYSCTL_FILE" ]]; then
        local existing; existing=$(cat "$SYSCTL_FILE" 2>/dev/null)
        if [[ "$existing" == "$new_content" ]]; then
            log_ok "Kernel parametreleri zaten güncel: $SYSCTL_FILE"
            return
        fi
    fi
    echo "$new_content" > "$SYSCTL_FILE"
    sysctl --system 2>&1 | grep -E "(Applying.*99-iscsi|Failed)" | tee -a "$LOG_FILE" || true
    log_ok "Kernel parametreleri uygulandı: $SYSCTL_FILE"
}

configure_io_scheduler() {
    log_section "I/O SCHEDULER AYARI"
    local applied=0
    if ! $DRY_RUN; then
        echo "# iSCSI Cluster I/O Scheduler – iscsi-manager $VERSION" > "$UDEV_FILE"
    fi
    # Zaten işlenmiş diskleri takip et (aynı fiziksel disk birden fazla LV altında olabilir)
    declare -A _seen_slaves
    local x vg_lv vg lv dev dm_dev dm_name
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv _ _ <<< "$x"
        IFS='/' read -r vg lv <<< "$vg_lv"
        dev="/dev/${vg}/${lv}"
        [[ -b "$dev" ]] || continue
        dm_dev=$(readlink -f "$dev" 2>/dev/null) || continue
        [[ -z "$dm_dev" ]] && continue
        dm_name=$(basename "$dm_dev")
        [[ -d "/sys/block/${dm_name}/slaves" ]] || continue
        local slave
        for slave in "/sys/block/${dm_name}/slaves/"/*/; do
            slave=$(basename "$slave")
            [[ -z "$slave" || "$slave" == "*" ]] && continue
            # Zaten işlendi mi?
            [[ -n "${_seen_slaves[$slave]:-}" ]] && continue
            _seen_slaves[$slave]=1
            local rot=1 sched dtype
            [[ -f "/sys/block/${slave}/queue/rotational" ]] && \
                rot=$(cat "/sys/block/${slave}/queue/rotational")
            if   [[ "$slave" =~ ^nvme ]]; then sched="none";         dtype="NVMe"
            elif [[ "$rot"   == "0"   ]]; then sched="mq-deadline";  dtype="SSD"
            else                               sched="mq-deadline";  dtype="HDD"
            fi
            log_info "  ${slave} (${dtype}) → ${sched}"
            if $DRY_RUN; then
                log_warn "  [DRY-RUN] echo ${sched} > /sys/block/${slave}/queue/scheduler"
            else
                [[ -f "/sys/block/${slave}/queue/scheduler" ]] && \
                    echo "$sched" > "/sys/block/${slave}/queue/scheduler" 2>/dev/null || true
                echo "ACTION==\"add|change\", KERNEL==\"${slave}\", ATTR{queue/scheduler}=\"${sched}\"" \
                    >> "$UDEV_FILE"
            fi
            (( applied++ ))
        done
    done
    if (( applied > 0 )) && ! $DRY_RUN; then
        udevadm control --reload-rules 2>/dev/null || true
        log_ok "I/O scheduler udev kuralları: $UDEV_FILE"
    elif (( applied == 0 )); then
        log_warn "Aktif block cihaz bulunamadı (LUN'lar oluşturulmamış olabilir)."
    fi
}

configure_lvm_target_server() {
    log_section "LVM TARGET SUNUCU AYARI"
    local lvm_conf="/etc/lvm/lvm.conf"
    if $DRY_RUN; then
        log_warn "[DRY-RUN] lvm.conf: write_cache_state=0, use_lvmpolld=1"; return
    fi
    if [[ -f "$lvm_conf" ]]; then
        cp "$lvm_conf" "${BACKUP_DIR}/lvm.conf.$(date +%Y%m%d%H%M%S).bak"
        sed -i 's/^\s*write_cache_state\s*=.*/\twrite_cache_state = 0/' "$lvm_conf"
        sed -i 's/^\s*use_lvmpolld\s*=.*/\tuse_lvmpolld = 1/' "$lvm_conf"
        log_ok "lvm.conf güncellendi."
    else
        log_warn "lvm.conf bulunamadı: $lvm_conf"
    fi
}

apply_cluster_optimizations() {
    log_section "CLUSTER OPTİMİZASYONLARI"
    CLUSTER_MODE=true
    save_config
    install_cluster_packages

    # Mevcut backstorelara cluster attribute'larını uygula
    if [[ -n "$ISCSI_TARGET_IQN" ]]; then
        local tcli_state=""
        tcli_state=$(targetcli ls 2>/dev/null) || true

        local x vg_lv lno vg lv bs dev found=0
        local cmds=""
        cmds=$(
        {
            for x in "${LUN_DEFINITIONS[@]:-}"; do
                [[ -z "$x" ]] && continue
                IFS=':' read -r vg_lv lno _ <<< "$x"
                IFS='/' read -r vg lv <<< "$vg_lv"
                dev="/dev/${vg}/${lv}"
                bs=$(_resolve_backstore_name "$dev" "$lv" "$lno" "$tcli_state")
                # Backstore mevcut mu?
                local bs_exists=false
                local d
                for d in /sys/kernel/config/target/core/iblock_*/"${bs}"; do
                    [[ -d "$d" ]] && bs_exists=true && break
                done
                $bs_exists || continue
                _cluster_backstore_attrs "$bs"
                (( found++ ))
            done
            if (( found > 0 )); then
                _cluster_tpg_params
            fi
        } )

        if [[ -n "$cmds" ]]; then
            backup_targetcli
            {
                echo "$cmds"
                echo "cd /"; echo "saveconfig"; echo "exit"
            } | _run_targetcli
            log_ok "$found backstore cluster attribute kontrol edildi."
        elif (( found > 0 )); then
            log_ok "$found backstore kontrol edildi – tüm attribute'lar güncel."
        else
            log_warn "Aktif backstore bulunamadı – önce LUN'ları oluşturun."
        fi
    fi

    configure_kernel_params
    configure_io_scheduler
    configure_lvm_target_server
    log_ok "Cluster optimizasyonları tamamlandı."
    press_enter
}

configure_alua_groups() {
    log_section "ALUA PORT GROUP"
    [[ -n "$ISCSI_TARGET_IQN" ]] || { log_warn "Target IQN yok."; press_enter; return; }
    [[ ${#LUN_DEFINITIONS[@]} -gt 0 ]] || { log_warn "LUN yok."; press_enter; return; }
    backup_targetcli
    local x vg_lv lno vg lv bs
    {
        for x in "${LUN_DEFINITIONS[@]:-}"; do
            [[ -z "$x" ]] && continue
            IFS=':' read -r vg_lv lno _ <<< "$x"
            IFS='/' read -r vg lv <<< "$vg_lv"
            bs="${lv}_lun${lno}"
            targetcli ls "/backstores/block/${bs}" &>/dev/null 2>&1 || continue
            echo "cd /backstores/block/${bs}/alua/default_tg_pt_gp"
            echo "set alua_access_state=0"
            echo "set alua_access_type=1"
            echo "set alua_write_metadata=1"
        done
        echo "cd /"; echo "saveconfig"; echo "exit"
    } | _run_targetcli
    log_ok "ALUA port group yapılandırıldı (${CLUSTER_ALUA_MODE})."
    press_enter
}

verify_scsi_pr() {
    log_section "SCSI PR DOĞRULAMA"
    if ! command -v sg_persist &>/dev/null; then
        log_warn "sg_persist bulunamadı. Kurulum: $PKG_MGR install sg3_utils"
        press_enter; return
    fi
    if [[ ${#LUN_DEFINITIONS[@]} -eq 0 ]]; then
        log_warn "Test edilecek LUN yok."; press_enter; return
    fi
    local i=1 x vg_lv lno
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv lno _ <<< "$x"
        echo "  ${i}. LUN${lno} → /dev/${vg_lv}"; (( i++ ))
    done
    local idx; idx=$(read_choice $(( i - 1 )))
    local sel="${LUN_DEFINITIONS[$((idx-1))]}"
    IFS=':' read -r vg_lv _ _ <<< "$sel"
    local dev="/dev/${vg_lv}"
    [[ -b "$dev" ]] || { log_error "Block device yok: $dev"; press_enter; return; }

    echo -e "\n${BOLD}PR Yetenekleri:${NC}"
    sg_persist --in --report-capabilities "$dev" 2>&1 | tee -a "$LOG_FILE"
    echo -e "\n${BOLD}Kayıtlı PR Anahtarları:${NC}"
    sg_persist --in --read-keys "$dev" 2>&1 | tee -a "$LOG_FILE"
    echo -e "\n${BOLD}Aktif Rezervasyonlar:${NC}"
    sg_persist --in --read-reservation "$dev" 2>&1 | tee -a "$LOG_FILE"
    echo ""

    if confirm "Test PR anahtarı kaydet (hemen silinecek)?" "h"; then
        local key="0x0000000000CAFE01"
        if sg_persist --out --register --param-rk=0 --param-sark="$key" "$dev" \
           2>&1 | tee -a "$LOG_FILE"; then
            log_ok "PR kaydı başarılı → emulate_pr çalışıyor!"
            sg_persist --out --register --param-rk="$key" --param-sark=0 "$dev" \
                &>/dev/null && log_ok "Test anahtarı silindi." \
                || log_warn "Silme başarısız. Manuel: sg_persist --out --register --param-rk=${key} --param-sark=0 ${dev}"
        else
            log_error "PR kaydı başarısız! emulate_pr=1 ayarını kontrol edin."
        fi
    fi
    press_enter
}

generate_multipath_config() {
    log_section "MULTİPATH KONFİGÜRASYON ÜRETECİ"
    local alua_policy prio_calc
    case "$CLUSTER_ALUA_MODE" in
        asymmetric) alua_policy="group_by_prio"; prio_calc="alua" ;;
        *)          alua_policy="multibus";       prio_calc="const" ;;
    esac
    local disco_lines="" login_lines="" ip
    for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
        [[ -z "$ip" ]] && continue
        disco_lines+="#    iscsiadm -m discovery -t st -p ${ip}:${ISCSI_PORTAL_PORT}"$'\n'
        login_lines+="#    iscsiadm -m node -T ${ISCSI_TARGET_IQN} -p ${ip}:${ISCSI_PORTAL_PORT} --login"$'\n'
    done
    {
        echo "# iSCSI Cluster Multipath Konfigurasyonu"
        echo "# Olusturuldu : $(_ts)"
        echo "# Target      : ${ISCSI_TARGET_IQN}"
        echo "# ALUA Modu   : ${CLUSTER_ALUA_MODE}"
        echo "defaults {"
        echo "    polling_interval          5"
        echo "    path_grouping_policy      ${alua_policy}"
        echo "    path_checker              tur"
        echo "    failback                  immediate"
        echo "    no_path_retry             fail"
        echo "    prio                      ${prio_calc}"
        echo "    fast_io_fail_tmo          5"
        echo "    dev_loss_tmo              60"
        echo "    user_friendly_names       yes"
        echo "    features                  \"1 queue_if_no_path\""
        echo "    hardware_handler          \"1 alua\""
        echo "}"
        echo "devices {"
        echo "    device {"
        echo "        vendor               \"LIO-ORG\""
        echo "        product              \".*\""
        echo "        hardware_handler     \"1 alua\""
        echo "        path_grouping_policy ${alua_policy}"
        echo "        prio                 ${prio_calc}"
        echo "        path_checker         tur"
        echo "        failback             immediate"
        echo "        no_path_retry        fail"
        echo "        fast_io_fail_tmo     5"
        echo "        dev_loss_tmo         60"
        echo "        features             \"1 queue_if_no_path\""
        echo "        rr_min_io            100"
        echo "        rr_weight            uniform"
        echo "    }"
        echo "}"
        echo ""
        echo "# Cluster node kurulum adimlari:"
        echo "# 1. dnf install device-mapper-multipath iscsi-initiator-utils"
        echo "# 2. systemctl enable --now iscsid multipathd"
        echo "# 3. Discovery:"
        printf '%s' "$disco_lines"
        echo "# 4. Login:"
        printf '%s' "$login_lines"
        echo "# 5. Yollari dogrula: multipath -ll"
    } > "$MULTIPATH_OUT"
    log_ok "Konfigürasyon kaydedildi: $MULTIPATH_OUT"
    echo -e "\n${YELLOW}Her cluster node'a kopyalayın:${NC}"
    local ai
    for ai in "${ALLOWED_INITIATORS[@]:-}"; do
        [[ -z "$ai" ]] && continue
        echo "  scp $MULTIPATH_OUT root@${ai##*:}:/etc/multipath.conf"
    done
    echo "  systemctl enable --now multipathd && multipath -ll"
    press_enter
}

# ─── Cluster Kılavuzu ─────────────────────────────────────────────────────────
show_cluster_guide() {
    local pg=1
    while true; do
        clear
        case "$pg" in
        1)
            echo -e "${CYAN}${BOLD}══ SAYFA 1/5: Genel Mimari ══${NC}\n"
            cat << 'INFO'
  ┌──────────── iSCSI Cluster Mimarisi ────────────────┐
  │  iSCSI TARGET SUNUCU (bu makine)                    │
  │  LVM LV → targetcli backstore → iSCSI LUN           │
  │  ● emulate_pr=1   SCSI Persistent Reservations      │
  │  ● emulate_caw=1  Compare And Write (atomik)         │
  │  ● ALUA portgroup (çoklu yol önceliği)               │
  ├──────────────────────────────────────────────────────┤
  │   NIC-1 (Storage Ağı 1)    NIC-2 (Storage Ağı 2)   │
  ├──────────────────┬──────────────────────────────────┤
  │  Node 1          │  Node 2                           │
  │  iscsi-initiator │  iscsi-initiator                  │
  │  dm-multipath    │  dm-multipath                     │
  │  GFS2/OCFS2      │  GFS2/OCFS2                      │
  │  Pacemaker       │  Pacemaker                        │
  └──────────────────┴──────────────────────────────────┘
    ←── Cluster heartbeat ağı (AYRI NIC!) ──→

  TEMEL KURALLAR:
  ① iSCSI ağı ve heartbeat ağı AYRI NIC olmalı
  ② Jumbo frame (MTU 9000) iSCSI verimini artırır
  ③ Her LUN için en az 2 farklı yol (MPIO) olmalı
  ④ STONITH/fencing olmadan cluster GÜVENLİ DEĞİLDİR
INFO
            ;;
        2)
            echo -e "${CYAN}${BOLD}══ SAYFA 2/5: TARGET Kurulum Adımları ══${NC}\n"
            cat << 'INFO'
  ADIM 1 – Temel kurulum
    Ana Menü → Tam Kurulum Sihirbazı
    ● IQN, portal IP, LUN, initiator IQN, CHAP girin.
    ● Cluster modu sorusuna EVET deyin.

  ADIM 2 – Cluster modu otomatik yapar:
    ✓ emulate_pr=1         SCSI Persistent Reservations
    ✓ emulate_caw=1        Compare And Write (atomik)
    ✓ emulate_3pc=1        Third Party Copy (XCOPY)
    ✓ emulate_tpu/tpws=1   UNMAP / WRITE SAME
    ✓ enforce_pr_isids=1   Session izolasyonu
    ✓ emulate_rest_reord=0 I/O sıralama kısıtı
    ✓ emulate_write_cache=0 Write-through
    ✓ emulate_fua_write=1  FUA desteği
    ✓ Kernel TCP buffer + keepalive sysctl
    ✓ I/O scheduler (SSD→mq-deadline, NVMe→none)
    ✓ LVM write-through ayarı

  ADIM 3 – SCSI PR doğrula
    Cluster Menüsü → SCSI PR Doğrulama

  ADIM 4 – Multipath config üret ve node'lara dağıt
    Cluster Menüsü → Multipath Konfigürasyon Üret
INFO
            ;;
        3)
            echo -e "${CYAN}${BOLD}══ SAYFA 3/5: Cluster Node (Initiator) Kurulumu ══${NC}\n"
            echo "  # Her cluster node'da (initiator makinede):"
            echo ""
            echo "  dnf install iscsi-initiator-utils device-mapper-multipath sg3_utils"
            echo ""
            echo "  # Her node'da FARKLI bir InitiatorName kullanın!"
            echo "  echo 'InitiatorName=iqn.YYYY-MM.com.sirket:node1' \\"
            echo "       > /etc/iscsi/initiatorname.iscsi"
            echo ""
            echo "  systemctl enable --now iscsid"
            echo ""
            echo "  # Target keşfi:"
            local ip
            for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
                [[ -z "$ip" ]] && continue
                echo "  iscsiadm -m discovery -t st -p ${ip}:${ISCSI_PORTAL_PORT}"
            done
            [[ ${#ISCSI_PORTAL_IPS[@]} -eq 0 ]] && \
                echo "  iscsiadm -m discovery -t st -p <PORTAL_IP>:3260"
            echo ""
            echo "  # MPIO için TÜM portallardan login:"
            for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
                [[ -z "$ip" ]] && continue
                echo "  iscsiadm -m node -T ${ISCSI_TARGET_IQN:-<TARGET_IQN>} \\"
                echo "           -p ${ip}:${ISCSI_PORTAL_PORT} --login"
            done
            echo ""
            echo "  # Multipath konfigürasyonunu target'tan kopyala:"
            echo "  scp target:${MULTIPATH_OUT} /etc/multipath.conf"
            echo "  systemctl enable --now multipathd"
            echo "  multipath -ll   # Her LUN için 2 yol görünmeli"
            ;;
        4)
            echo -e "${CYAN}${BOLD}══ SAYFA 4/5: Cluster Dosya Sistemi ══${NC}\n"
            cat << 'INFO'
  ─── SEÇENEK A: GFS2 (RHEL/OEL önerilen) ──────────────
  dnf install dlm corosync pacemaker pcs gfs2-utils

  pcs cluster setup --name mycluster node1 node2
  pcs cluster start --all && pcs cluster enable --all

  pcs resource create dlm systemd:dlm \
      clone clone-max=2 clone-node-max=1

  # GFS2 format (YALNIZCA TEK NODE'DA, bir kere!)
  mkfs.gfs2 -p lock_dlm -t mycluster:myvol \
            -j 2 /dev/mapper/mpathX

  mount -t gfs2 /dev/mapper/mpathX /mnt/shared
  # /etc/fstab: /dev/mapper/mpathX /mnt/shared gfs2 defaults,_netdev 0 0

  ─── SEÇENEK B: OCFS2 ─────────────────────────────────
  dnf install ocfs2-tools corosync
  mkfs.ocfs2 -N 2 -L "shared_vol" /dev/mapper/mpathX
  mount -t ocfs2 /dev/mapper/mpathX /mnt/shared

  ─── SEÇENEK C: lvmlockd (Shared LVM VG) ─────────────
  dnf install lvm2-lockd sanlock
  # lvm.conf: use_lvmlockd = 1
  systemctl enable --now lvmlockd wdmd sanlock
  vgchange --lock-type sanlock <vgname>
INFO
            ;;
        5)
            echo -e "${CYAN}${BOLD}══ SAYFA 5/5: STONITH / Fencing ══${NC}\n"
            cat << 'INFO'
  ╔═══════════════════════════════════════════════════╗
  ║  UYARI: STONITH olmadan cluster GÜVENLİ DEĞİL!   ║
  ║  Split-brain → iki node aynı diske yazar → bozulur ║
  ╚═══════════════════════════════════════════════════╝

  ─── SCSI PR Tabanlı Fencing (fence_scsi) ────────────
  dnf install fence-agents-scsi

  pcs stonith create myFence fence_scsi \
      devices=/dev/mapper/mpathX \
      pcmk_host_map="node1:1;node2:2" \
      pcmk_reboot_action=off

  pcs property set stonith-enabled=true
  pcs property set no-quorum-policy=freeze

  # Fencing testi (dikkatli! node2 kısa süre devre dışı kalır):
  pcs stonith fence node2

  ─── IPMI/BMC Fencing (ikincil yöntem) ───────────────
  pcs stonith create bmcFence fence_ipmilan \
      ipaddr=<BMC_IP> login=admin passwd=pass lanplus=1

  ─── Kontrol Komutları ───────────────────────────────
  pcs status
  corosync-cfgtool -s
  dlm_tool status
  sg_persist --in --read-keys /dev/mapper/mpathX
INFO
            ;;
        esac

        echo ""
        printf "${CYAN}── Sayfa %d/5 ────────────────────────────${NC}\n" "$pg"
        local navs=()
        (( pg > 1 )) && navs+=("Önceki Sayfa")
        (( pg < 5 )) && navs+=("Sonraki Sayfa")
        navs+=("Menüye Dön")
        show_menu "Gezinti" "${navs[@]}"
        local ch; ch=$(read_choice "${#navs[@]}")
        case "${navs[$((ch-1))]}" in
            "Önceki Sayfa") (( pg-- )) ;;
            "Sonraki Sayfa") (( pg++ )) ;;
            *) return ;;
        esac
        clear
    done
}

# ─── Cluster Durum Ekranı ─────────────────────────────────────────────────────
show_cluster_status() {
    log_section "CLUSTER MODU DURUMU"
    local cm; $CLUSTER_MODE && cm="${GREEN}Aktif${NC}" || cm="${RED}Devre Dışı${NC}"
    echo -e "  Cluster Modu : ${cm}"
    echo    "  Cluster FS   : $CLUSTER_FS_TYPE"
    echo    "  ALUA Modu    : $CLUSTER_ALUA_MODE"
    echo    "  Digest       : $CLUSTER_DIGEST"
    echo    "  MaxBurst     : $(( ISCSI_MAX_BURST / 1048576 )) MB"
    echo    "  LoginTimeout : ${ISCSI_LOGIN_TIMEOUT} sn"
    echo ""
    local x vg_lv lno vg lv bs
    echo -e "  ${BOLD}Backstore PR Durumu:${NC}"
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv lno _ <<< "$x"
        IFS='/' read -r vg lv <<< "$vg_lv"
        bs="${lv}_lun${lno}"
        if targetcli ls "/backstores/block/${bs}" &>/dev/null 2>&1; then
            local pr; pr=$(targetcli ls "/backstores/block/${bs}" 2>/dev/null \
                | grep -i emulate_pr | awk '{print $NF}' || echo "?")
            local caw; caw=$(targetcli ls "/backstores/block/${bs}" 2>/dev/null \
                | grep -i emulate_caw | awk '{print $NF}' || echo "?")
            local pi="${RED}✗${NC}"; [[ "$pr"  == "1" ]] && pi="${GREEN}✓${NC}"
            local ci="${RED}✗${NC}"; [[ "$caw" == "1" ]] && ci="${GREEN}✓${NC}"
            printf "    LUN%s (%s): " "$lno" "$bs"
            echo -e "PR=${pi}  CAW=${ci}"
        fi
    done
    echo ""
    echo -e "  ${BOLD}Dosyalar:${NC}"
    local f icon
    for f in "$SYSCTL_FILE" "$UDEV_FILE" "$MULTIPATH_OUT"; do
        [[ -f "$f" ]] && icon="${GREEN}✓${NC}" || icon="${RED}✗${NC}"
        printf "    "; echo -e "${icon} $f"
    done
    press_enter
}

# ─── Servis / Firewall / SELinux ──────────────────────────────────────────────
enable_services() {
    log_section "SERVİSLER"
    local svc
    for svc in target firewalld; do
        if $DRY_RUN; then
            log_warn "[DRY-RUN] systemctl enable --now $svc"; continue
        fi
        systemctl enable --now "$svc" 2>&1 | tee -a "$LOG_FILE" || true
        systemctl is-active --quiet "$svc" \
            && log_ok "  $svc – çalışıyor" \
            || log_warn "  $svc – başlatılamadı"
    done
}

configure_firewall() {
    log_section "GÜVENLIK DUVARI"
    if $DRY_RUN; then log_warn "[DRY-RUN] firewall-cmd ..."; return; fi
    firewall-cmd --permanent --add-service=iscsi-target 2>&1 | tee -a "$LOG_FILE" || true
    firewall-cmd --permanent --add-port="${ISCSI_PORTAL_PORT}/tcp" 2>&1 | tee -a "$LOG_FILE"
    firewall-cmd --reload 2>&1 | tee -a "$LOG_FILE"
    log_ok "Firewall güncellendi."
}

configure_selinux() {
    log_section "SELINUX"
    local s; s=$(getenforce 2>/dev/null || echo "Disabled")
    [[ "$s" == "Disabled" ]] && { log_warn "SELinux devre dışı."; return; }
    log_info "SELinux: $s"
    local x vg_lv vg lv
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv _ _ <<< "$x"
        IFS='/' read -r vg lv <<< "$vg_lv"
        [[ -b "/dev/${vg}/${lv}" ]] || continue
        if $DRY_RUN; then
            log_warn "[DRY-RUN] chcon /dev/${vg}/${lv}"; continue
        fi
        chcon -t tgtd_var_lib_t "/dev/${vg}/${lv}" 2>/dev/null || \
        semanage fcontext -a -t tgtd_var_lib_t "/dev/${vg}/${lv}" 2>/dev/null || \
        log_warn "  /dev/${vg}/${lv}: context ayarlanamadı."
    done
    $DRY_RUN || setsebool -P iscsi_tcp_connect 1 2>/dev/null || true
    log_ok "SELinux tamamlandı."
}

# ─── Durum / Client Bilgisi ───────────────────────────────────────────────────
show_status() {
    log_section "SİSTEM DURUMU"
    local cm; $CLUSTER_MODE && cm="${GREEN}Aktif${NC}" || cm="${RED}Devre Dışı${NC}"
    echo -e "  Target IQN   : ${ISCSI_TARGET_IQN:-(tanımlanmamış)}"
    local ip
    for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
        [[ -z "$ip" ]] && continue; echo "  Portal       : ${ip}:${ISCSI_PORTAL_PORT}"
    done
    echo -e "  Cluster Modu : ${cm} (FS:${CLUSTER_FS_TYPE} ALUA:${CLUSTER_ALUA_MODE})"
    local chap_s="Devre Dışı"; $CHAP_ENABLED && chap_s="Aktif (${CHAP_USERNAME})"
    echo    "  CHAP         : $chap_s"
    echo ""
    echo -e "  ${BOLD}LUN'lar:${NC}"
    local x vg_lv lno sz vg lv st
    if [[ ${#LUN_DEFINITIONS[@]} -eq 0 ]]; then
        echo "  (yok)"
    else
        for x in "${LUN_DEFINITIONS[@]:-}"; do
            [[ -z "$x" ]] && continue
            IFS=':' read -r vg_lv lno sz <<< "$x"
            IFS='/' read -r vg lv <<< "$vg_lv"
            st="${RED}✗${NC}"; [[ -b "/dev/${vg}/${lv}" ]] && st="${GREEN}✓${NC}"
            printf "    LUN%-3s /dev/%-28s %-8s " "$lno" "$vg_lv" "$sz"
            echo -e "$st"
        done
    fi
    echo ""
    echo -e "  ${BOLD}Initiator'lar:${NC}"
    if [[ ${#ALLOWED_INITIATORS[@]} -eq 0 ]]; then
        echo "  (yok)"
    else
        local ai
        for ai in "${ALLOWED_INITIATORS[@]:-}"; do
            [[ -z "$ai" ]] && continue; echo "  - $ai"
        done
    fi
    echo ""
    echo -e "  ${BOLD}Servisler:${NC}"
    local svc
    for svc in target firewalld; do
        systemctl is-active --quiet "$svc" \
            && echo -e "  ${GREEN}✓${NC} $svc" || echo -e "  ${RED}✗${NC} $svc"
    done
    echo ""
    echo -e "  ${BOLD}targetcli /iscsi:${NC}"
    targetcli ls /iscsi 2>/dev/null || echo "  (erişim yok)"
    echo ""
    echo -e "  ${BOLD}Dinlenen portlar:${NC}"
    ss -tlnp 2>/dev/null | grep ":${ISCSI_PORTAL_PORT}" || echo "  (yok)"
    press_enter
}

print_client_info() {
    log_section "CLIENT BAĞLANTI BİLGİSİ"
    if [[ -z "$ISCSI_TARGET_IQN" ]]; then
        log_warn "Target IQN tanımlanmamış."; press_enter; return
    fi
    echo "  dnf install iscsi-initiator-utils device-mapper-multipath"
    echo ""
    local ip
    for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
        [[ -z "$ip" ]] && continue
        echo "  iscsiadm -m discovery -t st -p ${ip}:${ISCSI_PORTAL_PORT}"
    done
    echo ""
    for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
        [[ -z "$ip" ]] && continue
        echo "  iscsiadm -m node -T ${ISCSI_TARGET_IQN} -p ${ip}:${ISCSI_PORTAL_PORT} --login"
    done
    $CLUSTER_MODE && echo -e "\n  ${YELLOW}Cluster için: Menü → Cluster Yönetimi → Multipath Konfigürasyon Üret${NC}"
    press_enter
}

# ─── Aktif Session Listesi ────────────────────────────────────────────────────
list_active_sessions() {
    log_section "AKTİF iSCSI CLIENT BAĞLANTILARI"
    echo ""

    local total_sessions=0

    # ── 1. targetcli sessions (en güvenilir yöntem) ──
    if command -v targetcli &>/dev/null; then
        echo -e "  ${BOLD}iSCSI Aktif Sessionlar:${NC}"
        local tcli_out
        # Bazı sürümler stdout, bazıları stderr kullanır — ikisini de yakala
        tcli_out=$(targetcli sessions 2>&1) || true
        if [[ -n "$tcli_out" ]]; then
            local has_session=false
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                # "No open sessions" veya benzeri boş mesaj kontrolü
                if echo "$line" | grep -qi "no open\|no active\|no session"; then
                    continue
                fi
                # Session satırı içeren satırları göster
                if echo "$line" | grep -qi "sid:\|session\|LOGGED_IN\|alias:"; then
                    echo -e "    ${GREEN}●${NC}  ${line}"
                    has_session=true
                    (( total_sessions++ ))
                fi
            done <<< "$tcli_out"
            if ! $has_session; then
                echo -e "    ${YELLOW}(aktif session yok)${NC}"
            fi
        else
            echo -e "    ${YELLOW}(targetcli sessions çıktı vermedi)${NC}"
        fi
    else
        echo -e "  ${YELLOW}targetcli komutu bulunamadı.${NC}"
    fi
    echo ""

    # ── 2. Aktif TCP bağlantıları (client IP'leri görünür) ──
    echo -e "  ${BOLD}TCP Bağlantıları (port ${ISCSI_PORTAL_PORT:-3260}):${NC}"
    local tcp_out
    tcp_out=$(ss -tn state established 2>/dev/null \
        | grep ":${ISCSI_PORTAL_PORT:-3260}" || true)
    if [[ -n "$tcp_out" ]]; then
        printf "    %-32s  %-32s\n" "Yerel Adres (Target)" "Uzak Adres (Client)"
        printf "    %-32s  %-32s\n" "────────────────────────────────" "────────────────────────────────"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local local_addr remote_addr
            local_addr=$(echo "$line" | awk '{print $3}')
            remote_addr=$(echo "$line" | awk '{print $4}')
            [[ -z "$local_addr" ]] && continue
            printf "    %-32s  ${GREEN}%-32s${NC}\n" "$local_addr" "$remote_addr"
        done <<< "$tcp_out"
    else
        echo -e "    ${YELLOW}(bağlı TCP oturumu yok)${NC}"
    fi
    echo ""

    # ── 3. configfs (ek detay — varsa) ──
    local configfs="/sys/kernel/config/target/iscsi"
    if [[ -d "$configfs" ]]; then
        local cfg_count=0
        local tgt_dir
        for tgt_dir in "${configfs}"/*/; do
            [[ -d "$tgt_dir" ]] || continue
            local tpgt_dir
            for tpgt_dir in "${tgt_dir}"tpgt_*/; do
                [[ -d "${tpgt_dir}sessions" ]] || continue
                local sess_dir
                for sess_dir in "${tpgt_dir}sessions"/*/; do
                    [[ -d "$sess_dir" ]] || continue
                    (( cfg_count++ ))
                done
            done
        done
        if (( cfg_count > 0 )); then
            echo -e "  ${BOLD}configfs Session Sayısı:${NC} ${cfg_count}"
        fi
    fi
    echo ""
    echo -e "  ${BOLD}Özet:${NC} ${total_sessions} aktif iSCSI session"
    press_enter
}

# ─── Mevcut LUN'a Yeni Client Ekle ───────────────────────────────────────────
add_client_to_lun() {
    log_section "MEVCUT LUN'A YENİ CLIENT EKLE"
    [[ -z "$ISCSI_TARGET_IQN" ]] && { log_warn "Target IQN tanımlanmamış."; press_enter; return; }
    [[ ${#LUN_DEFINITIONS[@]} -eq 0 ]] && { log_warn "Önce LUN tanımlayın."; press_enter; return; }

    echo -e "  ${YELLOW}Client'ta initiator IQN'ini öğrenmek için:${NC}"
    echo -e "  ${BOLD}cat /etc/iscsi/initiatorname.iscsi${NC}\n"

    local iqn; iqn=$(input_text "Yeni Client Initiator IQN" "" validate_iqn)

    # Aynı IQN kontrolü
    local ai
    for ai in "${ALLOWED_INITIATORS[@]:-}"; do
        [[ "$ai" == "$iqn" ]] && { log_warn "Bu initiator zaten tanımlı: ${iqn}"; press_enter; return; }
    done

    # Hangi LUN'lara erişim verileceğini seç
    echo -e "\n${BOLD}Hangi LUN'lara erişim verilsin?${NC}"
    echo -e "  ${YELLOW}Boş bırakırsanız tüm LUN'lara erişim verilir.${NC}\n"
    local i=1 x vg_lv lno sz
    local all_lun_nos=()
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv lno sz <<< "$x"
        echo "  ${i}. LUN${lno} → /dev/${vg_lv} (${sz})"
        all_lun_nos+=("$lno")
        (( i++ ))
    done
    echo ""
    printf "${CYAN}LUN numaraları (boşlukla ayırın, boş=tümü): ${NC}" >&2
    local sel_input; read -r sel_input < /dev/tty

    local selected_luns=()
    if [[ -z "$sel_input" ]]; then
        selected_luns=("${all_lun_nos[@]}")
    else
        local num
        for num in $sel_input; do
            local found_lun=false
            local ln
            for ln in "${all_lun_nos[@]}"; do
                [[ "$ln" == "$num" ]] && { found_lun=true; break; }
            done
            $found_lun && selected_luns+=("$num") || log_warn "  LUN${num} tanımlı değil – atlandı."
        done
    fi

    if [[ ${#selected_luns[@]} -eq 0 ]]; then
        log_warn "Geçerli LUN seçilmedi."; press_enter; return
    fi

    echo ""
    echo -e "  Client    : ${BOLD}${iqn}${NC}"
    echo -e "  LUN'lar   : ${BOLD}LUN${selected_luns[*]}${NC}"
    confirm "Ekleme yapılsın mı?" || { press_enter; return; }

    ALLOWED_INITIATORS+=("$iqn")
    save_config
    backup_targetcli

    {
        echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls"
        echo "create ${iqn}"
        local lno
        for lno in "${selected_luns[@]}"; do
            echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls/${iqn}"
            echo "create mapped_lun=${lno} tpg_lun_or_backstore=${lno}"
        done
        echo "cd /"; echo "saveconfig"; echo "exit"
    } | _run_targetcli && log_ok "Client eklendi: ${iqn}"

    press_enter
}

# ─── Bağlı Client Sil / LUN Erişimini Kaldır ─────────────────────────────────
remove_client_from_lun() {
    log_section "BAĞLI CLIENT SİL / LUN ERİŞİMİNİ KALDIR"
    [[ -z "$ISCSI_TARGET_IQN" ]] && { log_warn "Target IQN tanımlanmamış."; press_enter; return; }
    [[ ${#ALLOWED_INITIATORS[@]} -eq 0 ]] && { log_warn "Tanımlı client yok."; press_enter; return; }

    echo -e "\n${BOLD}Client seçin:${NC}"
    local i=1 ai
    for ai in "${ALLOWED_INITIATORS[@]:-}"; do
        [[ -z "$ai" ]] && continue
        echo "  ${i}. ${ai}"; (( i++ ))
    done
    local idx; idx=$(read_choice $(( i - 1 )))
    local sel_client="${ALLOWED_INITIATORS[$((idx-1))]}"

    echo ""
    show_menu "Silme Kapsamı" \
        "Yalnızca belirli bir LUN'dan kaldır (ACL kalır)" \
        "Client'ı tamamen sil (tüm LUN erişimi + ACL)"
    local scope; scope=$(read_choice 2)

    if [[ "$scope" == "1" ]]; then
        # Belirli bir LUN'dan kaldır
        [[ ${#LUN_DEFINITIONS[@]} -eq 0 ]] && { log_warn "LUN tanımlı değil."; press_enter; return; }
        echo -e "\n${BOLD}Hangi LUN'dan kaldırılsın?${NC}"
        local j=1 x vg_lv lno sz
        for x in "${LUN_DEFINITIONS[@]:-}"; do
            [[ -z "$x" ]] && continue
            IFS=':' read -r vg_lv lno sz <<< "$x"
            echo "  ${j}. LUN${lno} → /dev/${vg_lv} (${sz})"
            (( j++ ))
        done
        local lidx; lidx=$(read_choice $(( j - 1 )))
        IFS=':' read -r _ sel_lno _ <<< "${LUN_DEFINITIONS[$((lidx-1))]}"

        confirm "${RED}LUN${sel_lno}${NC} → ${sel_client} erişimi kesilsin mi?" "h" || { press_enter; return; }
        backup_targetcli
        {
            echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls/${sel_client}"
            echo "delete mapped_lun=${sel_lno}"
            echo "cd /"; echo "saveconfig"; echo "exit"
        } | _run_targetcli && log_ok "LUN${sel_lno} → ${sel_client} erişimi kaldırıldı."
    else
        # Client'ı tamamen sil
        confirm "${RED}${sel_client}${NC} tamamen silinsin mi (tüm LUN erişimi kaldırılır)?" "h" \
            || { press_enter; return; }
        backup_targetcli
        {
            echo "cd /iscsi/${ISCSI_TARGET_IQN}/tpg1/acls"
            echo "delete ${sel_client}"
            echo "cd /"; echo "saveconfig"; echo "exit"
        } | _run_targetcli

        local nl=() ai2
        for ai2 in "${ALLOWED_INITIATORS[@]:-}"; do
            [[ -z "$ai2" || "$ai2" == "$sel_client" ]] && continue
            nl+=("$ai2")
        done
        ALLOWED_INITIATORS=(); [[ ${#nl[@]} -gt 0 ]] && ALLOWED_INITIATORS=("${nl[@]}")
        save_config
        log_ok "Client silindi: ${sel_client}"
    fi
    press_enter
}

# ─── Yapılandırma Güncelleme Menüsü ──────────────────────────────────────────
# ─── Yapılandırmayı Sıfırla (Güvenli Sıfırlama) ──────────────────────────────
reset_configuration() {
    log_section "YAPILANDIRMAYI SIFIRLA"
    echo -e "${RED}${BOLD}  ⚠  DİKKAT — BU İŞLEM GERİ ALINAMAZ!${NC}\n"

    if ! is_system_configured && [[ ! -f "$CONFIG_FILE" ]]; then
        log_warn "Sıfırlanacak bir yapılandırma bulunamadı."
        press_enter; return
    fi

    echo -e "${BOLD}  Aşağıdaki işlemler yapılacak:${NC}"
    echo "    1. targetcli yapılandırmasının yedeği alınacak"
    echo "    2. Tüm aktif iSCSI session'ları kesilecek"
    echo "    3. targetcli yapılandırması temizlenecek (target/LUN/ACL/portal silinir)"
    echo "    4. config.sh dosyası yedeklenip silinecek"
    echo "    5. Bellek değişkenleri sıfırlanacak"
    echo ""
    echo -e "${YELLOW}  Korunacak öğeler:${NC}"
    echo "    ✓ LVM logical volume'ları (lv_*) – veriler korunur"
    echo "    ✓ Volume Group'lar"
    echo "    ✓ Önceki yedekler /etc/iscsi-manager/backups/ altında"
    echo "    ✓ Kernel/sysctl/udev kuralları (cluster optimizasyonları)"
    echo ""

    if is_system_configured; then
        _show_current_config_summary
        echo ""
    fi

    # ── İlk onay ──
    if ! confirm "Yapılandırmayı SIFIRLAMAK istiyor musunuz?" "h"; then
        log_info "İptal edildi."
        press_enter; return
    fi

    # ── Aktif session uyarısı ──
    local active_sessions=0
    if command -v targetcli &>/dev/null; then
        local sess_out; sess_out=$(targetcli sessions 2>&1 || true)
        if echo "$sess_out" | grep -qi "LOGGED_IN\|sid:"; then
            active_sessions=$(echo "$sess_out" | grep -ci "LOGGED_IN\|sid:")
            echo ""
            echo -e "${RED}${BOLD}  ⚠  ${active_sessions} aktif client bağlantısı var!${NC}"
            echo "  Sıfırlama bu bağlantıları zorla kesecek ve client'larda I/O hatası oluşturabilir."
            echo ""
            if ! confirm "Aktif bağlantılara rağmen devam edilsin mi?" "h"; then
                log_info "İptal edildi."
                press_enter; return
            fi
        fi
    fi

    # ── İkinci onay (yazılı) ──
    echo ""
    echo -e "${RED}${BOLD}  Son onay:${NC} Devam etmek için ${BOLD}SIFIRLA${NC} yazıp Enter'a basın."
    printf "${CYAN}> ${NC}" >&2
    local confirmation; read -r confirmation < /dev/tty
    if [[ "$confirmation" != "SIFIRLA" ]]; then
        log_info "Onay alınamadı – işlem iptal edildi."
        press_enter; return
    fi

    # ── 1. Yedek al ──
    log_info "1/5 – targetcli yapılandırması yedekleniyor..."
    backup_targetcli

    # config.sh yedeği
    if [[ -f "$CONFIG_FILE" ]]; then
        local cfg_bak="${BACKUP_DIR}/config.sh.$(date +%Y%m%d_%H%M%S).bak"
        cp "$CONFIG_FILE" "$cfg_bak" 2>/dev/null && \
            log_ok "config.sh yedeği: $cfg_bak"
    fi

    # ── 2. targetcli temizle ──
    log_info "2/5 – targetcli yapılandırması temizleniyor..."
    if command -v targetcli &>/dev/null && ! $DRY_RUN; then
        # Tüm block backstore'larını targetcli ls ile listele
        local bs_list=()
        local bs_out
        bs_out=$(targetcli ls /backstores/block 2>/dev/null) || true
        while IFS= read -r line; do
            # Sadece "/dev/..." içeren satırlar gerçek block backstore'lardır
            [[ "$line" =~ /dev/ ]] || continue
            local bs_name
            bs_name=$(echo "$line" | sed -n 's/^\s*o- \([a-zA-Z0-9_-]\+\)\s.*/\1/p')
            [[ -n "$bs_name" ]] && bs_list+=("$bs_name")
        done <<< "$bs_out"

        local cur_iqn="$ISCSI_TARGET_IQN"
        {
            # Önce target'ı sil (LUN'lar, ACL'ler, portaller dahil)
            if [[ -n "$cur_iqn" ]]; then
                echo "cd /iscsi"
                echo "delete ${cur_iqn}"
            fi
            # Block backstore'ları sil
            local bs_name
            for bs_name in "${bs_list[@]:-}"; do
                [[ -z "$bs_name" ]] && continue
                echo "cd /backstores/block"
                echo "delete ${bs_name}"
            done
            echo "cd /"
            echo "saveconfig"
            echo "exit"
        } | _run_targetcli
        log_ok "targetcli temizlendi (${#bs_list[@]} backstore silindi)."
    fi

    # ── 3. iSCSI servisini yeniden başlat (kalıntı session'ları temizle) ──
    log_info "3/5 – iSCSI target servisi yeniden başlatılıyor..."
    if ! $DRY_RUN; then
        systemctl restart target 2>&1 | tee -a "$LOG_FILE" || \
            log_warn "Servis yeniden başlatılamadı (kritik değil)."
    fi

    # ── 4. config.sh sil ──
    log_info "4/5 – config.sh dosyası kaldırılıyor..."
    if ! $DRY_RUN && [[ -f "$CONFIG_FILE" ]]; then
        rm -f "$CONFIG_FILE" && log_ok "config.sh kaldırıldı."
    fi

    # ── 5. Bellek değişkenlerini sıfırla ──
    log_info "5/5 – Bellek değişkenleri sıfırlanıyor..."
    ISCSI_TARGET_IQN=""
    ISCSI_PORTAL_PORT="3260"
    ISCSI_PORTAL_IPS=()
    LUN_DEFINITIONS=()
    ALLOWED_INITIATORS=()
    CHAP_ENABLED=false
    CHAP_USERNAME=""
    CHAP_PASSWORD=""
    CLUSTER_MODE=false
    CLUSTER_FS_TYPE="gfs2"
    CLUSTER_DIGEST="None"
    CLUSTER_ALUA_MODE="symmetric"

    echo ""
    log_ok "═══ Yapılandırma sıfırlama tamamlandı ═══"
    echo ""
    echo -e "${BOLD}  Sonraki adımlar:${NC}"
    echo "    • Sıfırdan kurulum için: ${BOLD}1. Tam Kurulum Sihirbazı${NC}"
    echo "    • İptal etmek isterseniz yedeklerden geri yükleme:"
    echo -e "      ${CYAN}targetcli restoreconfig ${BACKUP_DIR}/<son_yedek>.json${NC}"
    echo ""
    press_enter
}


# ─── Tam Yapılandırma Güncelleme Alt Menüsü ──────────────────────────────────
menu_full_config_update() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}"
        echo "  ╔═══════════════════════════════════════════════╗"
        echo "  ║       Tam Yapılandırma Güncelleme            ║"
        echo "  ╚═══════════════════════════════════════════════╝"
        echo -e "${NC}"
        if is_system_configured; then
            _show_current_config_summary
            echo ""
        else
            log_warn "Henüz tam yapılandırılmış bir sistem yok."
            echo ""
        fi

        show_menu "Hangi alanı güncellemek istiyorsunuz?" \
            "Target IQN değiştir" \
            "Portal IP/port güncelle" \
            "CHAP ayarlarını güncelle" \
            "Cluster modu / FS / ALUA / Digest güncelle" \
            "Yapılandırmayı tekrar uygula (idempotent)" \
            "Geri"
        local ch; ch=$(read_choice 6)
        case "$ch" in
            1) _update_target_iqn ;;
            2) manage_portals ;;
            3) manage_chap ;;
            4) _update_cluster_settings ;;
            5)
                if [[ -z "$ISCSI_TARGET_IQN" ]]; then
                    log_warn "Önce Target IQN tanımlayın."; press_enter
                else
                    configure_iscsi_target
                    $CLUSTER_MODE && apply_cluster_optimizations
                    press_enter
                fi
                ;;
            6) return ;;
        esac
    done
}

_update_target_iqn() {
    log_section "TARGET IQN GÜNCELLE"
    [[ -z "$ISCSI_TARGET_IQN" ]] && { log_warn "Mevcut Target IQN yok."; press_enter; return; }
    echo -e "  Mevcut IQN  : ${YELLOW}${ISCSI_TARGET_IQN}${NC}"
    echo -e "  ${RED}DİKKAT:${NC} IQN değişikliği client'larda yeniden bağlantı gerektirir!"
    echo ""
    if ! confirm "Devam edilsin mi?" "h"; then press_enter; return; fi

    local new_iqn; new_iqn=$(input_text "Yeni Target IQN" "$ISCSI_TARGET_IQN" validate_iqn)
    if [[ "$new_iqn" == "$ISCSI_TARGET_IQN" ]]; then
        log_info "IQN aynı – değişiklik yapılmadı."; press_enter; return
    fi

    confirm "${RED}IQN '${ISCSI_TARGET_IQN}' → '${new_iqn}'${NC} olarak değiştirilsin mi?" "h" \
        || { press_enter; return; }

    backup_targetcli
    # Eski IQN'i sil ve yeniden config'le yeniden oluştur
    {
        echo "cd /iscsi"
        echo "delete ${ISCSI_TARGET_IQN}"
        echo "cd /"
        echo "saveconfig"
        echo "exit"
    } | _run_targetcli

    ISCSI_TARGET_IQN="$new_iqn"
    save_config
    configure_iscsi_target
    log_ok "Target IQN güncellendi: $new_iqn"
    press_enter
}

_update_cluster_settings() {
    log_section "CLUSTER AYARLARINI GÜNCELLE"
    show_menu "Cluster Modu" \
        "Etkinleştir" \
        "Devre Dışı Bırak" \
        "Sadece FS / ALUA / Digest güncelle" \
        "Geri"
    local ch; ch=$(read_choice 4)
    case "$ch" in
        1)
            if $CLUSTER_MODE; then
                log_info "Cluster modu zaten aktif."
            else
                CLUSTER_MODE=true
                save_config
                log_ok "Cluster modu etkinleştirildi."
            fi
            ;;
        2)
            if ! $CLUSTER_MODE; then
                log_info "Cluster modu zaten devre dışı."
            else
                confirm "${RED}Cluster modu kapatılsın mı?${NC}" "h" || { press_enter; return; }
                CLUSTER_MODE=false
                save_config
                log_ok "Cluster modu devre dışı bırakıldı."
            fi
            ;;
        3) ;;
        4) return ;;
    esac

    # Cluster sub-ayarlar
    show_menu "Dosya Sistemi" "GFS2" "OCFS2" "lvmlockd" "Raw" "Değiştirme"
    local fs; fs=$(read_choice 5)
    case "$fs" in
        1) CLUSTER_FS_TYPE="gfs2";;
        2) CLUSTER_FS_TYPE="ocfs2";;
        3) CLUSTER_FS_TYPE="lvmlockd";;
        4) CLUSTER_FS_TYPE="raw";;
    esac

    show_menu "ALUA Modu" "Simetrik" "Asimetrik" "Değiştirme"
    local am; am=$(read_choice 3)
    case "$am" in
        1) CLUSTER_ALUA_MODE="symmetric";;
        2) CLUSTER_ALUA_MODE="asymmetric";;
    esac

    show_menu "iSCSI Digest" "None" "CRC32C" "Değiştirme"
    local dm; dm=$(read_choice 3)
    case "$dm" in
        1) CLUSTER_DIGEST="None";;
        2) CLUSTER_DIGEST="CRC32C";;
    esac

    save_config
    log_ok "Cluster ayarları güncellendi."
    confirm "Yapılandırmayı şimdi targetcli'ye uygulansın mı?" "e" \
        && configure_iscsi_target
    press_enter
}

# ─── Yapılandırma Güncelleme Menüsü ──────────────────────────────────────────
menu_update() {
    while true; do
        clear
        show_menu "Yapılandırmayı Güncelle" \
            "Aktif Bağlantıları Listele" \
            "Mevcut LUN'a Yeni Client Ekle" \
            "Bağlı Client Sil / LUN Erişimini Kaldır" \
            "Yeni LUN Ekle" \
            "Tam Yapılandırma Güncelleme (IQN/Portal/CHAP/Cluster)" \
            "Ana Menüye Dön"
        local ch; ch=$(read_choice 6)
        case "$ch" in
            1) list_active_sessions ;;
            2) add_client_to_lun ;;
            3) remove_client_from_lun ;;
            4) create_single_lun ;;
            5) menu_full_config_update ;;
            6) return ;;
        esac
    done
}


# ─── Sistem Yapılandırılmış mı? ──────────────────────────────────────────────
is_system_configured() {
    # Hem config.sh'da hem de targetcli'de yapılandırma varsa "yapılandırılmış" sayılır
    [[ -n "$ISCSI_TARGET_IQN" ]] || return 1
    [[ ${#LUN_DEFINITIONS[@]} -gt 0 ]] || return 1
    # configfs'de target gerçekten var mı?
    [[ -d "/sys/kernel/config/target/iscsi/${ISCSI_TARGET_IQN}" ]] || return 1
    return 0
}

_show_current_config_summary() {
    echo -e "${BOLD}  Mevcut Yapılandırma:${NC}"
    echo -e "    Target IQN  : ${GREEN}${ISCSI_TARGET_IQN}${NC}"
    local p; for p in "${ISCSI_PORTAL_IPS[@]:-}"; do
        [[ -z "$p" ]] && continue
        echo -e "    Portal      : ${GREEN}${p}:${ISCSI_PORTAL_PORT}${NC}"
    done
    local x vg_lv lno sz
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv lno sz <<< "$x"
        echo -e "    LUN${lno}        : ${GREEN}/dev/${vg_lv} (${sz})${NC}"
    done
    local ai
    for ai in "${ALLOWED_INITIATORS[@]:-}"; do
        [[ -z "$ai" ]] && continue
        echo -e "    Initiator   : ${GREEN}${ai}${NC}"
    done
    local cm_txt="Hayır"
    $CLUSTER_MODE && cm_txt="Evet (${CLUSTER_FS_TYPE} / ${CLUSTER_ALUA_MODE})"
    echo -e "    Cluster     : ${GREEN}${cm_txt}${NC}"
    local ch_txt="Devre Dışı"
    $CHAP_ENABLED && ch_txt="Aktif (${CHAP_USERNAME})"
    echo -e "    CHAP        : ${GREEN}${ch_txt}${NC}"
}

wizard_full_setup() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════╗"
    echo "  ║     iSCSI Target – Tam Kurulum Sihirbazı     ║"
    echo "  ╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"

    # ── Sistem zaten yapılandırılmış mı? ──
    if is_system_configured; then
        echo -e "${YELLOW}${BOLD}  ⚠  Sistem zaten yapılandırılmıştır.${NC}\n"
        _show_current_config_summary
        echo ""
        echo -e "${BOLD}  Yapılabilecekler:${NC}"
        echo -e "    • ${BOLD}8. Yapılandırmayı Güncelle${NC}     – Mevcut sistemi günceller (LUN/client ekle/sil)"
        echo -e "    • ${BOLD}9. Tüm Yapılandırmayı Uygula${NC}   – config.sh'ı targetcli'ye yansıtır (idempotent)"
        echo -e "    • ${BOLD}10. Yapılandırmayı Sıfırla${NC}     – Sistemi temizler, sıfırdan başlamak için"
        echo ""
        log_warn "Sıfırdan kurulum yapmak için önce ana menüden \"10. Yapılandırmayı Sıfırla\" seçeneğini kullanın."
        press_enter
        return
    fi

    $DRY_RUN && echo -e "  ${RED}[DRY-RUN MODU]${NC}"
    press_enter

    log_section "1/7 – TARGET IQN"
    echo -e "  Örnek: iqn.2025-01.com.sirket:storage01"
    ISCSI_TARGET_IQN=$(input_text "Target IQN" \
        "${ISCSI_TARGET_IQN:-iqn.$(date +%Y-%m).com.sirket:storage01}" validate_iqn)

    log_section "2/7 – PORTAL IP'LERİ"
    ISCSI_PORTAL_IPS=()
    while true; do
        local ip; ip=$(input_text "Portal #$((${#ISCSI_PORTAL_IPS[@]}+1)) IP adresi" "" validate_ip)
        ISCSI_PORTAL_IPS+=("$ip")
        confirm "Başka portal eklensin mi?" "h" || break
    done
    ISCSI_PORTAL_PORT=$(input_text "iSCSI port numarası" "$ISCSI_PORTAL_PORT" validate_port)

    log_section "3/7 – LUN TANIMLARI"
    list_vgs
    LUN_DEFINITIONS=()
    local lc=0
    while true; do
        local vg_lv; vg_lv=$(input_text "  LUN${lc} VG/LV (örn: vg_data/lv_shared0${lc})" "" validate_vg_lv)
        local sz;    sz=$(input_text    "  LUN${lc} boyutu (örn: 100G)" "" validate_lvm_size)
        LUN_DEFINITIONS+=("${vg_lv}:${lc}:${sz}")
        log_ok "  LUN${lc}: /dev/${vg_lv} (${sz})"
        (( lc++ ))
        confirm "Başka LUN eklensin mi?" "h" || break
    done

    log_section "4/7 – INITIATOR'LAR"
    ALLOWED_INITIATORS=()
    while true; do
        local iqn; iqn=$(input_text "  Initiator #$((${#ALLOWED_INITIATORS[@]}+1)) IQN" "" validate_iqn)
        ALLOWED_INITIATORS+=("$iqn")
        log_ok "  Eklendi: $iqn"
        confirm "Başka initiator eklensin mi?" "h" || break
    done

    log_section "5/7 – CHAP"
    if confirm "CHAP kimlik doğrulama etkinleştirilsin mi?" "h"; then
        CHAP_ENABLED=true
        CHAP_USERNAME=$(input_text "  Kullanıcı adı" "${CHAP_USERNAME:-iscsi_user}" validate_nonempty)
        CHAP_PASSWORD=$(input_password "  Parola")
    else
        CHAP_ENABLED=false
    fi

    log_section "6/7 – CLUSTER MODU"
    echo "  Cluster modu etkinleştirilirse şunlar otomatik uygulanır:"
    echo "    ✓ SCSI PR (emulate_pr=1)  – STONITH/fencing için zorunlu"
    echo "    ✓ CAW (emulate_caw=1)     – GFS2/OCFS2 atomik yazma için zorunlu"
    echo "    ✓ ALUA, kernel ve I/O optimizasyonları"
    echo ""
    if confirm "Cluster modu etkinleştirilsin mi?" "h"; then
        CLUSTER_MODE=true
        echo ""
        show_menu "Cluster Dosya Sistemi" \
            "GFS2  – RHEL/OEL önerilen (Pacemaker+DLM)" \
            "OCFS2 – Oracle Cluster FS" \
            "lvmlockd – Shared LVM VG (sanlock)" \
            "Raw – Uygulama kendi kilitleme yapıyor"
        local cfs; cfs=$(read_choice 4)
        case "$cfs" in 1) CLUSTER_FS_TYPE="gfs2";;  2) CLUSTER_FS_TYPE="ocfs2";;
                        3) CLUSTER_FS_TYPE="lvmlockd";; 4) CLUSTER_FS_TYPE="raw";; esac

        show_menu "ALUA Modu" \
            "Simetrik  – tüm portaller eşit (round-robin MPIO)" \
            "Asimetrik – Portal 1 birincil, diğerleri yedek"
        local am; am=$(read_choice 2)
        [[ "$am" == "2" ]] && CLUSTER_ALUA_MODE="asymmetric" || CLUSTER_ALUA_MODE="symmetric"

        show_menu "iSCSI Digest" \
            "None   – maksimum performans (10GbE+ için)" \
            "CRC32C – bit hata koruması (GbE için)"
        local dm; dm=$(read_choice 2)
        [[ "$dm" == "2" ]] && CLUSTER_DIGEST="CRC32C" || CLUSTER_DIGEST="None"
    else
        CLUSTER_MODE=false
    fi

    log_section "7/7 – ÖZET VE ONAY"
    echo -e "${GREEN}"
    echo "  Target IQN   : $ISCSI_TARGET_IQN"
    local ip
    for ip in "${ISCSI_PORTAL_IPS[@]:-}"; do
        [[ -z "$ip" ]] && continue; echo "  Portal       : ${ip}:${ISCSI_PORTAL_PORT}"
    done
    local cm_txt="Hayır"; $CLUSTER_MODE && cm_txt="Evet (${CLUSTER_FS_TYPE} / ${CLUSTER_ALUA_MODE})"
    echo "  Cluster Modu : $cm_txt"
    local ch_txt="Hayır"; $CHAP_ENABLED && ch_txt="Evet (${CHAP_USERNAME})"
    echo "  CHAP         : $ch_txt"
    local x; for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv lno sz <<< "$x"
        echo "  LUN${lno}         : /dev/${vg_lv} (${sz})"
    done
    local ai; for ai in "${ALLOWED_INITIATORS[@]:-}"; do
        [[ -z "$ai" ]] && continue; echo "  Initiator    : $ai"
    done
    echo -e "${NC}"

    confirm "Kurulum başlatılsın mı?" || { log_warn "İptal edildi."; press_enter; return; }

    save_config
    install_packages
    $CLUSTER_MODE && install_cluster_packages

    log_section "LVM LV OLUŞTURMA"
    for x in "${LUN_DEFINITIONS[@]:-}"; do
        [[ -z "$x" ]] && continue
        IFS=':' read -r vg_lv lno sz <<< "$x"
        IFS='/' read -r vg lv <<< "$vg_lv"
        if $DRY_RUN; then
            log_warn "[DRY-RUN] lvcreate -L $sz -n $lv $vg"; continue
        fi
        vgs "$vg" &>/dev/null || { log_warn "  VG '$vg' yok – atlandı."; continue; }
        if lvs "${vg}/${lv}" &>/dev/null; then
            log_warn "  LV /dev/${vg_lv} zaten var – atlandı."
        else
            lvcreate -L "$sz" -n "$lv" "$vg" 2>&1 | tee -a "$LOG_FILE" \
                && log_ok "  /dev/${vg_lv}" || log_warn "  Oluşturulamadı."
        fi
    done

    enable_services
    configure_iscsi_target
    $CLUSTER_MODE && apply_cluster_optimizations
    configure_firewall
    configure_selinux

    log_ok "══ Kurulum tamamlandı! ══"
    show_status
    print_client_info
}

# ─── Alt Menüler ──────────────────────────────────────────────────────────────
menu_lun() {
    while true; do
        clear
        show_menu "LUN / Backstore Yönetimi" \
            "Listele" "Ekle" "LUN → Initiator Bağla" "Kaldır" "Ana Menüye Dön"
        local ch; ch=$(read_choice 5)
        case "$ch" in
            1) list_luns ;; 2) create_single_lun ;; 3) map_lun_to_initiator ;;
            4) remove_lun ;; 5) return ;;
        esac
    done
}

menu_initiator() {
    while true; do
        clear
        show_menu "Initiator Yönetimi" "Listele" "Ekle" "Sil" "Ana Menüye Dön"
        local ch; ch=$(read_choice 4)
        case "$ch" in
            1) list_initiators ;; 2) add_initiator ;;
            3) remove_initiator ;; 4) return ;;
        esac
    done
}

menu_cluster() {
    while true; do
        clear
        local cm; $CLUSTER_MODE && cm="${GREEN}Aktif${NC}" || cm="${RED}Devre Dışı${NC}"
        printf "\n  Cluster: "; echo -e "${cm}  |  FS: ${CLUSTER_FS_TYPE}  |  ALUA: ${CLUSTER_ALUA_MODE}  |  Digest: ${CLUSTER_DIGEST}\n"
        show_menu "Cluster Yönetimi" \
            "Cluster Modunu Etkinleştir" \
            "ALUA Port Group Modu Seç" \
            "Cluster Dosya Sistemi Seç" \
            "iSCSI Digest Modu Seç" \
            "Multipath Konfigürasyon Üret" \
            "SCSI PR Doğrulama" \
            "Cluster Durumu" \
            "Cluster Kurulum Kılavuzu" \
            "Ana Menüye Dön"
        local ch; ch=$(read_choice 9)
        case "$ch" in
            1) apply_cluster_optimizations ;;
            2)
                show_menu "ALUA Modu" "Simetrik (round-robin)" "Asimetrik (active-standby)"
                local a; a=$(read_choice 2)
                [[ "$a" == "2" ]] && CLUSTER_ALUA_MODE="asymmetric" \
                                  || CLUSTER_ALUA_MODE="symmetric"
                save_config; log_ok "ALUA: $CLUSTER_ALUA_MODE"; press_enter
                ;;
            3)
                show_menu "Cluster FS" "GFS2" "OCFS2" "lvmlockd" "Raw"
                local f; f=$(read_choice 4)
                case "$f" in 1) CLUSTER_FS_TYPE="gfs2";; 2) CLUSTER_FS_TYPE="ocfs2";;
                             3) CLUSTER_FS_TYPE="lvmlockd";; 4) CLUSTER_FS_TYPE="raw";; esac
                save_config; log_ok "FS: $CLUSTER_FS_TYPE"; press_enter
                ;;
            4)
                show_menu "Digest" "None (performans)" "CRC32C (bit hata koruması)"
                local d; d=$(read_choice 2)
                [[ "$d" == "2" ]] && CLUSTER_DIGEST="CRC32C" || CLUSTER_DIGEST="None"
                save_config; log_ok "Digest: $CLUSTER_DIGEST"; press_enter
                ;;
            5) generate_multipath_config ;;
            6) verify_scsi_pr ;;
            7) show_cluster_status ;;
            8) show_cluster_guide ;;
            9) return ;;
        esac
    done
}

# ─── Mevcut targetcli Yapılandırmasını Otomatik Tespit ────────────────────────
detect_existing_config() {
    # Zaten config varsa atla
    [[ -f "$CONFIG_FILE" ]] && return 0

    # targetcli kurulu mu?
    command -v targetcli &>/dev/null || return 1

    # targetcli'de bir hedef tanımlı mı?
    local tcli_full
    tcli_full=$(targetcli ls 2>/dev/null) || return 1
    echo "$tcli_full" | grep -q "iqn\." || return 1

    log_section "MEVCUT YAPILANDIRMA TESPİT EDİLDİ"
    log_info "targetcli'de aktif bir yapılandırma bulundu."
    echo -e "  ${YELLOW}config.sh dosyası yok – mevcut ayarlar içe aktarılabilir.${NC}\n"

    # ── Target IQN ──
    local detected_iqn
    detected_iqn=$(echo "$tcli_full" \
        | grep -E 'o-\s+iqn\.' \
        | grep -v 'acls' \
        | head -1 \
        | sed -n 's/.*o- \(iqn\.[^ ]*\).*/\1/p')
    if [[ -z "$detected_iqn" ]]; then
        log_warn "Target IQN tespit edilemedi."
        return 1
    fi
    echo -e "  Target IQN : ${GREEN}${detected_iqn}${NC}"

    # ── Portal IP'leri ──
    local -a detected_portals=()
    local detected_port="3260"
    while IFS= read -r line; do
        local ip_port
        ip_port=$(echo "$line" | sed -n 's/.*o- \([0-9.]*:[0-9]*\).*/\1/p')
        if [[ -n "$ip_port" ]]; then
            local ip="${ip_port%%:*}"
            local port="${ip_port##*:}"
            detected_portals+=("$ip")
            detected_port="$port"
            echo -e "  Portal      : ${GREEN}${ip}:${port}${NC}"
        fi
    done < <(echo "$tcli_full" | grep -E 'o-\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:')

    # ── LUN'lar ──
    # Önce backstore'lardan boyut bilgisini al: dev_path → size
    declare -A bs_sizes
    while IFS= read -r line; do
        local dev_path size_raw
        dev_path=$(echo "$line" | sed -n 's|.*\(/dev/[a-zA-Z0-9_-]*/[a-zA-Z0-9_-]*\).*|\1|p')
        size_raw=$(echo "$line" | sed -n 's|.* (\([0-9.]*[MGTP]iB\)).*|\1|p')
        if [[ -n "$dev_path" && -n "$size_raw" ]]; then
            # 100.0GiB → 100G  /  50.0GiB → 50G  /  1.5TiB → 1.5T
            local sz
            sz=$(echo "$size_raw" | sed 's/iB//;s/\.0\([MGTP]\)$/\1/')
            bs_sizes["$dev_path"]="$sz"
        fi
    done < <(echo "$tcli_full" | grep -E 'o-\s+\S+.*\[/dev/')

    # LUN eşlemeleri: lun satırından lun numarası ve dev_path al
    local -a detected_luns=()
    while IFS= read -r line; do
        local lun_no dev_path
        lun_no=$(echo "$line" | sed -n 's/.*o- lun\([0-9]*\).*/\1/p')
        dev_path=$(echo "$line" | sed -n 's|.*(\(/dev/[a-zA-Z0-9_-]*/[a-zA-Z0-9_-]*\)).*|\1|p')
        if [[ -n "$lun_no" && -n "$dev_path" ]]; then
            local vg_lv="${dev_path#/dev/}"
            local sz="${bs_sizes[$dev_path]:-??}"
            detected_luns+=("${vg_lv}:${lun_no}:${sz}")
            echo -e "  LUN${lun_no}       : ${GREEN}/dev/${vg_lv} (${sz})${NC}"
        fi
    done < <(echo "$tcli_full" | grep -E 'o- lun[0-9]+')

    # ── Initiator ACL'leri ──
    local -a detected_initiators=()
    while IFS= read -r line; do
        local ini_iqn
        ini_iqn=$(echo "$line" | sed -n 's/.*o- \(iqn\.[^ ]*\).*/\1/p')
        if [[ -n "$ini_iqn" && "$ini_iqn" != "$detected_iqn" ]]; then
            # Duplicate kontrolü
            local dup=false ex
            for ex in "${detected_initiators[@]:-}"; do
                [[ "$ex" == "$ini_iqn" ]] && { dup=true; break; }
            done
            if ! $dup; then
                detected_initiators+=("$ini_iqn")
                echo -e "  Initiator   : ${GREEN}${ini_iqn}${NC}"
            fi
        fi
    done < <(echo "$tcli_full" | grep -E 'o-\s+iqn\.' | grep -i "Mapped LUNs")

    # ── Cluster modu tespiti (emulate_pr kontrolü — configfs'den) ──
    local detected_cluster=false
    local pr_files=(/sys/kernel/config/target/core/iblock_*/*/attrib/emulate_pr)
    if [[ -f "${pr_files[0]:-}" ]]; then
        local pr_val; pr_val=$(cat "${pr_files[0]}" 2>/dev/null)
        [[ "$pr_val" == "1" ]] && detected_cluster=true
    fi
    local cl_txt; $detected_cluster && cl_txt="${GREEN}Aktif (PR etkin)${NC}" || cl_txt="Devre Dışı"
    echo -e "  Cluster     : ${cl_txt}"
    echo ""

    if ! confirm "Bu yapılandırma içe aktarılsın mı?" "e"; then
        log_info "İçe aktarma atlandı. Sihirbazı kullanabilirsiniz (seçenek 1)."
        return 1
    fi

    # ── İçe aktar ──
    ISCSI_TARGET_IQN="$detected_iqn"
    ISCSI_PORTAL_PORT="$detected_port"
    [[ ${#detected_portals[@]} -gt 0 ]]    && ISCSI_PORTAL_IPS=("${detected_portals[@]}")
    [[ ${#detected_luns[@]} -gt 0 ]]       && LUN_DEFINITIONS=("${detected_luns[@]}")
    [[ ${#detected_initiators[@]} -gt 0 ]] && ALLOWED_INITIATORS=("${detected_initiators[@]}")
    CLUSTER_MODE=$detected_cluster

    save_config
    log_ok "Yapılandırma içe aktarıldı ve kaydedildi: $CONFIG_FILE"
    press_enter
    return 0
}

# ─── Ana Menü ─────────────────────────────────────────────────────────────────
menu_main() {
    while true; do
        clear
        local cm; $CLUSTER_MODE && cm="AKTİF" || cm="KAPALI"
        echo -e "${CYAN}${BOLD}"
        echo "  ╔══════════════════════════════════════════════════════╗"
        echo "  ║        iSCSI Target Sunucu Yönetim Paneli           ║"
        printf "  ║  %-52s║\n" "  $OS_NAME $OS_VERSION | Sürüm: $VERSION"
        printf "  ║  %-52s║\n" "  IQN: ${ISCSI_TARGET_IQN:-(tanımlanmamış)}"
        printf "  ║  %-52s║\n" "  Cluster: $cm | FS: $CLUSTER_FS_TYPE | ALUA: $CLUSTER_ALUA_MODE"
        $DRY_RUN && printf "  ║  %-52s║\n" "  [!] DRY-RUN MODU"
        echo "  ╚══════════════════════════════════════════════════════╝"
        echo -e "${NC}"

        show_menu "Ana Menü" \
            "Tam Kurulum Sihirbazı" \
            "Sistem Durumu" \
            "LUN / Backstore Yönetimi" \
            "Initiator Yönetimi" \
            "Cluster Yönetimi" \
            "Portal Yönetimi" \
            "CHAP Kimlik Doğrulama" \
            "Yapılandırmayı Güncelle  ★" \
            "Tüm Yapılandırmayı Uygula (idempotent)" \
            "Yapılandırmayı Sıfırla  ⚠" \
            "Firewall ve SELinux Güncelle" \
            "Client Bağlantı Bilgisi" \
            "Çıkış"

        local ch; ch=$(read_choice 13)
        case "$ch" in
            1)  wizard_full_setup ;;
            2)  show_status ;;
            3)  menu_lun ;;
            4)  menu_initiator ;;
            5)  menu_cluster ;;
            6)  manage_portals ;;
            7)  manage_chap ;;
            8)  menu_update ;;
            9)
                if [[ -z "$ISCSI_TARGET_IQN" ]]; then
                    log_warn "Önce Target IQN tanımlayın."; press_enter; continue
                fi
                local x vg_lv vg lv sz
                for x in "${LUN_DEFINITIONS[@]:-}"; do
                    [[ -z "$x" ]] && continue
                    IFS=':' read -r vg_lv _ sz <<< "$x"
                    IFS='/' read -r vg lv <<< "$vg_lv"
                    $DRY_RUN && continue
                    vgs "$vg" &>/dev/null || continue
                    lvs "${vg}/${lv}" &>/dev/null || \
                        lvcreate -L "$sz" -n "$lv" "$vg" 2>&1 | tee -a "$LOG_FILE"
                done
                configure_iscsi_target
                $CLUSTER_MODE && apply_cluster_optimizations
                press_enter ;;
            10) reset_configuration ;;
            11) configure_firewall; configure_selinux; press_enter ;;
            12) print_client_info ;;
            13) echo -e "\n${GREEN}  İyi çalışmalar!${NC}\n"; exit 0 ;;
        esac
    done
}

# ─── Giriş Noktası ────────────────────────────────────────────────────────────
main() {
    [[ $EUID -eq 0 ]] || die "Root yetkisi gerekli: sudo bash $0"
    init_dirs
    echo "=== iSCSI Manager $VERSION – $(_ts) ===" >> "$LOG_FILE" 2>/dev/null || true
    detect_os
    if ! load_config; then
        # config.sh yok — targetcli'de mevcut yapılandırma var mı bak
        detect_existing_config || \
            log_info "Yeni kurulum – sihirbazı kullanın (seçenek 1)."
    fi
    menu_main
}

main "$@"
