#!/bin/bash
#
# pcp-setup.sh - PCP (Performance Co-Pilot) tam izleme kurulum ve yapilandirmasi
#
# Yaptiklari:
#  1. RHEL/Ubuntu tabanli dagitimlarda pcp, pcp-gui, sistem araclari ve ek
#     PMDA modullerini (lmsensors, smart, dm, bonding ...) kurar.
#  2. proc PMDA'ya -A ekler: pmlogger 'pcp' kullanicisiyla calistigi icin
#     bu bayrak olmadan SADECE pcp kullanicisinin prosesleri arsivlenir.
#  3. CPU, bellek, disk, filesystem, network/ethernet, prosesler (kullanici
#     kimlikleriyle), donanim envanteri ve sensor/SMART verilerini surekli
#     diske kaydeden pmlogger yapilandirmasi olusturur.
#  4. Gunluk arsiv rotasyonu + sikistirma + 14 gun saklama (pmlogger_daily).
#  5. pcp-log-guard: /var/log/pcp ayri bir LV/bolum ise %80 dolulukta,
#     degilse 2GB sinirinda eski arsivleri siler; acil durumda (%90+)
#     pmlogger'i durdurarak diskin ASLA tamamen dolmasini engeller.
#  6. hotproc filtresi, pmrep inceleme sablonlari (:canli :obur :agirlik) ve
#     pmie esik alarmlari (pmieconf hazir kurallari).
#
# Idempotanslik: her adim once mevcut durumu kontrol eder; dosya icerigi ve
# izni ayniysa dokunmaz, servisleri yalnizca ilgili yapilandirma degistiyse
# yeniden baslatir, unit dosyasi degismediyse daemon-reload yapmaz. Ciktida
# her adim "[+] yapildi" ya da "[=] zaten ayni, atlandi" olarak isaretlenir.
#
# Kullanim (root):
#   ./pcp-setup.sh                 # varsayilanlar: 60sn ornekleme, 14 gun, 2GB, %80
#   ./pcp-setup.sh -i 30 -k 14 -l 2 -t 80
#   ./pcp-setup.sh -n              # kuru calisma: hicbir sey degistirme, farklari goster
#   ./pcp-setup.sh -f              # zorla: dosyalari yeniden yaz, servisleri yeniden baslat
#     -i  ornekleme araligi (saniye)          [60]
#     -k  arsiv saklama suresi (gun)          [14]
#     -l  ayri volum degilse log siniri (GB)  [2]
#     -t  ayri volum ise doluluk esigi (%)    [80]
#     -n  kuru calisma (dry-run)
#     -f  zorla (mevcut hotproc.conf dahil her seyi yeniden yaz)
#     -h  yardim
#
set -o pipefail

INTERVAL=60
KEEP_DAYS=14
MAX_SIZE_GB=2
THRESHOLD_PCT=80
DRYRUN=0
FORCE=0

while getopts "i:k:l:t:nfh" opt; do
    case $opt in
        i) INTERVAL=$OPTARG ;;
        k) KEEP_DAYS=$OPTARG ;;
        l) MAX_SIZE_GB=$OPTARG ;;
        t) THRESHOLD_PCT=$OPTARG ;;
        n) DRYRUN=1 ;;
        f) FORCE=1 ;;
        h|*) grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
    esac
done
for v in INTERVAL KEEP_DAYS MAX_SIZE_GB THRESHOLD_PCT; do
    [[ ${!v} =~ ^[0-9]+$ ]] || { echo "HATA: $v sayi olmali: ${!v}" >&2; exit 1; }
done

[ "$(id -u)" -eq 0 ] || { echo "HATA: root olarak calistirin." >&2; exit 1; }

# Sikilastirilmis sistemlerde (umask 027/077) root'un yazdigi dosyalari
# 'pcp' kullanicisi okuyamaz ve pmlogger "Permission denied" ile crashloop'a
# girer; olusturulan tum dosyalar dunya-okur olmali.
umask 022

N_CHG=0; N_SKIP=0
log()  { echo "[pcp-setup] $*"; }
chg()  { N_CHG=$((N_CHG+1));   echo "[pcp-setup]   [+] $*"; }
skip() { N_SKIP=$((N_SKIP+1)); echo "[pcp-setup]   [=] $* (zaten, atlandi)"; }
warn() { echo "[pcp-setup] UYARI: $*" >&2; }
die()  { echo "[pcp-setup] HATA: $*" >&2; exit 1; }
[ "$DRYRUN" -eq 1 ] && log "KURU CALISMA: hicbir sey degistirilmeyecek, yalnizca farklar gosterilecek"
[ "$FORCE" -eq 1 ]  && log "ZORLA modu: ayni olsa da dosyalar yeniden yazilir, servisler yeniden baslatilir"

# run KOMUT...  : kuru calismada yalnizca yazar, aksi halde calistirir
run() {
    if [ "$DRYRUN" -eq 1 ]; then echo "[pcp-setup]   [n] $*"; return 0; fi
    "$@"
}

# put_file HEDEF MOD [ETIKET] : stdin'deki icerigi HEDEF'e yazar.
#   Icerik ve izin zaten ayniysa dokunmaz (donus 1). Farkliysa ayni dizinde
#   gecici dosyaya yazip mv ile atomik degistirir (donus 0). -f ile ayni
#   icerik de "degisti" sayilir ki bagli servisler yeniden baslatilsin.
put_file() {
    local dest=$1 mode=$2 label=${3:-$1} tmp
    if [ "$DRYRUN" -eq 1 ]; then tmp=$(mktemp) || die "mktemp basarisiz"
    else mkdir -p "$(dirname "$dest")"; tmp=$(mktemp "$dest.XXXXXX") || die "gecici dosya acilamadi: $dest"; fi
    cat > "$tmp"
    if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
        rm -f "$tmp"
        if [ "$(stat -c %a "$dest")" != "$mode" ]; then
            run chmod "$mode" "$dest"; chg "$label: icerik ayni, izin $mode yapildi"; return 0
        fi
        if [ "$FORCE" -eq 1 ]; then chg "$label: ayni icerik (zorla: degisti sayildi)"; return 0; fi
        skip "$label"; return 1
    fi
    if [ "$DRYRUN" -eq 1 ]; then
        if [ -f "$dest" ]; then chg "$label: icerik farkli, yazilacak ($(diff "$dest" "$tmp" | grep -c '^[<>]') satir fark)"
        else chg "$label: yok, olusturulacak"; fi
        rm -f "$tmp"; return 0
    fi
    if ! { chmod "$mode" "$tmp" && mv -f "$tmp" "$dest"; }; then die "yazilamadi: $dest"; fi
    chg "$label: yazildi"
    return 0
}

# ensure_mode DOSYA MOD : izin farkliysa duzelt
ensure_mode() {
    [ -e "$1" ] || return 0
    if [ "$(stat -c %a "$1")" != "$2" ]; then run chmod "$2" "$1"; chg "$1: izin $2 yapildi"; fi
}

# svc_enable SERVIS : etkin degilse etkinlestir
svc_enable() {
    if [ "$(systemctl is-enabled "$1" 2>/dev/null)" = enabled ]; then skip "$1 etkin"
    else run systemctl enable -q "$1" && chg "$1 etkinlestirildi"; fi
}

# svc_apply SERVIS DEGISTI_MI : degistiyse restart, aktif degilse start, aksi halde dokunma
svc_apply() {
    local s=$1 changed=$2
    if [ "$changed" -eq 1 ] || [ "$FORCE" -eq 1 ]; then
        run systemctl restart "$s" || return 1
        chg "$s yeniden baslatildi"
    elif [ "$(systemctl is-active "$s" 2>/dev/null)" != active ]; then
        run systemctl start "$s" || return 1
        chg "$s baslatildi"
    else
        skip "$s aktif, yapilandirma degismedi"
    fi
    return 0
}

# ---------------------------------------------------------------- 1. OS tespiti
# shellcheck source=/dev/null
. /etc/os-release 2>/dev/null || die "/etc/os-release okunamadi"
OSFAM=""
case " $ID $ID_LIKE " in
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*) OSFAM=rhel ;;
    *" ubuntu "*|*" debian "*)                                                OSFAM=deb ;;
esac
[ -n "$OSFAM" ] || die "desteklenmeyen dagitim: $ID ($ID_LIKE)"
log "Dagitim: $PRETTY_NAME ($OSFAM ailesi)"

# ------------------------------------------------------------ 2. paket kurulumu
# ZORUNLU  : bunlar olmadan hicbir sey calismaz -> yoksa dur
# OPSIYONEL: her biri tek tek denenir, bulunamazsa UYARI verilip devam edilir.
#            Kayitli olmayan RHEL / yalnizca yerel ISO repo'su olan ya da tamamen
#            cevrimdisi sistemlerde lm_sensors, pcp-pmda-* gibi paketler
#            repo'da bulunmayabilir; bu kurulumu DURDURMAMALIDIR.
pkg_installed() {
    if [ "$OSFAM" = rhel ]; then rpm -q "$1" >/dev/null 2>&1
    else dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; fi
}
pkg_install_opt() {   # tek paket; basarisizlik olumcul degil
    local p=$1
    pkg_installed "$p" && return 0
    [ "$DRYRUN" -eq 1 ] && return 1
    if [ "$OSFAM" = rhel ]; then dnf -y install "$p" >/dev/null 2>&1
    else apt-get -y -qq install "$p" >/dev/null 2>&1; fi
    pkg_installed "$p"
}

if [ "$OSFAM" = rhel ]; then
    PKGS_REQ=(pcp pcp-conf pcp-system-tools)
    PKGS_OPT=(pcp-gui pcp-doc gawk smartmontools lm_sensors
              pcp-pmda-lmsensors pcp-pmda-smart pcp-pmda-dm pcp-pmda-bonding
              pcp-pmda-nfsclient pcp-pmda-sockets pcp-pmda-systemd)
else
    export DEBIAN_FRONTEND=noninteractive
    PKGS_REQ=(pcp)
    PKGS_OPT=(pcp-gui pcp-doc gawk smartmontools lm-sensors)
fi

EKSIK_REQ=(); EKSIK_OPT=()
for p in "${PKGS_REQ[@]}"; do pkg_installed "$p" || EKSIK_REQ+=("$p"); done
for p in "${PKGS_OPT[@]}"; do pkg_installed "$p" || EKSIK_OPT+=("$p"); done

# apt update yalnizca kurulacak paket varsa (apt update kendi basina atlama yapmaz)
if [ "$OSFAM" = deb ] && [ "$DRYRUN" -eq 0 ] && [ $(( ${#EKSIK_REQ[@]} + ${#EKSIK_OPT[@]} )) -gt 0 ]; then
    log "Paket listesi guncelleniyor (apt update)..."
    apt-get -qq update >/dev/null 2>&1 || warn "apt update hatali, mevcut cache ile devam"
fi

if [ ${#EKSIK_REQ[@]} -gt 0 ]; then
    if [ "$DRYRUN" -eq 1 ]; then
        chg "zorunlu paketler kurulacak: ${EKSIK_REQ[*]}"
    else
        log "Zorunlu paketler kuruluyor: ${EKSIK_REQ[*]}"
        if [ "$OSFAM" = rhel ]; then dnf -y install "${EKSIK_REQ[@]}" || true
        else apt-get -y -qq install "${EKSIK_REQ[@]}" || true; fi
        for p in "${PKGS_REQ[@]}"; do
            pkg_installed "$p" || die "zorunlu paket kurulamadi: $p (repo erisimi yok mu? cevrimdisi kurulum icin readme.txt)"
        done
        chg "zorunlu paketler kuruldu: ${EKSIK_REQ[*]}"
    fi
else
    skip "zorunlu paketler kurulu: ${PKGS_REQ[*]}"
fi

if [ ${#EKSIK_OPT[@]} -gt 0 ] && [ "$DRYRUN" -eq 1 ]; then
    chg "opsiyonel paketler denenecek (repoda olmayanlar atlanir): ${EKSIK_OPT[*]}"
elif [ ${#EKSIK_OPT[@]} -gt 0 ]; then
    log "Opsiyonel paketler deneniyor (bulunamayanlar atlanir): ${EKSIK_OPT[*]}"
    KURULU_OPT=(); ATLANAN_OPT=()
    for p in "${EKSIK_OPT[@]}"; do
        if pkg_install_opt "$p"; then KURULU_OPT+=("$p"); else ATLANAN_OPT+=("$p"); fi
    done
    [ ${#KURULU_OPT[@]}  -gt 0 ] && chg "opsiyonel paketler kuruldu: ${KURULU_OPT[*]}"
    [ ${#ATLANAN_OPT[@]} -gt 0 ] && warn "bulunamadi (bu alanlarda izleme sinirli olur): ${ATLANAN_OPT[*]}"
else
    skip "opsiyonel paketler kurulu"
fi

# PCP yol degiskenleri (iki dagitimda da /etc/pcp.conf standarttir)
if [ -f /etc/pcp.conf ]; then
    # shellcheck source=/dev/null
    . /etc/pcp.conf
elif [ "$DRYRUN" -eq 1 ]; then
    warn "/etc/pcp.conf yok (pcp kurulu degil); kuru calisma varsayilan yollarla devam ediyor"
else
    die "/etc/pcp.conf yok - pcp kurulumu eksik"
fi
: "${PCP_SYSCONF_DIR:=/etc/pcp}"
: "${PCP_ARCHIVE_DIR:=/var/log/pcp/pmlogger}"
: "${PCP_PMDAS_DIR:=/var/lib/pcp/pmdas}"
: "${PCP_BINADM_DIR:=/usr/libexec/pcp/bin}"
: "${PCP_SYSCONFIG_DIR:=/etc/sysconfig}"
: "${PCP_LOG_DIR:=/var/log/pcp}"
PMLOGGER_CFG_DIR=/var/lib/pcp/config/pmlogger
STATE_DIR=/var/lib/pcp-setup          # script'in kendi isaret dosyalari
PCP_OK=0; command -v pminfo >/dev/null 2>&1 && PCP_OK=1

# lm-sensors ilk donanim tespiti (non-interaktif; sensor yoksa zararsiz).
# sensors-detect calistiginda yapilandirma dosyasina "# Generated by
# sensors-detect" basligi yazar (RHEL: /etc/sysconfig/lm_sensors - DIKKAT: bu
# dosya paketle de gelir, varligi tek basina kanit degildir; Debian:
# /etc/modules). Bu baslik ya da script'in kendi isaret dosyasi varsa
# tekrar calistirilmaz; -f ile yeniden calistirilir.
if command -v sensors-detect >/dev/null 2>&1; then
    if [ "$FORCE" -eq 0 ] && { grep -qs '^# Generated by sensors-detect' /etc/sysconfig/lm_sensors \
         /etc/conf.d/lm_sensors /etc/modules || [ -e "$STATE_DIR/sensors-detect.done" ]; }; then
        skip "sensors-detect daha once calismis"
    else
        run bash -c 'yes "" | sensors-detect --auto >/dev/null 2>&1 || true'
        run mkdir -p "$STATE_DIR"; run touch "$STATE_DIR/sensors-detect.done"
        chg "sensors-detect calistirildi"
    fi
fi

# --------------------------------- 3. proc PMDA -A (tum prosesler arsivlensin)
CHANGED_PMCD=0
PMCD_CONF="$PCP_SYSCONF_DIR/pmcd/pmcd.conf"
if grep -qE '^proc[[:space:]].*pmdaproc' "$PMCD_CONF" 2>/dev/null; then
    if grep -qE '^proc[[:space:]].*pmdaproc.* -A' "$PMCD_CONF"; then
        skip "proc PMDA'da -A mevcut"
    else
        [ -e "$PMCD_CONF.pcp-setup.orig" ] || run cp -p "$PMCD_CONF" "$PMCD_CONF.pcp-setup.orig"
        run sed -i '/^proc[[:space:]].*pmdaproc/ s/$/ -A/' "$PMCD_CONF"
        chg "proc PMDA'ya -A eklendi (pmlogger tum prosesleri gorebilecek)"
        warn "-A ile pmcd/pmproxy'e erisebilen istemciler tum proses adlarini/istatistiklerini okuyabilir"
        CHANGED_PMCD=1
    fi
elif [ "$PCP_OK" -eq 1 ]; then
    warn "pmcd.conf icinde proc PMDA satiri bulunamadi!"
fi

# ------------------------------------------- 4. ek PMDA'larin etkinlestirilmesi
# .NeedInstall dosyasi birakilir; pmcd yeniden baslarken PMDA'yi kendisi kurar.
# Sabit liste yerine SISTEMDE KURULU olan PMDA'lar taranir: cevrimdisi/ISO
# repo'lu sistemlerde hangi pcp-pmda-* paketlerinin geldigi degisir.
# Beyaz liste: yalnizca ek yapilandirma gerektirmeyen, guvenli PMDA'lar.
# pmcd, kurulumu basarisiz olan PMDA icin .NeedInstall.failed birakir (orn.
# bonding arayuzu olmayan makinede bonding); bunlar tekrar denenmez, yoksa
# her calismada bosuna pmcd yeniden baslatilir.
PMDA_ISTENEN="lmsensors smart dm bonding nfsclient sockets systemd mounts perfevent"
PMDA_ACILAN=""; PMDA_ZATEN=""; PMDA_YOK=""; PMDA_HATALI=""
for pmda in $PMDA_ISTENEN; do
    d="$PCP_PMDAS_DIR/$pmda"
    if [ -d "$d" ] && [ -x "$d/Install" ]; then
        if grep -qE "^${pmda}[[:space:]]" "$PMCD_CONF" 2>/dev/null; then
            PMDA_ZATEN="$PMDA_ZATEN $pmda"
        elif [ -e "$d/.NeedInstall.failed" ] && [ "$FORCE" -eq 0 ]; then
            PMDA_HATALI="$PMDA_HATALI $pmda"
        elif [ -e "$d/.NeedInstall" ]; then
            PMDA_ZATEN="$PMDA_ZATEN $pmda(bekliyor)"
        else
            run rm -f "$d/.NeedInstall.failed"
            run touch "$d/.NeedInstall" && PMDA_ACILAN="$PMDA_ACILAN $pmda" && CHANGED_PMCD=1
        fi
    else
        PMDA_YOK="$PMDA_YOK $pmda"
    fi
done
[ -n "$PMDA_ACILAN" ] && chg "PMDA etkinlestiriliyor:$PMDA_ACILAN"
[ -n "$PMDA_ZATEN" ]  && skip "PMDA etkin:$PMDA_ZATEN"
[ -n "$PMDA_HATALI" ] && warn "PMDA kurulumu daha once basarisiz olmus, tekrar denenmiyor (-f ile denenir):$PMDA_HATALI"
[ -n "$PMDA_YOK" ]    && warn "PMDA kurulu degil, atlaniyor:$PMDA_YOK"

# --- 4b. hotproc: olceklenebilir proses izleme -------------------------------
# proc PMDA tum prosesleri (yuzlerce) her ornekte tarar; hotproc yalnizca
# esigi asanlari izler. Buyuk sunucularda pmcd yukunu ve arsiv boyutunu
# 10-20 kat dusurur. hotproc.conf YOKSA hotproc.nprocs=0 doner ve
# hotproc.* metrikleri bos kalir - varsayilan kurulumda bu dosya yoktur.
# Mevcut (elle ayarlanmis olabilecek) dosyaya dokunulmaz; -f ile yenilenir.
HOTPROC_CONF="$PCP_PMDAS_DIR/proc/hotproc.conf"
if [ -d "$PCP_PMDAS_DIR/proc" ]; then
    if [ -f "$HOTPROC_CONF" ] && [ "$FORCE" -eq 0 ]; then
        skip "hotproc yapilandirmasi mevcut: $HOTPROC_CONF"
    else
        if put_file "$HOTPROC_CONF" 644 "hotproc filtresi $HOTPROC_CONF" <<'HP_EOF'
#pmdahotproc
Version 1.0
# pcp-setup.sh / pcp_setup rolu: CPU payi %10'u asan VEYA 100 MB'tan cok RSS
# kullanan prosesler "sicak" sayilir ve hotproc.* altinda ayrica izlenir.
cpuburn > 0.10 || residentsize > 102400
HP_EOF
        then CHANGED_PMCD=1; fi
    fi
elif [ "$PCP_OK" -eq 1 ]; then
    warn "proc PMDA dizini yok, hotproc atlaniyor"
fi

# ---------------------- 5. pmcd'yi baslat, PMDA kurulumlarinin oturmasini bekle
# Yapilandirma canli metrik agacindan uretilecegi icin pmcd once ayaga kalkmali;
# ayrica pmlogger, pmcd durumu degisirken calisirsa dogrulama dongusune girip
# pmlogger.log'u sisirebiliyor (derived metrik + "PMCD state changed" hatasi).
# pmcd YALNIZCA pmcd.conf / PMDA listesi / hotproc.conf degistiyse yeniden
# baslatilir; aksi halde calisiyorsa dokunulmaz.
if [ "$PCP_OK" -eq 1 ]; then
    svc_enable pmcd
    PMCD_RESTARTED=0
    if svc_apply pmcd "$CHANGED_PMCD"; then :; else die "pmcd baslatilamadi"; fi
    { [ "$CHANGED_PMCD" -eq 1 ] || [ "$FORCE" -eq 1 ]; } && PMCD_RESTARTED=1
    if [ "$DRYRUN" -eq 0 ]; then
        "$PCP_BINADM_DIR/pmcd_wait" -t 60 2>/dev/null
        # PMDA .NeedInstall kurulumlarinin bitmesini bekle: Debian/Ubuntu'da bunlar
        # pmcd "Started" dedikten SONRA arka planda calisir ve her biri pmcd'yi
        # yeniden baslatabilir - bu sirada pmlogger baslatilirsa hemen durdurulur.
        for _ in $(seq 1 60); do
            ls "$PCP_PMDAS_DIR"/*/.NeedInstall >/dev/null 2>&1 && { sleep 2; continue; }
            pgrep -f "$PCP_PMDAS_DIR/.*/Install" >/dev/null 2>&1 && { sleep 2; continue; }
            break
        done
        [ "$PMCD_RESTARTED" -eq 1 ] && sleep 5   # pmcd durumunun oturmasi icin
    fi
fi

# ----------------------------------------------- 6. pmlogger izleme yapilandirmasi
# Metrik listesi canli pmns'ten uretilir. Haric tutulanlar:
#  - derived metrikler (PMID domain 511): pmcd durum degisiminde pmlogger'i
#    hata dongusune sokabiliyor; zaten temel metriklerden yeniden hesaplanabilir
#  - proc.psinfo.environ: tum proseslerin environment'i (parola/secret riski)
# Dosyada tarih damgasi YOKTUR: icerik yalnizca metrik agaci ya da aralik
# degistiginde degisir, boylece gereksiz pmlogger yeniden baslatmasi olmaz.
CHANGED_PMLOGGER=0
gen_leaves() { pminfo -m "$@" 2>/dev/null | awk '$2 == "PMID:" && $3 !~ /^511\./ && $1 !~ /environ/ { print "    " $1 }' | sort -u; }

CFG="$PMLOGGER_CFG_DIR/config.pcp-full"
if [ "$PCP_OK" -eq 1 ] && [ "$(systemctl is-active pmcd 2>/dev/null)" = active ]; then
    SYS_METRICS=$(gen_leaves kernel.all kernel.percpu kernel.pernode mem swap disk \
                             filesys vfs network nfs nfs4 rpc proc.nprocs proc.runq)
    PROC_METRICS=$(gen_leaves proc.psinfo proc.id proc.memory proc.io proc.schedstat proc.fd.count)
    HW_METRICS=$(gen_leaves lmsensors smart dmcache vdo)
    HINV_METRICS=$(gen_leaves hinv kernel.uname)
    [ -n "$SYS_METRICS" ]  || die "sistem metrik listesi uretilemedi (pmcd calismiyor mu?)"
    [ -n "$PROC_METRICS" ] || die "proses metrik listesi uretilemedi (proc PMDA sorunlu mu?)"

    log "pmlogger yapilandirmasi: $CFG (ornekleme: ${INTERVAL}s)"
    log "  metrik sayisi: sistem $(echo "$SYS_METRICS" | wc -l), proses $(echo "$PROC_METRICS" | wc -l), donanim $(echo "$HW_METRICS" | grep -c . ), envanter $(echo "$HINV_METRICS" | wc -l)"
    if {
    cat <<EOF
# pcp-setup.sh tarafindan uretildi - elle duzenlemeyin, script tekrar calisinca uzerine yazar.
# Tam sistem izleme: CPU, bellek, disk, fs, network, prosesler, donanim.
# Liste kurulum anindaki canli metrik agacindan uretilmistir;
# derived metrikler (domain 511) ve proc.psinfo.environ bilerek haric.

# --- sistem geneli: CPU, bellek, disk, filesystem, network/ethernet ----------
log mandatory on every $INTERVAL seconds {
$SYS_METRICS
}

# --- proses detaylari (kullanici kimlikleriyle) ------------------------------
log mandatory on every $INTERVAL seconds {
$PROC_METRICS
}
EOF
    if [ -n "$HW_METRICS" ]; then
    cat <<EOF

# --- donanim: sensorler (lmsensors), disk sagligi (smart), dm ----------------
log advisory on every 300 seconds {
$HW_METRICS
}
EOF
    fi
    cat <<EOF

# --- donanim envanteri (arsiv basina bir kez) --------------------------------
log mandatory on once {
$HINV_METRICS
}

[access]
disallow .* : all;
disallow :* : all;
allow local:* : enquire;
EOF
    } | put_file "$CFG" 644 "pmlogger yapilandirmasi $CFG"; then CHANGED_PMLOGGER=1; fi
else
    warn "pmcd calismiyor, pmlogger yapilandirmasi uretilemedi (kuru calismada normal)"
fi

# birincil pmlogger'i bu yapilandirmaya yonlendir
CTRL=""
for f in "$PCP_SYSCONF_DIR/pmlogger/control.d/local" "$PCP_SYSCONF_DIR/pmlogger/control"; do
    [ -f "$f" ] && grep -qE '^[^#]*LOCALHOSTNAME.*-c[[:space:]]' "$f" && { CTRL=$f; break; }
done
# DIKKAT: yedek ASLA control.d/ icine konmaz - pmlogger_check oradaki her
# dosyayi kontrol dosyasi olarak okur ve ayni arsiv dizinini iki kez gorunce
# "Duplicate pmlogger instances" hatasiyla cikar (PCP 7'de pmlogger_farm'i,
# BindsTo nedeniyle de pmlogger'i dusurur).
BAKDIR="$PCP_SYSCONF_DIR/pmlogger/backup.pcp-setup"
# onceki surumlerin control.d icine biraktigi yedekleri de tasiyarak duzelt
for old in "$PCP_SYSCONF_DIR"/pmlogger/control.d/*.pcp-setup.orig; do
    [ -e "$old" ] || continue
    run mkdir -p "$BAKDIR"; run mv "$old" "$BAKDIR/"
    chg "control.d altindaki eski yedek tasindi: $old -> $BAKDIR/"
    CHANGED_PMLOGGER=1
done
if [ -n "$CTRL" ]; then
    if grep -qE '^[^#]*LOCALHOSTNAME.*-c[[:space:]]+config\.pcp-full([[:space:]]|$)' "$CTRL"; then
        skip "birincil pmlogger config.pcp-full'a yonlendirilmis: $CTRL"
    else
        run mkdir -p "$BAKDIR"
        [ -e "$BAKDIR/$(basename "$CTRL").orig" ] || run cp -p "$CTRL" "$BAKDIR/$(basename "$CTRL").orig"
        run sed -i -E '/^[^#]*LOCALHOSTNAME/ s/-c[[:space:]]+[^[:space:]]+/-c config.pcp-full/' "$CTRL"
        chg "birincil pmlogger config.pcp-full'a yonlendirildi: $CTRL"
        CHANGED_PMLOGGER=1
    fi
else
    CTRL="$PCP_SYSCONF_DIR/pmlogger/control.d/local"
    if put_file "$CTRL" 644 "pmlogger kontrol dosyasi $CTRL" <<'EOF'
$version=1.1
LOCALHOSTNAME	y	n	PCP_ARCHIVE_DIR/LOCALHOSTNAME	-r -T24h10m -c config.pcp-full -v 100Mb
EOF
    then CHANGED_PMLOGGER=1; fi
fi
ensure_mode "$CTRL" 644     # pmlogger_daily/check 'pcp' kullanicisiyla okur

# ---------------- 6b. inceleme sablonlari: pmrep :canli / :obur / :agirlik ----
# Hazir sablonlar /etc/pcp/pmrep/ altina konur; boylece o dizindeki 90'dan
# fazla hazir sablonla birlikte okunur.  DIKKAT: ~/.pcp/pmrep.conf OLUSTURMAYIN;
# pmrep ilk buldugu yapilandirmayi kullanir ve /etc/pcp/pmrep/ altindaki tum
# hazir sablonlar (:vmstat, :sar-*, :pidstat-*) erisilemez hale gelir.
PMREP_DIR="$PCP_SYSCONF_DIR/pmrep"
if [ -d "$PMREP_DIR" ]; then
    put_file "$PMREP_DIR/ozel.conf" 644 "pmrep sablonlari $PMREP_DIR/ozel.conf (:canli :obur :agirlik)" <<'PMREP_EOF'
# pcp-setup.sh / pcp_setup Ansible rolu tarafindan olusturuldu.
# Kullanim:  pmrep -t 1s -z :canli        (canli, tek ekranda dort alt sistem)
#            pmrep -t 2s -J 10 -6 proc.hog.cpu :obur | head -12
#            pmrep -a ARSIV -z -S @03:00 -T @04:00 -t 5m :canli   (gecmis)

# --- :canli  CPU + RAM + Disk + Ag tek satirda -------------------------------
[canli]
header = yes
unitinfo = no
instinfo = no
globals = no
timestamp = yes
precision = 1
delimiter = " "
repeat_header = 20
kernel.cpu.util.user  = cpu_us,,,,6
kernel.cpu.util.sys   = cpu_sy,,,,6
kernel.cpu.util.wait  = cpu_wa,,,,6
kernel.all.load       = load1,1 minute,,,6
mem.util.used         = mem_use,,MB,,8
mem.util.available    = mem_free,,MB,,8
disk.all.read_bytes   = dsk_rd,,KB,,8
disk.all.write_bytes  = dsk_wr,,KB,,8
disk.all.total        = iops,,,,7
network.all.in.bytes  = net_in,,KB,,8
network.all.out.bytes = net_out,,KB,,8

# --- :obur  en cok kaynak yiyen prosesler (siralamak icin -J ve -6 gerekir) ---
[obur]
header = yes
instinfo = no
unitinfo = no
globals = no
timestamp = yes
precision = 1
delimiter = " "
repeat_header = 15
colxrow = "    PID / Komut satiri"
proc.hog.cpu = CPU_pct,,,,8

# --- :agirlik  disk cihaz basina doygunluk/gecikme ---------------------------
[agirlik]
header = yes
instinfo = no
unitinfo = no
globals = no
timestamp = yes
precision = 2
delimiter = " "
repeat_header = 20
colxrow = "     Cihaz"
disk.dev.util     = util_pct,,,,9
disk.dev.await    = await_ms,,,,9
disk.dev.avg_qlen = kuyruk,,,,8
disk.dev.read_bytes  = oku_KB,,KB,,9
disk.dev.write_bytes = yaz_KB,,KB,,9
PMREP_EOF
elif [ "$PCP_OK" -eq 1 ]; then
    warn "$PMREP_DIR yok, pmrep sablonlari atlaniyor"
fi

# ------------------------------ 6c. pmie: esik alarmlari (syslog'a yazar) -----
# pmieconf ile gelen hazir kural kutuphanesi kullanilir; kendi kuralimizi
# yazmak yerine esiklerini ayarlamak surum yukseltmelerinde bakim gerektirmez.
# pmieconf'un enable/modify komutlari bir sey degistirmese de basarili doner;
# bu yuzden once MEVCUT DURUM okunur, yalnizca farkli olanlar uygulanir.
PMIE_CFG=/var/lib/pcp/config/pmie/config.default
CHANGED_PMIE=0
# Temiz kurulumda config.default henuz yoktur: pmie ilk basladiginda pmie_check
# onu pmieconf ile uretir. Once bu dogal yol denenir; olmazsa pmieconf'un ilk
# "enable" komutu dosyayi varsayilanlarla kendisi olusturur.
if command -v pmieconf >/dev/null 2>&1 && [ ! -f "$PMIE_CFG" ] && [ -d "$(dirname "$PMIE_CFG")" ] && [ "$DRYRUN" -eq 0 ]; then
    log "pmie yapilandirmasi ($PMIE_CFG) yok; pmie baslatilarak uretiliyor..."
    systemctl start pmie >/dev/null 2>&1
    for _ in $(seq 1 15); do [ -f "$PMIE_CFG" ] && break; sleep 2; done
    [ -f "$PMIE_CFG" ] || warn "pmie_check dosyayi uretmedi; pmieconf ile olusturulacak"
fi
if command -v pmieconf >/dev/null 2>&1 && [ -d "$(dirname "$PMIE_CFG")" ]; then
    ETKIN=$(pmieconf -f "$PMIE_CFG" rules enabled 2>/dev/null)
    ACILAN_KURAL=""; ZATEN_KURAL=""
    for kural in cpu.util cpu.load_average cpu.system memory.exhausted \
                 memory.swap_low filesys.filling filesys.vfs_files \
                 per_disk.average_wait_time per_netif.errors; do
        if grep -qE "^[[:space:]]+${kural}[[:space:]]" <<<"$ETKIN"; then
            ZATEN_KURAL="$ZATEN_KURAL $kural"
        elif run pmieconf -f "$PMIE_CFG" enable "$kural" 2>/dev/null; then
            ACILAN_KURAL="$ACILAN_KURAL $kural"; CHANGED_PMIE=1
        fi
    done
    [ -n "$ACILAN_KURAL" ] && chg "pmie kurallari etkinlestirildi:$ACILAN_KURAL"
    [ -n "$ZATEN_KURAL" ]  && skip "pmie kurallari etkin:$ZATEN_KURAL"
    # esikler: sanal/kucuk sunucularda varsayilanlar cok gec tetikleniyor
    for esik in "cpu.util threshold 90%" "filesys.filling threshold 90%"; do
        read -r r v d <<<"$esik"
        if pmieconf -f "$PMIE_CFG" list "$r" "$v" 2>/dev/null | grep -qE "^[[:space:]]*${v}[[:space:]]*=[[:space:]]*${d}[[:space:]]*$"; then
            skip "pmie esigi $r.$v = $d"
        else
            run pmieconf -f "$PMIE_CFG" modify "$r" "$v" "$d" 2>/dev/null && { chg "pmie esigi $r.$v = $d yapildi"; CHANGED_PMIE=1; }
        fi
    done
    svc_enable pmie
    svc_apply pmie "$CHANGED_PMIE" || warn "pmie baslatilamadi"
    log "  alarmlar: journalctl -t pmie  /  $PCP_LOG_DIR/pmie/$(hostname)/pmie.log"
elif [ "$PCP_OK" -eq 1 ]; then
    warn "pmieconf veya $PMIE_CFG yok, alarm yapilandirmasi atlaniyor"
fi

# ------------------------- 7. gunluk rotasyon: sikistir + $KEEP_DAYS gun sakla
TIMERS="$PCP_SYSCONFIG_DIR/pmlogger_timers"
DAILY_PARAMS="-E -x 0 -k $KEEP_DAYS"      # -x 0: rotasyonda hemen sikistir, -k: gun sonra sil
WANT_LINE="PMLOGGER_DAILY_PARAMS=\"$DAILY_PARAMS\""
if [ -f "$TIMERS" ] && grep -qxF "$WANT_LINE" "$TIMERS"; then
    skip "gunluk rotasyon: $WANT_LINE ($TIMERS)"
elif [ -f "$TIMERS" ] && grep -qE '^PMLOGGER_DAILY_PARAMS=' "$TIMERS"; then
    run sed -i -E "s|^PMLOGGER_DAILY_PARAMS=.*|$WANT_LINE|" "$TIMERS"
    chg "gunluk rotasyon parametresi guncellendi: $WANT_LINE ($TIMERS)"
else
    run mkdir -p "$(dirname "$TIMERS")"
    run bash -c "echo '$WANT_LINE' >> '$TIMERS'"
    chg "gunluk rotasyon parametresi eklendi: $WANT_LINE ($TIMERS)"
fi
ensure_mode "$TIMERS" 644    # pmlogger_daily/check 'pcp' kullanicisiyla okur

# --------------------------------- 8. disk koruma: pcp-log-guard kurulumu
GUARD=/usr/local/sbin/pcp-log-guard.sh
GUARD_CONF="$PCP_SYSCONF_DIR/pcp-log-guard.conf"
CHANGED_UNITS=0

put_file "$GUARD_CONF" 644 "pcp-log-guard ayarlari $GUARD_CONF" <<EOF
# pcp-log-guard yapilandirmasi (pcp-setup.sh tarafindan olusturuldu)
THRESHOLD_PCT=$THRESHOLD_PCT   # ayri volumde bu dolulukta eski arsivler silinir
TARGET_PCT=$(( THRESHOLD_PCT - 10 ))       # silme bu dolulugun altina inince durur
EMERG_PCT=90                   # her durumda: fs bu seviyeye gelirse acil mudahale
MAX_SIZE_GB=$MAX_SIZE_GB       # ayri volum DEGILSE toplam pcp log siniri
KEEP_DAYS=$KEEP_DAYS
LOG_MAX_MB=200                 # pmlogger.log bu boyutu asarsa sifirlanir (tasma sigortasi)
EOF

put_file "$GUARD" 755 "disk koruma scripti $GUARD" <<'GUARD_EOF'
#!/bin/bash
#
# pcp-log-guard.sh - PCP arsivlerinin diski doldurmasini engeller.
# pcp-setup.sh / pcp_setup Ansible rolu tarafindan kurulur, systemd timer ile
# 10 dakikada bir calisir.
#
# Mantik:
#  - /var/log/pcp ayri bir bolum/LV ise: doluluk >= THRESHOLD_PCT oldugunda
#    rotasyon/sikistirma calistirilir ve en eski arsiv setleri TARGET_PCT'ye
#    inilene kadar silinir.
#  - Ayri bolum degilse: toplam pcp log boyutu MAX_SIZE_GB'yi asarsa eski
#    arsivler sinirin %90'ina inilene kadar silinir.
#  - Her iki durumda: dosya sistemi EMERG_PCT'ye ulasirsa gunun arsivi haric
#    her sey silinir; hala kritikse pmlogger durdurulur (disk ASLA pcp
#    yuzunden dolmaz). Doluluk TARGET_PCT altina inince pmlogger otomatik
#    tekrar baslatilir.
#  - Aktif (bugunun) arsivi asla silinmez.
#  - Ayni anda tek kopya calisir (flock); timer ile elle calistirma cakismaz.
#
set -o pipefail
# shellcheck source=/dev/null
. /etc/pcp.conf 2>/dev/null
: "${PCP_ARCHIVE_DIR:=/var/log/pcp/pmlogger}"
: "${PCP_BINADM_DIR:=/usr/libexec/pcp/bin}"
: "${PCP_SYSCONF_DIR:=/etc/pcp}"

THRESHOLD_PCT=80; TARGET_PCT=70; EMERG_PCT=90; MAX_SIZE_GB=2; KEEP_DAYS=14; LOG_MAX_MB=200
# shellcheck source=/dev/null
[ -f "$PCP_SYSCONF_DIR/pcp-log-guard.conf" ] && . "$PCP_SYSCONF_DIR/pcp-log-guard.conf"

PCPLOG=$(dirname "$PCP_ARCHIVE_DIR")           # genellikle /var/log/pcp
TODAY=$(date +%Y%m%d)
STOPFLAG=/run/pcp-log-guard.pmlogger-stopped
LOCK=/run/lock/pcp-log-guard.lock

say() { logger -t pcp-log-guard "$*"; echo "[pcp-log-guard] $*"; }

# ayni anda iki kopya (timer + elle calistirma) ayni arsivleri silmeye
# kalkmasin; kilit alinamazsa sessizce cik
exec 9>"$LOCK" || exit 0
flock -n 9 || { say "baska bir kopya calisiyor, cikiliyor"; exit 0; }

fs_pct()   { df -P "$PCPLOG" | awk 'NR==2 { sub(/%/,"",$5); print $5 }'; }
logs_size(){ du -sb "$PCPLOG" 2>/dev/null | awk '{print $1}'; }

# /var/log/pcp (veya arsiv dizini) kendi basina bir mount noktasi mi?
DEDICATED=0
mp=$(findmnt -no TARGET --target "$PCPLOG" 2>/dev/null)
if [ "$mp" = "$PCPLOG" ] || [ "$mp" = "$PCP_ARCHIVE_DIR" ]; then DEDICATED=1; fi

# en eski kapali arsiv setini sil; silinecek bir sey yoksa 1 doner
cull_oldest() {
    local oldest
    oldest=$(find "$PCP_ARCHIVE_DIR" -mindepth 2 -maxdepth 2 -name '*.meta*' \
                  ! -name "${TODAY}*" 2>/dev/null \
             | sed -E 's/\.meta(\.(xz|zst|gz|bz2|lzma|lz4))?$//' \
             | awk -F/ '{ print $NF "\t" $0 }' | sort | head -1 | cut -f2-)
    [ -n "$oldest" ] || return 1
    say "eski arsiv siliniyor: $oldest.*"
    rm -f "$oldest".*
}

rotate_compress() {
    # birikmis arsiv parcalarini birlestir, sikistir, saklama suresini uygula
    "$PCP_BINADM_DIR/pmlogger_daily" -E -x 0 -k "$KEEP_DAYS" >/dev/null 2>&1
}

# ---- tasma sigortasi: pmlogger hata dongusune girip kendi log dosyasini ------
# ---- sisirebilir; LOG_MAX_MB asilirsa dosya sifirlanir ------------------------
for lf in "$PCP_ARCHIVE_DIR"/*/pmlogger.log "$PCP_ARCHIVE_DIR"/*/pmlogger.log.prev; do
    [ -f "$lf" ] || continue
    if [ "$(stat -c %s "$lf")" -gt $(( LOG_MAX_MB * 1048576 )) ]; then
        say "asiri buyuk log dosyasi sifirlaniyor: $lf ($(numfmt --to=iec "$(stat -c %s "$lf")"))"
        : > "$lf"
    fi
done

# ---- mod bazli sinir kontrolu ------------------------------------------------
if [ "$DEDICATED" -eq 1 ]; then
    if [ "$(fs_pct)" -ge "$THRESHOLD_PCT" ]; then
        say "ayri volum %$(fs_pct) dolu (esik %$THRESHOLD_PCT): rotasyon + temizlik"
        rotate_compress
        while [ "$(fs_pct)" -ge "$TARGET_PCT" ]; do cull_oldest || break; done
        say "temizlik sonrasi doluluk: %$(fs_pct)"
    fi
else
    LIMIT=$(( MAX_SIZE_GB * 1024 * 1024 * 1024 ))
    if [ "$(logs_size)" -gt "$LIMIT" ]; then
        say "pcp log boyutu $(numfmt --to=iec "$(logs_size)") > ${MAX_SIZE_GB}GB: rotasyon + temizlik"
        rotate_compress
        while [ "$(logs_size)" -gt $(( LIMIT * 90 / 100 )) ]; do cull_oldest || break; done
        say "temizlik sonrasi boyut: $(numfmt --to=iec "$(logs_size)")"
    fi
fi

# ---- acil durum: dosya sistemi dolmak uzere -----------------------------------
# NOT: ayri volum degilse bu olcum kok dosya sistemine aittir; disk PCP disi bir
# nedenle dolsa bile eski arsivler feda edilir (izleme verisi diskten degerli degil)
if [ "$(fs_pct)" -ge "$EMERG_PCT" ]; then
    say "ACIL: $PCPLOG dosya sistemi %$(fs_pct) dolu, eski arsivlerin tumu siliniyor"
    rotate_compress
    while [ "$(fs_pct)" -ge "$EMERG_PCT" ]; do cull_oldest || break; done
    if [ "$(fs_pct)" -ge "$EMERG_PCT" ]; then
        say "KRITIK: temizlik yetersiz, disk dolmasin diye pmlogger durduruluyor!"
        systemctl stop pmlogger && touch "$STOPFLAG"
    fi
fi

# guard'in durdurdugu pmlogger'i alan acilinca geri baslat
if [ -f "$STOPFLAG" ] && [ "$(fs_pct)" -lt "$TARGET_PCT" ]; then
    say "doluluk %$(fs_pct), pmlogger yeniden baslatiliyor"
    systemctl start pmlogger && rm -f "$STOPFLAG"
fi
exit 0
GUARD_EOF

if put_file /etc/systemd/system/pcp-log-guard.service 644 "pcp-log-guard.service" <<EOF
[Unit]
Description=PCP arsiv disk koruma kontrolu
After=pmlogger.service

[Service]
Type=oneshot
ExecStart=$GUARD
EOF
then CHANGED_UNITS=1; fi
if put_file /etc/systemd/system/pcp-log-guard.timer 644 "pcp-log-guard.timer" <<'EOF'
[Unit]
Description=PCP arsiv disk korumasi (10 dakikada bir)

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF
then CHANGED_UNITS=1; fi
if [ "$CHANGED_UNITS" -eq 1 ]; then run systemctl daemon-reload; chg "systemd daemon-reload (unit dosyalari degisti)"
else skip "systemd unit dosyalari ayni, daemon-reload gerekmedi"; fi
if [ "$(systemctl is-enabled pcp-log-guard.timer 2>/dev/null)" = enabled ] && \
   [ "$(systemctl is-active  pcp-log-guard.timer 2>/dev/null)" = active ]; then
    skip "pcp-log-guard.timer etkin ve aktif (10 dakikada bir kontrol)"
else
    run systemctl enable -q --now pcp-log-guard.timer && chg "pcp-log-guard.timer etkinlestirildi (10 dakikada bir kontrol)"
fi

# ------------------------------------------ 9. pmlogger'i etkinlestir & baslat
PMLOGGER_RESTARTED=0
if [ "$PCP_OK" -eq 1 ]; then
    svc_enable pmlogger
    # onceki crashloop kilitlerini ac (PCP 7'de pmlogger BindsTo=pmlogger_farm)
    [ "$DRYRUN" -eq 1 ] || systemctl reset-failed pmlogger pmlogger_farm >/dev/null 2>&1
    svc_apply pmlogger "$CHANGED_PMLOGGER" || die "pmlogger baslatilamadi"
    { [ "$CHANGED_PMLOGGER" -eq 1 ] || [ "$FORCE" -eq 1 ]; } && PMLOGGER_RESTARTED=1
    for t in pmlogger_daily.timer pmlogger_check.timer; do
        if [ "$(systemctl is-enabled "$t" 2>/dev/null)" = enabled ] && [ "$(systemctl is-active "$t" 2>/dev/null)" = active ]; then
            skip "$t etkin"
        else
            run systemctl enable -q --now "$t" && chg "$t etkinlestirildi"
        fi
    done
fi

if [ "$DRYRUN" -eq 1 ]; then
    echo
    log "Kuru calisma tamamlandi: $N_CHG degisiklik yapilacak, $N_SKIP adim zaten yerinde."
    log "Mevcut kurulumu sinamak icin: ./pcp-dogrula.sh"
    exit 0
fi

# --------------------------------------------------------------- 10. dogrulama
log "Dogrulama yapiliyor..."
[ "$PMLOGGER_RESTARTED" -eq 1 ] && sleep $(( INTERVAL < 15 ? INTERVAL + 5 : 15 ))
ERR=0

for s in pmcd pmlogger; do
    if [ "$(systemctl is-active $s)" != active ]; then
        # PMDA kurulumu gibi es zamanli bir pmcd yeniden baslatmasi servisi
        # dusurmus olabilir; bir kez toparlamayi dene
        systemctl reset-failed $s >/dev/null 2>&1
        systemctl start $s >/dev/null 2>&1
        sleep 5
    fi
    if [ "$(systemctl is-active $s)" = active ]; then log "  [OK] $s aktif"
    else warn "  [!!] $s AKTIF DEGIL"; ERR=1; fi
done

NP_ROOT=$(pminfo -f proc.psinfo.pid 2>/dev/null | grep -c inst)
NP_PCP=$(runuser -u pcp -- pminfo -f proc.psinfo.pid 2>/dev/null | grep -c inst)
if [ "$NP_PCP" -ge $(( NP_ROOT * 8 / 10 )) ] && [ "$NP_PCP" -gt 10 ]; then
    log "  [OK] proses gorunurlugu: pcp kullanicisi $NP_PCP / root $NP_ROOT proses goruyor"
else
    warn "  [!!] pcp kullanicisi sadece $NP_PCP proses goruyor (root: $NP_ROOT) - arsivde proses verisi eksik kalir"
    ERR=1
fi

for m in lmsensors smart; do
    if pminfo "$m" >/dev/null 2>&1; then log "  [OK] $m metrikleri mevcut"
    else warn "  [--] $m metrikleri yok (donanim/PMDA destegi olmayabilir)"; fi
done

HOSTDIR="$PCP_ARCHIVE_DIR/$(hostname)"
NEWEST=$(find "$HOSTDIR" -name '*.0' -newermt '-5 minutes' 2>/dev/null | head -1)
if [ -n "$NEWEST" ]; then log "  [OK] arsiv diske yaziliyor: $NEWEST"
else warn "  [!!] $HOSTDIR altinda guncel arsiv bulunamadi"; ERR=1; fi

# canli arsiv "Latest" folio dosyasindan bulunur (lexical ls yaniltici olabilir)
ARCH=$(awk '/^Archive:/ { print $3 }' "$HOSTDIR/Latest" 2>/dev/null)
if [ -n "$ARCH" ]; then
    NINST=$(pminfo -f -a "$ARCH" proc.psinfo.pid 2>/dev/null | grep -c inst)
    if [ "$NINST" -gt 10 ]; then
        log "  [OK] arsivde $NINST prosesin verisi kaydediliyor"
    else
        warn "  [!!] arsivde sadece $NINST proses var (ilk ornek henuz diske inmemis olabilir;"
        warn "       birkac dakika sonra kontrol: pminfo -f -a $ARCH proc.psinfo.pid | grep -c inst)"
    fi
fi

# --- yeni yetenekler: hotproc, sablonlar, alarmlar, turetilmis metrikler ---
# hotproc'un DOGRU olcusu yuklu filtre ifadesidir; nprocs bos sistemde
# hakli olarak 0 olur ve ~20 sn (2 refresh dongusu) sonra dolar.
HOTCFG=$(pminfo -f hotproc.control.config 2>/dev/null | awk -F'"' '/value/ {print $2}')
NHOT=$(pminfo -f hotproc.nprocs 2>/dev/null | awk '/value/ {print $2}')
if [ -n "$HOTCFG" ]; then
    log "  [OK] hotproc filtresi yuklu: $HOTCFG"
    if [ -n "$NHOT" ] && [ "$NHOT" -gt 0 ] 2>/dev/null; then
        log "  [OK] hotproc su an $NHOT sicak proses izliyor"
    else
        log "  [--] hotproc.nprocs=0: su an esigi asan proses yok (bos sistemde normal;"
        log "       yuk altinda ~20 sn icinde dolar - kontrol: pminfo -f hotproc.nprocs)"
    fi
else
    warn "  [!!] hotproc filtresi yuklenmemis (proc PMDA hotproc.conf'u okumadi mi?)"; ERR=1
fi

for ms in canli obur agirlik; do
    if pmrep -t 1s -s 2 -z ":$ms" >/dev/null 2>&1; then log "  [OK] pmrep sablonu calisiyor: :$ms"
    else warn "  [!!] pmrep sablonu calismiyor: :$ms"; ERR=1; fi
done
# hazir sablonlarin hala erisilebilir oldugunu dogrula (~/.pcp/pmrep.conf tuzagi)
if pmrep -t 1s -s 2 -z :vmstat >/dev/null 2>&1; then
    log "  [OK] hazir sablonlar erisilebilir (:vmstat)"
else
    warn "  [!!] hazir sablonlar erisilemiyor - ~/.pcp/pmrep.conf var mi?"; ERR=1
fi

for dm in kernel.cpu.util.user disk.dev.util disk.dev.await proc.hog.cpu; do
    if pmrep -t 1s -s 2 "$dm" >/dev/null 2>&1; then log "  [OK] turetilmis metrik: $dm"
    else warn "  [--] turetilmis metrik yok: $dm (/etc/pcp/derived/ eksik olabilir)"; fi
done

if [ "$(systemctl is-active pmie 2>/dev/null)" = active ]; then
    log "  [OK] pmie alarm motoru aktif"
else
    warn "  [--] pmie aktif degil (alarm uretilmez)"
fi

LOGSZ=$(stat -c %s "$HOSTDIR/pmlogger.log" 2>/dev/null || echo 0)
if [ "$LOGSZ" -lt 5242880 ]; then log "  [OK] pmlogger.log boyutu normal ($(( LOGSZ / 1024 )) KB)"
else warn "  [!!] pmlogger.log anormal buyuk ($(( LOGSZ / 1048576 )) MB) - dogrulama dongusu olabilir"; ERR=1; fi

echo
log "Kurulum tamamlandi: $N_CHG degisiklik yapildi, $N_SKIP adim zaten yerindeydi. Ozet:"
log "  Ornekleme       : sistem+proses ${INTERVAL}s, sensor/SMART 300s"
log "  Arsiv dizini    : $HOSTDIR"
log "  Rotasyon        : gunluk (00:10), aninda sikistirma, $KEEP_DAYS gun saklama"
if [ "$(findmnt -no TARGET --target "$(dirname "$PCP_ARCHIVE_DIR")" 2>/dev/null)" = "$(dirname "$PCP_ARCHIVE_DIR")" ]; then
    log "  Disk korumasi   : /var/log/pcp AYRI volum -> %$THRESHOLD_PCT dolulukta temizlik"
else
    log "  Disk korumasi   : ayri volum degil -> ${MAX_SIZE_GB}GB siniri"
fi
log "  Acil koruma     : fs %90+ olursa eski arsivler silinir, yetmezse pmlogger durur"
log "  Sicak prosesler : hotproc (cpuburn>%10 || RSS>100MB)"
log "  Alarmlar        : pmie + pmieconf hazir kurallari -> syslog"
log "  Inceleme        : pmrep -t 1s -z :canli | :obur | :agirlik"
log "  Rapor icin      : pcp-top-apps.sh bu arsivlerle dogrudan calisir"
log "  Ayrintili test  : ./pcp-dogrula.sh"
exit $ERR
