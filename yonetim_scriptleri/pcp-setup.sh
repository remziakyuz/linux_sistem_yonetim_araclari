#!/bin/bash
# 2026.07.10
# Remzi AKYUZ
# remzi@akyuz.tech
# pcp-setup.sh - PCP (Performance Co-Pilot) tam izleme kurulum ve yapilandirmasi
#
# Yaptiklari:
#  1. RHEL/Ubuntu tabanli dagitimlarda pcp, pcp-gui, sistem araclari ve ek
#     PMDA modullerini (lmsensors, smart, dm, bonding) kurar.
#  2. proc PMDA'ya -A ekler: pmlogger 'pcp' kullanicisiyla calistigi icin
#     bu bayrak olmadan SADECE pcp kullanicisinin prosesleri arsivlenir.
#  3. CPU, bellek, disk, filesystem, network/ethernet, prosesler (kullanici
#     kimlikleriyle), donanim envanteri ve sensor/SMART verilerini surekli
#     diske kaydeden pmlogger yapilandirmasi olusturur.
#  4. Gunluk arsiv rotasyonu + sikistirma + 14 gun saklama (pmlogger_daily).
#  5. pcp-log-guard: /var/log/pcp ayri bir LV/bolum ise %80 dolulukta,
#     degilse 2GB sinirinda eski arsivleri siler; acil durumda (%90+)
#     pmlogger'i durdurarak diskin ASLA tamamen dolmasini engeller.
#
# Kullanim (root):
#   ./pcp-setup.sh                 # varsayilanlar: 60sn ornekleme, 14 gun, 2GB, %80
#   ./pcp-setup.sh -i 30 -k 14 -l 2 -t 80
#     -i  ornekleme araligi (saniye)          [60]
#     -k  arsiv saklama suresi (gun)          [14]
#     -l  ayri volum degilse log siniri (GB)  [2]
#     -t  ayri volum ise doluluk esigi (%)    [80]
#
set -o pipefail

INTERVAL=60
KEEP_DAYS=14
MAX_SIZE_GB=2
THRESHOLD_PCT=80

while getopts "i:k:l:t:h" opt; do
    case $opt in
        i) INTERVAL=$OPTARG ;;
        k) KEEP_DAYS=$OPTARG ;;
        l) MAX_SIZE_GB=$OPTARG ;;
        t) THRESHOLD_PCT=$OPTARG ;;
        h|*) grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "HATA: root olarak calistirin." >&2; exit 1; }

# Sikilastirilmis sistemlerde (umask 027/077) root'un yazdigi dosyalari
# 'pcp' kullanicisi okuyamaz ve pmlogger "Permission denied" ile crashloop'a
# girer; olusturulan tum dosyalar dunya-okur olmali.
umask 022

log()  { echo "[pcp-setup] $*"; }
warn() { echo "[pcp-setup] UYARI: $*" >&2; }
die()  { echo "[pcp-setup] HATA: $*" >&2; exit 1; }

# ---------------------------------------------------------------- 1. OS tespiti
. /etc/os-release 2>/dev/null || die "/etc/os-release okunamadi"
OSFAM=""
case " $ID $ID_LIKE " in
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*) OSFAM=rhel ;;
    *" ubuntu "*|*" debian "*)                                                OSFAM=deb ;;
esac
[ -n "$OSFAM" ] || die "desteklenmeyen dagitim: $ID ($ID_LIKE)"
log "Dagitim: $PRETTY_NAME ($OSFAM ailesi)"

# ------------------------------------------------------------ 2. paket kurulumu
if [ "$OSFAM" = rhel ]; then
    PKGS_CORE="pcp pcp-system-tools pcp-gui lm_sensors smartmontools gawk"
    PKGS_PMDA="pcp-pmda-lmsensors pcp-pmda-smart pcp-pmda-dm pcp-pmda-bonding"
    log "Paketler kuruluyor: $PKGS_CORE"
    dnf -y install $PKGS_CORE || die "temel paket kurulumu basarisiz"
    for p in $PKGS_PMDA; do
        dnf -y install "$p" >/dev/null 2>&1 && log "  + $p" || warn "$p kurulamadi (repo'da yok olabilir), atlaniyor"
    done
else
    export DEBIAN_FRONTEND=noninteractive
    log "Paket listesi guncelleniyor (apt update)..."
    apt-get -qq update || warn "apt update hatali, mevcut cache ile devam"
    PKGS_CORE="pcp pcp-gui lm-sensors smartmontools gawk"
    log "Paketler kuruluyor: $PKGS_CORE (PMDA'lar pcp paketinin icindedir)"
    apt-get -y -qq install $PKGS_CORE || die "paket kurulumu basarisiz"
fi

# PCP yol degiskenleri (iki dagitimda da /etc/pcp.conf standarttir)
. /etc/pcp.conf || die "/etc/pcp.conf yok - pcp kurulumu eksik"
: "${PCP_SYSCONF_DIR:=/etc/pcp}"
: "${PCP_ARCHIVE_DIR:=/var/log/pcp/pmlogger}"
: "${PCP_PMDAS_DIR:=/var/lib/pcp/pmdas}"
: "${PCP_BINADM_DIR:=/usr/libexec/pcp/bin}"
: "${PCP_SYSCONFIG_DIR:=/etc/sysconfig}"
PMLOGGER_CFG_DIR=/var/lib/pcp/config/pmlogger

# lm-sensors ilk kurulum tespiti (non-interaktif; sensor yoksa zararsiz)
command -v sensors-detect >/dev/null 2>&1 && { yes "" | sensors-detect --auto >/dev/null 2>&1 || true; }

# --------------------------------- 3. proc PMDA -A (tum prosesler arsivlensin)
PMCD_CONF="$PCP_SYSCONF_DIR/pmcd/pmcd.conf"
if grep -qE '^proc[[:space:]].*pmdaproc' "$PMCD_CONF" 2>/dev/null; then
    if ! grep -qE '^proc[[:space:]].*pmdaproc.* -A' "$PMCD_CONF"; then
        [ -e "$PMCD_CONF.pcp-setup.orig" ] || cp -p "$PMCD_CONF" "$PMCD_CONF.pcp-setup.orig"
        sed -i '/^proc[[:space:]].*pmdaproc/ s/$/ -A/' "$PMCD_CONF"
        log "proc PMDA'ya -A eklendi (pmlogger tum prosesleri gorebilecek)"
        warn "-A ile pmcd/pmproxy'e erisebilen istemciler tum proses adlarini/istatistiklerini okuyabilir"
    else
        log "proc PMDA'da -A zaten mevcut"
    fi
else
    warn "pmcd.conf icinde proc PMDA satiri bulunamadi!"
fi

# ------------------------------------------- 4. ek PMDA'larin etkinlestirilmesi
# .NeedInstall dosyasi birakilir; pmcd yeniden baslarken PMDA'yi kendisi kurar.
for pmda in lmsensors smart dm bonding; do
    d="$PCP_PMDAS_DIR/$pmda"
    if [ -d "$d" ]; then
        touch "$d/.NeedInstall" && log "PMDA etkinlestirilecek: $pmda"
    else
        warn "PMDA dizini yok, atlaniyor: $pmda"
    fi
done

# ---------------------- 5. pmcd'yi baslat, PMDA kurulumlarinin oturmasini bekle
# Yapilandirma canli metrik agacindan uretilecegi icin pmcd once ayaga kalkmali;
# ayrica pmlogger, pmcd durumu degisirken calisirsa dogrulama dongusune girip
# pmlogger.log'u sisirebiliyor (derived metrik + "PMCD state changed" hatasi).
log "pmcd baslatiliyor (PMDA kurulumlari dahil)..."
systemctl enable pmcd >/dev/null 2>&1
systemctl restart pmcd || die "pmcd baslatilamadi"
"$PCP_BINADM_DIR/pmcd_wait" -t 60 2>/dev/null
# PMDA .NeedInstall kurulumlarinin bitmesini bekle: Debian/Ubuntu'da bunlar
# pmcd "Started" dedikten SONRA arka planda calisir ve her biri pmcd'yi
# yeniden baslatabilir - bu sirada pmlogger baslatilirsa hemen durdurulur.
for i in $(seq 1 60); do
    ls "$PCP_PMDAS_DIR"/*/.NeedInstall >/dev/null 2>&1 && { sleep 2; continue; }
    pgrep -f "$PCP_PMDAS_DIR/.*/Install" >/dev/null 2>&1 && { sleep 2; continue; }
    break
done
sleep 5   # pmcd durumunun oturmasi icin

# ----------------------------------------------- 6. pmlogger izleme yapilandirmasi
# Metrik listesi canli pmns'ten uretilir. Haric tutulanlar:
#  - derived metrikler (PMID domain 511): pmcd durum degisiminde pmlogger'i
#    hata dongusune sokabiliyor; zaten temel metriklerden yeniden hesaplanabilir
#  - proc.psinfo.environ: tum proseslerin environment'i (parola/secret riski)
gen_leaves() { pminfo -m "$@" 2>/dev/null | awk '$2 == "PMID:" && $3 !~ /^511\./ && $1 !~ /environ/ { print "    " $1 }' | sort -u; }

SYS_METRICS=$(gen_leaves kernel.all kernel.percpu kernel.pernode mem swap disk \
                         filesys vfs network nfs nfs4 rpc proc.nprocs proc.runq)
PROC_METRICS=$(gen_leaves proc.psinfo proc.id proc.memory proc.io proc.schedstat proc.fd.count)
HW_METRICS=$(gen_leaves lmsensors smart dmcache vdo)
HINV_METRICS=$(gen_leaves hinv kernel.uname)
[ -n "$SYS_METRICS" ]  || die "sistem metrik listesi uretilemedi (pmcd calismiyor mu?)"
[ -n "$PROC_METRICS" ] || die "proses metrik listesi uretilemedi (proc PMDA sorunlu mu?)"

CFG="$PMLOGGER_CFG_DIR/config.pcp-full"
log "pmlogger yapilandirmasi yaziliyor: $CFG (ornekleme: ${INTERVAL}s)"
log "  metrik sayisi: sistem $(echo "$SYS_METRICS" | wc -l), proses $(echo "$PROC_METRICS" | wc -l), donanim $(echo "$HW_METRICS" | grep -c . ), envanter $(echo "$HINV_METRICS" | wc -l)"
mkdir -p "$PMLOGGER_CFG_DIR"
{
cat <<EOF
# pcp-setup.sh tarafindan olusturuldu - $(date '+%F %T')
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
} > "$CFG"
# onceki calismadan kalan dar izinleri de duzelt: pmlogger 'pcp' kullanicisi
# olarak okuyabilmeli (umask > ile uzerine yazmada mevcut modu degistirmez)
chmod 644 "$CFG"

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
mkdir -p "$BAKDIR"
# onceki surumlerin control.d icine biraktigi yedekleri de tasiyarak duzelt
for old in "$PCP_SYSCONF_DIR"/pmlogger/control.d/*.pcp-setup.orig; do
    [ -e "$old" ] && { mv "$old" "$BAKDIR/"; warn "control.d altindaki eski yedek tasindi: $old -> $BAKDIR/"; }
done
if [ -n "$CTRL" ]; then
    [ -e "$BAKDIR/$(basename "$CTRL").orig" ] || cp -p "$CTRL" "$BAKDIR/$(basename "$CTRL").orig"
    sed -i -E '/^[^#]*LOCALHOSTNAME/ s/-c[[:space:]]+[^[:space:]]+/-c config.pcp-full/' "$CTRL"
    log "Birincil pmlogger config.pcp-full'a yonlendirildi: $CTRL"
else
    CTRL="$PCP_SYSCONF_DIR/pmlogger/control.d/local"
    mkdir -p "$(dirname "$CTRL")"
    printf '$version=1.1\nLOCALHOSTNAME\ty\tn\tPCP_ARCHIVE_DIR/LOCALHOSTNAME\t-r -T24h10m -c config.pcp-full -v 100Mb\n' >> "$CTRL"
    log "Birincil pmlogger satiri eklendi: $CTRL"
fi

# ------------------------- 6. gunluk rotasyon: sikistir + $KEEP_DAYS gun sakla
TIMERS="$PCP_SYSCONFIG_DIR/pmlogger_timers"
DAILY_PARAMS="-E -x 0 -k $KEEP_DAYS"      # -x 0: rotasyonda hemen sikistir, -k: gun sonra sil
if [ -f "$TIMERS" ] && grep -qE '^PMLOGGER_DAILY_PARAMS=' "$TIMERS"; then
    sed -i -E "s|^PMLOGGER_DAILY_PARAMS=.*|PMLOGGER_DAILY_PARAMS=\"$DAILY_PARAMS\"|" "$TIMERS"
else
    mkdir -p "$(dirname "$TIMERS")"
    echo "PMLOGGER_DAILY_PARAMS=\"$DAILY_PARAMS\"" >> "$TIMERS"
fi
chmod 644 "$TIMERS" "$CTRL"    # pmlogger_daily/check 'pcp' kullanicisiyla okur
log "Gunluk rotasyon: sikistirma acik, saklama $KEEP_DAYS gun ($TIMERS)"

# --------------------------------- 7. disk koruma: pcp-log-guard kurulumu
GUARD=/usr/local/sbin/pcp-log-guard.sh
GUARD_CONF="$PCP_SYSCONF_DIR/pcp-log-guard.conf"

cat > "$GUARD_CONF" <<EOF
# pcp-log-guard yapilandirmasi (pcp-setup.sh tarafindan olusturuldu)
THRESHOLD_PCT=$THRESHOLD_PCT   # ayri volumde bu dolulukta eski arsivler silinir
TARGET_PCT=$(( THRESHOLD_PCT - 10 ))       # silme bu dolulugun altina inince durur
EMERG_PCT=90                   # her durumda: fs bu seviyeye gelirse acil mudahale
MAX_SIZE_GB=$MAX_SIZE_GB       # ayri volum DEGILSE toplam pcp log siniri
KEEP_DAYS=$KEEP_DAYS
LOG_MAX_MB=200                 # pmlogger.log bu boyutu asarsa sifirlanir (tasma sigortasi)
EOF

cat > "$GUARD" <<'GUARD_EOF'
#!/bin/bash
#
# pcp-log-guard.sh - PCP arsivlerinin diski doldurmasini engeller.
# pcp-setup.sh tarafindan kurulur, systemd timer ile 10 dakikada bir calisir.
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
#
set -o pipefail
. /etc/pcp.conf 2>/dev/null
: "${PCP_ARCHIVE_DIR:=/var/log/pcp/pmlogger}"
: "${PCP_BINADM_DIR:=/usr/libexec/pcp/bin}"
: "${PCP_SYSCONF_DIR:=/etc/pcp}"

THRESHOLD_PCT=80; TARGET_PCT=70; EMERG_PCT=90; MAX_SIZE_GB=2; KEEP_DAYS=14; LOG_MAX_MB=200
[ -f "$PCP_SYSCONF_DIR/pcp-log-guard.conf" ] && . "$PCP_SYSCONF_DIR/pcp-log-guard.conf"

PCPLOG=$(dirname "$PCP_ARCHIVE_DIR")           # genellikle /var/log/pcp
TODAY=$(date +%Y%m%d)
STOPFLAG=/run/pcp-log-guard.pmlogger-stopped

say() { logger -t pcp-log-guard "$*"; echo "[pcp-log-guard] $*"; }

fs_pct()   { df -P "$PCPLOG" | awk 'NR==2 { sub(/%/,"",$5); print $5 }'; }
logs_size(){ du -sb "$PCPLOG" 2>/dev/null | awk '{print $1}'; }

# /var/log/pcp (veya arsiv dizini) kendi basina bir mount noktasi mi?
DEDICATED=0
mp=$(findmnt -no TARGET --target "$PCPLOG" 2>/dev/null)
[ "$mp" = "$PCPLOG" ] || [ "$mp" = "$PCP_ARCHIVE_DIR" ] && DEDICATED=1

# en eski kapali arsiv setini sil; silinecek bir sey yoksa 1 doner
cull_oldest() {
    local oldest
    oldest=$(find "$PCP_ARCHIVE_DIR" -mindepth 2 -maxdepth 2 -name '*.meta*' \
                  ! -name "${TODAY}*" 2>/dev/null \
             | sed -E 's/\.meta(\.(xz|zst|gz|bz2|lzma))?$//' \
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
chmod 755 "$GUARD"
log "Disk korumasi kuruldu: $GUARD (ayar: $GUARD_CONF)"

cat > /etc/systemd/system/pcp-log-guard.service <<EOF
[Unit]
Description=PCP arsiv disk koruma kontrolu
After=pmlogger.service

[Service]
Type=oneshot
ExecStart=$GUARD
EOF
cat > /etc/systemd/system/pcp-log-guard.timer <<'EOF'
[Unit]
Description=PCP arsiv disk korumasi (10 dakikada bir)

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now pcp-log-guard.timer >/dev/null 2>&1
log "pcp-log-guard.timer etkin (10 dakikada bir kontrol)"

# ------------------------------------------ 8. pmlogger'i etkinlestir & baslat
log "pmlogger baslatiliyor..."
systemctl enable pmlogger >/dev/null 2>&1
# onceki crashloop kilitlerini ac (PCP 7'de pmlogger BindsTo=pmlogger_farm)
systemctl reset-failed pmlogger pmlogger_farm >/dev/null 2>&1
systemctl restart pmlogger || die "pmlogger baslatilamadi"
systemctl enable --now pmlogger_daily.timer pmlogger_check.timer >/dev/null 2>&1

# --------------------------------------------------------------- 9. dogrulama
log "Dogrulama yapiliyor..."
sleep $(( INTERVAL < 15 ? INTERVAL + 5 : 15 ))
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
    pminfo "$m" >/dev/null 2>&1 && log "  [OK] $m metrikleri mevcut" \
                                || warn "  [--] $m metrikleri yok (donanim/PMDA destegi olmayabilir)"
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

LOGSZ=$(stat -c %s "$HOSTDIR/pmlogger.log" 2>/dev/null || echo 0)
if [ "$LOGSZ" -lt 5242880 ]; then log "  [OK] pmlogger.log boyutu normal ($(( LOGSZ / 1024 )) KB)"
else warn "  [!!] pmlogger.log anormal buyuk ($(( LOGSZ / 1048576 )) MB) - dogrulama dongusu olabilir"; ERR=1; fi

echo
log "Kurulum tamamlandi. Ozet:"
log "  Ornekleme       : sistem+proses ${INTERVAL}s, sensor/SMART 300s"
log "  Arsiv dizini    : $HOSTDIR"
log "  Rotasyon        : gunluk (00:10), aninda sikistirma, $KEEP_DAYS gun saklama"
if [ "$(findmnt -no TARGET --target "$(dirname "$PCP_ARCHIVE_DIR")" 2>/dev/null)" = "$(dirname "$PCP_ARCHIVE_DIR")" ]; then
    log "  Disk korumasi   : /var/log/pcp AYRI volum -> %$THRESHOLD_PCT dolulukta temizlik"
else
    log "  Disk korumasi   : ayri volum degil -> ${MAX_SIZE_GB}GB siniri"
fi
log "  Acil koruma     : fs %90+ olursa eski arsivler silinir, yetmezse pmlogger durur"
log "  Rapor icin      : pcp-top-apps.sh bu arsivlerle dogrudan calisir"
exit $ERR
