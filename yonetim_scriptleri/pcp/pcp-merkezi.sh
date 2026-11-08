#!/bin/bash
#
# pcp-merkezi.sh - PCP arsivlerini merkezi pmlogger sunucusunda toplama
#
# Surum 1.2 (2026-10-30). Plan: PLAN.txt (ayni dizin).
# 1.2: -K merkez saklama gunu (varsayilan 32: aylik periyodik yukler); -M kur yazar.
# 1.1: -Y yerel gecmisi merkeze kopyalar, saklama ancak kopya basariliysa kisalir (K8).
#
# Yontem CEKME (pull): merkezdeki pmlogger istemcinin pmcd'sine ic agdan
# (44321/tcp) baglanir ve arsivi merkezde yazar. Istemcide yeni servis
# kurulmaz; yerel birincil pmlogger KAPATILMAZ, saklamasi N gune iner (ag
# kesintisinde merkezdeki boslugu kapatir). Betik yonetim makinesinde calisir,
# merkeze ve istemcilere root ile SSH yapar (dis ag adresleri).
#
# Kullanim:
#   ./pcp-merkezi.sh -i 172.16.210.83              # RAPOR: ne yapilacagi, DEGISIKLIK YOK
#   ./pcp-merkezi.sh -i 172.16.210.83 -u           # uygula
#   ./pcp-merkezi.sh -i 172.16.210.83 -k 8 -u      # onerilen: yerelde 8 gun
#   ./pcp-merkezi.sh -i 172.16.210.80,172.16.210.82 -d   # yalniz dogrula
#   ./pcp-merkezi.sh -M kur -i 172.16.210.80 -u    # merkezde eksik PCP'yi de kur
#   ./pcp-merkezi.sh -i 172.16.210.83 -G -u        # geri al
#     -m ADRES  merkezin SSH adresi (varsayilan 172.16.211.246)
#     -c ADRES  merkezin ic ag adresi (varsayilan 172.16.16.246). Istemci
#               guvenlik duvari 44321'i YALNIZ bu adrese acar; istemcinin ic ag
#               adresi bu adresin /24'unde aranir.
#     -M KIP    merkez denetimi: kontrol (varsayilan) | kur | uyar | atla
#                 kontrol: merkez hazir degilse istemcilere DOKUNULMAZ (rc 2)
#                 kur    : eksik paket/servis merkezde kurulur (-u ile), sonra
#                          kontrol ile ayni denetim
#                 uyar   : sorun raporlanir, istemciler yine yapilandirilir
#                 atla   : merkez denetlenmez
#     -K GUN    merkezde tutulacak arsiv gunu (varsayilan 32; 8..400). 32 gun:
#               aylik periyodik yukler bir onceki ayin ayni gunuyle karsilastirilir
#               (ay 28-31 gun + 1 gun pay). Farkliysa rapor/uyari; -M kur -u yazar
#               (PMLOGGER_DAILY_PARAMS -k K; yedekli). Istemcileri durdurmaz.
#     -k GUN    istemcide tutulacak arsiv gunu (varsayilan 3; 1..28). 8'in
#               altinda UYARI: onerilen alt sinir 8 gun, canli ortamda -k 8 kullanilir.
#     -i LISTE  istemcilerin SSH adresleri, virgulle (zorunlu)
#     -a AD     merkezdeki ad (yalniz tek istemcide; varsayilan kisa hostname)
#     -A DIZIN  merkez arsiv koku (varsayilan /var/log/pcp/merkez)
#     -u        uygula (yoksa RAPOR kipi)
#     -d        yalniz dogrulama (salt okuma)
#     -G        geri al (-u ile uygular; -u yoksa ne yapilacagini yazar)
#     -Y        yerel gecmis: istemcinin mevcut yerel arsivleri merkezde
#               <kok>/<ad>/yerel-gecmis/ altina kopyalanir (yalniz merkezde
#               olmayan dosyalar). Saklama -k N ancak kopya basariliysa yazilir.
#               Varsayilan KAPALI (yuk notu).
#     -h        yardim
#
# Yapilanlar (uygula):
#   Merkez (-M kur): dnf install pcp pcp-system-tools; pmcd, pmlogger,
#     pmlogger_daily.timer, pmlogger_farm_check.timer etkin; arsiv koku
#     pcp:pcp 0775 + SELinux etiketi; merkez saklamasi PMLOGGER_DAILY_PARAMS
#     -k K (-K, varsayilan 32; mevcut diger secenekler korunur, yoksa -x 1).
#     Disk bolumlemez.
#   Istemci: /var/backup/pcp-merkezi (saklama SAHIPLIK ISARETI - playbook-pcp
#     v1.5 ve log-saklama 1.11 bu dizini gorunce -k'ye dokunmaz); ic ag
#     arayuzunun bolgesine rich rule (kaynak <merkez ic>/32, 44321/tcp;
#     calisan + kalici, --reload YOK); merkez kaydi basarili olduktan SONRA
#     PMLOGGER_DAILY_PARAMS -k N (diger secenekler korunur).
#     Tek sahip: rol playbook'u (couchbase/temel/proxy/patroni/postgresql-onlem),
#     log-saklama yedek izi ya da "Ansible managed" basligi varsa -k YAZILMAZ.
#     pmcd [access], PMCD_LOCAL ve proc -A DEGISTIRILMEZ.
#   Merkez kaydi: istemcinin config.default'u + aciklama ilk satiri ->
#     /var/lib/pcp/config/pmlogger/config.<ad>. Ilk satir "#pmlogconf" OLMADIGI
#     icin pmlogger_check dosyayi pmlogconf ile yeniden URETMEZ (yeniden uretim
#     istemcide kapatilan zoneinfo/buddyinfo gruplarini acabilirdi).
#     /etc/pcp/pmlogger/control.d/<ad> (ic ag adresi, arsiv <kok>/<ad>);
#     pmlogger_farm_check.service ile baslatma.
#   Ilk kayitta ve kayit listesi degistiginde UYUM KAPISI: merkezden 2 dk
#     deneme kaydi; metrik adlari istemcinin yerel arsiviyle karsilastirilir,
#     %95 altinda o istemcide DURULUR (-k yazilmaz).
#   Her degisiklikten once yedek: /var/backup/pcp-merkezi/<yol>-<damga> +
#   manifest-<damga>.txt. Betik hedef sunucularda dosya SILMEZ (yalniz kendi
#   gecici betik dosyasini /tmp'den siler); geri alma dosyalari yedek agacina
#   TASIR.
#
# UYARI - yerel arsiv silinmesi: uzun yerel -k (onerilen 32) -> N sonrasi ilk pmlogger_daily (gece
#   00:10) N gunden eski YEREL arsivleri siler (PCP'nin kendi bakimi). Merkezde
#   yalniz kayit baslangicindan sonraki veri vardir. Betik istemcideki en eski
#   yerel arsiv gununu raporlar.
#
# YUK NOTU (sisteme yuk bindirmeme kurali 01.10.2026 - EN YUKSEK ONCELIK):
#   - Tespit: rpm, systemctl, ss, firewall-cmd, ip, df, stat, sha256sum (tek
#     dosya), pgrep; istemcide yerel arsivin metrik listesi icin 'pminfo -a'
#     (tek arsivin .meta dosyasi, salt okuma). Buyuk find/du ve
#     /proc/<pid>/smaps okuyan komut YOK. Kisa surelidir.
#   - Uyum kapisi (yalniz ilk kayitta/kayit listesi degisince): istemci basina
#     2 dk ek pmlogger = istemcide pmcd + PMDA'larin (proc dahil: tum sureclerin
#     stat/status/io dosyalari; smaps/maps/environ OKUNMAZ) yerel pmlogger ile
#     ayni okumayi bir kez daha yapmasi. Etkisi OLCULMEDI, sure sinirli.
#   - Kalici etki: merkez pmlogger'i istemcide yerel pmlogger ile ayni okuma
#     kumesini ikinci kez ceker. OLCULDU (29.10.2026, rh442, 10 dk pencereler):
#     ek pmcd + PMDA CPU tek cekirdegin ~%0,02'si (PLAN.txt bolum 8). Ic ag
#     trafigi istemci basina gunde ~150 MB ham.
#   - Merkez -M kur: dnf paket kurulumu (depo IO).
#   - -Y (varsayilan KAPALI): istemcide 'tar' ile yerel arsiv dosyalarinin
#     okunmasi (istemci basina 32 gunde 1-3 GB'a kadar disk okumasi ve ic ag
#     trafigi; nice -n 19 + ionice -c3 ile en dusuk oncelik). Etkisi OLCULMEDI.
#     Merkezde yerel-gecmis dizini pmlogger_daily kapsami disindadir (PLAN.txt).
#
# Cikis: 0 tamam, 1 uyari/sorun var, 2 durdu (hicbir istemci ya da o istemci
# yarim birakilmadan durduruldu).
#
set -o pipefail
SURUM="1.2"

MERKEZ=172.16.211.246
MERKEZ_IC=172.16.16.246
MKIP=kontrol
GUN=3; GUN_VERILDI=0
MERKEZ_GUN=32
ISTEMCILER=""
AD_ZORLA=""
KOK=/var/log/pcp/merkez
KIP=rapor
GERI=0
YKOPYA=0
ESIK=95                  # uyum kapisi: yerel metriklerin en az %95'i
BOS_MB_ISTEMCI=2048      # merkez kokunde istemci basina en az bos alan
SSHOPT=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
DAMGA=$(date +%Y%m%dT%H%M%S)
RC=0; DEGISEN=0

yardim() { sed -n '3,/^# Cikis/p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
bilgi()  { echo "[pcp-merkezi]   $*"; }
ok()     { echo "[pcp-merkezi] OK      $*"; }
uyar()   { echo "[pcp-merkezi] UYARI   $*"; [ "$RC" -lt 1 ] && RC=1; }
sorun()  { echo "[pcp-merkezi] SORUN   $*"; [ "$RC" -lt 1 ] && RC=1; }
plan()   { echo "[pcp-merkezi] YAPILACAK $*"; }
olum()   { echo "[pcp-merkezi] DURDU   $*" >&2; exit 2; }
baslik() { echo; echo "== $* =="; }

while getopts "m:c:M:k:K:i:a:A:udGYh" o; do
    case "$o" in
        m) MERKEZ=$OPTARG ;;
        c) MERKEZ_IC=$OPTARG ;;
        M) MKIP=$OPTARG ;;
        k) GUN=$OPTARG; GUN_VERILDI=1 ;;
        K) MERKEZ_GUN=$OPTARG ;;
        i) ISTEMCILER=$OPTARG ;;
        a) AD_ZORLA=$OPTARG ;;
        A) KOK=$OPTARG ;;
        u) KIP=uygula ;;
        d) KIP=dogrula ;;
        G) GERI=1 ;;
        Y) YKOPYA=1 ;;
        h) yardim 0 ;;
        *) yardim 2 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || olum "fazla arguman: $* (-h)"
case "$MKIP" in kontrol|kur|uyar|atla) ;; *) olum "-M kontrol|kur|uyar|atla olmali: $MKIP" ;; esac
[[ "$GUN" =~ ^[0-9]+$ ]] && [ "$GUN" -ge 1 ] && [ "$GUN" -le 28 ] || olum "-k 1..28 olmali: $GUN"
[[ "$MERKEZ_GUN" =~ ^[0-9]+$ ]] && [ "$MERKEZ_GUN" -ge 8 ] && [ "$MERKEZ_GUN" -le 400 ] || olum "-K 8..400 olmali: $MERKEZ_GUN"
[ -n "$ISTEMCILER" ] || olum "-i ile en az bir istemci verin (-h)"
IPRE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$MERKEZ_IC" =~ $IPRE ]] || olum "-c IPv4 adresi olmali: $MERKEZ_IC"
[[ "$KOK" =~ ^/[A-Za-z0-9._/-]+$ ]] || olum "-A mutlak yol olmali: $KOK"
IFS=',' read -r -a ILIST <<< "$ISTEMCILER"
[ -z "$AD_ZORLA" ] || [ "${#ILIST[@]}" -eq 1 ] || olum "-a yalniz tek istemciyle kullanilir"
[ -z "$AD_ZORLA" ] || [[ "$AD_ZORLA" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || olum "-a gecersiz ad: $AD_ZORLA"
[ "$KIP" = dogrula ] && [ "$GERI" -eq 1 ] && olum "-d ile -G birlikte kullanilmaz"
IC_PFX=${MERKEZ_IC%.*}
YEREL_GECICI=$(mktemp -d "${TMPDIR:-/tmp}/pcp-merkezi.XXXXXX") || olum "gecici dizin acilamadi"
trap 'rm -rf "$YEREL_GECICI"' EXIT

# uzak HOST [ARG...] < betik : betigi uzak /tmp'ye yazip bash ile calistirir
# (bash -s kullanilmaz: betigin stdin'ini okuyan bir komut betigin geri kalanini yerdi)
UZAK_SURE=600
uzak() {
    local h=$1 q; shift
    q=$(printf '%q ' "$@")
    timeout "$UZAK_SURE" ssh "${SSHOPT[@]}" "root@$h" \
        "f=\$(mktemp /tmp/pcp-merkezi.XXXXXX) && cat > \"\$f\" && bash \"\$f\" $q; rc=\$?; rm -f \"\$f\"; exit \$rc"
}
# anahtar=deger ciktisini T[] dizisine al
declare -A T
oku() { local s; T=(); while IFS= read -r s; do [[ "$s" == *=* ]] && T[${s%%=*}]=${s#*=}; done <<< "$1"; }
# uzak cikti satirlarini yorumla (DEGISTI/UYARI/HATA/EKSIK/BILGI)
yorumla() {
    local s
    while IFS= read -r s; do
        case "$s" in
            DEGISTI\ *) echo "[pcp-merkezi] DEGISTI ${s#DEGISTI }"; DEGISEN=$((DEGISEN + 1)) ;;
            UYARI\ *)   uyar "${s#UYARI }" ;;
            HATA\ *)    sorun "${s#HATA }" ;;
            BILGI\ *)   bilgi "${s#BILGI }" ;;
            EKSIK\ *)   bilgi "  eksik metrik: ${s#EKSIK }" ;;
            *=*) ;;
            ?*)         bilgi "  $s" ;;
        esac
    done <<< "$1"
}

# ============================================================================
# Uzak betikler
# ============================================================================
read -r -d '' B_MERKEZ_TESPIT <<'EOF'
KOK=$1
s() { if rpm -q "$1" >/dev/null 2>&1; then rpm -q --qf '%{VERSION}-%{RELEASE}' "$1"; else echo yok; fi; }
echo "FQDN=$(hostname -f 2>/dev/null)"
echo "PCP=$(s pcp)"; echo "SYSTOOLS=$(s pcp-system-tools)"
for u in pmcd pmlogger pmlogger_farm pmlogger_daily.timer pmlogger_farm_check.timer chronyd; do
    v=${u//[.-]/_}
    echo "A_$v=$(systemctl is-active "$u" 2>/dev/null)"
    echo "E_$v=$(systemctl is-enabled "$u" 2>/dev/null)"
done
echo "SYNC=$(chronyc tracking 2>/dev/null | awk -F': *' '/^Leap status/{print $2}')"
echo "SELINUX=$(getenforce 2>/dev/null)"
if [ -d "$KOK" ]; then
    echo "KOK=1"
    echo "KOK_MNT=$(findmnt -no TARGET --target "$KOK" 2>/dev/null)"
    echo "KOK_SAHIP=$(stat -c %U:%G "$KOK")"
    echo "KOK_MOD=$(stat -c %a "$KOK")"
    echo "KOK_ETIKET=$(stat -c %C "$KOK" 2>/dev/null | cut -d: -f3)"
    echo "KOK_BOS_MB=$(df -Pm "$KOK" | awk 'NR==2{print $4}')"
    [ -n "$(restorecon -n -v "$KOK" 2>/dev/null)" ] && echo "KOK_ETIKET_FARKLI=1" || echo "KOK_ETIKET_FARKLI=0"
else
    echo "KOK=0"
fi
echo "DAILY=$(grep -E '^PMLOGGER_DAILY_PARAMS=' /etc/sysconfig/pmlogger_timers 2>/dev/null | tail -1 | sed -E 's/^[^=]*=//; s/^"//; s/"$//')"
EOF

read -r -d '' B_MERKEZ_KUR <<'EOF'
KOK=$1; D=$2
B=/var/backup/pcp-merkezi; MAN=$B/manifest-$D.txt
iz() { mkdir -p "$B"; echo "$*" >> "$MAN"; }
[ -d "$KOK" ] || { echo "HATA arsiv koku $KOK yok - diski hazirlayin (PLAN.txt 5.1); betik disk bolumlemez"; exit 2; }
eksik=""
for p in pcp pcp-system-tools; do rpm -q "$p" >/dev/null 2>&1 || eksik="$eksik $p"; done
if [ -n "$eksik" ]; then
    timeout 900 dnf -y -q install $eksik </dev/null >/tmp/pcp-merkezi-dnf.log 2>&1 || { echo "HATA dnf install$eksik basarisiz:"; tail -5 /tmp/pcp-merkezi-dnf.log; exit 2; }
    echo "DEGISTI paket kuruldu:$eksik"; iz "KURULDU paket$eksik"
fi
for u in pmcd pmlogger pmlogger_daily.timer pmlogger_farm_check.timer; do
    if ! systemctl is-enabled -q "$u" 2>/dev/null; then
        systemctl enable -q "$u" && { echo "DEGISTI $u etkinlestirildi"; iz "ETKIN $u"; }
    fi
    if ! systemctl is-active -q "$u"; then
        timeout 180 systemctl start "$u" && { echo "DEGISTI $u baslatildi"; iz "BASLADI $u"; } || echo "HATA $u baslatilamadi"
    fi
done
systemctl is-active -q pmlogger_farm || { timeout 120 systemctl start pmlogger_farm && { echo "DEGISTI pmlogger_farm baslatildi"; iz "BASLADI pmlogger_farm"; }; }
if [ "$(stat -c %U:%G "$KOK")" != pcp:pcp ]; then
    iz "SAHIP $KOK $(stat -c %U:%G "$KOK") -> pcp:pcp"; chown pcp:pcp "$KOK" && echo "DEGISTI $KOK sahibi pcp:pcp"
fi
if [ "$(stat -c %a "$KOK")" != 775 ]; then
    iz "IZIN $KOK $(stat -c %a "$KOK") -> 775"; chmod 0775 "$KOK" && echo "DEGISTI $KOK izni 0775"
fi
if [ -n "$(restorecon -n -v "$KOK" 2>/dev/null)" ]; then
    iz "ETIKET $KOK $(stat -c %C "$KOK")"; restorecon "$KOK" && echo "DEGISTI $KOK SELinux etiketi $(stat -c %C "$KOK" | cut -d: -f3)"
fi
exit 0
EOF

# MERKEZ_SAKLAMA GUN DAMGA: merkez pmlogger_daily -k GUN (diger secenekler korunur; satir yoksa -x 1 -k GUN)
read -r -d '' B_MERKEZ_SAKLAMA <<'EOF'
GUN=$1; D=$2
B=/var/backup/pcp-merkezi; MAN=$B/manifest-$D.txt; F=/etc/sysconfig/pmlogger_timers
ESKI=$(grep -E '^PMLOGGER_DAILY_PARAMS=' "$F" 2>/dev/null | tail -1 | sed -E 's/^[^=]*=//; s/^"//; s/"$//')
if grep -qE '^PMLOGGER_DAILY_PARAMS=' "$F" 2>/dev/null; then
    if [[ " $ESKI " =~ [[:space:]]-k[[:space:]]*[0-9]+ ]]; then YENI=$(sed -E "s/(^|[[:space:]])-k[[:space:]]*[0-9]+/\1-k $GUN/" <<< "$ESKI")
    else YENI=$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<< "$ESKI -k $GUN"); fi
else
    YENI="-x 1 -k $GUN"
fi
[ "$YENI" = "$ESKI" ] && exit 0
mkdir -p "$B$(dirname "$F")"
[ -f "$F" ] && cp -p "$F" "$B$F-$D" && echo "YEDEK $F -> $B$F-$D" >> "$MAN"
if grep -qE '^PMLOGGER_DAILY_PARAMS=' "$F" 2>/dev/null; then
    sed -i -E "s|^PMLOGGER_DAILY_PARAMS=.*|PMLOGGER_DAILY_PARAMS=\"$YENI\"|" "$F"
else
    printf 'PMLOGGER_DAILY_PARAMS="%s"\n' "$YENI" >> "$F"
fi
echo "DEGISTI $F PMLOGGER_DAILY_PARAMS \"$ESKI\" -> \"$YENI\"" >> "$MAN"
echo "DEGISTI merkez saklama PMLOGGER_DAILY_PARAMS \"$ESKI\" -> \"$YENI\" (sonraki pmlogger_daily'den itibaren)"
exit 0
EOF

read -r -d '' B_ISTEMCI_TESPIT <<'EOF'
MIC=$1; PFX=$2
echo "AD=$(hostname -s)"; echo "FQDN=$(hostname -f 2>/dev/null)"; echo "HOSTNAME=$(hostname)"
read -r IF IP < <(ip -4 -o addr show | awk -v p="$PFX." '{split($4,a,"/"); if (index(a[1],p)==1) {print $2, a[1]; exit}}')
echo "IC_IF=$IF"; echo "IC_IP=$IP"
if rpm -q pcp >/dev/null 2>&1; then echo "PCP=$(rpm -q --qf '%{VERSION}-%{RELEASE}' pcp)"; else echo "PCP=yok"; fi
echo "PMCD=$(systemctl is-active pmcd 2>/dev/null)"; echo "PMLOGGER=$(systemctl is-active pmlogger 2>/dev/null)"
echo "PORT=$(ss -ltnH 'sport = :44321' 2>/dev/null | wc -l)"
C=/var/lib/pcp/config/pmlogger/config.default
[ -f "$C" ] && echo "CFG_SATIR=$(wc -l < "$C")" || echo "CFG_SATIR=0"
F=/etc/sysconfig/pmlogger_timers
echo "DAILY_VAR=$(grep -cE '^PMLOGGER_DAILY_PARAMS=' "$F" 2>/dev/null)"
echo "DAILY=$(grep -E '^PMLOGGER_DAILY_PARAMS=' "$F" 2>/dev/null | tail -1 | sed -E 's/^[^=]*=//; s/^"//; s/"$//')"
echo "FW=$(systemctl is-active firewalld 2>/dev/null)"
if [ -n "$IF" ] && systemctl is-active -q firewalld; then
    Z=$(firewall-cmd --get-zone-of-interface="$IF" 2>/dev/null) || Z=$(firewall-cmd --get-default-zone)
    echo "ZONE=$Z"
    K="rule family=\"ipv4\" source address=\"$MIC/32\" port port=\"44321\" protocol=\"tcp\" accept"
    firewall-cmd -q --zone="$Z" --query-rich-rule="$K" && echo "KURAL_CALISAN=1" || echo "KURAL_CALISAN=0"
    firewall-cmd -q --permanent --zone="$Z" --query-rich-rule="$K" && echo "KURAL_KALICI=1" || echo "KURAL_KALICI=0"
    echo "DIGER_44321=$(firewall-cmd --zone="$Z" --list-rich-rules 2>/dev/null | grep '44321' | grep -vcF "$MIC/32")"
    firewall-cmd -q --zone="$Z" --query-port=44321/tcp && echo "PORT_ACIK=1" || echo "PORT_ACIK=0"
    firewall-cmd -q --zone="$Z" --query-service=pmcd 2>/dev/null && echo "SERVIS_ACIK=1" || echo "SERVIS_ACIK=0"
fi
S=""
for a in couchbase-onlem temel-onlem proxy-onlem patroni-onlem postgresql-onlem; do [ -d "/var/backup/$a" ] && S="$S $a"; done
ls /var/backup/log-saklama/etc/sysconfig/pmlogger_timers-* >/dev/null 2>&1 && S="$S log-saklama"
grep -qi 'ansible managed' "$F" 2>/dev/null && S="$S ansible-managed-basligi"
echo "SAHIP=${S# }"
[ -d /var/backup/pcp-merkezi ] && echo "ISARET=1" || echo "ISARET=0"
echo "PROC_A=$(grep -E '^[^#]*pmdaproc' /etc/pcp/pmcd/pmcd.conf 2>/dev/null | grep -cE -- '(^|[[:space:]])-A([[:space:]]|$)')"
AD_DIR=/var/log/pcp/pmlogger/$(hostname)
SON=$(ls -1t "$AD_DIR"/*.meta "$AD_DIR"/*.meta.xz "$AD_DIR"/*.meta.zst 2>/dev/null | head -1)
echo "YEREL_ARSIV=${SON%.meta*}"
echo "EN_ESKI=$(ls -1 "$AD_DIR" 2>/dev/null | grep -oE '^[0-9]{8}' | sort | head -1)"
echo "TIMERS_ILK_YEDEK=$(ls -1 /var/backup/pcp-merkezi/etc/sysconfig/pmlogger_timers-* 2>/dev/null | sort | head -1)"
EOF

# ISTEMCI_UYGULA ADIM MIC ZONE GUN DAMGA ; ADIM = kural | saklama | geri
read -r -d '' B_ISTEMCI_UYGULA <<'EOF'
ADIM=$1; MIC=$2; Z=$3; GUN=$4; D=$5
B=/var/backup/pcp-merkezi; MAN=$B/manifest-$D.txt
F=/etc/sysconfig/pmlogger_timers
K="rule family=\"ipv4\" source address=\"$MIC/32\" port port=\"44321\" protocol=\"tcp\" accept"
iz() { mkdir -p "$B"; echo "$*" >> "$MAN"; }
yedekle() { [ -f "$1" ] || return 0; mkdir -p "$B$(dirname "$1")"; cp -p "$1" "$B$1-$D" && iz "YEDEK $1 -> $B$1-$D"; }
case "$ADIM" in
kural)
    if [ ! -d "$B" ]; then
        mkdir -p "$B" && iz "ISARET $B (pcp-merkezi saklama sahibi; playbook-pcp v1.5 / log-saklama 1.11)" \
            && echo "DEGISTI $B olusturuldu (saklama sahiplik isareti)"
    fi
    systemctl is-active -q firewalld || { echo "HATA firewalld calismiyor - kural yazilmadi"; exit 2; }
    if ! firewall-cmd -q --permanent --zone="$Z" --query-rich-rule="$K"; then
        yedekle "/etc/firewalld/zones/$Z.xml"
        firewall-cmd -q --permanent --zone="$Z" --add-rich-rule="$K" || { echo "HATA kalici kural eklenemedi"; exit 2; }
        iz "KURAL kalici $Z: $K"; echo "DEGISTI guvenlik duvari (kalici, $Z): $MIC/32 -> 44321/tcp"
    fi
    if ! firewall-cmd -q --zone="$Z" --query-rich-rule="$K"; then
        firewall-cmd -q --zone="$Z" --add-rich-rule="$K" || { echo "HATA calisan kural eklenemedi"; exit 2; }
        iz "KURAL calisan $Z: $K"; echo "DEGISTI guvenlik duvari (calisan, $Z): $MIC/32 -> 44321/tcp"
    fi
    ;;
saklama)
    ESKI=$(grep -E '^PMLOGGER_DAILY_PARAMS=' "$F" 2>/dev/null | tail -1 | sed -E 's/^[^=]*=//; s/^"//; s/"$//')
    if grep -qE '^PMLOGGER_DAILY_PARAMS=' "$F" 2>/dev/null; then
        if [[ " $ESKI " =~ [[:space:]]-k[[:space:]]*[0-9]+ ]]; then
            YENI=$(sed -E "s/(^|[[:space:]])-k[[:space:]]*[0-9]+/\1-k $GUN/" <<< "$ESKI")
        else
            YENI=$(sed -E 's/[[:space:]]+$//' <<< "$ESKI -k $GUN" | sed -E 's/^[[:space:]]+//')
        fi
    else
        YENI="-x 1 -k $GUN"
    fi
    [ "$YENI" = "$ESKI" ] && exit 0
    yedekle "$F"
    if grep -qE '^PMLOGGER_DAILY_PARAMS=' "$F" 2>/dev/null; then
        sed -i -E "s|^PMLOGGER_DAILY_PARAMS=.*|PMLOGGER_DAILY_PARAMS=\"$YENI\"|" "$F"
    else
        printf 'PMLOGGER_DAILY_PARAMS="%s"\n' "$YENI" >> "$F"
    fi
    iz "DEGISTI $F PMLOGGER_DAILY_PARAMS \"$ESKI\" -> \"$YENI\""
    echo "DEGISTI $F PMLOGGER_DAILY_PARAMS \"$ESKI\" -> \"$YENI\""
    ;;
geri)
    [ -d "$B" ] || { echo "BILGI $B yok - istemcide geri alinacak bir sey yok"; exit 0; }
    if systemctl is-active -q firewalld; then
        if firewall-cmd -q --permanent --zone="$Z" --query-rich-rule="$K"; then
            yedekle "/etc/firewalld/zones/$Z.xml"
            firewall-cmd -q --permanent --zone="$Z" --remove-rich-rule="$K" && iz "KURAL kaldirildi kalici $Z" && echo "DEGISTI kalici kural kaldirildi ($Z)"
        fi
        if firewall-cmd -q --zone="$Z" --query-rich-rule="$K"; then
            firewall-cmd -q --zone="$Z" --remove-rich-rule="$K" && iz "KURAL kaldirildi calisan $Z" && echo "DEGISTI calisan kural kaldirildi ($Z)"
        fi
    fi
    ILK=$(ls -1 "$B$F"-* 2>/dev/null | sort | head -1)
    if [ -n "$ILK" ] && ! cmp -s "$ILK" "$F"; then
        yedekle "$F"
        cp -p "$ILK" "$F" && iz "GERI $F <- $ILK" && echo "DEGISTI $F ilk yedekten geri geldi ($(grep -E '^PMLOGGER_DAILY_PARAMS=' "$F" | tail -1))"
    fi
    H=$B-geri-alindi-$D
    iz "TASINDI $B -> $H (saklama sahiplik isareti kalkti)"
    mv "$B" "$H" && echo "DEGISTI $B -> $H (sahiplik isareti kalkti; playbook-pcp yeniden sahip)"
    ;;
esac
exit 0
EOF

read -r -d '' B_MERKEZ_ISTEMCI_TESPIT <<'EOF'
AD=$1; IP=$2; KOK=$3
CFG=/var/lib/pcp/config/pmlogger/config.$AD; CTL=/etc/pcp/pmlogger/control.d/$AD
[ -f "$CFG" ] && echo "CFG_SHA=$(sha256sum < "$CFG" | cut -c1-64)" || echo "CFG_SHA="
[ -f "$CTL" ] && echo "CTL_SHA=$(sha256sum < "$CTL" | cut -c1-64)" || echo "CTL_SHA="
[ -f "$CFG" ] && echo "CFG_ZONEINFO=$(grep -cE '^[^#]*mem\.(zoneinfo|buddyinfo)' "$CFG")"
# ayni ic ag adresi baska bir control dosyasinda mi
echo "BASKA_CTL=$(grep -lE "^[^#\$]*[[:space:]]*${IP//./\\.}[[:space:]]" /etc/pcp/pmlogger/control /etc/pcp/pmlogger/control.d/* 2>/dev/null | grep -vx "$CTL" | tr '\n' ' ')"
if [ -d "$KOK/$AD" ]; then
    echo "DIZIN=1"; echo "DIZIN_SAHIP=$(stat -c %U:%G "$KOK/$AD")"
    SON=$(ls -1t "$KOK/$AD" 2>/dev/null | grep -E '\.[0-9]+$' | head -1)
    [ -n "$SON" ] && echo "SON_YAS=$(( $(date +%s) - $(stat -c %Y "$KOK/$AD/$SON") ))" || echo "SON_YAS="
    echo "SON_DOSYA=$SON"
else
    echo "DIZIN=0"
fi
echo "PID=$(pgrep -u pcp -f "pmlogger .*-h ${IP//./\\.}( |$)" 2>/dev/null | head -1)"
EOF

# MERKEZ_KAYIT AD IP KOK DAMGA KAPI ESIK ; govdeye config ve yerel metrik listesi eklenir
read -r -d '' B_MERKEZ_KAYIT_ON <<'EOF'
AD=$1; IP=$2; KOK=$3; D=$4; KAPI=$5; ESIK=$6
B=/var/backup/pcp-merkezi; MAN=$B/manifest-$D.txt
CFG=/var/lib/pcp/config/pmlogger/config.$AD; CTL=/etc/pcp/pmlogger/control.d/$AD
DD=$B/deneme-$AD-$D
iz() { mkdir -p "$B"; echo "$*" >> "$MAN"; }
yedekle() { [ -f "$1" ] || return 0; mkdir -p "$B$(dirname "$1")"; cp -p "$1" "$B$1-$D" && iz "YEDEK $1 -> $B$1-$D"; }
mkdir -p "$DD"
EOF

read -r -d '' B_MERKEZ_KAYIT_SON <<'EOF'
chown -R pcp:pcp "$DD"
if [ "$KAPI" = 1 ]; then
    if ! timeout 30 pminfo -h "$IP" -f pmcd.version >"$DD/pminfo.txt" 2>&1; then
        echo "HATA merkez $IP:44321'e baglanamadi: $(head -1 "$DD/pminfo.txt")"; exit 2
    fi
    echo "BILGI uyum kapisi: 2 dk deneme kaydi ($DD)"
    (cd "$DD" && timeout 200 runuser -u pcp -- pmlogger -h "$IP" -c "$DD/config" -T 120sec -l "$DD/pmlogger.log" "$DD/deneme" </dev/null >/dev/null 2>&1)
    [ -f "$DD/deneme.meta" ] || { echo "HATA deneme kaydi arsiv uretmedi: $(tail -2 "$DD/pmlogger.log" 2>/dev/null | tr '\n' ' ')"; exit 2; }
    pminfo -a "$DD/deneme" 2>/dev/null | LC_ALL=C sort -u > "$DD/merkez-metrikler.txt"
    LC_ALL=C sort -u -o "$DD/yerel-metrikler.txt" "$DD/yerel-metrikler.txt"
    TOP=$(grep -c . "$DD/yerel-metrikler.txt"); MRK=$(grep -c . "$DD/merkez-metrikler.txt")
    EKS=$(LC_ALL=C comm -23 "$DD/yerel-metrikler.txt" "$DD/merkez-metrikler.txt" | grep -c .)
    if [ "$TOP" -gt 0 ]; then
        ORAN=$(( (TOP - EKS) * 100 / TOP ))
        echo "BILGI uyum kapisi: yerel arsiv $TOP metrik, deneme $MRK metrik, eksik $EKS (%$ORAN)"
        LC_ALL=C comm -23 "$DD/yerel-metrikler.txt" "$DD/merkez-metrikler.txt" | head -15 | sed 's/^/EKSIK /'
        [ "$ORAN" -ge "$ESIK" ] || { echo "HATA uyum kapisi gecmedi (%$ORAN < %$ESIK) - kayit yapilmadi"; exit 2; }
    else
        echo "UYARI yerel arsiv metrik listesi alinamadi; yalniz deneme kaydi denetlendi ($MRK metrik)"
        [ "$MRK" -gt 100 ] || { echo "HATA deneme kaydinda $MRK metrik - kayit yapilmadi"; exit 2; }
    fi
fi
CFG_DEG=0
if ! cmp -s "$DD/config" "$CFG"; then
    yedekle "$CFG"
    install -o pcp -g pcp -m 0644 "$DD/config" "$CFG" && iz "YAZILDI $CFG" && echo "DEGISTI $CFG yazildi"; CFG_DEG=1
fi
if ! cmp -s "$DD/control" "$CTL"; then
    yedekle "$CTL"
    install -o root -g root -m 0644 "$DD/control" "$CTL" && iz "YAZILDI $CTL" && echo "DEGISTI $CTL yazildi"
fi
if [ ! -d "$KOK/$AD" ]; then
    install -d -o pcp -g pcp -m 0775 "$KOK/$AD" && iz "DIZIN $KOK/$AD" && echo "DEGISTI $KOK/$AD olusturuldu"
    restorecon "$KOK/$AD" 2>/dev/null
fi
P=$(pgrep -u pcp -f "pmlogger .*-h ${IP//./\\.}( |$)" | head -1)
if [ -n "$P" ] && [ "$CFG_DEG" = 1 ]; then
    kill -INT "$P" && iz "DURDURULDU pmlogger $P (yeni kayit listesi)" && echo "DEGISTI eski pmlogger $P durduruldu (yeni kayit listesi)"
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$P" 2>/dev/null || break; sleep 1; done
    P=""
fi
if [ -z "$P" ]; then
    timeout 300 systemctl start pmlogger_farm_check.service
    for _ in $(seq 1 30); do
        P=$(pgrep -u pcp -f "pmlogger .*-h ${IP//./\\.}( |$)" | head -1); [ -n "$P" ] && break; sleep 2
    done
    [ -n "$P" ] && echo "DEGISTI pmlogger baslatildi (pid $P)" || echo "HATA pmlogger baslamadi - journalctl -u pmlogger_farm_check; $KOK/$AD/pmlogger.log"
fi
exit 0
EOF

read -r -d '' B_MERKEZ_GERI <<'EOF'
AD=$1; IP=$2; D=$3
B=/var/backup/pcp-merkezi; MAN=$B/manifest-$D.txt
CFG=/var/lib/pcp/config/pmlogger/config.$AD; CTL=/etc/pcp/pmlogger/control.d/$AD
iz() { mkdir -p "$B"; echo "$*" >> "$MAN"; }
tasi() { [ -f "$1" ] || return 0; mkdir -p "$B$(dirname "$1")"; mv "$1" "$B$1-$D" && iz "TASINDI $1 -> $B$1-$D" && echo "DEGISTI $1 -> $B$1-$D"; }
tasi "$CTL"; tasi "$CFG"
P=$(pgrep -u pcp -f "pmlogger .*-h ${IP//./\\.}( |$)" | head -1)
if [ -n "$P" ]; then kill -INT "$P" && iz "DURDURULDU pmlogger $P" && echo "DEGISTI pmlogger $P durduruldu (arsivler yerinde kalir)"; fi
exit 0
EOF

# ============================================================================
# Merkez
# ============================================================================
baslik "pcp-merkezi $SURUM - kip: $KIP$([ "$GERI" -eq 1 ] && echo ' (geri al)'), merkez $MERKEZ (ic $MERKEZ_IC), -M $MKIP, yerel -k $GUN"
[ "$GUN" -lt 8 ] && [ "$GERI" -eq 0 ] && [ "$KIP" != dogrula ] && uyar "-k $GUN onerilen alt sinirin (8 gun) altinda - yalniz test ortami icin; canli ortamda -k 8"

merkez_tespit() { M_CIKTI=$(uzak "$MERKEZ" "$KOK" <<< "$B_MERKEZ_TESPIT") || return 1; oku "$M_CIKTI"; declare -gA MT=(); local k; for k in "${!T[@]}"; do MT[$k]=${T[$k]}; done; }
merkez_denetle() { # sorunlari MSORUN dizisine yazar
    MSORUN=()
    [[ "${MT[PCP]}" == 7.* ]] || MSORUN+=("pcp 7.x kurulu degil (${MT[PCP]})")
    [ "${MT[SYSTOOLS]}" != yok ] || MSORUN+=("pcp-system-tools kurulu degil (pmrep/pmlogsummary analiz araclari)")
    local u
    for u in pmcd pmlogger pmlogger_farm pmlogger_daily_timer pmlogger_farm_check_timer; do
        [ "${MT[A_$u]}" = active ] || MSORUN+=("${u//_timer/.timer} calismiyor (${MT[A_$u]})")
    done
    [ "${MT[A_chronyd]}" = active ] && [ "${MT[SYNC]}" = Normal ] || MSORUN+=("saat esitlemesi yok (chronyd ${MT[A_chronyd]}, ${MT[SYNC]})")
    if [ "${MT[KOK]}" != 1 ]; then MSORUN+=("arsiv koku $KOK yok (PLAN.txt 5.1)"); return; fi
    [ "${MT[KOK_SAHIP]}" = pcp:pcp ] || MSORUN+=("$KOK sahibi ${MT[KOK_SAHIP]} (pcp:pcp olmali)")
    [ "${MT[KOK_ETIKET_FARKLI]}" = 0 ] || MSORUN+=("$KOK SELinux etiketi ${MT[KOK_ETIKET]} (restorecon gerekli)")
    local gerek=$(( BOS_MB_ISTEMCI * ${#ILIST[@]} ))
    [ "${MT[KOK_BOS_MB]:-0}" -ge "$gerek" ] || MSORUN+=("$KOK bos ${MT[KOK_BOS_MB]} MB < $gerek MB (istemci basina $BOS_MB_ISTEMCI)")
}

if [ "$MKIP" = atla ] && [ "$KIP" != dogrula ]; then
    bilgi "merkez denetimi ATLANDI (-M atla)"
    merkez_tespit || olum "merkeze SSH yapilamadi: $MERKEZ"
else
    baslik "Merkez denetimi ($MERKEZ)"
    merkez_tespit || olum "merkeze SSH yapilamadi: $MERKEZ"
    bilgi "${MT[FQDN]}: pcp ${MT[PCP]}, SELinux ${MT[SELINUX]}, arsiv koku $KOK (baglama ${MT[KOK_MNT]:-?}, bos ${MT[KOK_BOS_MB]:-?} MB, etiket ${MT[KOK_ETIKET]:-?})"
    MK=$(grep -oE -- '(^|[[:space:]])-k[[:space:]]*[0-9]+' <<< " ${MT[DAILY]}" | grep -oE '[0-9]+' | tail -1)
    bilgi "merkez saklama: PMLOGGER_DAILY_PARAMS='${MT[DAILY]}' (-k ${MK:-yok: PCP varsayilani 14}; hedef -K $MERKEZ_GUN)"
    merkez_denetle
    if [ "${#MSORUN[@]}" -gt 0 ] && [ "$MKIP" = kur ] && [ "$GERI" -eq 0 ] && [ "$KIP" != dogrula ]; then
        if [ "$KIP" = uygula ]; then
            bilgi "merkez hazirlaniyor (-M kur)"
            UZAK_SURE=1500
            CIKTI=$(uzak "$MERKEZ" "$KOK" "$DAMGA" <<< "$B_MERKEZ_KUR"); r=$?
            UZAK_SURE=600
            yorumla "$CIKTI"
            [ "$r" -eq 0 ] || olum "merkez hazirlanamadi (rc $r)"
            merkez_tespit || olum "merkeze SSH yapilamadi"
            merkez_denetle
        else
            for s in "${MSORUN[@]}"; do plan "merkez (-M kur): $s -> giderilecek"; done
        fi
    fi
    if [ "${MK:-14}" != "$MERKEZ_GUN" ] && [ "$GERI" -eq 0 ] && [ "${MT[PCP]}" != yok ]; then
        if [ "$MKIP" = kur ] && [ "$KIP" = uygula ]; then
            CIKTI=$(uzak "$MERKEZ" "$MERKEZ_GUN" "$DAMGA" <<< "$B_MERKEZ_SAKLAMA"); r=$?; yorumla "$CIKTI"
            [ "$r" -eq 0 ] || sorun "merkez saklama yazilamadi (rc $r)"
        elif [ "$MKIP" = kur ] && [ "$KIP" = rapor ]; then
            plan "merkez (-M kur): saklama -k ${MK:-14} -> -k $MERKEZ_GUN (PMLOGGER_DAILY_PARAMS, yedekli)"
        else
            uyar "merkez saklama -k ${MK:-14} gun; hedef -K $MERKEZ_GUN (aylik periyodik yukler). Duzeltmek icin: -M kur -u"
        fi
    elif [ "${MT[PCP]}" != yok ]; then
        ok "merkez saklama -k $MERKEZ_GUN gun"
    fi
    [ "${MT[KOK]}" = 1 ] && [ -n "${MT[KOK_MNT]}" ] && [ "${MT[KOK_MNT]}" != "$KOK" ] && uyar "$KOK ayri baglama noktasi degil (${MT[KOK_MNT]} icinde) - disk dolarsa sistem etkilenir"
    if [ "${#MSORUN[@]}" -eq 0 ]; then
        ok "merkez PCP toplamaya hazir (pcp ${MT[PCP]}, pmlogger_farm calisiyor, $KOK yazilabilir)"
    else
        if [ "$MKIP" = kur ] && [ "$KIP" = rapor ]; then
            uyar "merkez hazir degil; -M kur -u ile yukaridaki eksikler giderilir"
        else
            for s in "${MSORUN[@]}"; do sorun "merkez: $s"; done
        fi
        if [ "$MKIP" = kontrol ] || { [ "$MKIP" = kur ] && [ "$KIP" = uygula ]; }; then
            [ "$KIP" = uygula ] && olum "merkez hazir degil - istemcilere DOKUNULMADI (-M kur ile hazirlayin ya da -M uyar)"
            bilgi "merkez hazir degil: uygula kipinde istemcilere dokunulmaz (rapor devam ediyor)"
        fi
    fi
fi

# ============================================================================
# Istemciler
# ============================================================================
k_hesapla() { # k_hesapla "MEVCUT" N -> yeni PMLOGGER_DAILY_PARAMS (istemci betigiyle ayni kural)
    local e=$1 n=$2
    if [ "$3" = 0 ]; then echo "-x 1 -k $n"
    elif [[ " $e " =~ [[:space:]]-k[[:space:]]*[0-9]+ ]]; then sed -E "s/(^|[[:space:]])-k[[:space:]]*[0-9]+/\1-k $n/" <<< "$e"
    else sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<< "$e -k $n"; fi
}

# -Y: istemcinin yerel arsivleri -> merkez <kok>/<ad>/yerel-gecmis (ada gore eksik dosyalar)
ARSIV_ADI='^[0-9]{8}[0-9A-Za-z._-]*$'
yerel_liste() { # yerel_liste HOST HOSTNAME -> "ad boyut" satirlari (tek dizin, maxdepth 1)
    timeout 60 ssh "${SSHOPT[@]}" "root@$1" "find /var/log/pcp/pmlogger/$(printf '%q' "$2") -maxdepth 1 -type f -printf '%f %s\\n'" 2>/dev/null \
        | awk -v re="$ARSIV_ADI" '$1 ~ re' | LC_ALL=C sort
}
merkez_liste() { # merkez_liste AD -> yerel-gecmis dosya adlari
    timeout 60 ssh "${SSHOPT[@]}" "root@$MERKEZ" "ls -1 $(printf '%q' "$KOK/$1/yerel-gecmis") 2>/dev/null" | LC_ALL=C sort
}
yerel_kopya() { # yerel_kopya HOST AD HOSTNAME plan|uygula
    local h=$1 ad=$2 hn=$3 kip=$4 eksik n mb dosyalar kalan
    local hedef="$KOK/$ad/yerel-gecmis" kaynak="/var/log/pcp/pmlogger/$hn"
    local -a rcs
    # bos ilk dosyada NR==FNR ikinci dosyaya da uyar: dosyalar f=1 / f=2 ile ayrilir
    eksik=$(awk 'f == 1 {m[$1] = 1; next} !($1 in m)' f=1 <(merkez_liste "$ad") f=2 <(yerel_liste "$h" "$hn"))
    if [ -z "$eksik" ]; then ok "$h: yerel gecmis merkezde ($hedef; eksik dosya yok)"; return 0; fi
    n=$(grep -c . <<< "$eksik"); mb=$(awk '{s+=$2} END{printf "%.0f", s/1048576}' <<< "$eksik")
    if [ "$kip" = plan ]; then
        plan "$h: yerel gecmis $n dosya (~$mb MB) -> merkez $hedef (-Y; nice/ionice)"; return 0
    fi
    bilgi "$h: yerel gecmis kopyalaniyor: $n dosya (~$mb MB) -> $hedef"
    dosyalar=$(awk '{print $1}' <<< "$eksik" | tr '\n' ' ')
    timeout 3600 ssh "${SSHOPT[@]}" "root@$h" "cd $(printf '%q' "$kaynak") && nice -n 19 ionice -c3 tar -cf - -- $dosyalar" \
        | timeout 3600 ssh "${SSHOPT[@]}" "root@$MERKEZ" "install -d -o pcp -g pcp -m 0775 $(printf '%q' "$hedef") && tar -C $(printf '%q' "$hedef") --no-same-owner -xf - && chown -R pcp:pcp $(printf '%q' "$hedef") && restorecon -R $(printf '%q' "$hedef") && mkdir -p /var/backup/pcp-merkezi && echo 'KOPYA $n dosya $hn:$kaynak -> $hedef' >> /var/backup/pcp-merkezi/manifest-$DAMGA.txt"
    rcs=("${PIPESTATUS[@]}")
    # tar rc 1 = okunurken degisen dosya (yazilmakta olan etkin arsiv): kabul
    if [ "${rcs[0]}" -gt 1 ] || [ "${rcs[1]}" -ne 0 ]; then sorun "$h: yerel gecmis kopyasi basarisiz (rc ${rcs[*]})"; return 1; fi
    kalan=$(awk 'f == 1 {m[$1] = 1; next} !($1 in m)' f=1 <(merkez_liste "$ad") f=2 - <<< "$eksik")
    [ -z "$kalan" ] || { sorun "$h: kopyadan sonra merkezde eksik dosya: $(awk '{print $1}' <<< "$kalan" | head -3 | tr '\n' ' ')"; return 1; }
    echo "[pcp-merkezi] DEGISTI $h: yerel gecmis $n dosya (~$mb MB) merkeze kopyalandi ($hedef)"; DEGISEN=$((DEGISEN + 1))
    [ "${rcs[0]}" -eq 1 ] && bilgi "$h: etkin (yazilmakta olan) yerel arsiv o anki haliyle kopyalandi"
    return 0
}

istemci_isle() {
    local h=$1 CIKTI r AD IP
    baslik "Istemci $h"
    CIKTI=$(uzak "$h" "$MERKEZ_IC" "$IC_PFX" <<< "$B_ISTEMCI_TESPIT") || { sorun "$h: SSH yapilamadi"; return 1; }
    oku "$CIKTI"; declare -A I=(); local k; for k in "${!T[@]}"; do I[$k]=${T[$k]}; done
    AD=${AD_ZORLA:-${I[AD]}}; IP=${I[IC_IP]}
    bilgi "${I[FQDN]}: merkezdeki ad '$AD', ic ag ${IP:-YOK} (${I[IC_IF]:-?}), pcp ${I[PCP]}, pmcd ${I[PMCD]}, pmlogger ${I[PMLOGGER]}"
    bilgi "yerel saklama: PMLOGGER_DAILY_PARAMS='${I[DAILY]}', en eski yerel arsiv ${I[EN_ESKI]:-?}; saklama sahipleri: ${I[SAHIP]:-yok}$([ "${I[ISARET]}" = 1 ] && echo ' + pcp-merkezi')"
    [ -n "$IP" ] || { sorun "$h: $IC_PFX.0/24 aginda adres yok - atlandi"; return 1; }
    [[ "${I[PCP]}" != yok ]] && [ "${I[PMCD]}" = active ] || { sorun "$h: pcp kurulu/calisir degil (pcp ${I[PCP]}, pmcd ${I[PMCD]}) - once playbook-pcp"; return 1; }
    [ "${I[PORT]:-0}" -gt 0 ] || { sorun "$h: pmcd 44321'de dinlemiyor (PMCD_LOCAL=1?) - cekme modeli icin uzak baglanti gerekir; atlandi"; return 1; }
    [ "${I[CFG_SATIR]:-0}" -gt 0 ] || { sorun "$h: config.default yok - atlandi"; return 1; }
    [ "${I[FW]}" = active ] || { sorun "$h: firewalld calismiyor - 44321 korumasiz olabilir; kural yazilamaz, atlandi"; return 1; }
    [ "${I[PROC_A]:-0}" = 0 ] || uyar "$h: proc PMDA -A ile calisiyor; pmcd uzaktan erisilebilir olacak (playbook-pcp guvenlik kapisi) - inceleyin"
    [ "${I[PORT_ACIK]:-0}" = 0 ] && [ "${I[SERVIS_ACIK]:-0}" = 0 ] || uyar "$h: 44321 bolgede herkese acik (port/servis) - merkez kurali disinda kaynaklar da baglanabilir"
    [ "${I[DIGER_44321]:-0}" = 0 ] || bilgi "$h: bolgede baska kaynaklar icin 44321 kurali var (${I[DIGER_44321]}) - dokunulmadi"
    local YAZK=1; [ -n "${I[SAHIP]}" ] && YAZK=0

    # merkezdeki durum
    local MC; MC=$(uzak "$MERKEZ" "$AD" "$IP" "$KOK" <<< "$B_MERKEZ_ISTEMCI_TESPIT") || { sorun "merkeze SSH yapilamadi"; return 1; }
    oku "$MC"; declare -A C=(); for k in "${!T[@]}"; do C[$k]=${T[$k]}; done
    [ -z "${C[BASKA_CTL]// /}" ] || { sorun "$h: $IP merkezde baska bir kayit dosyasinda da var: ${C[BASKA_CTL]} - atlandi"; return 1; }

    # hedef dosyalar (yerelde hazirlanir)
    local GD="$YEREL_GECICI/$AD"; mkdir -p "$GD"
    local BAS="# pcp-merkezi: ${I[FQDN]} ($IP) istemcisinin config.default kopyasi; pmlogconf ile yeniden uretilmez. Degisiklik istemcide yapilir, pcp-merkezi.sh yeniden kosulur."
    if [ "$GERI" -eq 0 ] && [ "$KIP" != dogrula ]; then
        timeout 60 ssh "${SSHOPT[@]}" "root@$h" cat /var/lib/pcp/config/pmlogger/config.default > "$GD/cfg.ham" || { sorun "$h: config.default okunamadi"; return 1; }
        grep -q '^PCPMERKEZI_SONU$' "$GD/cfg.ham" && { sorun "$h: config.default beklenmeyen satir iceriyor"; return 1; }
        { echo "$BAS"; printf '%s\n' "$(cat "$GD/cfg.ham")"; } > "$GD/config"
    fi
    {
        echo "# pcp-merkezi.sh tarafindan yazildi: ${I[FQDN]} (ic ag $IP). Elle degistirmeyin; geri alma: pcp-merkezi.sh -G"
        echo "\$version=1.1"
        printf '%s\tn   n\t%s\t-r -T24h10m -c config.%s -v 100Mb\n' "$IP" "$KOK/$AD" "$AD"
    } > "$GD/control"
    local CFG_ISTENEN="" CTL_ISTENEN
    [ -f "$GD/config" ] && CFG_ISTENEN=$(sha256sum < "$GD/config" | cut -c1-64)
    CTL_ISTENEN=$(sha256sum < "$GD/control" | cut -c1-64)
    local DAILY_ISTENEN; DAILY_ISTENEN=$(k_hesapla "${I[DAILY]}" "$GUN" "${I[DAILY_VAR]:-0}")

    # ---- geri alma ----
    if [ "$GERI" -eq 1 ]; then
        if [ "$KIP" != uygula ]; then
            [ -n "${C[CTL_SHA]}" ] && plan "merkez: control.d/$AD ve config.$AD yedek agacina tasinacak, pmlogger durdurulacak (arsivler $KOK/$AD'da kalir)"
            [ "${I[KURAL_KALICI]}${I[KURAL_CALISAN]}" != 00 ] && plan "$h: $MERKEZ_IC/32 -> 44321 kurali kaldirilacak"
            [ -n "${I[TIMERS_ILK_YEDEK]}" ] && plan "$h: pmlogger_timers ilk yedekten ($(basename "${I[TIMERS_ILK_YEDEK]}")) geri gelecek"
            [ "${I[ISARET]}" = 1 ] && plan "$h: /var/backup/pcp-merkezi -> pcp-merkezi-geri-alindi-$DAMGA"
            return 0
        fi
        CIKTI=$(uzak "$MERKEZ" "$AD" "$IP" "$DAMGA" <<< "$B_MERKEZ_GERI"); r=$?; yorumla "$CIKTI"
        [ "$r" -eq 0 ] || { sorun "merkez geri alma rc $r - istemciye dokunulmadi"; return 1; }
        CIKTI=$(uzak "$h" geri "$MERKEZ_IC" "${I[ZONE]}" "$GUN" "$DAMGA" <<< "$B_ISTEMCI_UYGULA"); r=$?; yorumla "$CIKTI"
        [ "$r" -eq 0 ] || sorun "$h geri alma rc $r"
        return 0
    fi

    # ---- plan ----
    local KURAL_GEREK=0 KAYIT_GEREK=0 KAPI=0 K_GEREK=0
    [ "${I[KURAL_KALICI]}" = 1 ] && [ "${I[KURAL_CALISAN]}" = 1 ] || KURAL_GEREK=1
    [ "${I[ISARET]}" = 1 ] || KURAL_GEREK=1
    if [ "$KIP" != dogrula ]; then
        [ "$CFG_ISTENEN" = "${C[CFG_SHA]}" ] && [ "$CTL_ISTENEN" = "${C[CTL_SHA]}" ] && [ "${C[DIZIN]}" = 1 ] && [ -n "${C[PID]}" ] || KAYIT_GEREK=1
        [ "$CFG_ISTENEN" = "${C[CFG_SHA]}" ] && [ -n "${C[CTL_SHA]}" ] || KAPI=1
    fi
    [ "$YAZK" = 1 ] && [ "$DAILY_ISTENEN" != "${I[DAILY]}" ] && K_GEREK=1

    if [ "$KIP" = rapor ]; then
        [ "$KURAL_GEREK" = 1 ] && plan "$h: /var/backup/pcp-merkezi isareti + guvenlik duvari (${I[ZONE]}) $MERKEZ_IC/32 -> 44321/tcp (calisan + kalici)"
        [ "$KAPI" = 1 ] && plan "merkez: uyum kapisi - 2 dk deneme kaydi ($IP), metrik karsilastirmasi (esik %$ESIK)"
        [ "$KAYIT_GEREK" = 1 ] && plan "merkez: config.$AD ($(grep -c . "$GD/config") satir), control.d/$AD, $KOK/$AD, pmlogger baslatma"
        [ "$YKOPYA" = 1 ] && yerel_kopya "$h" "$AD" "${I[HOSTNAME]}" plan
        [ "$K_GEREK" = 1 ] && plan "$h: PMLOGGER_DAILY_PARAMS '${I[DAILY]}' -> '$DAILY_ISTENEN' (sonraki pmlogger_daily $GUN gunden eski YEREL arsivleri siler; en eski: ${I[EN_ESKI]:-?})"
        [ "$YAZK" = 0 ] && bilgi "$h: yerel saklamayi '${I[SAHIP]}' yonetiyor - -k YAZILMAZ (tek sahip ilkesi)"
        [ "$KURAL_GEREK$KAYIT_GEREK$K_GEREK" = 000 ] && [ "$YKOPYA" = 0 ] && ok "$h: yapilacak degisiklik yok"
        return 0
    fi

    if [ "$KIP" = uygula ]; then
        if [ "$KURAL_GEREK" = 1 ]; then
            CIKTI=$(uzak "$h" kural "$MERKEZ_IC" "${I[ZONE]}" "$GUN" "$DAMGA" <<< "$B_ISTEMCI_UYGULA"); r=$?; yorumla "$CIKTI"
            [ "$r" -eq 0 ] || { sorun "$h: guvenlik duvari adimi rc $r - durduruldu"; return 1; }
        fi
        if [ "$KAYIT_GEREK" = 1 ]; then
            local YM="$GD/yerel-metrikler.txt"
            : > "$YM"
            if [ "$KAPI" = 1 ] && [ -n "${I[YEREL_ARSIV]}" ]; then
                timeout 120 ssh "${SSHOPT[@]}" "root@$h" "pminfo -a $(printf '%q' "${I[YEREL_ARSIV]}")" 2>/dev/null | sort -u > "$YM"
            fi
            local GOVDE
            GOVDE="$B_MERKEZ_KAYIT_ON"$'\n'"cat > \"\$DD/config\" <<'PCPMERKEZI_SONU'"$'\n'"$(cat "$GD/config")"$'\n'"PCPMERKEZI_SONU"
            GOVDE+=$'\n'"cat > \"\$DD/control\" <<'PCPMERKEZI_SONU'"$'\n'"$(cat "$GD/control")"$'\n'"PCPMERKEZI_SONU"
            GOVDE+=$'\n'"cat > \"\$DD/yerel-metrikler.txt\" <<'PCPMERKEZI_SONU'"$'\n'"$(cat "$YM")"$'\n'"PCPMERKEZI_SONU"
            GOVDE+=$'\n'"sed -i '/^\$/d' \"\$DD/yerel-metrikler.txt\""$'\n'"$B_MERKEZ_KAYIT_SON"
            CIKTI=$(uzak "$MERKEZ" "$AD" "$IP" "$KOK" "$DAMGA" "$KAPI" "$ESIK" <<< "$GOVDE"); r=$?; yorumla "$CIKTI"
            [ "$r" -eq 0 ] || { sorun "$h: merkez kaydi rc $r - yerel saklama DEGISTIRILMEDI"; return 1; }
            grep -q '^HATA ' <<< "$CIKTI" && { sorun "$h: merkez kaydinda hata - yerel saklama DEGISTIRILMEDI"; return 1; }
        fi
        if [ "$YKOPYA" = 1 ]; then
            yerel_kopya "$h" "$AD" "${I[HOSTNAME]}" uygula || { sorun "$h: yerel gecmis kopyalanamadi - yerel saklama DEGISTIRILMEDI"; return 1; }
        fi
        if [ "$K_GEREK" = 1 ]; then
            CIKTI=$(uzak "$h" saklama "$MERKEZ_IC" "${I[ZONE]}" "$GUN" "$DAMGA" <<< "$B_ISTEMCI_UYGULA"); r=$?; yorumla "$CIKTI"
            [ "$r" -eq 0 ] || sorun "$h: saklama adimi rc $r"
            bilgi "$h: sonraki pmlogger_daily (00:10) $GUN gunden eski yerel arsivleri siler (en eski: ${I[EN_ESKI]:-?})"
        fi
        [ "$YAZK" = 0 ] && bilgi "$h: yerel saklamayi '${I[SAHIP]}' yonetiyor - -k YAZILMADI (tek sahip ilkesi)"
        # yeniden tespit (dogrulama icin)
        CIKTI=$(uzak "$h" "$MERKEZ_IC" "$IC_PFX" <<< "$B_ISTEMCI_TESPIT") && { oku "$CIKTI"; for k in "${!T[@]}"; do I[$k]=${T[$k]}; done; }
        MC=$(uzak "$MERKEZ" "$AD" "$IP" "$KOK" <<< "$B_MERKEZ_ISTEMCI_TESPIT") && { oku "$MC"; for k in "${!T[@]}"; do C[$k]=${T[$k]}; done; }
    fi

    # ---- dogrulama ----
    local hata=0
    if [ -n "${C[PID]}" ]; then ok "merkez: $AD pmlogger calisiyor (pid ${C[PID]})"; else sorun "merkez: $AD icin pmlogger calismiyor"; hata=1; fi
    if [ -n "${C[SON_YAS]}" ] && [ "${C[SON_YAS]}" -le 900 ]; then ok "merkez: $KOK/$AD/${C[SON_DOSYA]} ${C[SON_YAS]} sn once yazildi"
    else sorun "merkez: $KOK/$AD son 15 dk yazilmamis (yas ${C[SON_YAS]:-dosya yok})"; hata=1; fi
    [ "${C[CTL_SHA]}" = "$CTL_ISTENEN" ] && ok "merkez: control.d/$AD beklenen icerikte" || { sorun "merkez: control.d/$AD beklenen icerikte degil"; hata=1; }
    if [ -n "$CFG_ISTENEN" ]; then
        [ "${C[CFG_SHA]}" = "$CFG_ISTENEN" ] && ok "merkez: config.$AD istemcinin config.default'u ile ayni" || { sorun "merkez: config.$AD istemciden farkli (betigi -u ile kosun)"; hata=1; }
    fi
    [ "${C[CFG_ZONEINFO]:-0}" = 0 ] && ok "merkez: config.$AD zoneinfo/buddyinfo kaydetmiyor" || { sorun "merkez: config.$AD zoneinfo/buddyinfo iceriyor (${C[CFG_ZONEINFO]})"; hata=1; }
    [ "${I[KURAL_KALICI]}" = 1 ] && [ "${I[KURAL_CALISAN]}" = 1 ] && ok "$h: 44321 yalniz $MERKEZ_IC/32'ye acik (${I[ZONE]}, calisan + kalici)" || { sorun "$h: merkez kurali eksik (kalici ${I[KURAL_KALICI]}, calisan ${I[KURAL_CALISAN]})"; hata=1; }
    [ "${I[ISARET]}" = 1 ] && ok "$h: saklama sahiplik isareti /var/backup/pcp-merkezi var" || { sorun "$h: /var/backup/pcp-merkezi yok"; hata=1; }
    if [ "$YAZK" = 1 ]; then
        if [ "$KIP" = dogrula ] && [ "$GUN_VERILDI" = 0 ]; then
            bilgi "$h: yerel saklama '${I[DAILY]}' (beklenen deger icin -k verin)"
        elif [ "$(k_hesapla "${I[DAILY]}" "$GUN" "${I[DAILY_VAR]:-0}")" = "${I[DAILY]}" ]; then ok "$h: yerel saklama '${I[DAILY]}'"
        else sorun "$h: yerel saklama '${I[DAILY]}' (beklenen -k $GUN)"; hata=1; fi
    fi
    [ "${I[PMLOGGER]}" = active ] && ok "$h: yerel pmlogger calisiyor (N gun tampon)" || { sorun "$h: yerel pmlogger ${I[PMLOGGER]}"; hata=1; }
    [ "${I[PROC_A]:-0}" = 0 ] && ok "$h: proc -A yok" || uyar "$h: proc -A var"
    return $hata
}

for h in "${ILIST[@]}"; do
    h=${h// /}
    [[ "$h" =~ $IPRE || "$h" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || { sorun "gecersiz istemci adresi: $h"; continue; }
    if [ "$KIP" = uygula ] && [ "$MKIP" != uyar ] && [ "$MKIP" != atla ] && [ "${#MSORUN[@]}" -gt 0 ]; then
        olum "merkez hazir degil"
    fi
    istemci_isle "$h" || { [ "$RC" -lt 1 ] && RC=1; }
done

baslik "Sonuc"
case "$KIP" in
    rapor)   bilgi "RAPOR kipi: hicbir sey degismedi. Uygulamak icin ayni komuta -u ekleyin." ;;
    uygula)  bilgi "degisiklik sayisi: $DEGISEN (yedek ve manifest: /var/backup/pcp-merkezi, damga $DAMGA)" ;;
    dogrula) bilgi "yalniz dogrulama yapildi" ;;
esac
[ "$RC" -eq 0 ] && ok "tamam" || bilgi "uyari/sorun var (rc $RC) - yukaridaki SORUN/UYARI satirlari"
exit "$RC"
