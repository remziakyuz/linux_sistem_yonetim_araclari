#!/usr/bin/env bash
#
# pcp-top-net.sh - PCP (Performance Co-Pilot) ile en cok ag trafigi olan ag
#                  kartlarini ve - verisi varsa - uygulamalari listeler.
#                  Canli sistem, uzak host veya pmlogger arsivi uzerinden calisir.
#
# Kullanim ornekleri:
#   ./pcp-top-net.sh                       # canli, 10 sn pencere, ag kartlari (+ bcc varsa surecler)
#   ./pcp-top-net.sh -t 30 -n 20           # 30 sn pencere, top 20
#   ./pcp-top-net.sh -t 5 -c 12            # 5 sn'lik 12 pencere art arda
#   ./pcp-top-net.sh -l                    # lo (loopback) dahil
#   ./pcp-top-net.sh -H sunucu.example.com # uzak pmcd
#   ./pcp-top-net.sh -A /var/log/pcp/pmlogger/$(hostname)/20261026.00.10 -S @03:00 -T @04:00
#   sudo ./pcp-top-net.sh -P -g            # SOKET ORNEKLEMESI (ss): uygulama bazli TCP trafigi
#                                          #   YUK NOTU'nu okuyun; varsayilan KAPALI
#   ./pcp-top-net.sh -C > net.csv          # CSV cikti
#
# NEDEN UYGULAMA BAZLI AG VERISI HER ZAMAN YOK:
#   Linux cekirdegi /proc altinda SUREC BASINA ag bayti sunmaz (/proc/<pid>/io
#   'daki rchar/wchar soket G/C'sini dosya G/C'siyle karisik verir). Bu yuzden
#   standart PCP (proc PMDA) ve pcp-zeroconf kaydinda surec bazli ag metrigi
#   YOKTUR; 'pcp atop -n' de netatop cekirdek modulu olmadan yalniz sistem geneli
#   basar. Uc yol vardir:
#     1. Ag karti bazli (VARSAYILAN, her zaman): network.interface.* - hangi kartta
#        ne kadar trafik var. Onerilen kayitta (config.default) 10 sn'de bir vardir.
#     2. bcc PMDA (eBPF, netproc modulu): bcc.proc.net.{tcp,udp}.{send,recv}.bytes.
#        Kurulu ve calisiyorsa betik OTOMATIK kullanir; betik bu PMDA'yi KURMAZ
#        (yapilandirma karari: varsayilan kapali, etkisi olculmedi - YUK NOTU).
#     3. -P soket ornekleme (ss -tinp): pencere basinda ve sonunda TCP soketlerinin
#        bytes_sent/bytes_received sayaclari alinir, fark surece yazilir. Yalniz
#        canli + yerel + TCP; pencere icinde acilip KAPANAN soket ve UDP GORULMEZ.
#
# YUK NOTU (sisteme yuk bindirmeme kurali):
#   - Varsayilan (ag karti): pmdalinux /proc/net/dev ve /sys/class/net okur, ag
#     kartina SIOCETHTOOL (hiz/cift yon) sorar - sysstat %ifutil ile ayni yol
#     (playbook-pcp README 4c T4). Kart sayisiyla orantili, kisa. Etkisi olculmedi.
#   - bcc yolu: betik yalniz OKUR. PMDA'nin kendisi her tcp_sendmsg/recvmsg ve
#     UDP cagrisina eBPF kprobe baglar - yuksek trafikli sunucuda etkisi
#     OLCULMEDI; bu yuzden onerilen yapilandirmada varsayilan kapalidir (once test sunucusunda olcun).
#   - -P (ss -tinp): cekirdek tum TCP soketlerini netlink ile doker; -p TUM
#     sureclerin /proc/<pid>/fd dizinlerini tarar (her fd icin readlink).
#     Analiz makinesinde 409 surec / 3 798 fd / 8 soket: 0,02 sn (26.10.2026).
#     On binlerce soket ya da yuz binlerce fd olan sunucuda etkisi OLCULMEDI ->
#     varsayilan KAPALI; canli ortamda once test sunucusunda olcun. smaps OKUNMAZ.
#   - Arsiv (-A): yalniz arsiv dosyasi okunur, izlenen sunucuya yuk YOK.
#
# Gereksinim: pcp-system-tools (pmrep), gawk; -P icin iproute (ss).
#
set -o pipefail

PROG=${0##*/}

# --- varsayilanlar -----------------------------------------------------------
COUNT=10          # -n : kac satir
WINDOW=10         # -t : pencere suresi (sn)
REPEAT=1          # -c : kac pencere (canli)
HOST=""           # -H : uzak pmcd host
ARCHIVE=""        # -A : pmlogger arsivi
START=""          # -S : arsivde baslangic
FINISH=""         # -T : arsivde bitis
TZONE=""          # -Z : saat dilimi
LOOPBACK=0        # -l : lo dahil
SOCKET=0          # -P : ss soket ornekleme (varsayilan kapali)
GROUP=0           # -g : -P / bcc'de komut adina gore topla
NOPROC=0          # -I : yalniz ag karti bolumu
CSV=0             # -C : CSV cikti

usage() {
    sed -n '2,/^set -o pipefail/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
    cat <<USAGE

Secenekler:
  -n SAYI     Listelenecek satir sayisi (varsayilan: $COUNT)
  -t SANIYE   Pencere suresi; arsivde ornekleme adimi (varsayilan: $WINDOW)
  -c SAYI     Art arda pencere sayisi, yalniz canli (varsayilan: $REPEAT)
  -H HOST     Uzak pmcd sunucusu
  -A ARSIV    pmlogger arsivi (uzantisiz yol ya da arsiv dizini)
  -S ZAMAN    Arsivde baslangic (orn: '@03:00', '-1h')
  -T ZAMAN    Arsivde bitis
  -Z TZ       Saat dilimi (varsayilan: sistemin; -H ile uzak sunucunun)
  -l          lo (loopback) arayuzunu de listele
  -P          Soket ornekleme (ss -tinp; yalniz canli/yerel/TCP; YUK NOTU)
  -g          Uygulama (komut adi) bazli topla (-P ve bcc bolumu)
  -I          Yalniz ag karti bolumu (surec bolumunu atla)
  -C          CSV cikti
  -h          Bu yardim
USAGE
}

while getopts 'n:t:c:H:A:S:T:Z:lPgICh' opt; do
    case "$opt" in
        n) COUNT=$OPTARG ;;
        t) WINDOW=$OPTARG ;;
        c) REPEAT=$OPTARG ;;
        H) HOST=$OPTARG ;;
        A) ARCHIVE=$OPTARG ;;
        S) START=$OPTARG ;;
        T) FINISH=$OPTARG ;;
        Z) TZONE=$OPTARG ;;
        l) LOOPBACK=1 ;;
        P) SOCKET=1 ;;
        g) GROUP=1 ;;
        I) NOPROC=1 ;;
        C) CSV=1 ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

for v in COUNT WINDOW REPEAT; do
    [[ ${!v} =~ ^[0-9]+$ ]] && [ "${!v}" -gt 0 ] || { echo "$PROG: $v pozitif tamsayi olmali: ${!v}" >&2; exit 2; }
done
for c in pmrep pminfo gawk; do
    command -v "$c" >/dev/null 2>&1 || { echo "$PROG: '$c' bulunamadi (dnf install pcp-system-tools gawk)" >&2; exit 1; }
done
[[ -n $HOST && -n $ARCHIVE ]] && { echo "$PROG: -H ve -A birlikte kullanilamaz" >&2; exit 2; }
if [[ $SOCKET -eq 1 ]]; then
    [[ -n $HOST || -n $ARCHIVE ]] && { echo "$PROG: -P yalniz canli ve yerel sistemde calisir" >&2; exit 2; }
    command -v ss >/dev/null 2>&1 || { echo "$PROG: -P icin 'ss' gerekir (dnf install iproute)" >&2; exit 1; }
    [[ $(id -u) -eq 0 ]] || echo "$PROG: UYARI: root degilsiniz - ss -p yalniz kendi sureclerinizin soket sahipligini gosterir." >&2
    echo "$PROG: YUK NOTU: -P her pencere basinda/sonunda 'ss -tinp' calistirir (tum TCP soketleri + tum sureclerin fd dizinleri). Buyuk sunucuda etkisi olculmedi." >&2
fi

# --- saat dilimi ve kaynak (pmrep CSV, -Z/-z yoksa UTC basar) ----------------
if [[ -z $TZONE ]]; then
    TZONE=$(timedatectl show -p Timezone --value 2>/dev/null)
    [[ -n $TZONE ]] || TZONE=$(readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||')
    [[ -n $TZONE ]] || TZONE=UTC
fi
SRC=(); QSRC=()
if [[ -n $ARCHIVE ]]; then
    [[ -e $ARCHIVE || -n $(compgen -G "$ARCHIVE.meta*") ]] || { echo "$PROG: arsiv bulunamadi: $ARCHIVE" >&2; exit 2; }
    SRC=(-a "$ARCHIVE" -Z "$TZONE" -u); QSRC=(-a "$ARCHIVE")
    [[ -n $START  ]] && SRC+=(-S "$START")
    [[ -n $FINISH ]] && SRC+=(-T "$FINISH")
    SAMPLES=(); MODE=arsiv
else
    if [[ -n $HOST ]]; then SRC=(-h "$HOST" -z); QSRC=(-h "$HOST"); else SRC=(-Z "$TZONE"); fi
    SAMPLES=(-s $((REPEAT + 1))); MODE=canli
fi

# --- hangi metrikler var? (arsivde olmayan metrik pmrep'i durdurur) ----------
var_mi() { pminfo "${QSRC[@]}" "$1" >/dev/null 2>&1; }
IMET=()
for m in network.interface.in.bytes network.interface.out.bytes network.interface.in.packets \
         network.interface.out.packets network.interface.in.errors network.interface.out.errors \
         network.interface.in.drops network.interface.out.drops network.interface.speed; do
    var_mi "$m" && IMET+=("$m")
done
[[ ${#IMET[@]} -ge 2 ]] || { echo "$PROG: network.interface.* okunamadi (pmcd erisimi ya da arsivde kayit yok)" >&2; exit 3; }
BMET=()
if [[ $NOPROC -eq 0 && $SOCKET -eq 0 ]]; then
    for m in bcc.proc.net.tcp.send.bytes bcc.proc.net.tcp.recv.bytes bcc.proc.net.udp.send.bytes bcc.proc.net.udp.recv.bytes; do
        var_mi "$m" && BMET+=("$m")
    done
fi

RAW=$(mktemp) || exit 1
SSD=$(mktemp -d) || exit 1
trap 'rm -rf "$RAW" "$RAW.err" "$SSD"' EXIT

# --- ss soket anlik goruntusu: "pid<TAB>komut<TAB>anahtar<TAB>gonderilen<TAB>alinan" ---
ss_al() {
    ss -tinpH 2>/dev/null | gawk '
        /^[^ \t]/ {                                   # soket satiri
            anahtar = $4 " " $5; pid = ""; cmd = ""
            if (match($0, /users:\(\("([^"]+)",pid=([0-9]+)/, u)) { cmd = u[1]; pid = u[2] }
            next
        }
        /^[ \t]/ && anahtar != "" {                   # ayrinti satiri
            tx = ""; rx = 0
            if (match($0, /bytes_sent:([0-9]+)/, a))         tx = a[1]
            else if (match($0, /bytes_acked:([0-9]+)/, a))   tx = a[1]
            if (match($0, /bytes_received:([0-9]+)/, a))     rx = a[1]
            if (tx == "") tx = 0
            printf "%s\t%s\t%s\t%s\t%s\n", (pid == "" ? "?" : pid), (cmd == "" ? "?" : cmd), anahtar, tx, rx
            anahtar = ""
        }'
}

# --- veri toplama ------------------------------------------------------------
if [[ $SOCKET -eq 1 && $MODE == canli ]]; then
    # pmrep (ag karti) arka planda, ss anlik goruntuleri pencere sinirlarinda
    pmrep "${SRC[@]}" -t "$WINDOW" "${SAMPLES[@]}" -r -o csv -l '|' -1 -P 0 "${IMET[@]}" > "$RAW" 2>"$RAW.err" &
    PMREP_PID=$!
    ss_al > "$SSD/0"
    for ((w = 1; w <= REPEAT; w++)); do
        sleep "$WINDOW"; ss_al > "$SSD/$w"
    done
    wait "$PMREP_PID" || { echo "$PROG: pmrep basarisiz: $(head -3 "$RAW.err")" >&2; exit 3; }
else
    pmrep "${SRC[@]}" -t "$WINDOW" "${SAMPLES[@]}" -r -o csv -l '|' -1 -P 0 "${IMET[@]}" "${BMET[@]}" > "$RAW" 2>"$RAW.err" \
        || { echo "$PROG: pmrep basarisiz: $(head -3 "$RAW.err")" >&2; exit 3; }
fi

# --- analiz ------------------------------------------------------------------
gawk -F'|' -v mode="$MODE" -v topn="$COUNT" -v csv="$CSV" -v lo="$LOOPBACK" -v group="$GROUP" \
     -v win="$WINDOW" -v nbcc="${#BMET[@]}" -v sock="$SOCKET" -v noproc="$NOPROC" -v ssd="$SSD" -v nwin="$REPEAT" '
function uq(s) { gsub(/^"|"$/, "", s); return s }
function ts(s,    a) { split(s, a, /[-: ]/); return mktime(a[1] " " a[2] " " a[3] " " a[4] " " a[5] " " a[6]) }
function hb(b,    u, i) { split("B KB MB GB TB PB", u, " "); i = 1; while (b >= 1024 && i < 6) { b /= 1024; i++ } return sprintf("%.1f %s", b, u[i]) }
function sayi(v) { return (v != "" && v ~ /^[0-9.eE+-]+$/) }
function bas_if(pen, sure,    k, n, i, j, t, sirali, kul) {
    n = 0
    for (k in IN) { if (!lo && k == "lo") continue; n++; sirali[n] = sprintf("%020.0f\t%s", IN[k] + OUT[k], k) }
    asort(sirali)
    if (!csv) {
        printf "\n--- AG KARTLARI  %s  (%s) ---\n", pen, (mode == "canli" ? win " sn pencere" : sprintf("%.1f dk", sure / 60))
        printf "%4s  %10s  %10s  %10s  %11s  %11s  %9s  %7s  %7s  %6s  %s\n", "#", "TOPLAM", "ALINAN", "GONDERILEN", "ALMA HIZI", "GONDERME", "PAKET/sn", "HATA", "DUSEN", "KUL%", "KART"
    }
    j = 0
    for (i = n; i >= 1 && j < topn; i--) {
        j++; split(sirali[i], t, "\t"); k = t[2]
        kul = ""
        if (HIZ[k] > 0 && HIZ[k] < 1e6 && sure > 0) {          # Mbyte/sn; sanal kartlarda anlamsiz deger gelebilir
            kul = 100 * ((IN[k] > OUT[k] ? IN[k] : OUT[k]) / sure) / (HIZ[k] * 1048576)
            kul = sprintf("%.1f", kul)
        }
        if (csv) printf "%s,kart,%s,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%s\n", pen, k, IN[k] + OUT[k], IN[k], OUT[k], PK[k], ER[k], DR[k], kul
        else printf "%4d  %10s  %10s  %10s  %9s/s  %9s/s  %9.1f  %7d  %7d  %6s  %s\n", j, hb(IN[k] + OUT[k]), hb(IN[k]), hb(OUT[k]),
                    hb(sure > 0 ? IN[k] / sure : 0), hb(sure > 0 ? OUT[k] / sure : 0), (sure > 0 ? PK[k] / sure : 0), ER[k], DR[k], (kul == "" ? "-" : kul), k
    }
    delete IN; delete OUT; delete PK; delete ER; delete DR
}
function bas_proc(pen, sure, kaynak,    k, n, i, j, t, sirali) {
    n = 0
    for (k in PTX) { n++; sirali[n] = sprintf("%020.0f\t%s", PTX[k] + PRX[k], k) }
    for (k in PRX) if (!(k in PTX)) { n++; sirali[n] = sprintf("%020.0f\t%s", PRX[k], k) }
    asort(sirali)
    if (!csv) {
        printf "\n--- UYGULAMA / SUREC AG TRAFIGI (%s)  %s ---\n", kaynak, pen
        printf "%4s  %10s  %10s  %10s  %11s  %7s  %s\n", "#", "TOPLAM", "GONDERILEN", "ALINAN", "ORT HIZ", (group ? "SUREC" : "PID"), "KOMUT"
        if (n == 0) print "      (pencerede trafik goren surec yok)"
    }
    j = 0
    for (i = n; i >= 1 && j < topn; i--) {
        j++; split(sirali[i], t, "\t"); k = t[2]
        if (csv) printf "%s,surec,\"%s\",%.0f,%.0f,%.0f,%s,,,\n", pen, PCMD[k], PTX[k] + PRX[k], PRX[k], PTX[k], (group ? NP[k] : PPID[k])
        else printf "%4d  %10s  %10s  %10s  %9s/s  %7s  %s\n", j, hb(PTX[k] + PRX[k]), hb(PTX[k]), hb(PRX[k]), hb(sure > 0 ? (PTX[k] + PRX[k]) / sure : 0), (group ? NP[k] : PPID[k]), PCMD[k]
    }
    delete PTX; delete PRX; delete NP; delete SEEN
}
function anahtar(inst,    pid, cmd) {
    pid = inst; sub(/ .*/, "", pid); cmd = inst; sub(/^[0-9]+ /, "", cmd)
    PIDOF = pid + 0; CMDOF = cmd
    return group ? cmd : inst
}
# ss anlik goruntuleri arasindaki fark: ayni soket (yerel+uzak adres) her iki goruntude varsa fark,
# yalniz sonrakinde varsa (pencerede acildi) tamami sayilir
function ss_fark(a, b,    satir, f, onceki_tx, onceki_rx, k, dtx, drx, key) {
    delete onceki_tx; delete onceki_rx
    while ((getline satir < a) > 0) { split(satir, f, "\t"); onceki_tx[f[3]] = f[4]; onceki_rx[f[3]] = f[5] }
    close(a)
    while ((getline satir < b) > 0) {
        split(satir, f, "\t")
        if (f[3] in onceki_tx) { dtx = f[4] - onceki_tx[f[3]]; drx = f[5] - onceki_rx[f[3]] } else { dtx = f[4]; drx = f[5] }
        if (dtx < 0) dtx = 0; if (drx < 0) drx = 0
        if (dtx + drx == 0) continue
        key = group ? f[2] : f[1] " " f[2]
        PTX[key] += dtx; PRX[key] += drx; PPID[key] = f[1]; PCMD[key] = f[2]
        if (!((key, f[1]) in SEEN)) { SEEN[key, f[1]] = 1; NP[key]++ }
    }
    close(b)
}
BEGIN { if (csv) print "pencere,tur,ad,toplam_bayt,alinan_bayt,gonderilen_bayt,paket_veya_pid,hata,dusen,kullanim_yuzde" }
/^Time\|/ { delete M; delete I; for (i = 2; i <= NF; i++) { h = uq($i); p = index(h, "-"); M[i] = substr(h, 1, p - 1); I[i] = substr(h, p + 1) }; next }
{
    t = ts($1); ns++
    if (t0 == "") t0 = t
    for (i = 2; i <= NF; i++) {
        if (!(i in M)) continue
        val = uq($i); if (!sayi(val)) continue
        m = M[i]; k = I[i]
        if (m == "network.interface.speed") { HIZ[k] = val + 0; continue }
        if (!((k, m) in son)) { son[k, m] = val + 0; if (m ~ /^network/) IN[k] += 0; continue }
        d = val - son[k, m]; son[k, m] = val + 0
        if (d < 0) continue
        if (m ~ /^bcc\./) {
            q = anahtar(k); PPID[q] = PIDOF; PCMD[q] = CMDOF
            if (m ~ /send\.bytes$/) PTX[q] += d; else PRX[q] += d
            if (!((q, k) in SEEN)) { SEEN[q, k] = 1; NP[q]++ }
            continue
        }
        if (m == "network.interface.in.bytes") IN[k] += d
        else if (m == "network.interface.out.bytes") OUT[k] += d
        else if (m ~ /packets$/) PK[k] += d
        else if (m ~ /errors$/) ER[k] += d
        else if (m ~ /drops$/) DR[k] += d
    }
    if (mode == "canli" && ns > 1) {
        bas_if($1, win)
        if (nbcc > 0) bas_proc($1, win, "bcc PMDA, TCP+UDP")
        if (sock) { ss_fark(ssd "/" (ns - 2), ssd "/" (ns - 1)); bas_proc($1, win, "ss soket ornekleme, yalniz TCP") }
    }
    tl = t
}
END {
    if (mode == "arsiv") {
        if (ns < 2) { print "UYARI: arsiv penceresinde en az iki ornek yok." > "/dev/stderr"; exit 0 }
        pen = strftime("%F %T", t0) " .. " strftime("%F %T", tl)
        bas_if(pen, tl - t0)
        if (nbcc > 0) bas_proc(pen, tl - t0, "bcc PMDA, TCP+UDP")
    }
    if (csv) exit 0
    if (!noproc && nbcc == 0 && !sock) {
        print "\nUygulama bazli ag trafigi: TOPLANMADI (gerekce: cekirdek surec basina ag sayaci sunmaz; bcc PMDA"
        print "  bu kaynakta yok ya da calismiyor). Secenekler: canli sistemde -P (ss soket ornekleme, YUK NOTU),"
        print "  ya da test sunucusunda olcup onayla bcc PMDA (netproc). Ayrinti: el kitabi 17.7."
    }
    print "\nNotlar: KUL% = max(alinan, gonderilen) hizi / kart hizi; sanal kartlarda hiz bilinmiyorsa \"-\"."
    print "        bond/team uyeleri, kopru (bridge), VLAN ve vnet kartlari AYNI trafigi birden cok kez gosterir;"
    print "        toplam icin yalniz fiziksel kartlari ya da yalniz bond kartini toplayin."
    if (sock) print "        -P: pencerede acilip kapanan soket ve UDP gorunmez; ayni soketi paylasan sureclerde ilk PID yazilir."
}' "$RAW"
