#!/usr/bin/env bash
#
# pcp-top-disk.sh - PCP (Performance Co-Pilot) ile en cok disk G/C yapan
#                   surecleri / uygulamalari ve en mesgul diskleri listeler.
#                   Canli sistem, uzak host veya pmlogger arsivi uzerinden calisir.
#
# Kullanim ornekleri:
#   sudo ./pcp-top-disk.sh                     # canli, 10 sn pencere, top 10 surec
#   sudo ./pcp-top-disk.sh -t 30 -n 20         # 30 sn pencere, top 20
#   sudo ./pcp-top-disk.sh -t 5 -c 12          # 5 sn'lik 12 pencere art arda (surekli izleme)
#   sudo ./pcp-top-disk.sh -g                  # komut adina gore topla (uygulama bazli)
#   sudo ./pcp-top-disk.sh -s write            # yazmaya gore sirala (read | write | total)
#   sudo ./pcp-top-disk.sh -L                  # mantiksal G/C (rchar/wchar: onbellek + soket dahil)
#   ./pcp-top-disk.sh -H sunucu.example.com    # uzak pmcd
#   ./pcp-top-disk.sh -A /var/log/pcp/pmlogger/$(hostname)/20261026.00.10 \
#                     -S '@03:00' -T '@04:00' -g          # arsivde pencere toplami
#   sudo ./pcp-top-disk.sh -C -n 50 > disk.csv  # CSV cikti
#
# Ne olcer:
#   Surec: proc.io.read_bytes / write_bytes / cancelled_write_bytes (fiziksel aygita
#   giden G/C; /proc/<pid>/io). TOPLAM = okuma + yazma - iptal edilen yazma. Pencere
#   boyunca ornekler arasi farklar toplanir; pencere icinde biten surecin o ana
#   kadarki G/C'si de sayilir. Iki ornek arasinda baslayip biten surecin G/C'si
#   onu TOPLAYAN (wait) ebeveynin sayacina eklenir (Linux cekirdegi): kisa omurlu
#   is (cron, betik, dd) ebeveyninde - cogu zaman bash, crond ya da PID 1
#   systemd - gorunur (26.10.2026 olculdu: 300 MB dd -> PID 1).
#   Disk: disk.dev.read_bytes / write_bytes / total / avactive (/proc/diskstats).
#   -L: proc.io.rchar / wchar - read()/write() bayti; sayfa onbellegi, pipe ve
#   SOKET G/C'si dahildir, fiziksel disk degildir.
#
# GORUNURLUK: proc PMDA istegi soran kullanicinin kimligiyle yanitlar; /proc/<pid>/io
#   yalniz sahibine aciktir. Root olmayan kullanici yalniz kendi sureclerini gorur
#   (sudo kullanin). Arsivde surec G/C'si yalniz pmcd.conf'ta proc PMDA '-A' varsa
#   tum surecler icin kayitlidir (playbook-pcp / pcp-setup.sh 4.0 bunu uc guvenlik
#   kapisiyla ekler). Betik gorunen surec oranini olcer ve dusukse UYARIR.
#
# YUK NOTU (sisteme yuk bindirmeme kurali):
#   - Canli: proc PMDA her ornekte TUM sureclerin /proc/<pid>/io ve status
#     dosyalarini okur (pencere basina 2 ornek; -c ile c+1). Bu okumalar bellek
#     kilidi (mmap_lock) ALMAZ, smaps OKUNMAZ; etkisi olculdu (playbook-pcp
#     README bolum 4/4c: 30 GB surecte %80 bellek baskisinda etkisiz). Cok sayida
#     surecte (>2 000) pmdaproc CPU'su artar - etkisi olculmedi; -t'yi 5 sn'nin
#     altina indirmeyin.
#   - Arsiv (-A): yalniz arsiv dosyasi okunur, izlenen sunucuya yuk YOK. Bir
#     gunluk arsivin tamami analiz makinesinde 1 cekirdekte birkac dakika
#     surebilir; -S/-T ile pencereyi daraltin. Canli ortam sunucusunda degil,
#     analiz makinesinde kosun.
#   - Uzak (-H): okuma uzak sunucuda yapilir (canli ile ayni yuk).
#
# Gereksinim: pcp-system-tools (pmrep), gawk.
#
set -o pipefail

PROG=${0##*/}

# --- varsayilanlar -----------------------------------------------------------
COUNT=10          # -n : kac satir
WINDOW=10         # -t : pencere / ornekleme araligi (sn); arsivde adim
REPEAT=1          # -c : kac pencere (canli)
HOST=""           # -H : uzak pmcd host
ARCHIVE=""        # -A : pmlogger arsivi (dosya ya da dizin)
START=""          # -S : arsivde baslangic
FINISH=""         # -T : arsivde bitis
TZONE=""          # -Z : arsiv saat dilimi (bos: yerel saat dilimi adi)
SORT_KEY=total    # -s : total | read | write
GROUP=0           # -g : komut adina gore topla
LOGICAL=0         # -L : rchar/wchar
KTHREADS=0        # -k : cekirdek is parcaciklarini dahil et
NODEV=0           # -D : disk cihaz bolumunu gosterme
CSV=0             # -C : CSV cikti
FILTER=""         # -f : surec adi duzenli ifadesi (pmrep -i)

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
  -Z TZ       Saat dilimi (varsayilan: sistemin, orn. Europe/Istanbul; -H ile uzak sunucunun)
  -s ANAHTAR  Siralama: total (vars.), read, write
  -g          Komut adina gore topla (uygulama bazli)
  -L          Mantiksal G/C (proc.io.rchar/wchar) - fiziksel disk DEGIL
  -k          Cekirdek is parcaciklarini da dahil et
  -f IFADE    Yalniz adi IFADE ile eslesen surecler (pmrep -i, orn. '.*java.*')
  -D          Disk cihaz bolumunu gosterme
  -C          CSV cikti
  -h          Bu yardim
USAGE
}

while getopts 'n:t:c:H:A:S:T:Z:s:f:gLkDCh' opt; do
    case "$opt" in
        n) COUNT=$OPTARG ;;
        t) WINDOW=$OPTARG ;;
        c) REPEAT=$OPTARG ;;
        H) HOST=$OPTARG ;;
        A) ARCHIVE=$OPTARG ;;
        S) START=$OPTARG ;;
        T) FINISH=$OPTARG ;;
        Z) TZONE=$OPTARG ;;
        s) SORT_KEY=$OPTARG ;;
        f) FILTER=$OPTARG ;;
        g) GROUP=1 ;;
        L) LOGICAL=1 ;;
        k) KTHREADS=1 ;;
        D) NODEV=1 ;;
        C) CSV=1 ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

for v in COUNT WINDOW REPEAT; do
    [[ ${!v} =~ ^[0-9]+$ ]] && [ "${!v}" -gt 0 ] || { echo "$PROG: $v pozitif tamsayi olmali: ${!v}" >&2; exit 2; }
done
case "$SORT_KEY" in total|read|write) ;; *) echo "$PROG: gecersiz siralama: $SORT_KEY" >&2; exit 2 ;; esac
for c in pmrep gawk; do
    command -v "$c" >/dev/null 2>&1 || { echo "$PROG: '$c' bulunamadi (dnf install pcp-system-tools gawk)" >&2; exit 1; }
done
[[ -n $HOST && -n $ARCHIVE ]] && { echo "$PROG: -H ve -A birlikte kullanilamaz" >&2; exit 2; }

# --- kaynak argumanlari ------------------------------------------------------
# Saat dilimi: pmrep CSV zaman damgasini -Z/-z verilmezse UTC basar (26.10.2026 olculdu);
# arsivde -z de UTC'ye dusebilir (POSIX etiket, el kitabi 10.3) -> yerel ve arsivde -Z, uzakta -z.
if [[ -z $TZONE ]]; then
    TZONE=$(timedatectl show -p Timezone --value 2>/dev/null)
    [[ -n $TZONE ]] || TZONE=$(readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||')
    [[ -n $TZONE ]] || TZONE=UTC
fi
SRC=()
if [[ -n $ARCHIVE ]]; then
    [[ -e $ARCHIVE || -e $ARCHIVE.meta || -n $(compgen -G "$ARCHIVE.meta*") ]] \
        || { echo "$PROG: arsiv bulunamadi: $ARCHIVE" >&2; exit 2; }
    SRC=(-a "$ARCHIVE" -Z "$TZONE" -u)          # -u: ara deger uretme yok, gercek kayitlar
    [[ -n $START  ]] && SRC+=(-S "$START")
    [[ -n $FINISH ]] && SRC+=(-T "$FINISH")
    SAMPLES=()                                    # arsivde pencerenin tamami
    MODE=arsiv
else
    if [[ -n $HOST ]]; then SRC=(-h "$HOST" -z); else SRC=(-Z "$TZONE"); fi
    SAMPLES=(-s $((REPEAT + 1)))
    MODE=canli
    if [[ -z $HOST && $(id -u) -ne 0 ]]; then
        echo "$PROG: UYARI: root degilsiniz - /proc/<pid>/io yalniz sahibine acik; yalniz kendi surecleriniz gorunur (sudo kullanin)." >&2
    fi
fi

if [[ $LOGICAL -eq 1 ]]; then
    PMET=(proc.io.rchar proc.io.wchar); RLBL="OKUMA(mant)"; WLBL="YAZMA(mant)"
else
    PMET=(proc.io.read_bytes proc.io.write_bytes proc.io.cancelled_write_bytes); RLBL="OKUMA"; WLBL="YAZMA"
fi
DMET=(disk.dev.read_bytes disk.dev.write_bytes disk.dev.total disk.dev.avactive)

# --- veri toplama: ham sayaclar, '|' ayracli CSV, dinamik baslik ----------------
# -r: ham sayac (oran donusumu yok; farklari awk alir), -1: surec kumesi degisince
# baslik yeniden basilir. proc.id.uid_nm: kullanici adi (anlik deger).
RAW=$(mktemp) || exit 1
trap 'rm -f "$RAW" "$RAW.err"' EXIT
IOPT=(); [[ -n $FILTER ]] && IOPT=(-i "$FILTER")
# Arsivde olmayan metrik pmrep'i tumden durdurur: once varligi denetlenir
if [[ $MODE == arsiv ]]; then
    for m in "${PMET[@]}"; do
        pminfo -a "$ARCHIVE" "$m" >/dev/null 2>&1 || { echo "$PROG: arsivde $m yok - surec G/C kaydedilmemis (pcp-zeroconf kurulu mu? el kitabi 17.3)" >&2; exit 3; }
    done
    if [[ $NODEV -eq 0 ]] && ! pminfo -a "$ARCHIVE" disk.dev.read_bytes >/dev/null 2>&1; then
        echo "$PROG: NOT: arsivde disk.dev.* yok (pcp-zeroconf config.default disk/perdisk grubunu kaydetmez) - cihaz bolumu toplanmadi." >&2
        NODEV=1
    fi
fi
# -f (pmrep -i) tum metriklere uygulanir; disk adlari surec deseniyle eslesmeyecegi icin cihaz bolumu kapatilir
[[ -n $FILTER ]] && NODEV=1
UIDM=()
for m in proc.id.uid_nm proc.id.uid; do
    [[ $MODE == arsiv ]] && ! pminfo -a "$ARCHIVE" "$m" >/dev/null 2>&1 && continue
    UIDM+=("$m")
done
DM=(); [[ $NODEV -eq 0 ]] && DM=("${DMET[@]}")
pmrep "${SRC[@]}" -t "$WINDOW" "${SAMPLES[@]}" -r -o csv -l '|' -1 -P 0 "${IOPT[@]}" \
      "${PMET[@]}" "${UIDM[@]}" "${DM[@]}" > "$RAW" 2>"$RAW.err" \
    || { echo "$PROG: pmrep basarisiz: $(head -3 "$RAW.err")" >&2; rm -f "$RAW.err"; exit 3; }
rm -f "$RAW.err"

# --- analiz ------------------------------------------------------------------
gawk -F'|' -v mode="$MODE" -v topn="$COUNT" -v sortkey="$SORT_KEY" -v group="$GROUP" \
     -v kthreads="$KTHREADS" -v csv="$CSV" -v logical="$LOGICAL" -v rlbl="$RLBL" -v wlbl="$WLBL" \
     -v nodev="$NODEV" -v win="$WINDOW" '
function uq(s) { gsub(/^"|"$/, "", s); return s }
function ts(s,    a) { split(s, a, /[-: ]/); return mktime(a[1] " " a[2] " " a[3] " " a[4] " " a[5] " " a[6]) }
function hb(b,    u, i) { split("B KB MB GB TB PB", u, " "); i = 1; while (b >= 1024 && i < 6) { b /= 1024; i++ } return sprintf("%.1f %s", b, u[i]) }
function anahtar(inst,    pid, cmd) {
    pid = inst; sub(/ .*/, "", pid); cmd = inst; sub(/^[0-9]+ /, "", cmd)
    if (cmd ~ /^\(/) { if (!kthreads) return ""; gsub(/[()]/, "", cmd); sub(/^kworker.*/, "kworker", cmd); cmd = "[kthread] " cmd }
    PIDOF = pid + 0; CMDOF = cmd
    return group ? cmd : inst
}
# bir pencerenin tablosunu bas ve sifirla
function bas(baslik, sure,    k, n, i, j, t, sirali, deger, u) {
    n = 0
    for (k in TOT) {
        deger = (sortkey == "read") ? RD[k] : (sortkey == "write") ? WR[k] : TOT[k]
        if (TOT[k] <= 0 && RD[k] <= 0 && WR[k] <= 0) continue
        n++; sirali[n] = sprintf("%020.0f\t%s", deger, k)
    }
    asort(sirali)
    if (csv) {
        j = 0
        for (i = n; i >= 1 && j < topn; i--) {
            j++; split(sirali[i], t, "\t"); k = t[2]
            printf "%s,%s,%s,%.0f,%.0f,%.0f,%.0f,\"%s\"\n", PENC, (group ? "" : PID[k]), (USR[k] != "" ? USR[k] : (UIDN[k] != "" ? "uid:" UIDN[k] : "")), TOT[k], RD[k], WR[k], (sure > 0 ? TOT[k] / sure : 0), CMD[k]
        }
    } else {
        printf "\n--- %s ---\n", baslik
        if (group) printf "%4s  %10s  %10s  %10s  %11s  %5s  %-10s  %s\n", "#", "TOPLAM", rlbl, wlbl, "ORT HIZ", "SUREC", "KULLANICI", "KOMUT"
        else       printf "%4s  %10s  %10s  %10s  %11s  %7s  %-10s  %s\n", "#", "TOPLAM", rlbl, wlbl, "ORT HIZ", "PID", "KULLANICI", "KOMUT"
        if (n == 0) print "      (pencerede G/C yapan surec gorulmedi)"
        j = 0
        for (i = n; i >= 1 && j < topn; i--) {
            j++; split(sirali[i], t, "\t"); k = t[2]
            u = USR[k]; if (u == "") u = (UIDN[k] != "" ? "uid:" UIDN[k] : "?")
            if (group) printf "%4d  %10s  %10s  %10s  %9s/s  %5d  %-10s  %s\n", j, hb(TOT[k]), hb(RD[k]), hb(WR[k]), hb(sure > 0 ? TOT[k] / sure : 0), NP[k], u, CMD[k]
            else       printf "%4d  %10s  %10s  %10s  %9s/s  %7d  %-10s  %s\n", j, hb(TOT[k]), hb(RD[k]), hb(WR[k]), hb(sure > 0 ? TOT[k] / sure : 0), PID[k], u, CMD[k]
        }
    }
    delete TOT; delete RD; delete WR; delete NP; delete SEEN
}
function bas_dev(baslik, sure,    d, n, i, t, sirali) {
    if (nodev) return
    n = 0
    for (d in DTOT) { n++; sirali[n] = sprintf("%020.0f\t%s", DTOT[d], d) }
    asort(sirali)
    if (csv) {
        for (i = n; i >= 1; i--) { split(sirali[i], t, "\t"); d = t[2]
            printf "%s,cihaz,,%.0f,%.0f,%.0f,%.0f,\"%s\"\n", PENC, DTOT[d], DRD[d], DWR[d], (sure > 0 ? DTOT[d] / sure : 0), d }
    } else {
        printf "\n--- DISK CIHAZLARI (%s) ---\n", baslik
        printf "%4s  %10s  %10s  %10s  %11s  %8s  %7s  %s\n", "#", "TOPLAM", "OKUMA", "YAZMA", "ORT HIZ", "IOPS", "MESGUL%", "CIHAZ"
        for (i = n; i >= 1; i--) { split(sirali[i], t, "\t"); d = t[2]
            printf "%4d  %10s  %10s  %10s  %9s/s  %8.1f  %7.1f  %s\n", n - i + 1, hb(DTOT[d]), hb(DRD[d]), hb(DWR[d]), hb(sure > 0 ? DTOT[d] / sure : 0),
                (sure > 0 ? DOPS[d] / sure : 0), (sure > 0 ? 100 * DACT[d] / 1000 / sure : 0), d }
    }
    delete DTOT; delete DRD; delete DWR; delete DOPS; delete DACT
}
/^Time\|/ {                                   # baslik: sutun -> metrik + ornek
    delete M; delete I
    for (i = 2; i <= NF; i++) { h = uq($i); p = index(h, "-"); M[i] = substr(h, 1, p - 1); I[i] = substr(h, p + 1) }
    next
}
{
    t = ts($1); nsample++
    if (t0 == "") t0 = t
    for (i = 2; i <= NF; i++) {
        if (!(i in M)) continue
        val = uq($i)
        if (M[i] ~ /^disk\.dev\./) {
            if (val == "" || val !~ /^[0-9.eE+]+$/) continue
            dv = I[i]
            if (!((dv, M[i]) in dson)) { dson[dv, M[i]] = val + 0; continue }
            d = val - dson[dv, M[i]]; dson[dv, M[i]] = val + 0
            if (d < 0) continue
            if (M[i] == "disk.dev.read_bytes")       { DRD[dv] += d * 1024; DTOT[dv] += d * 1024 }   # Kbyte
            else if (M[i] == "disk.dev.write_bytes") { DWR[dv] += d * 1024; DTOT[dv] += d * 1024 }
            else if (M[i] == "disk.dev.total")       DOPS[dv] += d
            else if (M[i] == "disk.dev.avactive")    DACT[dv] += d                                   # ms
            continue
        }
        k = anahtar(I[i]); if (k == "") continue
        if (M[i] == "proc.id.uid_nm") { if (val != "") USR[k] = val; tum[I[i]] = 1; continue }
        if (M[i] == "proc.id.uid")    { if (val != "") UIDN[k] = val; tum[I[i]] = 1; continue }
        if (val == "" || val !~ /^[0-9.eE+]+$/) continue
        gorulen[I[i]] = 1
        PID[k] = PIDOF; CMD[k] = CMDOF
        if (!((I[i], M[i]) in son)) { son[I[i], M[i]] = val + 0; continue }
        d = val - son[I[i], M[i]]; son[I[i], M[i]] = val + 0
        if (d < 0) continue                                   # sayac sifirlandi / PID yeniden kullanildi
        if (M[i] ~ /read_bytes$|rchar$/)            { RD[k] += d; TOT[k] += d }
        else if (M[i] ~ /cancelled_write_bytes$/)   { WR[k] -= d; TOT[k] -= d }
        else if (M[i] ~ /write_bytes$|wchar$/)      { WR[k] += d; TOT[k] += d }
        if (!((k, I[i]) in SEEN)) { SEEN[k, I[i]] = 1; NP[k]++ }
    }
    if (mode == "canli" && nsample > 1) {
        PENC = $1
        bas(sprintf("SUREC G/C  %s  (%d sn pencere)", $1, win), win)
        bas_dev($1, win)
    }
    tl = t
}
BEGIN { if (csv) print "pencere,pid,kullanici,toplam_bayt,okuma_bayt,yazma_bayt,ort_bayt_sn,komut" }
END {
    if (mode == "arsiv") {
        sure = tl - t0
        if (nsample < 2) print "\nUYARI: arsiv penceresinde en az iki ornek yok (pencere dar ya da kayit yok)." > "/dev/stderr"
        else {
            PENC = strftime("%F %T", t0) " .. " strftime("%F %T", tl)
            bas(sprintf("SUREC G/C  %s .. %s  (%.1f dk, %d ornek)", strftime("%F %T", t0), strftime("%F %T", tl), sure / 60, nsample), sure)
            bas_dev(sprintf("%s .. %s", strftime("%F %T", t0), strftime("%F %T", tl)), sure)
        }
    }
    ng = length(gorulen); nt = length(tum)
    if (!csv && !logical && nt > 0) {
        printf "\nGorunurluk: G/C degeri %d / %d surecte goruldu (%%%d).", ng, nt, 100 * ng / nt
        if (100 * ng < 80 * nt) {
            if (mode == "arsiv") printf " EKSIK: pencerenin tamaminda ya da bir kisminda proc PMDA -A yoktu - o surelerde arsivde yalniz pcp kullanicisinin surecleri var (el kitabi 17.4)."
            else printf " EKSIK: root degilsiniz ya da uzak pmcd uzerinde proc -A yok."
        }
        printf "\n"
    }
    if (!csv) {
        if (logical) print "Notlar: TOPLAM = rchar + wchar (read()/write() bayti: sayfa onbellegi, pipe, SOKET dahil; disk DEGIL)."
        else         print "Notlar: TOPLAM = okuma + yazma - iptal edilen yazma (fiziksel aygit). ORT HIZ = TOPLAM / pencere."
        print "        Pencerede baslayip biten kisa surecin G/C si onu toplayan ebeveynde (bash, crond, PID 1) gorunur."
        print "        Uzun donem (gun/hafta) uygulama raporu: pcp-top-apps.sh"
    }
}' "$RAW"
