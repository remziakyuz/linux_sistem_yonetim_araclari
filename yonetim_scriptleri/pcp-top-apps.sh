#!/bin/bash
# 2026.07.10
# Remzi AKYUZ
# remzi@akyuz.tech
# 
# pcp-top-apps.sh
#
# PCP (Performance Co-Pilot) arsivlerinden son N gunun (bugun dahil)
# en fazla CPU / bellek / disk-I/O kullanan uygulamalarini raporlar.
# Ayni komut adina sahip prosesler tek uygulama olarak toplanir.
#
# NOT: Standart PCP proc PMDA'sinda proses-bazli network metrigi YOKTUR
# (kernel /proc altinda bunu sunmaz). Network bolumu bu yuzden sistem
# geneli interface bazlidir. Proses-bazli network icin pcp-pmda-bcc
# (bcc.proc.net.*) veya netatop gerekir; arsivde bcc metrigi varsa
# script bunu otomatik raporlar.
#
# Gereksinimler: pcp (pmlogsummary, pminfo), gawk
# Arsivlerde proc.* metrikleri loglanmis olmalidir (bkz. script sonundaki uyari).
#
# Kullanim:
#   ./pcp-top-apps.sh                    # son 14 gun, top 200
#   ./pcp-top-apps.sh -d 7 -n 50         # son 7 gun, top 50
#   ./pcp-top-apps.sh -A /var/log/pcp/pmlogger/web01 -o /tmp/rapor.txt
#   ./pcp-top-apps.sh -k                 # kernel threadleri de dahil et
#   ./pcp-top-apps.sh -c /tmp/csvdir     # ham verileri CSV olarak da yaz
#
set -o pipefail

DAYS=14
TOPN=200
ARCHIVE_DIR=""
OUTFILE=""
CSVDIR=""
INCLUDE_KTHREADS=0

usage() {
    grep '^# ' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

while getopts "d:n:A:o:c:kh" opt; do
    case $opt in
        d) DAYS=$OPTARG ;;
        n) TOPN=$OPTARG ;;
        A) ARCHIVE_DIR=$OPTARG ;;
        o) OUTFILE=$OPTARG ;;
        c) CSVDIR=$OPTARG ;;
        k) INCLUDE_KTHREADS=1 ;;
        h|*) usage ;;
    esac
done

for cmd in pmlogsummary pminfo gawk; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "HATA: '$cmd' bulunamadi (dnf install pcp gawk)" >&2; exit 2; }
done

[ -z "$ARCHIVE_DIR" ] && ARCHIVE_DIR="/var/log/pcp/pmlogger/$(hostname)"
[ -d "$ARCHIVE_DIR" ] || { echo "HATA: arsiv dizini yok: $ARCHIVE_DIR" >&2; exit 2; }
[ -z "$OUTFILE" ] && OUTFILE="./pcp_top_apps_$(hostname -s)_$(date +%Y%m%d_%H%M).txt"
[ -n "$CSVDIR" ] && mkdir -p "$CSVDIR"

TMPD=$(mktemp -d) || exit 2
trap 'rm -rf "$TMPD"' EXIT

# --- Son N gunun arsivlerini topla (bugun dahil; pmlogger_daily YYYYMMDD.* adlandirmasi) ---
ARCHIVES=()
for i in $(seq 0 $((DAYS - 1))); do
    d=$(date -d "-$i day" +%Y%m%d)
    for f in "$ARCHIVE_DIR"/"$d"*.meta*; do
        [ -e "$f" ] || continue
        base=${f%.xz}; base=${base%.zst}; base=${base%.meta}
        ARCHIVES+=("$base")
    done
done
# ayni arsiv birden fazla eslesmesin
mapfile -t ARCHIVES < <(printf '%s\n' "${ARCHIVES[@]}" | sort -u)

if [ ${#ARCHIVES[@]} -eq 0 ]; then
    echo "HATA: $ARCHIVE_DIR altinda son $DAYS gune ait arsiv bulunamadi." >&2
    exit 2
fi
echo "Bulunan arsiv sayisi: ${#ARCHIVES[@]} ($ARCHIVE_DIR, son $DAYS gun)" >&2

# --- proc metrikleri loglanmis mi kontrol et ---
HAVE_PROC=0
for a in "${ARCHIVES[@]}"; do
    if pminfo -a "$a" proc.psinfo.utime >/dev/null 2>&1; then HAVE_PROC=1; break; fi
done
if [ $HAVE_PROC -eq 0 ]; then
    cat >&2 <<'EOF'
UYARI: Arsivlerde proc.* (proses bazli) metrikler yok!
Varsayilan pmlogger yapilandirmasi proses metriklerini KAYDETMEZ.
Etkinlestirmek icin /var/lib/pcp/config/pmlogger/config.default (veya
config.<host>) dosyasina sunlari ekleyip pmlogger'i yeniden baslatin:

  log mandatory on every 60 seconds {
      proc.psinfo.utime  proc.psinfo.stime  proc.psinfo.rss
      proc.io.read_bytes proc.io.write_bytes
  }

Bu calistirmada yalnizca sistem geneli network raporu uretilebilecek.
EOF
fi

# proses bazli network var mi (pcp-pmda-bcc)?
HAVE_BCCNET=0
pminfo -a "${ARCHIVES[0]}" bcc.proc.net.tcp.tx >/dev/null 2>&1 && HAVE_BCCNET=1

METRICS="network.interface.in.bytes network.interface.out.bytes"
[ $HAVE_PROC -eq 1 ] && METRICS="proc.psinfo.utime proc.psinfo.stime proc.psinfo.rss proc.io.read_bytes proc.io.write_bytes $METRICS"
[ $HAVE_BCCNET -eq 1 ] && METRICS="$METRICS bcc.proc.net.tcp.tx bcc.proc.net.tcp.rx"

# --- Her arsivi ozetle ve tek gawk ile topla ---
# pmlogsummary -lM cikti formati:
#   commencing/ending satirlari (arsiv suresi icin)
#   metrik ["PID komut"] ortalama maksimum birim
# Sayaclar (utime, io, network) otomatik rate'e cevrilir:
#   utime+stime -> boyutsuz (cekirdek orani), io/net -> byte/sec
for a in "${ARCHIVES[@]}"; do
    echo "==ARCHIVE== $a"
    pmlogsummary -lM "$a" $METRICS 2>/dev/null
done | gawk -v topn="$TOPN" -v tmpd="$TMPD" -v kthreads="$INCLUDE_KTHREADS" '
function month(m) { return (index("JanFebMarAprMayJunJulAugSepOctNovDec", m) + 2) / 3 }
function ts(mon, day, hms, year,    t) {
    split(hms, t, /[:.]/)
    return mktime(year " " month(mon) " " day " " t[1] " " t[2] " " t[3])
}
function flush_archive() {
    if (a_start > 0 && a_end > a_start) {
        dur = a_end - a_start
        total_dur += dur
        for (c in a_cpu)  cpu_sec[c] += a_cpu[c] * dur
        for (c in a_rss)  rss_w[c]   += a_rss[c] * dur
        for (c in a_rd)   io_rd[c]   += a_rd[c] * dur
        for (c in a_wr)   io_wr[c]   += a_wr[c] * dur
        for (c in a_ntx)  net_tx[c]  += a_ntx[c] * dur
        for (c in a_nrx)  net_rx[c]  += a_nrx[c] * dur
        for (i in a_ifin)  if_in[i]  += a_ifin[i] * dur
        for (i in a_ifout) if_out[i] += a_ifout[i] * dur
        days[strftime("%Y-%m-%d", a_start)] = 1
        for (k in a_ipeak) {
            split(k, kk, SUBSEP)
            if (a_ipeak[k] > cpu_peak[kk[1]]) cpu_peak[kk[1]] = a_ipeak[k]
        }
    }
    delete a_cpu; delete a_rss; delete a_rd; delete a_wr
    delete a_ntx; delete a_nrx; delete a_ifin; delete a_ifout; delete a_ipeak
    a_start = 0; a_end = 0
}
/^==ARCHIVE==/  { flush_archive(); next }
/commencing/    { a_start = ts($3, $4, $5, $6); next }
/ending/        { a_end   = ts($3, $4, $5, $6); next }
{
    if (!match($0, /^([a-z._]+) \["([^"]+)"\] +([-+0-9.eE]+) +([-+0-9.eE]+)/, m)) next
    metric = m[1]; inst = m[2]; avg = m[3] + 0; mx = m[4] + 0

    if (metric ~ /^network\.interface/) {
        if (metric ~ /in\.bytes$/)  a_ifin[inst]  = avg
        else                        a_ifout[inst] = avg
        next
    }

    # proses instance adi: "PID komut" -> PID ayrilir, komut adi grup anahtaridir
    pid = inst; sub(/ .*/, "", pid)
    cmd = inst; sub(/^[0-9]+ /, "", cmd)

    if (cmd ~ /^\(/) {                      # kernel thread
        if (!kthreads) next
        gsub(/[()]/, "", cmd)
        sub(/^kworker.*/, "kworker", cmd)   # kworker/u8:3-xyz -> tek grupta topla
        cmd = "[kthread] " cmd
    }

    if (!((cmd, pid) in seen)) { seen[cmd, pid] = 1; nproc[cmd]++ }

    if      (metric == "proc.psinfo.utime" || metric == "proc.psinfo.stime") {
        a_cpu[cmd] += avg                   # cekirdek orani (1.0 = 1 core)
        a_ipeak[cmd, pid] += mx * 100       # utime+stime tepe toplami (yaklasik)
    }
    else if (metric == "proc.psinfo.rss") {
        a_rss[cmd] += avg                   # Kbyte
        if (mx > rss_peak[cmd]) rss_peak[cmd] = mx
    }
    else if (metric == "proc.io.read_bytes")  a_rd[cmd] += avg
    else if (metric == "proc.io.write_bytes") a_wr[cmd] += avg
    else if (metric == "bcc.proc.net.tcp.tx") a_ntx[cmd] += avg
    else if (metric == "bcc.proc.net.tcp.rx") a_nrx[cmd] += avg
}
END {
    flush_archive()
    if (total_dur <= 0) exit 3
    printf "%d %d\n", total_dur, length(days) > (tmpd "/meta")

    for (c in cpu_sec)
        printf "%.3f\t%.2f\t%.2f\t%d\t%s\n", cpu_sec[c], 100 * cpu_sec[c] / total_dur, cpu_peak[c], nproc[c], c > (tmpd "/cpu")
    for (c in rss_w)
        printf "%.1f\t%.1f\t%d\t%s\n", rss_w[c] / total_dur, rss_peak[c], nproc[c], c > (tmpd "/mem")
    for (c in io_rd) io_all[c] = 1
    for (c in io_wr) io_all[c] = 1
    for (c in io_all)
        printf "%.0f\t%.0f\t%.0f\t%d\t%s\n", io_rd[c] + io_wr[c], io_rd[c], io_wr[c], nproc[c], c > (tmpd "/io")
    for (c in net_tx) nt_all[c] = 1
    for (c in net_rx) nt_all[c] = 1
    for (c in nt_all)
        printf "%.0f\t%.0f\t%.0f\t%d\t%s\n", net_tx[c] + net_rx[c], net_tx[c], net_rx[c], nproc[c], c > (tmpd "/pnet")
    for (i in if_in)
        printf "%.0f\t%.0f\t%.0f\t%s\n", if_in[i] + if_out[i], if_in[i], if_out[i], i > (tmpd "/net")
}'
rc=$?
[ $rc -ne 0 ] && { echo "HATA: arsiv ozetleme basarisiz (rc=$rc)" >&2; exit $rc; }

read -r TOTAL_DUR NDAYS < "$TMPD/meta"

# insan-okur boyut formati (girdi: byte)
hbytes() { gawk -v b="$1" 'BEGIN{ s="B KB MB GB TB PB"; split(s,u," "); i=1; while (b>=1024 && i<6){b/=1024;i++} printf "%.2f %s", b, u[i] }'; }

{
    echo "==============================================================================="
    echo " PCP TOP UYGULAMA RAPORU  -  $(hostname)"
    echo " Kapsam   : son $DAYS gun (bugun dahil), $NDAYS gun icin veri bulundu"
    echo " Arsiv    : $ARCHIVE_DIR (${#ARCHIVES[@]} arsiv, toplam $(gawk -v s="$TOTAL_DUR" 'BEGIN{printf "%.1f saat", s/3600}') kayit)"
    echo " Rapor    : $(date '+%F %T')  |  Top $TOPN, komut adina gore gruplu"
    echo "==============================================================================="

    if [ -s "$TMPD/cpu" ]; then
        echo ""
        echo "--- TOP $TOPN CPU KULLANIMI (toplam CPU zamanina gore) ----------------------"
        printf "%4s  %14s  %9s  %9s  %6s  %s\n" "#" "CPU-SAAT" "ORT %CPU" "TEPE %CPU" "PROC#" "KOMUT"
        sort -t$'\t' -k1,1 -rn "$TMPD/cpu" | head -n "$TOPN" | gawk -F'\t' \
            '{ printf "%4d  %14.2f  %9.2f  %9.2f  %6d  %s\n", NR, $1/3600, $2, $3, $4, $5 }'

        echo ""
        echo "--- TOP $TOPN BELLEK KULLANIMI (ortalama RSS'e gore) ------------------------"
        printf "%4s  %14s  %14s  %6s  %s\n" "#" "ORT RSS" "TEPE RSS(tek)" "PROC#" "KOMUT"
        sort -t$'\t' -k1,1 -rn "$TMPD/mem" | head -n "$TOPN" | gawk -F'\t' '
            function h(kb){ s="KB MB GB TB"; split(s,u," "); i=1; while (kb>=1024 && i<4){kb/=1024;i++} return sprintf("%.2f %s",kb,u[i]) }
            { printf "%4d  %14s  %14s  %6d  %s\n", NR, h($1), h($2), $3, $4 }'

        echo ""
        echo "--- TOP $TOPN DISK I/O (okuma+yazma toplam byte) -----------------------------"
        printf "%4s  %14s  %14s  %14s  %6s  %s\n" "#" "TOPLAM" "OKUMA" "YAZMA" "PROC#" "KOMUT"
        sort -t$'\t' -k1,1 -rn "$TMPD/io" | head -n "$TOPN" | gawk -F'\t' '
            function h(b){ s="B KB MB GB TB PB"; split(s,u," "); i=1; while (b>=1024 && i<6){b/=1024;i++} return sprintf("%.2f %s",b,u[i]) }
            $1 > 0 { printf "%4d  %14s  %14s  %14s  %6d  %s\n", NR, h($1), h($2), h($3), $4, $5 }'
    fi

    echo ""
    if [ -s "$TMPD/pnet" ]; then
        echo "--- TOP $TOPN NETWORK KULLANIMI (proses bazli, bcc PMDA) ---------------------"
        printf "%4s  %14s  %14s  %14s  %6s  %s\n" "#" "TOPLAM" "TX" "RX" "PROC#" "KOMUT"
        sort -t$'\t' -k1,1 -rn "$TMPD/pnet" | head -n "$TOPN" | gawk -F'\t' '
            function h(b){ s="B KB MB GB TB PB"; split(s,u," "); i=1; while (b>=1024 && i<6){b/=1024;i++} return sprintf("%.2f %s",b,u[i]) }
            $1 > 0 { printf "%4d  %14s  %14s  %14s  %6d  %s\n", NR, h($1), h($2), h($3), $4, $5 }'
    else
        echo "--- NETWORK KULLANIMI (sistem geneli, interface bazli) -----------------------"
        echo " NOT: Standart PCP arsivlerinde proses bazli network metrigi yoktur."
        echo "      Uygulama bazli network icin 'pcp-pmda-bcc' kurup bcc.proc.net.tcp.*"
        echo "      metriklerini loglayin; script bir sonraki calismada otomatik kullanir."
        printf "%4s  %14s  %14s  %14s  %s\n" "#" "TOPLAM" "GELEN(RX)" "GIDEN(TX)" "INTERFACE"
        sort -t$'\t' -k1,1 -rn "$TMPD/net" | gawk -F'\t' '
            function h(b){ s="B KB MB GB TB PB"; split(s,u," "); i=1; while (b>=1024 && i<6){b/=1024;i++} return sprintf("%.2f %s",b,u[i]) }
            { printf "%4d  %14s  %14s  %14s  %s\n", NR, h($1), h($2), h($3), $4 }'
    fi

    echo ""
    echo "Notlar:"
    echo " * CPU-SAAT   : pencere icindeki toplam islemci zamani (cekirdek-saat)."
    echo " * ORT %CPU   : tum pencereye yayilmis ortalama (100 = surekli 1 cekirdek)."
    echo " * TEPE %CPU  : tek prosesin arsiv ornekleme araligindaki en yuksek orani."
    echo " * PROC#      : bu komut adiyla gorulen farkli PID sayisi."
    echo " * Degerler pmlogger ornekleme araligina gore yaklasik degerlerdir."
} | tee "$OUTFILE"

# ham veriler CSV olarak istenmisse
if [ -n "$CSVDIR" ]; then
    { echo "cpu_saniye,ort_yuzde_cpu,tepe_yuzde_cpu,proc_sayisi,komut"; sort -t$'\t' -k1,1 -rn "$TMPD/cpu" | tr '\t' ','; } > "$CSVDIR/cpu.csv" 2>/dev/null
    { echo "ort_rss_kb,tepe_rss_kb,proc_sayisi,komut";                  sort -t$'\t' -k1,1 -rn "$TMPD/mem" | tr '\t' ','; } > "$CSVDIR/mem.csv" 2>/dev/null
    { echo "toplam_byte,okuma_byte,yazma_byte,proc_sayisi,komut";       sort -t$'\t' -k1,1 -rn "$TMPD/io"  | tr '\t' ','; } > "$CSVDIR/io.csv"  2>/dev/null
    { echo "toplam_byte,rx_byte,tx_byte,interface";                     sort -t$'\t' -k1,1 -rn "$TMPD/net" | tr '\t' ','; } > "$CSVDIR/net.csv" 2>/dev/null
    echo "CSV dosyalari: $CSVDIR/{cpu,mem,io,net}.csv" >&2
fi

echo "" >&2
echo "Rapor dosyasi: $OUTFILE" >&2
