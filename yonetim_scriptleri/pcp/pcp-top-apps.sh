#!/bin/bash
#
# pcp-top-apps.sh
#
# PCP (Performance Co-Pilot) arsivlerinden son N gunun (bugun dahil)
# en fazla CPU / bellek / disk-I/O kullanan uygulamalarini ve kullanicilarini
# raporlar. Ayni komut adina sahip prosesler tek uygulama olarak toplanir;
# arsivde proc.id.uid varsa ayni kaynaklar kullanici bazinda da toplanir.
#
# NOT: Standart PCP proc PMDA'sinda proses-bazli network metrigi YOKTUR
# (kernel /proc altinda bunu sunmaz). Network bolumu bu yuzden sistem
# geneli interface bazlidir. Proses-bazli network icin pcp-pmda-bcc
# (bcc.proc.net.*) veya netatop gerekir; arsivde bcc metrigi varsa
# script bunu otomatik raporlar.
#
# Gereksinimler: pcp (pmlogsummary, pminfo), gawk
# Arsivlerde proc.* metrikleri loglanmis olmalidir (bkz. script sonundaki uyari).
# Arsivler paralel ozetlenir (-j); bir gunluk arsivin ozeti ~30 sn surebilir.
#
# Kullanim:
#   ./pcp-top-apps.sh                    # son 14 gun, top 200
#   ./pcp-top-apps.sh -d 7 -n 50         # son 7 gun, top 50
#   ./pcp-top-apps.sh -A /var/log/pcp/pmlogger/web01 -o /tmp/rapor.txt
#   ./pcp-top-apps.sh -k                 # kernel threadleri de dahil et
#   ./pcp-top-apps.sh -c /tmp/csvdir     # ham verileri CSV olarak da yaz
#   ./pcp-top-apps.sh -j 2               # ayni anda 2 arsiv ozetle (varsayilan: cekirdek sayisi, en fazla 4)
#
set -o pipefail

DAYS=14
TOPN=200
ARCHIVE_DIR=""
OUTFILE=""
CSVDIR=""
INCLUDE_KTHREADS=0
JOBS=""

usage() {
    grep '^# ' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

while getopts "d:n:A:o:c:j:kh" opt; do
    case $opt in
        d) DAYS=$OPTARG ;;
        n) TOPN=$OPTARG ;;
        A) ARCHIVE_DIR=$OPTARG ;;
        o) OUTFILE=$OPTARG ;;
        c) CSVDIR=$OPTARG ;;
        j) JOBS=$OPTARG ;;
        k) INCLUDE_KTHREADS=1 ;;
        h|*) usage ;;
    esac
done
for v in DAYS TOPN; do
    [[ ${!v} =~ ^[0-9]+$ ]] && [ "${!v}" -gt 0 ] || { echo "HATA: $v pozitif sayi olmali: ${!v}" >&2; exit 1; }
done

for cmd in pmlogsummary pminfo gawk; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "HATA: '$cmd' bulunamadi (dnf install pcp gawk)" >&2; exit 2; }
done

[ -z "$ARCHIVE_DIR" ] && ARCHIVE_DIR="/var/log/pcp/pmlogger/$(hostname)"
[ -d "$ARCHIVE_DIR" ] || { echo "HATA: arsiv dizini yok: $ARCHIVE_DIR" >&2; exit 2; }
[ -z "$OUTFILE" ] && OUTFILE="./pcp_top_apps_$(hostname -s)_$(date +%Y%m%d_%H%M).txt"
[ -n "$CSVDIR" ] && mkdir -p "$CSVDIR"
if [ -z "$JOBS" ]; then
    JOBS=$(nproc 2>/dev/null || echo 1); [ "$JOBS" -gt 4 ] && JOBS=4
fi
[[ $JOBS =~ ^[0-9]+$ ]] && [ "$JOBS" -gt 0 ] || JOBS=1

TMPD=$(mktemp -d) || exit 2
trap 'rm -rf "$TMPD"' EXIT
mkdir -p "$TMPD/sum"

# --- Son N gunun arsivlerini topla (bugun dahil; pmlogger_daily YYYYMMDD.* adlandirmasi) ---
# Sikistirilmis (.xz/.zst/.gz/.lz4 ...) arsivleri PCP dogrudan okur; taban ad
# ".meta" ve varsa sikistirma sonekinden arindirilarak bulunur.
ARCHIVES=()
for i in $(seq 0 $((DAYS - 1))); do
    d=$(date -d "-$i day" +%Y%m%d)
    for f in "$ARCHIVE_DIR"/"$d"*.meta*; do
        [ -e "$f" ] || continue
        ARCHIVES+=("$(sed -E 's/\.meta(\.[a-z0-9]+)?$//' <<<"$f")")
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
HAVE_PROC=0; HAVE_UID=0
for a in "${ARCHIVES[@]}"; do
    if pminfo -a "$a" proc.psinfo.utime >/dev/null 2>&1; then HAVE_PROC=1; break; fi
done
if [ $HAVE_PROC -eq 0 ]; then
    cat >&2 <<'EOF'
UYARI: Arsivlerde proc.* (proses bazli) metrikler yok!
Varsayilan pmlogger yapilandirmasi proses metriklerini KAYDETMEZ.
Etkinlestirmek icin pcp-setup.sh calistirin ya da pmlogger yapilandirmasina
(control.d/local'daki -c ile gosterilen dosya) sunlari ekleyip pmlogger'i
yeniden baslatin:

  log mandatory on every 60 seconds {
      proc.psinfo.utime  proc.psinfo.stime  proc.psinfo.rss  proc.id.uid
      proc.io.read_bytes proc.io.write_bytes
  }

Bu calistirmada yalnizca sistem geneli network raporu uretilebilecek.
EOF
else
    for a in "${ARCHIVES[@]}"; do
        if pminfo -a "$a" proc.id.uid >/dev/null 2>&1; then HAVE_UID=1; break; fi
    done
fi

# proses bazli network var mi (pcp-pmda-bcc)?
HAVE_BCCNET=0
pminfo -a "${ARCHIVES[0]}" bcc.proc.net.tcp.tx >/dev/null 2>&1 && HAVE_BCCNET=1

METRICS="network.interface.in.bytes network.interface.out.bytes"
[ $HAVE_PROC -eq 1 ]   && METRICS="proc.psinfo.utime proc.psinfo.stime proc.psinfo.rss proc.io.read_bytes proc.io.write_bytes $METRICS"
[ $HAVE_UID -eq 1 ]    && METRICS="proc.id.uid $METRICS"
[ $HAVE_BCCNET -eq 1 ] && METRICS="$METRICS bcc.proc.net.tcp.tx bcc.proc.net.tcp.rx"

# --- Her arsivi ozetle (paralel) ve tek gawk ile topla ---
# pmlogsummary -lM cikti formati:
#   commencing/ending satirlari (arsiv suresi icin)
#   metrik ["PID komut"] ortalama maksimum birim
# Sayaclar (utime, io, network) otomatik rate'e cevrilir:
#   utime+stime -> boyutsuz (cekirdek orani), io/net -> byte/sec
# proc.id.uid instant oldugu icin ortalamasi = uid (sabit).
summarize_one() {   # $1 = sira no, $2 = arsiv
    # shellcheck disable=SC2086   # METRICS bilerek kelimelere ayrilir
    { echo "==ARCHIVE== $2"; pmlogsummary -lM "$2" $METRICS 2>/dev/null; } > "$TMPD/sum/$1"
}
export -f summarize_one; export METRICS TMPD
echo "Arsivler ozetleniyor ($JOBS paralel is)..." >&2
i=0
for a in "${ARCHIVES[@]}"; do i=$((i+1)); printf '%d %s\n' "$i" "$a"; done \
    | xargs -P "$JOBS" -L1 bash -c 'summarize_one "$@"' _

# uid -> kullanici adi (arsiv yerel makineye aitse dogru; degilse sayi kalir)
getent passwd 2>/dev/null | awk -F: '{ print $3 "\t" $1 }' > "$TMPD/passwd"

find "$TMPD/sum" -type f -printf '%f\n' | sort -n | sed "s|^|$TMPD/sum/|" | xargs cat \
  | gawk -v topn="$TOPN" -v tmpd="$TMPD" -v kthreads="$INCLUDE_KTHREADS" '
function month(m) { return (index("JanFebMarAprMayJunJulAugSepOctNovDec", m) + 2) / 3 }
function ts(mon, day, hms, year,    t) {
    split(hms, t, /[:.]/)
    return mktime(year " " month(mon) " " day " " t[1] " " t[2] " " t[3])
}
function flush_archive(    c, k, kk, u) {
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
        # kullanici bazli toplamlar: proses (cmd,pid) -> uid
        for (k in a_uid) {
            u = a_uid[k]
            u_cpu[u] += a_pcpu[k] * dur
            u_rss[u] += a_prss[k] * dur
            u_io[u]  += (a_prd[k] + a_pwr[k]) * dur
            if (!((u, k) in useen)) { useen[u, k] = 1; u_nproc[u]++ }
        }
    }
    delete a_cpu; delete a_rss; delete a_rd; delete a_wr
    delete a_ntx; delete a_nrx; delete a_ifin; delete a_ifout; delete a_ipeak
    delete a_uid; delete a_pcpu; delete a_prss; delete a_prd; delete a_pwr
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
    key = cmd SUBSEP pid

    if (!((cmd, pid) in seen)) { seen[cmd, pid] = 1; nproc[cmd]++ }

    if      (metric == "proc.psinfo.utime" || metric == "proc.psinfo.stime") {
        a_cpu[cmd] += avg                   # cekirdek orani (1.0 = 1 core)
        a_pcpu[key] += avg
        a_ipeak[cmd, pid] += mx * 100       # utime+stime tepe toplami (yaklasik)
    }
    else if (metric == "proc.psinfo.rss") {
        a_rss[cmd] += avg                   # Kbyte
        a_prss[key] += avg
        if (mx > rss_peak[cmd]) rss_peak[cmd] = mx
    }
    else if (metric == "proc.io.read_bytes")  { a_rd[cmd] += avg; a_prd[key] += avg }
    else if (metric == "proc.io.write_bytes") { a_wr[cmd] += avg; a_pwr[key] += avg }
    else if (metric == "proc.id.uid")         a_uid[key] = int(avg + 0.5)
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
    # kullanici: uid \t cpu_sn \t ort_rss_kb \t io_byte \t proc#
    for (u in u_cpu)
        printf "%d\t%.3f\t%.1f\t%.0f\t%d\n", u, u_cpu[u], u_rss[u] / total_dur, u_io[u], u_nproc[u] > (tmpd "/user")
}'
rc=$?
[ $rc -ne 0 ] && { echo "HATA: arsiv ozetleme basarisiz (rc=$rc)" >&2; exit $rc; }

read -r TOTAL_DUR NDAYS < "$TMPD/meta"

# kullanici satirlarina ad ekle (bulunamazsa uid sayisi kalir)
if [ -s "$TMPD/user" ]; then
    gawk -F'\t' 'NR==FNR { name[$1] = $2; next } { print $2 "\t" $3 "\t" $4 "\t" $5 "\t" (($1 in name) ? name[$1] : "uid:" $1) }' \
        "$TMPD/passwd" "$TMPD/user" > "$TMPD/user2"
fi

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

    if [ -s "$TMPD/user2" ]; then
        echo ""
        echo "--- KULLANICI BAZINDA TOPLAM (proc.id.uid; CPU zamanina gore) ----------------"
        printf "%4s  %14s  %9s  %14s  %14s  %6s  %s\n" "#" "CPU-SAAT" "ORT %CPU" "ORT RSS" "DISK I/O" "PROC#" "KULLANICI"
        sort -t$'\t' -k1,1 -rn "$TMPD/user2" | head -n "$TOPN" | gawk -F'\t' -v dur="$TOTAL_DUR" '
            function hk(kb){ s="KB MB GB TB"; split(s,u," "); i=1; while (kb>=1024 && i<4){kb/=1024;i++} return sprintf("%.2f %s",kb,u[i]) }
            function hb(b){ s="B KB MB GB TB PB"; split(s,u," "); i=1; while (b>=1024 && i<6){b/=1024;i++} return sprintf("%.2f %s",b,u[i]) }
            { printf "%4d  %14.2f  %9.2f  %14s  %14s  %6d  %s\n", NR, $1/3600, 100*$1/dur, hk($2), hb($3), $4, $5 }'
        echo " NOT: Kullanici adlari bu makinenin passwd veritabanindan cozulur; baska"
        echo "      sunucunun arsivinde ad eslesmeyen kullanicilar uid:N olarak gorunur."
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
    echo " * PROC#      : bu komut adiyla (veya kullaniciyla) gorulen farkli PID sayisi."
    echo " * Degerler pmlogger ornekleme araligina gore yaklasik degerlerdir."
} | tee "$OUTFILE"

# ham veriler CSV olarak istenmisse
if [ -n "$CSVDIR" ]; then
    { echo "cpu_saniye,ort_yuzde_cpu,tepe_yuzde_cpu,proc_sayisi,komut"; sort -t$'\t' -k1,1 -rn "$TMPD/cpu" | tr '\t' ','; } > "$CSVDIR/cpu.csv" 2>/dev/null
    { echo "ort_rss_kb,tepe_rss_kb,proc_sayisi,komut";                  sort -t$'\t' -k1,1 -rn "$TMPD/mem" | tr '\t' ','; } > "$CSVDIR/mem.csv" 2>/dev/null
    { echo "toplam_byte,okuma_byte,yazma_byte,proc_sayisi,komut";       sort -t$'\t' -k1,1 -rn "$TMPD/io"  | tr '\t' ','; } > "$CSVDIR/io.csv"  2>/dev/null
    { echo "toplam_byte,rx_byte,tx_byte,interface";                     sort -t$'\t' -k1,1 -rn "$TMPD/net" | tr '\t' ','; } > "$CSVDIR/net.csv" 2>/dev/null
    if [ -s "$TMPD/user2" ]; then
    { echo "cpu_saniye,ort_rss_kb,io_byte,proc_sayisi,kullanici";       sort -t$'\t' -k1,1 -rn "$TMPD/user2" | tr '\t' ','; } > "$CSVDIR/user.csv" 2>/dev/null
    fi
    echo "CSV dosyalari: $CSVDIR/{cpu,mem,io,net,user}.csv" >&2
fi

echo "" >&2
echo "Rapor dosyasi: $OUTFILE" >&2
