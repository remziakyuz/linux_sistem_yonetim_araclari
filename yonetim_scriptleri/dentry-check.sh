#!/usr/bin/env bash
#
# dentry-check.sh v0.10 - dentry / inode onbellegi teshisi.  SALT OKUNUR.
#
# Hicbir sey yazmaz: drop_caches yok, sysctl degistirmez, surece baglanmaz.
# -t secenegi bpftrace ile SADECE okuma yapan tracepoint'leri dinler.
#
# Kullanim:
#   ./dentry-check.sh           # anlik durum, aninda doner
#   ./dentry-check.sh -w 60     # 60 sn arayla iki ornek: buyuyor mu, sabit mi
#   sudo ./dentry-check.sh -t   # ek olarak 20 sn ENOENT izle (bpftrace gerekir)
#   sudo ./dentry-check.sh -t -T 60   # izleme suresini 60 sn yap
#   ./dentry-check.sh -V              # surum bilgisi
#
# Cikti dogrudan yapistirilabilir; yorum satirlari da rapora dahildir.
#
set -uo pipefail
export LC_ALL=C

VERSION=0.10
PROG=${0##*/}
WAIT=0; TRACE=0; TSEC=20
usage(){ sed -n '2,/^[^#]/p' "$0" | sed -e '$d' -e 's/^#\{1,\} \{0,1\}//'; exit "${1:-0}"; }
while getopts 'w:tT:hV' o; do
    case $o in
        V) echo "$PROG $VERSION"; exit 0 ;;
        w) WAIT=$OPTARG ;;
        t) TRACE=1 ;;
        T) TSEC=$OPTARG ;;
        h) usage 0 ;;
        *) usage 2 ;;
    esac
done

PS=$(getconf PAGESIZE 2>/dev/null || echo 4096)
line(){ printf '%s\n' "------------------------------------------------------------------"; }
gb(){ awk -v k="${1:-0}" 'BEGIN{printf "%.2f", k/1048576}'; }

# dentry-state alanlari (fs/dcache.c, struct dentry_stat_t):
#   nr_dentry nr_unused age_limit want_pages nr_negative dummy
# nr_negative cekirdek 4.20+ ile geldi; RHEL 9 (5.14) icerir.
read_state(){ read -r D_NR D_UNUSED D_AGE D_WANT D_NEG _ < /proc/sys/fs/dentry-state; }

echo
echo "DENTRY / INODE ONBELLEK TESHISI - $(hostname) $(date '+%F %T')  [$PROG v$VERSION]"
line

# ---------------------------------------------------------------- 1. sayilar
if [[ -r /proc/sys/fs/dentry-state ]]; then
    read_state
    D_NEG=${D_NEG:-0}
    D_POS=$(( D_NR - D_NEG ))
    printf "  %-34s %14s\n" "nr_dentry (toplam)"        "$D_NR"
    printf "  %-34s %14s  %5s%%\n" "  nr_negative (inode'suz)" "$D_NEG" \
        "$(awk -v a="$D_NEG" -v b="$D_NR" 'BEGIN{printf "%.1f", (b?a*100/b:0)}')"
    printf "  %-34s %14s  %5s%%\n" "  pozitif (inode tutan)"   "$D_POS" \
        "$(awk -v a="$D_POS" -v b="$D_NR" 'BEGIN{printf "%.1f", (b?a*100/b:0)}')"
    printf "  %-34s %14s\n" "nr_unused (kullanilmayan)"  "$D_UNUSED"
    # Negatif dentry basina ~192 bayt (struct dentry) + isim.
    printf "  %-34s %14s GB\n" "negatif dentry'nin kapladigi (yak.)" \
        "$(awk -v n="$D_NEG" 'BEGIN{printf "%.2f", n*192/1073741824}')"
else
    echo "  /proc/sys/fs/dentry-state okunamiyor"
fi
echo

# ------------------------------------------------------------- 2. slab detayi
# ONEMLI: /proc/slabinfo'da $2=active_objs (canli), $3=num_objs (ayrilmis slot).
# Ikisi ayri seydir; bellek $15(num_slabs) * $6(pagesperslab) uzerinden hesaplanir.
echo "SLAB (aktif nesne / ayrilmis slot / bellek)"
line
if [[ -r /proc/slabinfo ]]; then
    printf "  %-20s %14s %14s %10s\n" "SLAB" "AKTIF" "SLOT" "BOYUT(GB)"
    awk -v ps="$PS" 'NR>2 && NF>=16 && $1 ~ /^(dentry|xfs_inode|ext4_inode_cache|inode_cache|proc_inode_cache|shmem_inode_cache|radix_tree_node|filp)$/ {
            printf "  %-20s %14d %14d %10.2f\n", $1, $2, $3, $15*$6*ps/1073741824
        }' /proc/slabinfo
    line
    # Pozitif dentry bir inode'u referansla tutar; dolayisiyla
    #   inode toplami ~ pozitif dentry sayisi olmali.
    INODES=$(awk 'NR>2 && NF>=16 && $1 ~ /inode/ {s+=$2} END{print s+0}' /proc/slabinfo)
    printf "  %-34s %14s\n" "tum *inode* slab'lari (aktif)" "$INODES"
    if [[ -n ${D_POS:-} ]] && (( INODES > 0 )); then
        printf "  %-34s %14s\n" "pozitif dentry / inode orani" \
            "$(awk -v a="$D_POS" -v b="$INODES" 'BEGIN{printf "%.2f", a/b}')"
    fi
else
    echo "  /proc/slabinfo icin root gerekiyor"
fi
echo

# --------------------------------------------------------------- 3. ayarlar
echo "ILGILI AYARLAR"
line
for f in vm/vfs_cache_pressure vm/min_free_kbytes vm/watermark_scale_factor \
         vm/swappiness fs/file-max fs/inode-nr; do
    [[ -r /proc/sys/$f ]] && printf "  %-34s %s\n" "${f#*/}" "$(tr '\t' ' ' < "/proc/sys/$f")"
done
printf "  %-34s %s\n" "mount sayisi" "$(wc -l < /proc/mounts)"
echo "  not: fs/inode-nr = 'ayrilmis inode' 'kullanilmayan inode'"
echo

# --------------------------------------------------- 4. reclaim gercekten aci veriyor mu
# Asil soru "9.85 GB cok mu" degil, "shrinker calisirken duruyor muyuz".
# PSI bunu dogrudan olcer: some/full avg10 sifirdan belirgin buyukse evet.
echo "BELLEK BASKISI (PSI) VE RECLAIM SAYACLARI"
line
if [[ -r /proc/pressure/memory ]]; then
    sed 's/^/  /' /proc/pressure/memory
    echo "  yorum: avg10 'some' > 1.00 ise reclaim gorunur gecikme uretiyor demektir"
else
    echo "  /proc/pressure/memory yok (CONFIG_PSI kapali)"
fi
awk '/^(allocstall|pgscan_kswapd|pgscan_direct|pgsteal_kswapd|pgsteal_direct|slabs_scanned|compact_stall|kswapd_low_wmark_hit_quickly)/ {printf "  %-34s %s\n", $1, $2}' /proc/vmstat
echo

# --------------------------------------------------------- 5. buyume hizi (-w)
if (( WAIT > 0 )); then
    echo "BUYUME HIZI ($WAIT saniye)"
    line
    if [[ -r /proc/sys/fs/dentry-state ]]; then
        s1_nr=$D_NR; s1_neg=$D_NEG
        sleep "$WAIT"
        read_state
        printf "  %-34s %14s -> %-14s (%+d)\n" "nr_dentry"   "$s1_nr"  "$D_NR"  $(( D_NR  - s1_nr ))
        printf "  %-34s %14s -> %-14s (%+d)\n" "nr_negative" "$s1_neg" "$D_NEG" $(( D_NEG - s1_neg ))
        rate=$(awk -v d="$(( D_NEG - s1_neg ))" -v w="$WAIT" 'BEGIN{printf "%.0f", d/w}')
        printf "  %-34s %14s adet/sn" "negatif dentry uretim hizi" "$rate"
        awk -v r="$rate" 'BEGIN{printf "  (~%.2f GB/gun)\n", r*86400*192/1073741824}'
        echo "  yorum: hiz ~0 ise birikim gecmiste olmus, su an buyumuyor demektir."
    fi
    echo
fi

# ------------------------------------------------------ 6. kim uretiyor (-t)
if (( TRACE == 1 )); then
    echo "ENOENT URETEN SURECLER VE YOLLAR ($TSEC saniye ornek)"
    line
    if ! command -v bpftrace >/dev/null 2>&1; then
        echo "  bpftrace yok. Kurulum: dnf install bpftrace"
        echo "  Alternatif (tek surec icin, kisa tutun):"
        echo "    timeout 10 strace -f -c -e trace=openat,newfstatat,statx -p <PID>"
    elif [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        echo "  root gerekiyor"
    else
        # Hangi tracepoint'ler var? Olmayani probe'a koyarsak bpftrace hata verir.
        TR=/sys/kernel/tracing/events/syscalls
        [[ -d $TR ]] || TR=/sys/kernel/debug/tracing/events/syscalls
        probes=""; enters=""
        for sc in openat newfstatat statx newstat newlstat; do
            [[ -d "$TR/sys_exit_$sc" ]] || continue
            probes+="${probes:+,}tracepoint:syscalls:sys_exit_$sc"
            enters+="${enters:+,}tracepoint:syscalls:sys_enter_$sc"
        done
        if [[ -z $probes ]]; then
            echo "  syscall tracepoint'leri gorunmuyor"
        else
            echo "  izlenen: ${probes//tracepoint:syscalls:/}"
            echo
            # enter'da yolu kopyala (str = kopya, pointer degil), exit'te ENOENT ise say.
            bpftrace -e "
                $enters { @p[tid] = str(args->filename, 96); }
                $probes /args->ret == -2/ { @yol[comm, @p[tid]] = count(); @surec[comm] = count(); }
                $probes { delete(@p[tid]); }
                END { clear(@p); print(@surec); print(@yol, 25); clear(@surec); clear(@yol); }
            " 2>/dev/null &
            bp=$!
            sleep "$TSEC"
            kill -INT "$bp" 2>/dev/null
            wait "$bp" 2>/dev/null
            echo
            echo "  @surec = ENOENT sayisi (surec basina), @yol = en cok kacirilan 25 yol"
        fi
    fi
    echo
fi

echo "OKUMA REHBERI"
line
cat <<'NOTE'
  * nr_negative / nr_dentry orani %90+ ise: bir sey surekli var olmayan yollara
    bakiyor. Bellek geri alinabilir, ama shrinker'in dolasacagi liste uzuyor.
  * Buyume hizi ~0 ise acil bir sey yok; gecmiste birikmis, oylece duruyor.
  * PSI 'some avg10' 0.00 civarindaysa bu onbellek su an kimseye zarar vermiyor.
  * Mudahale gerekiyorsa once KAYNAGI kesin. vm.vfs_cache_pressure yukseltmek
    (100 -> 150) semptomu bastirir; xfs_inode onbellegini de daha hizli atar,
    bu makinede xfs_inode kucuk oldugu icin riski dusuktur.
  * 'echo 2 > /proc/sys/vm/drop_caches' PRODUKSIYONDA KULLANMAYIN: dentry ile
    birlikte inode onbellegini de atar, XFS metadata okumalari yeniden diske
    iner ve Couchbase gecikmesi firlar.
NOTE
echo
