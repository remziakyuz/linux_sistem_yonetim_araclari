#!/usr/bin/env bash
#
# pcp-top-mem.sh - PCP (Performance Co-Pilot) ile en cok bellek kullanan
#                  surecleri listeler. Canli sistem, uzak host veya
#                  pmlogger arsivi uzerinden calisir.
#
# Kullanim ornekleri:
#   ./pcp-top-mem.sh                        # yerel sistem, top 10, tek atis
#   ./pcp-top-mem.sh -n 20                  # top 20
#   ./pcp-top-mem.sh -i 2                   # 2 sn'de bir surekli izle
#   ./pcp-top-mem.sh -i 2 -c 30             # 2 sn'de bir, 30 ornek al ve cik
#   ./pcp-top-mem.sh -H sunucu.example.com  # uzak pmcd
#   ./pcp-top-mem.sh -A /var/log/pcp/pmlogger/$(hostname)/20260907.12.53 \
#                    -S '@03:00' -T '@03:05'
#   ./pcp-top-mem.sh -s vmswap              # swap'e gore sirala
#   ./pcp-top-mem.sh -x                     # ek kolonlar (vmsize, vmlib, vmswap)
#   ./pcp-top-mem.sh -C -n 20 > top20.csv   # CSV cikti
#
# ARSIV (-A): onerilen kayit (pcp-zeroconf config.default, playbook-pcp / pcp-setup.sh
# 4.0) surec bellegini 60 sn'de bir kaydeder: proc.psinfo.rss, proc.memory.vmsize,
# vmswap, vmdata, vmlib ... (proc.memory.vmrss ve vmpeak KAYDEDILMEZ). Betik arsivde
# olmayan metrigi atlar; vmrss yoksa ayni degeri veren proc.psinfo.rss'i kullanir.
# Kayit yapilandirmasina elle satir EKLEMEYIN: tek sahip ilkesi (el kitabi 17.2) -
# arsivde surec bellegi yoksa pcp-zeroconf kurulu degildir.
# Arsivde kullanici adi ve surec ayrintisi yalniz proc PMDA -A varsa tum surecler
# icindir (el kitabi 17.4).
#
# YUK NOTU (sisteme yuk bindirmeme kurali):
#   Canli: proc PMDA her ornekte tum sureclerin /proc/<pid>/status ve statm
#   dosyalarini okur - bellek boyutundan bagimsiz, mmap_lock ALMAZ, smaps
#   OKUNMAZ (playbook-pcp README 4a olcumu). -i ile 1 sn'nin altina inmeyin;
#   cok sayida surecte (>2 000) pmdaproc CPU'su artar, etkisi olculmedi.
#   PSS/USS gereken durumda proc.smaps.* KULLANMAYIN: her surecin tum sayfa
#   tablosunu yurur (01.10.2026 donma olayinin nedeni).
#   Arsiv: yalniz dosya okunur, izlenen sunucuya yuk yok.
#   Arsivde N/A: istenen an ilk surec kaydindan (60 sn'de bir) once ya da pmlogger
#   yeniden basladiktan hemen sonra; -S'yi birkac dakika kaydirin.
#
set -euo pipefail

PROG=${0##*/}

# --- varsayilanlar -----------------------------------------------------------
COUNT=10          # -n : kac surec
INTERVAL=""       # -i : ornekleme araligi (sn); bos ise tek atis
SAMPLES=""        # -c : kac ornek (sadece -i ile anlamli)
HOST=""           # -H : uzak pmcd host
ARCHIVE=""        # -A : pmlogger arsivi
START=""          # -S : arsivde baslangic zamani
FINISH=""         # -T : arsivde bitis zamani
SORT_KEY="vmrss"  # -s : vmrss | vmsize | vmswap | vmdata
UNIT="MB"         # -u : KB | MB | GB
EXTENDED=0        # -x : ek kolonlar
CSV=0             # -C : CSV cikti
WIDTH=14          # -w : kolon genisligi
INSTWIDTH=38      # -W : instance (PID + komut) kolonunun genisligi

usage() {
    # dosya basindaki aciklama blogu (shebang'den sonraki '#' satirlari)
    sed -n '2,/^[^#]/p' "$0" | sed -e '$d' -e 's/^#\{1,\} \{0,1\}//'
    cat <<USAGE

Secenekler:
  -n SAYI     Listelenecek surec sayisi (varsayilan: $COUNT)
  -i SANIYE   Surekli izleme, verilen aralikla
  -c SAYI     Alinacak ornek sayisi (-i ile birlikte)
  -H HOST     Uzak pmcd sunucusu
  -A ARSIV    pmlogger arsivi (uzantisiz yol)
  -S ZAMAN    Arsivde baslangic (orn: '@03:00' veya '-1h')
  -T ZAMAN    Arsivde bitis
  -s ANAHTAR  Siralama metrigi: vmrss (vars.), vmsize, vmswap, vmdata
  -u BIRIM    Olcek: KB, MB (vars.), GB
  -x          Genisletilmis kolonlar (vmsize, vmlib, vmswap, vmpeak)
  -C          CSV formatinda cikti
  -w SAYI     Metrik kolonlarinin genisligi (varsayilan: $WIDTH)
  -W SAYI     PID/komut kolonunun genisligi (varsayilan: $INSTWIDTH)
  -h          Bu yardim
USAGE
}

while getopts 'n:i:c:H:A:S:T:s:u:w:W:xCh' opt; do
    case "$opt" in
        n) COUNT=$OPTARG ;;
        i) INTERVAL=$OPTARG ;;
        c) SAMPLES=$OPTARG ;;
        H) HOST=$OPTARG ;;
        A) ARCHIVE=$OPTARG ;;
        S) START=$OPTARG ;;
        T) FINISH=$OPTARG ;;
        s) SORT_KEY=$OPTARG ;;
        u) UNIT=$OPTARG ;;
        w) WIDTH=$OPTARG ;;
        W) INSTWIDTH=$OPTARG ;;
        x) EXTENDED=1 ;;
        C) CSV=1 ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

command -v pmrep >/dev/null 2>&1 || {
    echo "$PROG: pmrep bulunamadi. 'dnf install pcp-system-tools' gerekiyor." >&2
    exit 1
}

case "$SORT_KEY" in
    vmrss|vmsize|vmswap|vmdata) ;;
    *) echo "$PROG: gecersiz siralama anahtari: $SORT_KEY" >&2; exit 2 ;;
esac
SORT_METRIC="proc.memory.$SORT_KEY"

# --- metrik listesi ----------------------------------------------------------
METRICS=(proc.id.uid_nm proc.memory.vmrss)
[[ $CSV -eq 1 ]] && METRICS=(proc.psinfo.pid proc.psinfo.cmd "${METRICS[@]}")
if [[ $EXTENDED -eq 1 ]]; then
    METRICS+=(proc.memory.vmsize proc.memory.vmlib proc.memory.vmpeak proc.memory.vmswap)
else
    METRICS+=(proc.memory.vmswap)
fi
# siralama metrigi listede yoksa ekle (orn. -s vmdata)
[[ " ${METRICS[*]} " == *" $SORT_METRIC "* ]] || METRICS+=("$SORT_METRIC")

# arsivde kaydedilmemis metrikler atlanir (pmrep aksi halde tumden durur)
if [[ -n $ARCHIVE ]]; then
    # proc.psinfo.rss her kayit profilinde vardir (vmrss yalniz bazilarinda; karisik arsiv dizininde
    # eski arsivde var, son pencerede yok olabilir) - ayni degeri verir
    if pminfo -a "$ARCHIVE" proc.psinfo.rss >/dev/null 2>&1; then
        METRICS=("${METRICS[@]/#proc.memory.vmrss/proc.psinfo.rss}")
        [[ $SORT_METRIC == proc.memory.vmrss ]] && SORT_METRIC=proc.psinfo.rss
    fi
    VAR=()
    for m in "${METRICS[@]}"; do
        if pminfo -a "$ARCHIVE" "$m" >/dev/null 2>&1; then VAR+=("$m")
        else echo "$PROG: NOT: $m arsivde yok, atlandi" >&2; fi
    done
    METRICS=("${VAR[@]}")
    pminfo -a "$ARCHIVE" "$SORT_METRIC" >/dev/null 2>&1 \
        || { echo "$PROG: siralama metrigi $SORT_METRIC arsivde yok" >&2; exit 1; }
fi

# --- pmrep argumanlari -------------------------------------------------------
ARGS=(
    -b "$UNIT"          # boyut olcegi
    -J "$COUNT"         # en yuksek degerli N instance
    -N "$SORT_METRIC"   # ranking referans metrigi
    -6 "$SORT_METRIC"   # colxrow siralama referansi
    -1                  # instance degisince basligi guncelle
    -P 1                # ondalik hane
)

if [[ $CSV -eq 1 ]]; then
    ARGS+=(-o csv)
else
    # colxrow modunda ilk kolonun genisligi = -X etiketinin uzunlugu,
    # o yuzden etiketi bosluklarla dolduruyoruz.
    inst_label=$(printf '%-*s' "$INSTWIDTH" 'PID (KOMUT)')
    ARGS+=(-X "$inst_label" -w "$WIDTH" -E 20)   # satir/sutun cevir, basligi tekrarla
fi

# Arsivde zaman verilmezse arsivin BASI kullanilirdi: surec grubu 60 sn'de bir kaydedildigi icin
# ilk surec kaydindan once ara deger uretilemez ve tum degerler N/A cikar (26.10.2026 Rocky 10'da
# goruldu). Varsayilan: arsiv sonundan 61 sn once (son iki surec kaydi arasinda kalir).
if [[ -n $ARCHIVE && -z $START ]]; then
    START=-61sec
    echo "$PROG: NOT: -S verilmedi - arsiv sonundan 61 sn onceki an raporlaniyor (baska an icin -S '@SS:DD')" >&2
fi

[[ -n $HOST    ]] && ARGS+=(-h "$HOST")
[[ -n $ARCHIVE ]] && ARGS+=(-a "$ARCHIVE")
[[ -n $START   ]] && ARGS+=(-S "$START")
[[ -n $FINISH  ]] && ARGS+=(-T "$FINISH")

if [[ -n $INTERVAL ]]; then
    ARGS+=(-t "$INTERVAL")
    [[ -n $SAMPLES ]] && ARGS+=(-s "$SAMPLES")
else
    ARGS+=(-s 1)        # tek atis
fi

exec pmrep "${ARGS[@]}" "${METRICS[@]}"
