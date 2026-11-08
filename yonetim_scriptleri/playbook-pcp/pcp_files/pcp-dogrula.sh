#!/bin/bash
#
# pcp-dogrula.sh - PCP kurulumunun ve izleme yeteneklerinin dogrulanmasi
#
# Surum 2.5 (2026-11-03): eksik surec G/C gorunurlugu proc_tum_surec_karari'na gore (dokunma = BILGI/ATLA, gerekirse = HATA;
#   playbook dogrulamasiyla ayni; capraz test 02.11 Rocky 10.2 tutarsizligi). Kullanilan karar ve kaynagi bolum 6'da ve
#   SONUC altinda (-q dahil) yazilir.
# Surum 2.4 (2026-11-02): kapali PMDA listesine opentelemetry (RHEL 10 pcp-zeroconf kurar; kalite denetimi R4)
# Surum 2.3 (2026-11-01): PMLOGGER_DAILY_PARAMS satir sonu yorumu / deger disi ek denetimi, -E yoksa ATLA, kayit grubu yolu memory/<grup>
# Surum 2.2 (2026-10-31): pmlogger yeniden baslama olcutu hatali cikisa bakar (-T sure sonu hata degil)
# Surum 2.1 (2026-10-23) - playbook-pcp (pcp-onlem) ile kurulur; tek kaynak
# playbook-pcp/pcp_files/pcp-dogrula.sh. Kaynak: pcp-setup projesinin
# pcp-dogrula.sh betigi; pcp-onlem duzenine uyarlandi (kayit profili
# config.default / config.pcp-tam, disk korumasi log-saklama bekcisi).
# Salt-okunur: sistemde hicbir degisiklik yapmaz.
#
# Kullanim:
#   ./pcp-dogrula.sh              # tam test (13 bolum)
#   ./pcp-dogrula.sh -q           # yalnizca hatalar + ozet
#   ./pcp-dogrula.sh -y           # CPU yuku uretip hotproc/top-N'i de test et (YUK NOTU)
#   ./pcp-dogrula.sh -h HOST      # uzak sunucuyu test et (pmcd erisimi gerekir)
#   ./pcp-dogrula.sh -H           # yardim
#
# YUK NOTU (sisteme yuk bindirmeme kurali):
#   Varsayilan kosum ~40 kisa PCP istemci komutu calistirir (pmstat, pcp atop,
#   pcp pidstat, pmrep ...; her biri 1-3 ornek, toplam 1-3 dk). proc PMDA bu
#   sirada tum sureclerin /proc/<pid>/stat ve status dosyalarini birkac kez
#   okur (smaps OKUNMAZ). Etkisi OLCULMEDI; yogun saatte kosulmaz.
#   -y secenegi 2 cekirdekte ~40 sn CPU YUKU URETIR: canli ortam sunucusunda
#   KOSULMAZ, yalniz test sunucusunda.
#
# Esikler (pcp-onlem degiskenleriyle ayni varsayilanlar; ortam degiskeniyle degistirilebilir):
#   PCP_DOGRULA_ORAN=80   surec G/C gorunurlugu alt siniri, yuzde (pcp_gorunurluk_orani)
#   PCP_DOGRULA_ENAZ=8    saklama -k alt siniri, gun (pcp_saklama_en_az_gun)
#   PCP_DOGRULA_PROC_KARAR=dokunma  proc -A karari (proc_tum_surec_karari): dokunma = eksik surec G/C BILGI (ATLA),
#                         gerekirse = HATA (playbook/pcp-setup.sh -A'yi bu kararla ekler)
#   PCP_DOGRULA_PMDALAR="dm dmcache kvm nfsclient openmetrics opentelemetry prometheus"  kapali olmasi beklenen PMDA'lar
#   PCP_DOGRULA_GRUPLAR="memory/zoneinfo memory/buddyinfo"  kayitta olmamasi beklenen pmlogconf gruplari
#
# Cikis kodu: 0 = tum testler gecti, 1 = en az bir test kaldi, 2 = pcp yok ya da gecersiz PCP_DOGRULA_PROC_KARAR
#
set -o pipefail
QUIET=0; YUK=0; HOST=""; T=20
ORAN=${PCP_DOGRULA_ORAN:-80}; ENAZ=${PCP_DOGRULA_ENAZ:-8}
PROC_KARAR=${PCP_DOGRULA_PROC_KARAR:-dokunma}
if [ -n "${PCP_DOGRULA_PROC_KARAR:-}" ]; then PROC_KAYNAK="PCP_DOGRULA_PROC_KARAR ile verildi"
else PROC_KAYNAK="varsayilan; proc_tum_surec_karari=gerekirse sunucuda PCP_DOGRULA_PROC_KARAR=gerekirse verin"; fi
case "$PROC_KARAR" in dokunma|gerekirse) ;; *) echo "PCP_DOGRULA_PROC_KARAR dokunma|gerekirse olmali: $PROC_KARAR" >&2; exit 2 ;; esac
KAPALI_PMDALAR=${PCP_DOGRULA_PMDALAR:-dm dmcache kvm nfsclient openmetrics opentelemetry prometheus}
KAPALI_GRUPLAR=${PCP_DOGRULA_GRUPLAR:-memory/zoneinfo memory/buddyinfo}
while getopts "qyh:H" o; do
  case $o in
    q) QUIET=1 ;;
    y) YUK=1 ;;
    h) HOST=$OPTARG ;;
    H|*) grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done
HOPT=(); [ -n "$HOST" ] && HOPT=(-h "$HOST")

GECTI=0; KALDI=0; ATLANDI=0
say()  { [ "$QUIET" -eq 1 ] || echo "$@"; }
bas()  { say; say "== $* =="; }
gecti(){ GECTI=$((GECTI+1)); say "  [OK]   $*"; }
kaldi(){ KALDI=$((KALDI+1)); echo "  [HATA] $*"; }
atla() { ATLANDI=$((ATLANDI+1)); say "  [ATLA] $*"; }

# komut calisir mi? (hata desenleri PCP araclarinin ortak ciktilaridir)
HATA_DESENI='invalid option|unrecognized|command not found|Cannot find|Usage:|Unknown metric|Invalid metric|not found|No value|Error|error -|Permission denied'
dene() {
  local ad="$1"; shift
  local o
  o=$(timeout $T bash -c "$*" 2>&1 | head -6)
  if grep -qiE "$HATA_DESENI" <<<"$o"; then
      kaldi "$ad :: $(grep -iEm1 "$HATA_DESENI" <<<"$o" | cut -c1-64)"
  else
      gecti "$ad"
  fi
}
metrik() {   # metrik gercekten DEGER uretiyor mu (yalnizca ad kontrolu degil)
  local m="$1"
  local o
  o=$(timeout $T pmrep "${HOPT[@]}" -t 1s -s 3 "$m" 2>&1 | tail -1)
  if grep -qiE 'Unknown|Invalid|Error' <<<"$o"; then kaldi "metrik $m :: yok"
  elif grep -qE '[0-9]' <<<"$o";              then gecti "metrik $m"
  else atla "metrik $m (deger uretmedi)"; fi
}

echo "================================================================"
echo " PCP DOGRULAMA  -  $(date '+%F %T')  -  ${HOST:-$(hostname)}"
echo "================================================================"

bas "1. ORTAM"
command -v pcp >/dev/null || { echo "HATA: pcp kurulu degil"; exit 2; }
pcp -V
say "  kernel : $(uname -r)"
# shellcheck source=/dev/null
say "  dagitim: $( . /etc/os-release; echo "$PRETTY_NAME")"
say "  metrik : $(pminfo "${HOPT[@]}" 2>/dev/null | wc -l)"
# shellcheck source=/dev/null
. /etc/pcp.conf 2>/dev/null
: "${PCP_ARCHIVE_DIR:=/var/log/pcp/pmlogger}"
: "${PCP_PMDAS_DIR:=/var/lib/pcp/pmdas}"
: "${PCP_SYSCONF_DIR:=/etc/pcp}"
: "${PCP_SYSCONFIG_DIR:=/etc/sysconfig}"

bas "2. SERVISLER"
for s in pmcd pmlogger pmie; do
  d=$(systemctl is-active $s 2>/dev/null)
  case "$s:$d" in
    pmcd:active|pmlogger:active) gecti "$s = $d" ;;
    pmie:active)                 gecti "pmie = active (alarmlar uretiliyor)" ;;
    pmie:*)                      atla  "pmie = $d (alarm uretilmez)" ;;
    *)                           kaldi "$s = $d" ;;
  esac
done
if [ -z "$HOST" ]; then
  NR_RESTART=$(systemctl show pmlogger -p NRestarts --value 2>/dev/null)
  if [ -n "$NR_RESTART" ]; then
    # -T24h10m sure sonu temiz cikis + Restart=always = beklenen yeniden baslatma; yalniz hatali cikis KALDI
    HATA=$(journalctl -u pmlogger.service --since -24h --no-pager -o cat 2>/dev/null \
        | grep -cE 'Failed with result|code=(killed|dumped)|status=[1-9]' || true)
    if [ "${HATA:-0}" -gt 0 ] || [ "$(systemctl show pmlogger -p Result --value 2>/dev/null)" != success ]; then
      kaldi "pmlogger son 24 saatte hatayla cikti ($HATA kayit, NRestarts=$NR_RESTART) - pmlogger.log'a bakin"
    elif [ "$NR_RESTART" -eq 0 ]; then gecti "pmlogger son acilistan beri yeniden baslamamis (NRestarts=0)"
    else gecti "pmlogger $NR_RESTART kez yeniden basladi, hata kaydi yok (-T24h10m sure sonu olabilir)"; fi
  fi
  for t in pmlogger_daily.timer pmlogger_check.timer; do
    if [ "$(systemctl is-active "$t" 2>/dev/null)" = active ]; then gecti "$t aktif"
    else kaldi "$t aktif degil (rotasyon/otomatik toparlama calismaz)"; fi
  done
fi

bas "3. TEMEL CANLI IZLEME"
H="${HOPT[*]}"
dene "pmstat"                "pmstat $H -t 1 -s 3"
dene "pcp dstat (4 alt sistem)" "pcp $H dstat -cmdn 1 3"
dene "pcp dstat + suclu proses"  "pcp $H dstat -cmdngyl --top-cpu-adv --top-io-adv 1 2"
dene "pcp atop -d"           "pcp $H atop -d 1 2"
dene "pcp iostat -x noidle"  "pcp $H iostat -t 1 -s 2 -x noidle"
dene "pcp free"              "pcp $H free -s 1 -c 2"
dene "pcp vmstat"            "pcp $H vmstat 1 2"
dene "pcp netstat -i"        "pcp $H netstat -i"
dene "pcp pidstat"           "pcp $H pidstat -t 1 -s 2"
dene "pcp pidstat -r"        "pcp $H pidstat -r -t 1 -s 2"
dene "pcp uptime"            "pcp $H uptime"

bas "4. ALT SISTEM METRIKLERI"
for m in kernel.all.load kernel.all.runnable kernel.all.blocked \
         mem.util.available mem.vmstat.pgmajfault swap.pagesout \
         disk.all.total disk.all.read_bytes filesys.full \
         network.all.in.bytes network.all.out.bytes network.tcp.retranssegs \
         proc.nprocs proc.psinfo.utime hinv.ncpu; do
  metrik "$m"
done

bas "5. TURETILMIS METRIKLER (/etc/pcp/derived)"
say "  dosyalar: $(find /etc/pcp/derived -maxdepth 1 -type f -printf '%f ' 2>/dev/null)"
for m in kernel.cpu.util.user kernel.cpu.util.sys kernel.cpu.util.idle kernel.cpu.util.wait \
         disk.dev.util disk.dev.await disk.dev.avg_qlen \
         proc.hog.cpu proc.hog.mem proc.io.total_bytes proc.psinfo.age; do
  metrik "$m"
done

bas "6. PROSES GORUNURLUGU (-A bayragi)"
say "  -A karari: $PROC_KARAR ($PROC_KAYNAK)"
# /proc/<pid>/stat herkese acik (surec SAYISI hep tam); /proc/<pid>/io yalniz sahibine acik:
# -A yoksa pcp kullanicisi (pmlogger) diger kullanicilarin surec G/C degerlerini goremez.
NR=$(pminfo "${HOPT[@]}" -f proc.psinfo.pid 2>/dev/null | grep -c 'inst \[')
if [ -z "$HOST" ] && [ "$(id -u)" -eq 0 ] && command -v runuser >/dev/null 2>&1; then
  RI=$(pminfo -f proc.io.read_bytes 2>/dev/null | grep -c 'inst \[')
  PI=$(runuser -u pcp -- pminfo -f proc.io.read_bytes 2>/dev/null | grep -c 'inst \[')
  if [ "$PI" -gt 0 ] && [ $(( PI * 100 )) -ge $(( RI * ORAN )) ]; then
    gecti "pcp kullanicisi surec G/C degerinin $PI / $RI kadarini goruyor (arsive tum surecler yazilir)"
  elif [ "$PROC_KARAR" = gerekirse ]; then
    kaldi "pcp kullanicisi surec G/C degerinin yalnizca $PI / $RI kadarini goruyor - arsivde surec G/C eksik (proc_tum_surec_karari=gerekirse, -A bekleniyordu)"
  else
    atla "BILGI: pcp kullanicisi surec G/C degerinin yalnizca $PI / $RI kadarini goruyor - arsivde surec G/C eksik; onerilen varsayilan -A eklememek (proc_tum_surec_karari=dokunma, -A yerel kullaniciya tum surec environ'unu acar)"
  fi
  if grep -E '^proc[[:space:]].*pmdaproc' "$PCP_SYSCONF_DIR/pmcd/pmcd.conf" 2>/dev/null | grep -qE '[[:space:]]-A([[:space:]]|$)'; then
    if grep -qE '^[[:space:]]*PMCD_LOCAL=1' "$PCP_SYSCONFIG_DIR/pmcd" 2>/dev/null; then gecti "proc -A var, pmcd yalniz yerel (PMCD_LOCAL=1)"
    else kaldi "proc -A var ama pmcd yalniz yerel degil - uzak istemci tum surec ayrintilarini okuyabilir"; fi
    if systemctl is-active --quiet pmproxy 2>/dev/null; then kaldi "proc -A var ve pmproxy calisiyor - uzak istemci tum surec ayrintilarini okuyabilir"
    else gecti "proc -A var, pmproxy calismiyor"; fi
  fi
else
  atla "pcp kullanicisi kontrolu (root degil, uzak host veya runuser yok); gorunen proses: $NR"
fi

bas "7. HOTPROC (olceklenebilir proses izleme)"
HC=$(pminfo "${HOPT[@]}" -f hotproc.control.config 2>/dev/null | awk -F'"' '/value/{print $2}')
if [ -n "$HC" ]; then
  gecti "filtre yuklu: $HC"
  NH=$(pminfo "${HOPT[@]}" -f hotproc.nprocs 2>/dev/null | awk '/value/{print $2}')
  if [ "${NH:-0}" -gt 0 ] 2>/dev/null; then gecti "su an $NH sicak proses"
  else atla "nprocs=0 (bos sistemde normal; yuk altinda ~20 sn'de dolar)"; fi
else
  atla "hotproc filtresi yuklu degil ($PCP_PMDAS_DIR/proc/hotproc.conf yok; pcp-onlem hotproc_karari varsayilan dokunma)"
fi

bas "8. RAPOR SABLONLARI"
for t in vmstat sar-u-ALL sar-n-DEV pidstat-d pmstat; do
  dene "hazir sablon :$t" "pmrep $H -t 1s -s 2 -z :$t"
done
for t in canli obur agirlik; do
  if grep -q "^\[$t\]" "$PCP_SYSCONF_DIR"/pmrep/*.conf 2>/dev/null; then
     dene "ozel sablon :$t" "pmrep $H -t 1s -s 2 -z :$t"
  else atla "ozel sablon :$t kurulu degil (pcp-onlem pmrep_sablon_karari)"; fi
done
# pmrep ilk buldugu yapilandirmayi kullanir; ev dizinindeki dosya /etc/pcp/pmrep/
# altindaki hazir sablonlarin tamamini gizler (arama sirasi: ./pmrep.conf,
# ~/.pmrep.conf, ~/.pcp/pmrep.conf, /etc/pcp/pmrep/pmrep.conf, /etc/pcp/pmrep/)
GIZLEYEN=""
for f in ./pmrep.conf "$HOME/.pmrep.conf" "$HOME/.pcp/pmrep.conf"; do [ -f "$f" ] && GIZLEYEN="$GIZLEYEN $f"; done
if [ -n "$GIZLEYEN" ]; then kaldi "hazir sablonlari gizleyen dosya var:$GIZLEYEN (silin ya da /etc/pcp/pmrep/ altina tasiyin)"
else gecti "ev dizininde pmrep.conf yok (hazir sablonlar gorunur)"; fi

bas "9. ARSIV (geriye donuk analiz)"
HD="$PCP_ARCHIVE_DIR/$(hostname)"
# pmlogger dizin adinda pmhostname kullanir (FQDN/kisa ad farki olabilir): en son yazilan Latest
[ -f "$HD/Latest" ] || HD=$(dirname "$(ls -t "$PCP_ARCHIVE_DIR"/*/Latest 2>/dev/null | head -1)" 2>/dev/null)
ARC=$(awk '/^Archive:/{print $3}' "$HD/Latest" 2>/dev/null)
[ -z "$ARC" ] && ARC=$(find "$HD" -maxdepth 1 -name '*.meta*' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- | sed -E 's/\.meta(\..*)?$//')
if [ -n "$ARC" ] && [ -z "$HOST" ]; then
  say "  arsiv: $ARC   ($(du -sh "$HD" 2>/dev/null | cut -f1))"
  dene "pmdumplog -L"           "pmdumplog -L $ARC"
  dene "arsivden pmrep"         "pmrep -a $ARC -z -t 5m -S -20min :vmstat"
  dene "arsivden pcp dstat"     "pcp -a $ARC -S -20min dstat -cmdn 300 2"
  dene "arsivden pcp atop"      "pcp -a $ARC -S -20min atop 300 2"
  dene "arsivden pmstat"        "pmstat -a $ARC -z -S -20min -t 5m"
  dene "pmlogsummary"           "pmlogsummary -HmM -S -20min $ARC kernel.all.load"
  NI=$(pminfo -f -a "$ARC" proc.psinfo.pid 2>/dev/null | grep -c inst)
  if [ "$NI" -gt 10 ]; then gecti "arsivde $NI prosesin verisi var"
  else kaldi "arsivde yalnizca $NI proses var (proc metrikleri kaydedilmiyor mu?)"; fi
  if pminfo -a "$ARC" hinv.ncpu >/dev/null 2>&1; then gecti "arsivde hinv.ncpu var (yuzde hesaplari calisir)"
  else kaldi "arsivde hinv.ncpu YOK - :vmstat gibi sablonlar N/A doner"; fi
  if pminfo -a "$ARC" proc.id.uid >/dev/null 2>&1; then gecti "arsivde proc.id.uid var (kullanici bazli rapor calisir)"
  else atla "arsivde proc.id.uid yok (pcp-top-apps.sh kullanici bolumu uretemez)"; fi
  # guvenlik: proses environment'i (parola/secret) arsive yazilmamali
  if pminfo -a "$ARC" proc.psinfo.environ >/dev/null 2>&1; then kaldi "arsivde proc.psinfo.environ VAR - parola/secret sizintisi riski, config'den cikarin"
  else gecti "arsivde proc.psinfo.environ yok (secret sizintisi yok)"; fi
  LOGSZ=$(stat -c %s "$HD/pmlogger.log" 2>/dev/null || echo 0)
  if [ "$LOGSZ" -lt 5242880 ]; then gecti "pmlogger.log boyutu normal ($(( LOGSZ / 1024 )) KB)"
  else kaldi "pmlogger.log anormal buyuk ($(( LOGSZ / 1048576 )) MB) - dogrulama dongusu olabilir"; fi
else
  atla "arsiv testleri (uzak host veya arsiv bulunamadi)"
fi

bas "10. PMLOGGER YAPILANDIRMASI"
CTRL=""
for f in "$PCP_SYSCONF_DIR/pmlogger/control.d/local" "$PCP_SYSCONF_DIR/pmlogger/control"; do
  [ -f "$f" ] && grep -qE '^[^#]*LOCALHOSTNAME.*-c[[:space:]]' "$f" && { CTRL=$f; break; }
done
if [ -n "$HOST" ]; then
  atla "yapilandirma dosyasi testleri (uzak host)"
else
  CC=""
  [ -n "$CTRL" ] && CC=$(grep -E '^[^#]*LOCALHOSTNAME' "$CTRL" | head -1 | grep -oE -- '-c[[:space:]]+[^[:space:]]+' | awk '{print $2}')
  if [ -n "$CTRL" ]; then gecti "birincil pmlogger kayit yapilandirmasi: ${CC:-?} ($CTRL)"
  else kaldi "birincil pmlogger kontrol satiri (LOCALHOSTNAME) bulunamadi"; fi
  case "$CC" in /*) CFG="$CC" ;; *) CFG="/var/lib/pcp/config/pmlogger/$CC" ;; esac
  if [ -n "$CC" ] && [ -f "$CFG" ]; then
    if [ "$CC" = "config.pcp-full" ]; then atla "eski pcp-setup tam profili (config.pcp-full) kullaniliyor - pcp-onlem kayit_profili=tam ya da varsayilan ile yenilenebilir"; fi
    if [ "$(stat -c %a "$CFG")" = 644 ]; then gecti "$CC izni 644 (pcp kullanicisi okuyabilir)"
    else kaldi "$CC izni $(stat -c %a "$CFG") - pmlogger 'pcp' kullanicisiyla okuyamayabilir (chmod 644)"; fi
    if grep -qE '^[[:space:]]+proc\.psinfo\.environ' "$CFG"; then kaldi "$CC proc.psinfo.environ icermemeli (parola sizintisi riski)"
    else gecti "$CC proc.psinfo.environ icermiyor"; fi
    if [ "$CC" != "config.default" ]; then
      # turetilmis metrikler (domain 511) kaydedilirse pmcd yeniden basladiginda pmlogger hata dongusune girer
      mapfile -t CFG_METRIKLER < <(grep -oE '^[[:space:]]+[a-z][a-z0-9_.]+' "$CFG" | tr -d ' ' | sort -u)
      D511=$(pminfo -m "${CFG_METRIKLER[@]}" 2>/dev/null | awk '$2=="PMID:" && $3 ~ /^511\./ {print $1}' | head -3 | tr '\n' ' ')
      if [ -z "$D511" ]; then gecti "$CC turetilmis (domain 511) metrik icermiyor"
      else kaldi "$CC turetilmis metrik icermemeli: $D511..."; fi
    fi
  elif [ -n "$CC" ]; then
    kaldi "kayit yapilandirma dosyasi yok: $CFG"
  fi
  STRAY=$(find "$PCP_SYSCONF_DIR/pmlogger/control.d" -maxdepth 1 -type f 2>/dev/null | grep -E '\.(orig|bak|old|rpmsave|rpmnew)$|~$' | head -3 | tr '\n' ' ')
  if [ -z "$STRAY" ]; then gecti "control.d altinda yedek/artik dosya yok (Duplicate pmlogger instances riski yok)"
  else kaldi "control.d altinda artik dosya var (PCP 7 pmlogger_check bunlari kontrol dosyasi sanir): $STRAY"; fi
  TIMERS="$PCP_SYSCONFIG_DIR/pmlogger_timers"
  # -k deseni pcp-onlem dogrulamasiyla ayni: '-k 8', '-k8', '-k=8'
  if grep -qE '^PMLOGGER_DAILY_PARAMS=.*-k[ =]?[0-9]+' "$TIMERS" 2>/dev/null; then
    K=$(grep -E '^PMLOGGER_DAILY_PARAMS=' "$TIMERS" | tail -1 | grep -oE -- '-k[ =]?[0-9]+' | tr -dc '0-9')
    if [ "$K" -ge "$ENAZ" ]; then gecti "gunluk dondurme parametresi: $(grep -E '^PMLOGGER_DAILY_PARAMS=' "$TIMERS" | tail -1)"
    else kaldi "saklama -k $K < yapilandirma kurali en az $ENAZ gun"; fi
    grep -E '^PMLOGGER_DAILY_PARAMS=' "$TIMERS" | tail -1 | grep -qE -- '[" ]-E[ "]' \
      || atla "PMLOGGER_DAILY_PARAMS icinde -E yok (paket varsayilani; tanimi tutarsiz metrik birlestirmeyi durdurur)"
  else atla "PMLOGGER_DAILY_PARAMS icinde -k yok (PCP varsayilani 14 gun)"; fi
  # systemd ortam dosyasi satir sonu yorumunu tanimaz: '#' ya da tirnak disi ek degerin parcasi olur, pmlogger_daily durur
  if grep -E '^PMLOGGER_DAILY_PARAMS=' "$TIMERS" 2>/dev/null | tail -1 \
       | grep -qE '^PMLOGGER_DAILY_PARAMS=.*#|^PMLOGGER_DAILY_PARAMS="[^"]*"[[:space:]]*[^[:space:]]'; then
    kaldi "PMLOGGER_DAILY_PARAMS satirinda deger disi ek (satir sonu yorumu?) - pmlogger_daily her gece hatayla durur"
  fi
  CHK="$PCP_ARCHIVE_DIR/pmlogger_check.log"
  if [ -f "$CHK" ] && grep -q 'Duplicate pmlogger' "$CHK"; then kaldi "pmlogger_check.log 'Duplicate pmlogger instances' iceriyor"
  else gecti "pmlogger_check.log'da Duplicate hatasi yok"; fi
fi

bas "11. ALARM MOTORU"
if command -v pmieconf >/dev/null 2>&1; then
  N=$(pmieconf -f /var/lib/pcp/config/pmie/config.default rules enabled 2>/dev/null | grep -c .)
  if [ "${N:-0}" -gt 0 ]; then gecti "$N pmie kurali etkin"; else atla "hicbir pmie kurali etkin degil"; fi
  say "  gunluk: /var/log/pcp/pmie/$(hostname)/pmie.log"
else atla "pmieconf yok"; fi

bas "12. DISK KORUMASI"
LSB=0; GRD=0
[ -x /usr/local/sbin/log-saklama-bekci ] && LSB=1
systemctl is-active pcp-log-guard.timer >/dev/null 2>&1 && GRD=1
if [ "$LSB" -eq 1 ] && [ "$GRD" -eq 1 ]; then
  kaldi "log-saklama bekcisi ve eski pcp-log-guard ayni anda etkin (iki silici) - pcp-onlem eski_kurulum_karari=otomatik"
elif [ "$LSB" -eq 1 ]; then
  if systemctl is-active log-saklama-bekci.timer >/dev/null 2>&1; then gecti "log-saklama bekcisi etkin (log-saklama-bekci.timer)"
  else kaldi "log-saklama bekcisi kurulu ama zamanlayicisi etkin degil"; fi
elif [ "$GRD" -eq 1 ]; then
  atla "eski pcp-log-guard etkin (log-saklama kurulunca pcp-onlem kapatir)"
else
  atla "/var/log/pcp icin bekci yok - saklama gunu alana sigdirilmis olmali (bolum 10)"
fi
say "  /var/log/pcp doluluk: $(df -h /var/log/pcp 2>/dev/null | awk 'NR==2{print $5" ("$3"/"$2")"}')"

# pcp-onlem kalemleri: yuk kurali geregi kapatilan PMDA'lar (dm: her device-mapper aygitina ioctl)
# ve kesmeleri kapatan kayit gruplari (zoneinfo/buddyinfo: bolge kilidi) kapali mi?
bas "13. KAPATILAN PMDA VE KAYIT GRUPLARI (yuk kurali)"
PMCDCONF="$PCP_SYSCONF_DIR/pmcd/pmcd.conf"; PMDAS="${PCP_PMDAS_DIR:-/var/lib/pcp/pmdas}"
for m in $KAPALI_PMDALAR; do
  if grep -qE "^${m}[[:space:]]" "$PMCDCONF" 2>/dev/null; then kaldi "$m PMDA pmcd.conf icinde etkin (pcp-onlem pmda_kapatma_karari=uygula ile kaldirilir)"
  elif ls "$PMDAS/$m"/.NeedInstall* >/dev/null 2>&1; then kaldi "$m icin bekleyen kurulum isareti var (pmcd baslarken PMDA kurulur)"
  elif [ -d "$PMDAS/$m" ] && ! grep -qE "^#.*${m}/pmda${m}" "$PMCDCONF" 2>/dev/null; then atla "$m kapali ama yeniden kurulum isareti yok (pcp-zeroconf guncellemesi geri kurabilir)"
  else gecti "$m PMDA kapali"; fi
done
GD="${PCP_VAR_DIR:-/var/lib/pcp}/config/pmlogconf"; CD="/var/lib/pcp/config/pmlogger/config.default"
for g in $KAPALI_GRUPLAR; do
  GF=$(readlink -f "$GD/$g" 2>/dev/null)
  if [ -z "$GF" ] || [ ! -f "$GF" ]; then atla "$g grup dosyasi yok ($GD/$g)"; continue; fi
  if grep -qE '^[[:space:]]*force[[:space:]]+exclude' "$GF"; then gecti "$g grubu force exclude (kayda alinmaz)"
  else kaldi "$g grubu force exclude degil (pmlogconf yoklamayla kayda alabilir) - pcp-onlem kayit_grubu_kapatma_karari=uygula"; fi
  KAYITTA=""
  for mt in $(awk '/^[[:space:]]+[a-z]/{print $1}' "$GF"); do grep -qE "^[[:space:]]+${mt}$" "$CD" 2>/dev/null && KAYITTA="$KAYITTA $mt"; done
  if [ -z "$KAYITTA" ]; then gecti "$g metrikleri config.default kaydinda yok"
  else kaldi "$g metrikleri kayitta:$KAYITTA (pmlogger yeniden baslatilmali ya da grup kapatilmali)"; fi
done

if [ "$YUK" -eq 1 ]; then
  bas "14. YUK ALTINDA TEST (hotproc + top-N siralama) - YUK URETIR, canli ortamda kosulmaz"
  say "  ~35 sn CPU yuku uretiliyor..."
  for _ in 1 2; do ( timeout 40 bash -c 'while :; do :; done' >/dev/null 2>&1 & ); done
  sleep 25
  NH=$(pminfo -f hotproc.nprocs 2>/dev/null | awk '/value/{print $2}')
  if [ "${NH:-0}" -gt 0 ] 2>/dev/null; then gecti "hotproc yuku yakaladi: $NH sicak proses"
  else kaldi "hotproc yuk altinda bile 0 proses gosteriyor"; fi
  TOPF=$(mktemp)
  timeout 25 pmrep -t 2s -s 3 -J 5 -6 proc.hog.cpu :obur >"$TOPF" 2>/dev/null
  SON=$(awk 'NR>1{print $1}' "$TOPF" | tail -1)
  if [ -n "$SON" ] && grep -q "^$SON" "$TOPF"; then
    gecti "top-N siralama calisiyor:"
    grep "^$SON" "$TOPF" | head -5 | sed 's/^/         /'
  else kaldi "top-N siralama sonuc vermedi"; fi
  rm -f "$TOPF"; sleep 16
fi

echo
echo "================================================================"
printf " SONUC: %d gecti, %d KALDI, %d atlandi\n" "$GECTI" "$KALDI" "$ATLANDI"
printf " -A karari: %s (%s)\n" "$PROC_KARAR" "$PROC_KAYNAK"
echo "================================================================"
[ "$KALDI" -eq 0 ] && { echo " Tum izleme yetenekleri calisir durumda."; exit 0; }
echo " Yukaridaki [HATA] satirlarina bakin."; exit 1
