#!/bin/bash
#
# pcp-dogrula.sh - PCP kurulumunun ve izleme yeteneklerinin dogrulanmasi
#
# pcp-setup.sh calistirildiktan sonra (veya herhangi bir PCP kurulumunda)
# hangi izleme/inceleme yeteneginin gercekten calistigini test eder.
# Salt-okunur: sistemde hicbir degisiklik yapmaz.
#
# Kullanim:
#   ./pcp-dogrula.sh              # tam test (13 bolum, ~80 test)
#   ./pcp-dogrula.sh -q           # yalnizca hatalar + ozet
#   ./pcp-dogrula.sh -y           # CPU yuku uretip hotproc/top-N'i de test et
#   ./pcp-dogrula.sh -h HOST      # uzak sunucuyu test et (pmcd erisimi gerekir)
#   ./pcp-dogrula.sh -H           # yardim
#
# Cikis kodu: 0 = tum testler gecti, 1 = en az bir test kaldi, 2 = pcp yok
#
set -o pipefail
QUIET=0; YUK=0; HOST=""; T=20
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
    if [ "$NR_RESTART" -eq 0 ]; then gecti "pmlogger son acilistan beri hic cokmemis (NRestarts=0)"
    else kaldi "pmlogger $NR_RESTART kez yeniden baslatilmis - crashloop belirtisi, pmlogger.log'a bakin"; fi
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
NR=$(pminfo "${HOPT[@]}" -f proc.psinfo.pid 2>/dev/null | grep -c inst)
if [ -z "$HOST" ] && [ "$(id -u)" -eq 0 ] && command -v runuser >/dev/null 2>&1; then
  NP=$(runuser -u pcp -- pminfo -f proc.psinfo.pid 2>/dev/null | grep -c inst)
  if [ "$NP" -gt 10 ] && [ "$NP" -ge $(( NR * 8 / 10 )) ]; then
    gecti "pcp kullanicisi $NP / root $NR proses goruyor (arsive tum prosesler yazilir)"
  else
    kaldi "pcp kullanicisi yalnizca $NP proses goruyor (root: $NR) - pmcd.conf'ta proc PMDA'ya -A gerekli"
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
  kaldi "hotproc filtresi yuklu degil - $PCP_PMDAS_DIR/proc/hotproc.conf yok"
fi

bas "8. RAPOR SABLONLARI"
for t in vmstat sar-u-ALL sar-n-DEV pidstat-d pmstat; do
  dene "hazir sablon :$t" "pmrep $H -t 1s -s 2 -z :$t"
done
for t in canli obur agirlik; do
  if grep -q "^\[$t\]" "$PCP_SYSCONF_DIR"/pmrep/*.conf 2>/dev/null; then
     dene "ozel sablon :$t" "pmrep $H -t 1s -s 2 -z :$t"
  else atla "ozel sablon :$t kurulu degil (pcp-setup.sh calistirilmamis)"; fi
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
CFG=/var/lib/pcp/config/pmlogger/config.pcp-full
CTRL=""
for f in "$PCP_SYSCONF_DIR/pmlogger/control.d/local" "$PCP_SYSCONF_DIR/pmlogger/control"; do
  [ -f "$f" ] && grep -qE '^[^#]*LOCALHOSTNAME.*-c[[:space:]]' "$f" && { CTRL=$f; break; }
done
if [ -n "$HOST" ]; then
  atla "yapilandirma dosyasi testleri (uzak host)"
elif [ -f "$CFG" ]; then
  gecti "config.pcp-full mevcut ($(grep -cE '^[[:space:]]+[a-z]' "$CFG") metrik satiri)"
  if [ "$(stat -c %a "$CFG")" = 644 ]; then gecti "config.pcp-full izni 644 (pcp kullanicisi okuyabilir)"
  else kaldi "config.pcp-full izni $(stat -c %a "$CFG") - pmlogger 'pcp' kullanicisiyla okuyamaz (chmod 644)"; fi
  if grep -qE '^[[:space:]]+proc\.psinfo\.environ' "$CFG"; then kaldi "config.pcp-full proc.psinfo.environ icermemeli (secret riski)"
  else gecti "config.pcp-full proc.psinfo.environ icermiyor"; fi
  # derived metrikler (domain 511) loglanirsa pmcd yeniden baslayinca pmlogger hata dongusune girer
  mapfile -t CFG_METRIKLER < <(grep -oE '^[[:space:]]+[a-z][a-z0-9_.]+' "$CFG" | tr -d ' ' | sort -u)
  D511=$(pminfo -m "${CFG_METRIKLER[@]}" 2>/dev/null | awk '$2=="PMID:" && $3 ~ /^511\./ {print $1}' | head -3 | tr '\n' ' ')
  if [ -z "$D511" ]; then gecti "config.pcp-full turetilmis (domain 511) metrik icermiyor"
  else kaldi "config.pcp-full turetilmis metrik icermemeli: $D511..."; fi
  if [ -n "$CTRL" ]; then
    if grep -qE '^[^#]*LOCALHOSTNAME.*-c[[:space:]]+config\.pcp-full' "$CTRL"; then gecti "birincil pmlogger config.pcp-full kullaniyor ($CTRL)"
    else kaldi "birincil pmlogger config.pcp-full kullanmiyor ($CTRL)"; fi
  else kaldi "birincil pmlogger kontrol satiri (LOCALHOSTNAME) bulunamadi"; fi
  STRAY=$(find "$PCP_SYSCONF_DIR/pmlogger/control.d" -maxdepth 1 -type f 2>/dev/null | grep -E '\.(orig|bak|old|~)$' | head -3 | tr '\n' ' ')
  if [ -z "$STRAY" ]; then gecti "control.d altinda yedek/artik dosya yok (Duplicate pmlogger instances riski yok)"
  else kaldi "control.d altinda artik dosya var (PCP 7 pmlogger_check bunlari kontrol dosyasi sanir): $STRAY"; fi
  TIMERS="$PCP_SYSCONFIG_DIR/pmlogger_timers"
  if grep -qE '^PMLOGGER_DAILY_PARAMS=.*-k[[:space:]]*[0-9]+' "$TIMERS" 2>/dev/null; then
    gecti "gunluk rotasyon parametresi: $(grep -E '^PMLOGGER_DAILY_PARAMS=' "$TIMERS")"
  else atla "PMLOGGER_DAILY_PARAMS ayarlanmamis (PCP varsayilani: 14 gun, gec sikistirma)"; fi
  CHK="$PCP_ARCHIVE_DIR/pmlogger_check.log"
  if [ -f "$CHK" ] && grep -q 'Duplicate pmlogger' "$CHK"; then kaldi "pmlogger_check.log 'Duplicate pmlogger instances' iceriyor"
  else gecti "pmlogger_check.log'da Duplicate hatasi yok"; fi
else
  atla "config.pcp-full yok (pcp-setup.sh calistirilmamis; PCP varsayilan yapilandirmasi kullaniliyor)"
fi

bas "11. ALARM MOTORU"
if command -v pmieconf >/dev/null 2>&1; then
  N=$(pmieconf -f /var/lib/pcp/config/pmie/config.default rules enabled 2>/dev/null | grep -c .)
  if [ "${N:-0}" -gt 0 ]; then gecti "$N pmie kurali etkin"; else atla "hicbir pmie kurali etkin degil"; fi
  say "  gunluk: /var/log/pcp/pmie/$(hostname)/pmie.log"
else atla "pmieconf yok"; fi

bas "12. DISK KORUMASI"
if [ -x /usr/local/sbin/pcp-log-guard.sh ]; then
  gecti "pcp-log-guard.sh kurulu"
  if systemctl is-active pcp-log-guard.timer >/dev/null 2>&1; then gecti "pcp-log-guard.timer aktif"
  else kaldi "pcp-log-guard.timer aktif degil"; fi
  if [ -r "$PCP_SYSCONF_DIR/pcp-log-guard.conf" ]; then
    gecti "esik ayarlari: $(grep -oE '^(THRESHOLD_PCT|MAX_SIZE_GB|KEEP_DAYS)=[0-9]+' "$PCP_SYSCONF_DIR/pcp-log-guard.conf" | tr '\n' ' ')"
  else atla "$PCP_SYSCONF_DIR/pcp-log-guard.conf yok (guard varsayilanlari kullanir)"; fi
else atla "pcp-log-guard kurulu degil (pcp-setup.sh calistirilmamis)"; fi
say "  /var/log/pcp doluluk: $(df -h /var/log/pcp 2>/dev/null | awk 'NR==2{print $5" ("$3"/"$2")"}')"

if [ "$YUK" -eq 1 ]; then
  bas "13. YUK ALTINDA TEST (hotproc + top-N siralama)"
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
echo "================================================================"
[ "$KALDI" -eq 0 ] && { echo " Tum izleme yetenekleri calisir durumda."; exit 0; }
echo " Yukaridaki [HATA] satirlarina bakin."; exit 1
