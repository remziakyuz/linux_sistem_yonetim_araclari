#!/bin/bash
#
# pcp-setup.sh - PCP (Performance Co-Pilot) kurulum ve izleme yapilandirmasi
#
# Surum 4.4.1 (2026-11-08): yalniz yorum ve ileti dili (kurulusa ozgu ifadeler "onerilen yapilandirma" oldu; GitHub paylasimi);
#   davranis ve degisken degerleri 4.4 ile ayni (playbook-pcp v1.13 esi).
# Surum 4.4 (2026-11-08): playbook-pcp v1.13 ile BIREBIR - DEBIAN 13 (trixie) DESTEGI (proje karari 07.11.2026):
#   - platform: RHEL 8/9/10 ailesi + Debian 13 (Ubuntu ve Debian 12 ve oncesi reddedilir; sinanmadi)
#   - paket sorgusu rpm / dpkg-query, kurulum dnf / apt-get (Recommends kurulmaz); apt paket listesi yalniz kurulacak
#     paket varsa ve 1 saatten eskiyse yenilenir (kosum basina en cok bir kez)
#   - servis ayar dosyalari pcp.conf PCP_SYSCONFIG_DIR dizininde: RHEL /etc/sysconfig, Debian /etc/default (pmcd,
#     pmlogger_timers; yedek izi /var/backup/pcp-onlem/etc/default/...)
#   - Debian paketi pmproxy'yi acilista baslayacak bicimde etkin, pmie'yi calismaz birakir: bu kosumda kurulan PCP'de
#     RHEL son durumu (pmproxy disable; pcp-zeroconf bu kosumda kurulduysa pmie baslatilir); dogrulama pmproxy acilista
#     baslayacaksa BILGI yazar
#   - ortak govdeler PCP_OLCUM_TAM_GUN / PCP_SAKLAMA_DOGRULA pmlogger_timers yolunu pcp.conf'tan okur (RHEL'de ayni)
#   Fark: playbook ek paket istendiginde apt listesini (1 saatten eskiyse) her durumda yeniler; betik yalniz eksik
#   paket varken (sonuc sistem durumunda ayni). Betik #!/bin/bash ile kosar: playbook'taki dash sorunu burada yok.
# Surum 4.3 (2026-11-07): playbook-pcp v1.12 ile BIREBIR (v1.10 / v1.11 / v1.12 tasindi):
#   - v1.10: bos alan kapisi PCP kuruluyken pcp-zeroconf kurulacaksa da olcer (yetersizse zeroconf kurulmaz, SORUN);
#     ek paketler (pcp_ek_paketler) kurulum kararina ve bos alan kapisina bagli
#   - v1.11: pmlogger sure denetimi (ortak govde PCP_GECE_YAYMA: sure gece isinden once dolacaksa SIGUSR2, gece
#     saatlerinde gonderilmez); kayit grubu kapatmada guvenli yazim (gecici dosya + mv, yedek alinamazsa dokunulmaz,
#     kesilen kosumda gecici dosya silinir, sonuc dosyadan dogrulanir)
#   - v1.12: yedek denetimi (4.2.1): yedek alinamazsa cikis 3, dosyalara dokunulmaz (playbook bu sunucuyu atlar ve
#     digerlerine devam eder; tek sunucuda esdeger davranis durmaktir)
# Surum 4.2.1 (2026-11-07, yama; playbook-pcp v1.11.1 yedek denetimi): yedek alinamazsa (/var/backup dolu,
#   salt okunur) "yedek" yazilmaz, manifeste satir girmez, SORUN ve cikis 3 - degisiklik oncesi yedekte hicbir
#   dosyaya dokunulmaz. 4.2 cp sonucunu denetlemiyor, yedeksiz devam ediyordu. Diger kararlar 4.2 / v1.9 ile ayni.
# Surum 4.2 (2026-11-02): playbook-pcp v1.9 (playbook-pcp/pcp-onlem.yml) ile BIREBIR
# ayni ozellikler ve degisken degerleri (proje karari 02.11.2026). 4.1'e gore:
#   - saklama hedefi 32 gun (aylik dongu: ay 28-31 gun + 1 gun pay), satir "-E -x 1 -k N" (v1.5/v1.7)
#   - saklama tavani GERCEK alandan: min(LV x pay, PCP kullanimi + bos alan - LV x 0,2); olcum yalniz
#     tamamlanmis tam gunlerden; kayit hacmi bu kosumda degisiyorsa (pcp-zeroconf, -A, hotproc, ek PMDA,
#     tam profil) hesap ERTELENIR (v1.6/v1.9)
#   - saklama sahipleri: pcp-merkezi eklendi; rol playbook'u yalniz pmlogger_timers YEDEGI varsa sahip (v1.5/v1.8)
#   - kapali PMDA listesine opentelemetry (v1.9); pmcd.conf yazimi gecici dosya + mv, isaret dosyadan dogrulanir
#   - proc -A varsayilani 'dokunma' (v1.8): -A yerel kullaniciya tum sureclerin environ'unu acar
#   - yeni kurulumda bos alan kapisi: 1536 MB + bolum %80 (v1.8)
#   - PCP gece isleri yayma, gece raporu kapatma, gecis kapisi, Persistent=false (v1.6-v1.9; govde playbook'tan AYNEN)
#   - rapor kipinde -e ile verilen karar kosumu BASTA durdurur (v1.7)
#   - kosum sonu yedegi + yeni dosyalar icin manifestte OLUSTURULDU satiri (v1.7/v1.9)
#   - dogrulama: pmlogger yeniden baslatmasi yalniz hatali cikista SORUN, gece isleri ve saklama alana sigma kalemleri
#   - yalniz RHEL 8/9/10 ailesi (playbook ile ayni; Ubuntu destegi 4.2'de kaldirildi - proje karari 02.11.2026)
#   Ortak kabuk govdeleri (# PCP_GECE_YAYMA, # PCP_OLCUM_TAM_GUN, # PCP_GECE_DOGRULA, # PCP_SAKLAMA_DOGRULA)
#   playbook'tan araclar/ortak-govde.sh ile alinir ve araclar/tutarlilik.sh ile birebirligi denetlenir.
# Surum 4.1 (2026-10-26): Ubuntu 22.04+ destegi (4.2'de kaldirildi).
# Surum 4.0 (2026-10-26): playbook-pcp v1.4 esi; 3.x (disk+ag 1 sn, kosulsuz -A, pcp-log-guard,
#   sensors-detect, pmie acik, 14 gun) KALDIRILDI - neden: PCP_EL_KITABI.md Bolum 17.9.
# Kural: onerilen yapilandirma once playbook'ta degisir, bu betik ona uyarlanir. Gorev sirasi, karar
# degiskenleri, esikler, isaret satirlari ve yedek yeri (/var/backup/pcp-onlem) playbook ile aynidir:
# betikle kurulan sunucuda playbook (ve tersi) degisiklik bulmaz.
#
# Platform: RHEL 8/9/10 ailesi (Rocky, AlmaLinux, Oracle Linux, CentOS Stream, Fedora) ve Debian 13 (trixie; 4.4).
#
# Kullanim (root):
#   ./pcp-setup.sh                         # RAPOR: tespit + rapor + dogrulama, DEGISIKLIK YOK
#   ./pcp-setup.sh -u -n                   # uygula kuru calisma: neyin degisecegini goster
#   ./pcp-setup.sh -u                      # uygula (varsayilan acik adimlar)
#   ./pcp-setup.sh -u -e kayit_profili=tam -e hotproc_karari=uygula
#   ./pcp-setup.sh -d                      # yalniz dogrulama blogu
#     -u        uygulama_modu=uygula (yoksa rapor; playbook: -e uygulama_modu=uygula)
#     -n        kuru calisma (playbook: --check): hicbir dosya/servis degismez
#     -e AD=DEG playbook degiskeni (birden cok kez; ayni adlar ve degerler). Rapor kipinde
#               degisiklik karari verilirse kosum BASTA durur (playbook v1.7 ile ayni)
#     -d        yalniz dogrulama (playbook: --tags dogrula)
#     -h        yardim
#
# Karar degiskenleri (-e ile; yalniz uygula modunda gecerli):
#   Varsayilan ACIK : kurulum_karari zeroconf_karari saklama_karari pmrep_sablon_karari
#                     dogrula_betigi_karari pmda_kapatma_karari kayit_grubu_kapatma_karari
#                     pcp_gece_karari (uygula|dokunma), eski_kurulum_karari (otomatik|dokunma)
#   Varsayilan KAPALI: proc_tum_surec_karari (dokunma|gerekirse), kayit_profili (dokunma|tam|varsayilan),
#                     hotproc_karari, pmie_karari (uygula|dokunma), pcp_ek_pmdalar, pcp_ek_paketler
#                     (virgulle: -e pcp_ek_pmdalar=bonding,mounts)
#   Esikler         : pcp_gorunurluk_orani(80) pcp_saklama_hedef_gun(32) pcp_saklama_en_az_gun(8;
#                     8 altina yalniz pcp_test_ortami=true) pcp_saklama_tolerans_gun(2)
#                     pcp_paylasimli_oran(0.25) pcp_kurulum_bos_alan_mb(1536) pcp_gece_pencere_dk(120;
#                     30-600) pcp_kontrol_pencere_dk(29; 5-29) pcp_tam_diskag_aralik(10)
#                     pcp_tam_aralik(60) pcp_tam_donanim_aralik(300)
#
# YUK NOTU (sisteme yuk bindirmeme kurali 01.10.2026 - EN YUKSEK ONCELIK; olcek kurali 30.10.2026):
#   Varsayilan acik adimlar:
#   - Tespit: rpm (Debian: dpkg-query)/systemctl/df; 'pminfo -f proc.psinfo.pid' ve 'pminfo -f proc.io.read_bytes' root ve pcp
#     kullanicisiyla birer kez (tum sureclerin /proc/<pid>/stat ve /proc/<pid>/io okumasi; smaps OKUNMAZ);
#     dogrulama blogu proc.io.read_bytes ikilisini bir kez daha kosar (kosum basina 6 surec agaci okumasi,
#     her biri timeout 60); 'du -sm /var/log/pcp' ve gun basina 'du -cm' (olculdu 25-30 ms); journalctl
#     son 24 saat (timeout 60). Etkisi OLCULMEDI, kisa surelidir.
#   - Uygula: dnf paket kurulumu (depo IO). Debian 13: apt-get (~6,5 MB, 17 paket; apt-get update yalniz kurulacak
#     paket varsa ve liste 1 saatten eskiyse). Debian paket betigi pmcd/pmlogger'i kurulumda hemen baslatir (RHEL'de
#     pcp-zeroconf ayni isi yapar); bu kosum PCP'yi kurduysa pmproxy disable, zeroconf'u kurduysa pmie baslatilir. PMDA kapatma (dm, kvm, nfsclient, openmetrics, opentelemetry)
#     ve kayit grubu kapatma (zoneinfo, buddyinfo): pmcd/pmlogger yeniden baslatilir (birkac sn ornek
#     kaybi). Yuk AZALTAN adimlardir.
#   - Gece isleri yayma: drop-in yazimi + daemon-reload (timeout 120); zamanlayicilar YENIDEN BASLATILMAZ.
#     Yuk AZALTAN adimdir: gece raporu (her gece tum gun arsivini /var/tmp altina acar) kapanir, gunluk ve
#     yarim saatlik isler sunucuya ozgu saate yayilir (400 VM'de ayni anda en cok ~10 birlestirme, bugun 400).
#     GECIS: kaydirmasi 10 dk'yi asan sunucuda ilk gecelerde pmlogger -T suresi dolunca gunde bir kendiliginden
#     yeniden baslar (birkac sn kayip; en cok ~12 gun, RHEL 8 ailesinde ~17). Eszamanli yeniden baslatma yuku
#     OLCULMEDI: 400-1000 VM'ye dalgalarla uygulanir (PCP_EL_KITABI.md 17.19).
#   Varsayilan KAPALI adimlar (etkisi OLCULMEDI; once test sunucusunda olcun):
#   - proc_tum_surec_karari=gerekirse: -A icin pmcd YENIDEN BASLATILIR; -A'nin actigi /proc/<pid>/io ve wchan
#     okumalari OLCULDU (bellek kilidi almaz), ama yerel root olmayan kullaniciya tum sureclerin environ'u acilir.
#   - kayit_profili=tam: ~700 disk/ag metrigi her disk/bolum/kart icin ayri, TUM surec agaci; arsiv boyutu
#     belirgin artar. proc.fd.count her surecin fd dizinini listeler. proc.memory.maps ve environ DISLANIR.
#   - hotproc: proc PMDA her yenilemede tum surecleri esige gore degerlendirir.
#   - pcp_ek_pmdalar: smart (smartctl disklere komut gonderir, SAN LUN etkisi bilinmiyor), sockets (ss
#     calistirir), perfevent (donanim sayaclari), lmsensors, systemd, mounts, bonding. Her biri pmcd yeniden
#     baslatmasi.
#   - pmie: esik alarmlari syslog'a yazar (gunluk hacmi artar).
#   - Kurulan pcp-dogrula.sh'in '-y' secenegi CPU YUKU URETIR: canli ortamda kosulmaz.
#
# Yedek: /var/backup/pcp-onlem/<orijinal yol>-<damga> + _kosum-<damga>.txt manifestosu (playbook ile ayni
# agac); kosum sonu: <dosya>-kosum-sonu-<damga> + _durum-<damga>.txt. Ilk kez olusturulan dosya manifeste
# "OLUSTURULDU  <dosya>  -" satiriyla girer (geri alma = /var/backup agacina tasima). Hicbir sey silinmez.
#
# Cikis kodu: 0 = tamam (dogrulama SORUN'lari bilgi kipidir, kosum durmaz),
#             1 = on kosul / kullanim hatasi, 2 = tam profil metrik listesi bos,
#             3 = yedek alinamadi (4.2.1; degisiklik oncesi yedekte hicbir dosyaya dokunulmadi, kosum sonu
#                 yedeginde degisiklikler yapildi - geri alma manifesti _kosum-<damga>.txt gecerli)
#
set -o pipefail
umask 022
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BETIK_DIZIN=$(cd "$(dirname "$0")" && pwd)

# ============================================================================
# DEGISKENLER (playbook-pcp v1.13 vars ile ayni adlar ve varsayilanlar)
# ============================================================================
playbook_adi=pcp-onlem
yedek_kok="/var/backup/$playbook_adi"
yedek_damga=$(date +%Y%m%dT%H%M%S)
uygulama_modu=rapor
kurulum_karari=uygula
zeroconf_karari=uygula
proc_tum_surec_karari=dokunma
pcp_kurulum_bos_alan_mb=1536
pcp_test_ortami=false
pcp_gorunurluk_orani=80
pcp_a_riskli_desen='proc\.smaps|hotproc\.smaps|proc\.memory\.maps|psinfo\.environ'
saklama_karari=uygula
pcp_saklama_hedef_gun=32
pcp_saklama_en_az_gun=8
pcp_saklama_tolerans_gun=2
pcp_paylasimli_oran=0.25
pcp_saklama_yonetenler="couchbase-onlem temel-onlem proxy-onlem patroni-onlem postgresql-onlem pcp-merkezi"
pcp_kayit_yonetenler="couchbase-onlem"
pmrep_sablon_karari=uygula
dogrula_betigi_karari=uygula
pcp_dogrula_yol=/usr/local/bin/pcp-dogrula.sh
eski_kurulum_karari=otomatik
pmda_kapatma_karari=uygula
pcp_kapali_pmdalar="dm dmcache kvm nfsclient openmetrics opentelemetry prometheus"
kayit_grubu_kapatma_karari=uygula
pcp_kapali_kayit_gruplari="memory/zoneinfo memory/buddyinfo"
pcp_gece_karari=uygula
pcp_gece_pencere_dk=120
pcp_kontrol_pencere_dk=29
kayit_profili=dokunma
pcp_tam_diskag_aralik=10
pcp_tam_aralik=60
pcp_tam_donanim_aralik=300
hotproc_karari=dokunma
pmie_karari=dokunma
pcp_pmie_kurallari="cpu.util cpu.load_average cpu.system memory.exhausted memory.swap_low filesys.filling filesys.vfs_files per_disk.average_wait_time per_netif.errors"
pcp_pmie_esikleri="cpu.util|threshold|90% filesys.filling|threshold|90%"
pcp_pmie_yapilandirma=/var/lib/pcp/config/pmie/config.default
pcp_ek_pmdalar=""
pcp_ek_paketler=""
pcp_pmlogger_dizin=/var/lib/pcp/config/pmlogger
pcp_tam_ad=config.pcp-tam
pcp_temel_paketler="pcp pcp-system-tools"

KURU=0; YALNIZ_DOGRULA=0
KARAR_ADLARI="kurulum_karari zeroconf_karari proc_tum_surec_karari saklama_karari pmrep_sablon_karari dogrula_betigi_karari eski_kurulum_karari pmda_kapatma_karari kayit_grubu_kapatma_karari pcp_gece_karari kayit_profili hotproc_karari pmie_karari pcp_ek_pmdalar pcp_ek_paketler"
IZINLI_AD=" uygulama_modu $KARAR_ADLARI pcp_kurulum_bos_alan_mb pcp_test_ortami pcp_gorunurluk_orani pcp_saklama_hedef_gun pcp_saklama_en_az_gun pcp_saklama_tolerans_gun pcp_paylasimli_oran pcp_kapali_pmdalar pcp_kapali_kayit_gruplari pcp_gece_pencere_dk pcp_kontrol_pencere_dk pcp_tam_diskag_aralik pcp_tam_aralik pcp_tam_donanim_aralik "
VERILEN=" "

yardim() { sed -n '2,/^set -o pipefail/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; }
while getopts "une:dh" o; do
    case $o in
        u) uygulama_modu=uygula ;;
        n) KURU=1 ;;
        e) ad=${OPTARG%%=*}; deg=${OPTARG#*=}
           [ "$ad" != "$OPTARG" ] || { echo "HATA: -e AD=DEGER bekleniyor: $OPTARG" >&2; exit 1; }
           case "$IZINLI_AD" in *" $ad "*) ;; *) echo "HATA: bilinmeyen degisken: $ad" >&2; exit 1 ;; esac
           printf -v "$ad" '%s' "${deg//,/ }"; VERILEN="$VERILEN$ad " ;;
        d) YALNIZ_DOGRULA=1 ;;
        h) yardim; exit 0 ;;
        *) yardim >&2; exit 1 ;;
    esac
done

N_DEG=0; N_AYNI=0
log()  { echo "[pcp-setup] $*"; }
chg()  { N_DEG=$((N_DEG+1));   echo "[pcp-setup]   [+] $*"; }
skip() { N_AYNI=$((N_AYNI+1)); echo "[pcp-setup]   [=] $*"; }
kuru() { N_DEG=$((N_DEG+1));   echo "[pcp-setup]   [n] $* (kuru calisma: YAPILMADI)"; }
bilgi(){ echo "[pcp-setup]   $*"; }
die()  { echo "[pcp-setup] HATA: $1" >&2; exit "${2:-1}"; }
liste_icinde() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }

# ============================================================================
# ON KOSULLAR (playbook: assert)
# ============================================================================
[ "$(id -u)" -eq 0 ] || die "root olarak calistirin"
[ -r /etc/os-release ] || die "/etc/os-release yok - platform belirlenemedi"
# shellcheck disable=SC1091
. /etc/os-release
ANA_SURUM=${VERSION_ID%%.*}
AILE=RedHat
case " ${ID:-} ${ID_LIKE:-} " in
    *" rhel "*|*" fedora "*|*" centos "*)
        [[ $ANA_SURUM =~ ^[0-9]+$ ]] && [ "$ANA_SURUM" -ge 8 ] || die "RHEL 8 ve uzeri gerekir (${PRETTY_NAME:-?})" ;;
    *)  # Debian 13 (4.4; playbook-pcp v1.13): Ubuntu (ID=ubuntu, ID_LIKE=debian) ve Debian 12 ve oncesi sinanmadi
        [ "${ID:-}" = debian ] || die "Bu betik yalniz RHEL 8/9/10 ailesinde ve Debian 13'te calisir (${PRETTY_NAME:-?}); playbook-pcp v1.13 ile ayni platform."
        [ "$ANA_SURUM" = 13 ] || die "Debian'da yalniz 13 (trixie) desteklenir (${PRETTY_NAME:-?}); playbook-pcp v1.13 ile ayni platform."
        AILE=Debian ;;
esac
# Platform farklari (playbook 'On kosul - platform'): servis ayar dizini = pcp.conf PCP_SYSCONFIG_DIR; PCP kurulu degilken
# de dosya adlari bilinsin diye platformdan. Debian'da pcp-system-tools yoktur (araclar pcp paketinde).
if [ "$AILE" = Debian ]; then
    pcp_ayar_dizin=/etc/default; pcp_temel_paketler="pcp"; pcp_depo_ipucu="Debian main deposu (apt kaynaklari)"
else
    pcp_ayar_dizin=/etc/sysconfig; pcp_depo_ipucu="AppStream/BaseOS"
fi
pcp_timers_dosya=$pcp_ayar_dizin/pmlogger_timers

deger_kontrol() {   # AD IZINLI...
    local ad=$1; shift
    liste_icinde "${!ad}" "$*" || die "$ad gecersiz: '${!ad}' (gecerli: $*)"
}
deger_kontrol uygulama_modu rapor uygula
for v in kurulum_karari zeroconf_karari saklama_karari pmrep_sablon_karari dogrula_betigi_karari \
         pmda_kapatma_karari kayit_grubu_kapatma_karari pcp_gece_karari hotproc_karari pmie_karari; do
    deger_kontrol "$v" uygula dokunma
done
deger_kontrol proc_tum_surec_karari gerekirse dokunma
deger_kontrol eski_kurulum_karari otomatik dokunma
deger_kontrol kayit_profili dokunma tam varsayilan
deger_kontrol pcp_test_ortami true false
for v in pcp_gorunurluk_orani pcp_saklama_hedef_gun pcp_saklama_en_az_gun pcp_saklama_tolerans_gun \
         pcp_kurulum_bos_alan_mb pcp_gece_pencere_dk pcp_kontrol_pencere_dk \
         pcp_tam_diskag_aralik pcp_tam_aralik pcp_tam_donanim_aralik; do
    [[ ${!v} =~ ^[0-9]+$ ]] || die "$v tamsayi olmali: ${!v}"
done
[ "$pcp_gece_pencere_dk" -ge 30 ] && [ "$pcp_gece_pencere_dk" -le 600 ] || die "pcp_gece_pencere_dk 30..600 olmali (0 = tum sunucular ayni anda)"
[ "$pcp_kontrol_pencere_dk" -ge 5 ] && [ "$pcp_kontrol_pencere_dk" -le 29 ] || die "pcp_kontrol_pencere_dk 5..29 olmali"
[ "$pcp_gorunurluk_orani" -ge 10 ] && [ "$pcp_gorunurluk_orani" -le 100 ] || die "pcp_gorunurluk_orani 10..100 olmali"
[ "$pcp_saklama_en_az_gun" -ge 2 ] && [ "$pcp_saklama_en_az_gun" -le "$pcp_saklama_hedef_gun" ] \
    || die "pcp_saklama_en_az_gun 2..pcp_saklama_hedef_gun olmali"
# en az 8 gunun altina yalniz acik test ortami isaretiyle inilir (lab ayari canli ortama tasinirsa o gece eski arsiv silinmesin)
[ "$pcp_saklama_en_az_gun" -ge 8 ] || [ "$pcp_test_ortami" = true ] \
    || die "pcp_saklama_en_az_gun 8 altinda yalniz -e pcp_test_ortami=true ile (lab ayari canli ortama kopyalanmasin)"
[ "$pcp_tam_diskag_aralik" -ge 1 ] && [ "$pcp_tam_aralik" -ge 1 ] && [ "$pcp_tam_donanim_aralik" -ge 1 ] \
    || die "tam profil araliklari en az 1 sn olmali"
awk -v o="$pcp_paylasimli_oran" 'BEGIN { exit !(o ~ /^[0-9.]+$/ && o > 0 && o <= 0.8) }' \
    || die "pcp_paylasimli_oran 0 < oran <= 0.8 olmali"
for m in $pcp_kapali_pmdalar $pcp_ek_pmdalar; do
    [[ $m =~ ^[a-z0-9_]+$ ]] || die "PMDA adi gecersiz: $m"
done
for m in $pcp_kapali_pmdalar; do
    liste_icinde "$m" "$pcp_ek_pmdalar" && die "$m hem pcp_kapali_pmdalar hem pcp_ek_pmdalar icinde"
    liste_icinde "$m" "root pmcd proc linux xfs mmv pmproxy" && die "temel PMDA kapatilamaz: $m"
done
for p in $pcp_ek_paketler; do
    [[ $p =~ ^(pcp-[a-z0-9-]+|smartmontools|lm_sensors|lm-sensors)$ ]] || die "pcp_ek_paketler yalniz pcp-*, smartmontools, lm_sensors (Debian: lm-sensors): $p"
done

# UYGULAMA MODU: rapor = degisiklik YOK. Rapor kipinde -e ile verilen degisiklik karari kosumu BASTA
# durdurur (playbook v1.7: ek degisken set_fact ile ezilemez, yedeksiz degisiklik yapilirdi).
if [ "$uygulama_modu" != uygula ]; then
    for v in $KARAR_ADLARI; do
        liste_icinde "$v" "$VERILEN" || continue
        case "$v" in
            pcp_ek_pmdalar|pcp_ek_paketler) [ -z "${!v}" ] && continue ;;
            *) [ "${!v}" = dokunma ] && continue ;;
        esac
        die "uygulama_modu=rapor iken -e ile degisiklik karari verildi ($v=${!v}); rapor modunda hicbir degisiklik yapilmaz ve yedek alinmaz. Uygulamak icin -u ekleyin, yalniz rapor icin karar degiskenlerini kaldirin."
    done
fi
if [ "$uygulama_modu" != uygula ] || [ "$YALNIZ_DOGRULA" -eq 1 ]; then
    kurulum_karari=dokunma; zeroconf_karari=dokunma; proc_tum_surec_karari=dokunma
    saklama_karari=dokunma; pmrep_sablon_karari=dokunma; dogrula_betigi_karari=dokunma
    eski_kurulum_karari=dokunma; pmda_kapatma_karari=dokunma; kayit_grubu_kapatma_karari=dokunma
    pcp_gece_karari=dokunma; kayit_profili=dokunma; hotproc_karari=dokunma; pmie_karari=dokunma
    pcp_ek_pmdalar=""; pcp_ek_paketler=""
fi
if [ "$YALNIZ_DOGRULA" -eq 1 ]; then
    log "YALNIZ DOGRULAMA (playbook: --tags dogrula)"
elif [ "$uygulama_modu" != uygula ]; then
    log "UYGULAMA MODU: rapor - sistemde HICBIR degisiklik yapilmaz (tespit/rapor + dogrulama); uygulamak icin -u"
else
    log "UYGULAMA MODU: uygula$([ "$KURU" -eq 1 ] && echo ' (KURU CALISMA - hicbir sey degismez)') - kurulum=$kurulum_karari, zeroconf=$zeroconf_karari, proc -A=$proc_tum_surec_karari, saklama=$saklama_karari, sablon=$pmrep_sablon_karari, dogrula betigi=$dogrula_betigi_karari, eski kurulum=$eski_kurulum_karari, PMDA kapatma=$pmda_kapatma_karari ($(echo "${pcp_kapali_pmdalar:-yok}" | tr ' ' ',')), kayit profili=$kayit_profili, hotproc=$hotproc_karari, pmie=$pmie_karari, ek PMDA=$(echo "${pcp_ek_pmdalar:-yok}" | tr ' ' ',')"
fi
UYGULA=0; [ "$uygulama_modu" = uygula ] && [ "$KURU" -eq 0 ] && [ "$YALNIZ_DOGRULA" -eq 0 ] && UYGULA=1

# ============================================================================
# KURULUM (tespitten ONCE - dosyalar paketle gelir)
# ============================================================================
PCP_KURULUM_RC=0; PCP_KURULUM_DEGISTI=0; ZEROCONF_DEGISTI=0; PAKET_HATA=""
if [ "$AILE" = Debian ]; then
    paket_var() { [ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" = "install ok installed" ]; }
    paket_surum() { paket_var "$1" && dpkg-query -W -f='${Version}' "$1" 2>/dev/null; }
else
    paket_var() { rpm -q "$1" >/dev/null 2>&1; }
    paket_surum() { rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null; }
fi
# Debian: apt paket listesi yalniz kurulacak paket varsa ve liste 1 saatten eskiyse yenilenir (playbook: apt update_cache +
# cache_valid_time 3600 - yas, ansible apt modulu gibi update-success-stamp ya da lists dizininin zamanindan); kosum basina
# en cok bir kez. YUK NOTU: depoya ust veri istegi (lab'da liste dizini 152 MB acik hali; indirme boyutu OLCULMEDI).
APT_YENILENDI=0
apt_liste_yenile() {
    local d=/var/lib/apt/periodic/update-success-stamp
    [ "$APT_YENILENDI" -eq 1 ] && return 0
    APT_YENILENDI=1
    [ -e "$d" ] || d=/var/lib/apt/lists
    if [ -n "$(find "$d" -maxdepth 0 -mmin -60 2>/dev/null)" ]; then bilgi "apt paket listesi 1 saatten yeni (apt-get update atlandi)"; return 0; fi
    if [ "$UYGULA" -eq 0 ]; then bilgi "apt paket listesi yenilenecekti (kuru calisma: apt-get update YAPILMADI)"; return 0; fi
    if timeout 600 apt-get -q update >/dev/null 2>&1; then bilgi "apt paket listesi yenilendi"
    else bilgi "UYARI: apt paket listesi yenilenemedi - eski listeyle kurulum denendi; apt kaynaklari ($pcp_depo_ipucu) kontrol edilmeli"; fi
}
paket_kur() {   # PAKET... ; eksik yoksa 0 doner ve hicbir sey yapmaz; DEGISTI=1 kuruldu ya da (kuru) kurulacakti
    local eksik=() p g rc
    DEGISTI=0
    for p in "$@"; do paket_var "$p" || eksik+=("$p"); done
    [ ${#eksik[@]} -eq 0 ] && { skip "paket kurulu: $*"; return 0; }
    DEGISTI=1   # playbook --check: dnf / apt 'changed' doner
    [ "$AILE" = Debian ] && apt_liste_yenile
    if [ "$UYGULA" -eq 0 ]; then kuru "$([ "$AILE" = Debian ] && echo apt-get || echo dnf) install ${eksik[*]}"; return 0; fi
    g=$(mktemp) || die "mktemp basarisiz"
    if [ "$AILE" = Debian ]; then
        # playbook apt modulu ile ayni secenekler (Recommends yok, yapilandirma dosyasi sorusu yok)
        DEBIAN_FRONTEND=noninteractive apt-get -y -q -o APT::Install-Recommends=no -o Dpkg::Options::=--force-confdef \
            -o Dpkg::Options::=--force-confold install "${eksik[@]}" >"$g" 2>&1; rc=$?
    else
        dnf -y -q install "${eksik[@]}" >"$g" 2>&1; rc=$?
    fi
    if [ "$rc" -eq 0 ]; then rm -f "$g"; chg "kuruldu: ${eksik[*]}"; return 0; fi
    DEGISTI=0; PAKET_HATA=$(tail -3 "$g" | tr '\n' ' ' | cut -c1-160); rm -f "$g"
    return 1
}
BOS_ALAN=""
if [ "$YALNIZ_DOGRULA" -eq 0 ]; then
    log "Kurulum"
    # Bos alan kapisi (v1.8; v1.10: PCP kuruluyken pcp-zeroconf kurulacaksa da olcer - zeroconf surec kaydini acar,
    # gunluk arsiv buyur): rapor kipinde de olcer (salt okuma). Bolum doldurulmaz.
    BOS_ALAN=$(
        set -o pipefail
        if paket_var pcp; then
            KAPSAM="pcp-zeroconf"
            { paket_var pcp-zeroconf || [ "$zeroconf_karari" != uygula ]; } && { echo "KURULU"; exit 0; }
        else
            KAPSAM="PCP"
        fi
        for d in /var/log/pcp /var/log /var /; do [ -d "$d" ] && break; done
        read -r BOY KUL BOS <<< "$(df -Pm "$d" | awk 'NR==2{print $2, $3, $4}')"
        GEREK=$pcp_kurulum_bos_alan_mb
        echo "bolum $d: boyut ${BOY} MB, kullanilan ${KUL} MB, bos ${BOS} MB, gereken ${GEREK} MB (kurulacak: $KAPSAM)"
        if [ -z "$BOS" ] || [ "$BOS" -lt "$GEREK" ] || [ $(( (KUL + GEREK) * 100 )) -gt $(( BOY * 80 )) ]; then echo "YETERSIZ"; fi
    )
    case "$BOS_ALAN" in
        *YETERSIZ*) bilgi "SORUN: $([[ $BOS_ALAN == *"kurulacak: pcp-zeroconf"* ]] && echo pcp-zeroconf || echo PCP) KURULMADI - $(printf '%s\n' "$BOS_ALAN" | head -1); bos alan $pcp_kurulum_bos_alan_mb MB'tan az ya da kurulum sonrasi bolum %80'i asar. /var/log/pcp icin ayri LV ya da alan acilmali; sonra betik yeniden kosulur." ;;
        KURULU|"") ;;
        *) bilgi "Bos alan kapisi: $BOS_ALAN" ;;
    esac
    if [ "$kurulum_karari" = uygula ] && [[ $BOS_ALAN != *YETERSIZ* ]]; then
        # shellcheck disable=SC2086   # bilerek bolunur (paket listesi)
        if paket_kur $pcp_temel_paketler; then PCP_KURULUM_DEGISTI=$DEGISTI
        else PCP_KURULUM_RC=1; bilgi "SORUN: $(echo "$pcp_temel_paketler" | tr ' ' '/') kurulamadi ($PAKET_HATA). Depo tanimi ($pcp_depo_ipucu) kontrol edilmeli."; fi
    fi
    # 09.10.2026 lab dersi: pcp-zeroconf AYRI cagri (depoda yoksa tek cagrida hicbir paket kurulmuyordu)
    if [ "$zeroconf_karari" = uygula ] && [[ $BOS_ALAN != *YETERSIZ* ]]; then
        if paket_kur pcp-zeroconf; then ZEROCONF_DEGISTI=$DEGISTI
        else bilgi "BILGI: pcp-zeroconf kurulamadi ($PAKET_HATA). PCP temel kaydi surer; surec basina CPU kaydi (proc.psinfo.utime/stime) YAPILMAZ. Paket $([ "$AILE" = Debian ] && echo 'Debian main' || echo AppStream) deposundadir; depo tanimi kontrol edilmeli."; fi
    fi
    # v1.10: kurulum karari ve bos alan kapisi ek paketlere de uygulanir
    if [ "$kurulum_karari" = uygula ] && [[ $BOS_ALAN != *YETERSIZ* ]]; then
        for p in $pcp_ek_paketler; do
            paket_kur "$p" || bilgi "BILGI: $p kurulamadi (depoda yok olabilir) - ilgili izleme alani eksik kalir"
        done
    fi
    if [ "$kurulum_karari" = uygula ] && [ "$PCP_KURULUM_RC" -eq 0 ] && paket_var pcp; then
        for s in pmcd pmlogger; do
            if [ "$(systemctl is-enabled "$s" 2>/dev/null)" = enabled ] && systemctl is-active --quiet "$s"; then
                skip "$s etkin ve calisiyor"
            elif [ "$UYGULA" -eq 1 ]; then
                systemctl enable --now "$s" >/dev/null 2>&1 && chg "$s etkinlestirildi/baslatildi"
            else kuru "systemctl enable --now $s"; fi
        done
    fi
    # Debian 13 (playbook 'Kurulum - Debian paket servis varsayilanini RHEL son durumuna esitle'): paket betigi pmproxy'yi
    # ACILISTA BASLAYACAK bicimde etkinlestirir (44322; calisirsa uzak istemci pmcd verisine ulasir - -A kapisi) ve pmie'yi
    # calismaz birakir. Yalniz BU KOSUMDA kurulan pakette RHEL son durumu; once kurulmus PCP'de servislere dokunulmaz.
    # pmproxy calisiyorsa durdurulmaz (bu kosumdan once baslatilmis), raporlanir. Kuru calismada atlanir (playbook --check).
    if [ "$AILE" = Debian ] && [ "$UYGULA" -eq 1 ] && { [ "$kurulum_karari" = uygula ] || [ "$zeroconf_karari" = uygula ]; } \
        && { [ "$PCP_KURULUM_DEGISTI" -eq 1 ] || [ "$ZEROCONF_DEGISTI" -eq 1 ]; }; then
        if [ "$PCP_KURULUM_DEGISTI" -eq 1 ] && [[ $BOS_ALAN == *"kurulacak: PCP"* ]]; then
            if [ "$(systemctl is-enabled pmproxy 2>/dev/null || true)" = enabled ]; then
                if timeout 60 systemctl disable pmproxy >/dev/null 2>&1; then chg "pmproxy acilista baslamaz (disable; Debian paketi etkin birakmisti)"
                else bilgi "SORUN: pmproxy disable edilemedi - acilista baslar (uzak istemci pmcd verisine ulasabilir)"; fi
            fi
            systemctl is-active --quiet pmproxy 2>/dev/null && bilgi "UYARI: pmproxy CALISIYOR - durdurulmadi (bu kosumdan once baslatilmis)"
        fi
        if [ "$ZEROCONF_DEGISTI" -eq 1 ] && ! systemctl is-active --quiet pmie 2>/dev/null; then
            if timeout 90 systemctl enable --now pmie >/dev/null 2>&1; then chg "pmie baslatildi (RHEL pcp-zeroconf ile ayni son durum)"
            else bilgi "UYARI: pmie baslatilamadi (systemctl status pmie)"; fi
        fi
    fi
    # pcp-zeroconf paket betigi pmcd'yi yeniden baslatir, PMDA kurulumunu arka planda surdurur
    if [ "$kurulum_karari" = uygula ] && [ "$UYGULA" -eq 1 ] && { [ "$PCP_KURULUM_DEGISTI" -eq 1 ] || [ "$ZEROCONF_DEGISTI" -eq 1 ]; }; then
        # shellcheck disable=SC1091
        [ -f /etc/pcp.conf ] && . /etc/pcp.conf
        "${PCP_BINADM_DIR:-/usr/libexec/pcp/bin}/pmcd_wait" -t 60 && bilgi "pmcd hazir" || bilgi "UYARI: pmcd 60 sn icinde hazir olmadi"
    fi
fi

# ============================================================================
# TESPIT (salt okuma; her kosumda) - playbook ile ayni kabuk kodu
# ============================================================================
tespit() {
    paket_var pcp && echo "PCP=1" || echo "PCP=0"
    paket_var pcp-zeroconf && echo "ZEROCONF=1" || echo "ZEROCONF=0"
    echo "PCP_SURUM=$(paket_surum pcp || echo yok)"
    for s in pmcd pmlogger pmie; do echo "$(echo "$s" | tr a-z A-Z)=$(systemctl is-active "$s" 2>/dev/null || true)"; done
    # shellcheck disable=SC1091
    [ -f /etc/pcp.conf ] && . /etc/pcp.conf
    PMDAS=${PCP_PMDAS_DIR:-/var/lib/pcp/pmdas}
    SYSCONF=${PCP_SYSCONF_DIR:-/etc/pcp}
    # servis ayar dizini: RHEL /etc/sysconfig, Debian /etc/default (PCP kurulu degilken platformdan)
    SCD=${PCP_SYSCONFIG_DIR:-$pcp_ayar_dizin}
    TMF="$SCD/pmlogger_timers"
    PMCDCONF="$SYSCONF/pmcd/pmcd.conf"
    echo "PMCDCONF=$PMCDCONF"
    echo "PMDAS=$PMDAS"
    if grep -qE '^proc[[:space:]].*pmdaproc' "$PMCDCONF" 2>/dev/null; then
        echo "PROC_SATIR=1"
        if grep -E '^proc[[:space:]].*pmdaproc' "$PMCDCONF" | grep -qE '[[:space:]]-A([[:space:]]|$)'; then echo "PROC_A=1"; else echo "PROC_A=0"; fi
    else
        echo "PROC_SATIR=0"; echo "PROC_A=0"
    fi
    # Gorunurluk (yalniz pmcd calisiyorsa): karar surec basina G/C degerinden (/proc/<pid>/io yalniz sahibine acik)
    if systemctl is-active --quiet pmcd 2>/dev/null && command -v pminfo >/dev/null 2>&1; then
        R=$(timeout 60 pminfo -f proc.psinfo.pid 2>/dev/null | grep -c 'inst \[' || true)
        P=$(timeout 60 runuser -u pcp -- pminfo -f proc.psinfo.pid 2>/dev/null | grep -c 'inst \[' || true)
        RI=$(timeout 60 pminfo -f proc.io.read_bytes 2>/dev/null | grep -c 'inst \[' || true)
        PI=$(timeout 60 runuser -u pcp -- pminfo -f proc.io.read_bytes 2>/dev/null | grep -c 'inst \[' || true)
        echo "GOR_ROOT=${R:-0}"; echo "GOR_PCP=${P:-0}"; echo "IO_ROOT=${RI:-0}"; echo "IO_PCP=${PI:-0}"
    else
        echo "GOR_ROOT=0"; echo "GOR_PCP=0"; echo "IO_ROOT=0"; echo "IO_PCP=0"
    fi
    # pmcd yalniz yerel mi: PMCD_LOCAL=1 satiri ACIK olmali (RHEL 10.2 ve Debian 13 paketinde YORUMDA gelir)
    grep -qE '^[[:space:]]*PMCD_LOCAL=1' "$SCD/pmcd" 2>/dev/null && echo "PMCD_YEREL=1" || echo "PMCD_YEREL=0"
    if grep -qE '^[[:space:]]*PMCD_LOCAL=1' "$SCD/pmcd" 2>/dev/null; then echo "PMCD_LOCAL_SATIR=acik"
    elif grep -qE '^[[:space:]]*#[[:space:]]*PMCD_LOCAL' "$SCD/pmcd" 2>/dev/null; then echo "PMCD_LOCAL_SATIR=yorumda"
    else echo "PMCD_LOCAL_SATIR=yok"; fi
    systemctl is-active --quiet pmproxy 2>/dev/null && echo "PMPROXY=1" || echo "PMPROXY=0"
    CTRL=""
    for f in "$SYSCONF/pmlogger/control.d/local" "$SYSCONF/pmlogger/control"; do
        [ -f "$f" ] && grep -qE '^[^#]*LOCALHOSTNAME.*-c[[:space:]]' "$f" && { CTRL=$f; break; }
    done
    echo "CTRL=$CTRL"
    CC=""
    [ -n "$CTRL" ] && CC=$(grep -E '^[^#]*LOCALHOSTNAME' "$CTRL" | head -1 | grep -oE -- '-c[[:space:]]+[^[:space:]]+' | awk '{print $2}' || true)
    echo "CTRL_C=$CC"
    [ -f "$pcp_pmlogger_dizin/config.default" ] && echo "CONFIG_DEFAULT=1" || echo "CONFIG_DEFAULT=0"
    case "$CC" in /*) CF="$CC" ;; "") CF="" ;; *) CF="$pcp_pmlogger_dizin/$CC" ;; esac
    RK=""; [ -n "$CF" ] && [ -f "$CF" ] && RK=$(grep -oE "$pcp_a_riskli_desen" "$CF" | sort -u | tr '\n' ' ' || true)
    echo "RISKLI_KAYIT=$RK"
    # Saklama sahipleri (log-saklama yonetici() ile ayni isaretler). Sahip = pmlogger_timers'i GERCEKTEN yedekleyip
    # yazmis playbook (yedek dosyasi); yalniz dizin yetmez (v1.8). pcp-merkezi kendine ayrilmis iz dizini kullanir.
    SAHIP=""
    for ad in $pcp_saklama_yonetenler; do
        if [ "$ad" = pcp-merkezi ]; then [ -d "/var/backup/$ad" ] && SAHIP="$SAHIP $ad"
        else ls "/var/backup/$ad$TMF-"* >/dev/null 2>&1 && SAHIP="$SAHIP $ad"; fi
    done
    ls "/var/backup/log-saklama$TMF-"* >/dev/null 2>&1 && SAHIP="$SAHIP log-saklama"
    grep -qi 'ansible managed' "$TMF" 2>/dev/null && SAHIP="$SAHIP ansible-managed-basligi"
    echo "SAHIP=${SAHIP# }"
    KAYIT=""
    for ad in $pcp_kayit_yonetenler; do [ -d "/var/backup/$ad" ] && KAYIT="$KAYIT $ad"; done
    echo "KAYIT_SAHIP=${KAYIT# }"
    [ -f "$TMF" ] && echo "TIMERS=1" || echo "TIMERS=0"
    echo "DAILY=$(grep -E '^PMLOGGER_DAILY_PARAMS=' "$TMF" 2>/dev/null | tail -1 | sed -E 's/^[^=]*=//; s/^"//; s/"$//')"
    [ -x /usr/local/sbin/log-saklama-bekci ] && echo "LS_BEKCI=1" || echo "LS_BEKCI=0"
    systemctl cat pcp-log-guard.timer >/dev/null 2>&1 && echo "GUARD=1" || echo "GUARD=0"
    echo "GUARD_DURUM=$(systemctl is-active pcp-log-guard.timer 2>/dev/null || true)"
    echo "ESKI_ORIG=$(ls -1 "$SYSCONF"/pmlogger/control.d/*.pcp-setup.orig "$PMCDCONF".pcp-setup.orig 2>/dev/null | tr '\n' ' ')"
    [ -d "$SYSCONF/pmlogger/backup.pcp-setup" ] && echo "ESKI_YEDEK_DIZIN=1" || echo "ESKI_YEDEK_DIZIN=0"
    AKTIF=""; ISARETSIZ=""; BEKLEYEN=""
    for m in $pcp_kapali_pmdalar; do
        grep -qE "^${m}[[:space:]]" "$PMCDCONF" 2>/dev/null && AKTIF="$AKTIF $m"
        grep -qE "^#.*$m/pmda$m" "$PMCDCONF" 2>/dev/null || ISARETSIZ="$ISARETSIZ $m"
        ls "$PMDAS/$m"/.NeedInstall* >/dev/null 2>&1 && BEKLEYEN="$BEKLEYEN $m"
    done
    echo "PMDA_AKTIF=${AKTIF# }"; echo "PMDA_ISARETSIZ=${ISARETSIZ# }"; echo "PMDA_BEKLEYEN=${BEKLEYEN# }"
    [ -f "$PMDAS/proc/hotproc.conf" ] && echo "HOTPROC=1" || echo "HOTPROC=0"
    [ -d "$SYSCONF/pmrep" ] && echo "PMREP_DIZIN=1" || echo "PMREP_DIZIN=0"
    true
}
declare -A pt=()
while IFS= read -r satir; do
    [[ $satir =~ ^[A-Z_]+= ]] || continue
    pt[${satir%%=*}]=${satir#*=}
done < <(tespit 2>/dev/null)
v() { printf '%s' "${pt[$1]:-$2}"; }
bos_degil() { [ -n "$(echo "$1" | tr -d '[:space:]')" ]; }

# Saklama icin gun basina arsiv boyutu: rol playbook'lariyla AYNI olcum (govde playbook'tan aynen)
olcum_tam_gun() (
# PCP_OLCUM_TAM_GUN (rol playbooklarinda birebir ayni)
# Gun boyutu YALNIZ tamamlanmis TAM gunlerden: bugun olculmez, en eski tamamlanmis gun sayilmaz (kurulum gunu
# yarim olabilir), en az 2 tam gun yoksa olcum YOK -> en az gun. Eski yontem ilk kurulumda yarim gunu olcup disk
# boyutundan bagimsiz hedef gunu yaziyordu. Ham gun = parca sayisi x pmlogger -v
# ile olculen boyutun buyugu (yeniden baslatma gecesi birlestirilen gun ham yazilir); xz gun = tamami sikistirilmis
# gunlerin en buyugu. AYRI=0: /var/log/pcp ayri bolum degil (paylasilan bolumde pay dusuk tutulur).
set -o pipefail
# pmlogger_timers yeri pcp.conf icindeki PCP_SYSCONFIG_DIR: RHEL /etc/sysconfig, Debian /etc/default; pcp.conf yoksa RHEL yolu
TM=$( [ -f /etc/pcp.conf ] && . /etc/pcp.conf; printf '%s' "${PCP_SYSCONFIG_DIR:-/etc/sysconfig}" )/pmlogger_timers
LV=$(df -Pm /var/log/pcp 2>/dev/null | awk 'NR==2{print $2}')
# R2: tavan bolum boyutundan degil GERCEK alandan - bos alan + PCP agacinin kendi kullanimi (du: arsiv agaci, gun basina
# ~10 dosya; YUK NOTU: olculdu 25-30 ms, patroni-kurulum P5b). Bolumu baskasi doldurmussa saklama ona gore kisalir.
BOS=$(df -Pm /var/log/pcp 2>/dev/null | awk 'NR==2{print $4}')
KUL=$(du -sm /var/log/pcp 2>/dev/null | cut -f1)
if [ "$(findmnt --target /var/log/pcp -n -o TARGET 2>/dev/null)" = "/var/log/pcp" ]; then AYRI=1; else AYRI=0; fi
D=/var/log/pcp/pmlogger/$(hostname)
[ -d "$D" ] || D=$(find /var/log/pcp/pmlogger -maxdepth 2 -name '*.index*' -printf '%h\n' 2>/dev/null | head -1)
HAM=0; XZ=0; GUN=0
if [ -n "$D" ] && [ -d "$D" ]; then
    BUGUN=$(date +%Y%m%d)
    PC=/etc/pcp/pmlogger
    VOL=$(grep -hoE -- '-v[[:space:]]*[0-9]+[Mm][Bb]' $PC/control $PC/control.d/* 2>/dev/null | head -1 | tr -dc '0-9' || true)
    VOL=${VOL:-100}
    GUNLER=$(find "$D" -maxdepth 1 -mindepth 1 -printf '%f\n' | grep -oE '^[0-9]{8}' | sort -u | grep -vx "$BUGUN" || true)
    GUN=$(printf '%s\n' "$GUNLER" | grep -c . || true)
    if [ "$GUN" -ge 3 ]; then
        for p in $(printf '%s\n' "$GUNLER" | tail -n +2); do
            b=$(du -cm "$D"/"$p".* 2>/dev/null | tail -1 | cut -f1)
            PARCA=$(find "$D" -maxdepth 1 -name "$p.*" -printf '%f\n' 2>/dev/null | grep -vE '[.](index|meta)([.]|$)' \
                | grep -E '[.][0-9]+([.](xz|zst|gz|bz2|lzma))?$' || true)
            n=$(printf '%s\n' "$PARCA" | grep -c . || true)
            h=$((n * VOL)); [ "$b" -gt "$h" ] && h=$b
            [ "$h" -gt "$HAM" ] && HAM=$h
            if [ -n "$PARCA" ] && ! printf '%s\n' "$PARCA" | grep -qvE '[.](xz|zst|gz|bz2|lzma)$'; then
                [ "$b" -gt "$XZ" ] && XZ=$b
            fi
        done
    fi
fi
K=$(grep -E '^PMLOGGER_DAILY_PARAMS=' "$TM" 2>/dev/null | tail -1 \
    | grep -oE -- '-k[ =]?[0-9]+' | tr -dc '0-9' || true)
echo "LV_MB=${LV:-0} HAM_MB=$HAM XZ_MB=$XZ GUN=$GUN AYRI=$AYRI MEVCUT_K=${K:-0} BOS_MB=${BOS:-0} PCP_MB=${KUL:-0}"
# PCP_OLCUM_TAM_GUN_SON (playbook-pcp'den araclar/ortak-govde.sh ile alinir; elle degistirmeyin)
)
declare -A po=()
for kv in $(olcum_tam_gun 2>/dev/null | tail -1); do po[${kv%%=*}]=${kv#*=}; done
o() { printf '%s' "${po[$1]:-0}"; }

# --- kararlarin hesaplanmasi (playbook 'Tespit - kararlarin hesaplanmasi' ile ayni formul) ---
_lv=$(o LV_MB); _ham=$(o HAM_MB); _xz=$(o XZ_MB); [ "$_xz" -gt 0 ] || _xz=$_ham
if [ "$(o AYRI)" = 1 ]; then _oran=0.8; else _oran=$pcp_paylasimli_oran; fi
# Tavan (R2): bolum boyutu x pay, AMA bolumdeki baska veri dusulur - PCP ancak bolum %80'e ulasana kadar buyur
_bos=$(o BOS_MB); _pcp_kul=$(o PCP_MB)
_tavan=$(awk -v lv="$_lv" -v o="$_oran" -v b="$_bos" -v k="$_pcp_kul" 'BEGIN {
    a = int(lv * o); if (b > 0 || k > 0) { u = int(k + b - lv * 0.2); if (u < a) a = u }; printf "%d", a }')
if [ "$_lv" -gt 0 ] && [ "$_xz" -gt 0 ]; then
    _sigan=$(awk -v t="$_tavan" -v h="$_ham" -v x="$_xz" 'BEGIN { printf "%d", 2 + int((t - 2 * h) / x) }')
else _sigan=$pcp_saklama_en_az_gun; fi
# R7: pcp-zeroconf bu kosumda kurulduysa (kuru: kurulacaksa) olcum onceki kucuk gunlerden gelir -> hesap ERTELENIR
_ertele=0; [ "$ZEROCONF_DEGISTI" -eq 1 ] && [ "$_ham" -gt 0 ] && _ertele=1
_hesap=$_sigan; [ "$_hesap" -lt "$pcp_saklama_en_az_gun" ] && _hesap=$pcp_saklama_en_az_gun
[ "$_hesap" -gt "$pcp_saklama_hedef_gun" ] && _hesap=$pcp_saklama_hedef_gun
_mevcut=$(v DAILY "" | grep -oE -- '-k[ =]?[0-9]+' | head -1 | tr -dc '0-9'); _mevcut=${_mevcut:-0}
_koru=0
[ "$_mevcut" -ge "$pcp_saklama_en_az_gun" ] && [ "$_mevcut" -le "$_hesap" ] \
    && [ "$_mevcut" -ge $((_hesap - pcp_saklama_tolerans_gun)) ] && _koru=1
if [ "$_koru" -eq 1 ] || { [ "$_ertele" -eq 1 ] && [ "$_mevcut" -ge "$pcp_saklama_en_az_gun" ]; }; then pcp_saklama_gun=$_mevcut
elif [ "$_ertele" -eq 1 ]; then pcp_saklama_gun=$pcp_saklama_en_az_gun
else pcp_saklama_gun=$_hesap; fi
pcp_saklama_notu="LV $_lv MB ($([ "$(o AYRI)" = 1 ] && echo 'ayri bolum' || echo 'paylasilan bolum'), pay $_oran, tavan $_tavan MB, bos $_bos MB), gun ham $_ham / xz $_xz MB -> sigan $_sigan gun"
[ "$_ertele" -eq 1 ] && pcp_saklama_notu="$pcp_saklama_notu - SAKLAMA HESABI ERTELENDI: pcp-zeroconf bu kosumda kuruldu (surec kaydi baslar, olcum onceki kucuk gunlerden); 3 tam gun sonra yeniden kosulmali"
[ "$_ham" -eq 0 ] && pcp_saklama_notu="$pcp_saklama_notu (OLCUM YOK: en az 3 tamamlanmis gun gerekir, en az gun yazildi)"
[ "$_koru" -eq 1 ] && pcp_saklama_notu="$pcp_saklama_notu, mevcut -k $_mevcut korundu (hesap $_hesap, tolerans $pcp_saklama_tolerans_gun gun)"

_io_root=$(v IO_ROOT 0); _io_pcp=$(v IO_PCP 0)
pcp_gorunurluk_eksik=0
[ "$_io_root" -gt 0 ] && [ $((_io_pcp * 100)) -lt $((_io_root * pcp_gorunurluk_orani)) ] && pcp_gorunurluk_eksik=1
pcp_a_yaz=0
[ "$proc_tum_surec_karari" = gerekirse ] && [ "$(v PROC_SATIR 0)" = 1 ] && [ "$(v PROC_A 0)" = 0 ] \
    && [ "$pcp_gorunurluk_eksik" -eq 1 ] && [ "$(v PMCD_YEREL 0)" = 1 ] && [ "$(v PMPROXY 1)" = 0 ] \
    && ! bos_degil "$(v RISKLI_KAYIT)" && pcp_a_yaz=1
pcp_saklama_yaz=0
[ "$saklama_karari" = uygula ] && [ "$(v TIMERS 0)" = 1 ] && [ -z "$(v SAHIP)" ] && pcp_saklama_yaz=1
pcp_profil_tam=0
[ "$kayit_profili" = tam ] && [ -z "$(v KAYIT_SAHIP)" ] && [ -n "$(v CTRL)" ] && pcp_profil_tam=1
pcp_profil_varsayilan=0
[ "$kayit_profili" = varsayilan ] && [ -n "$(v CTRL)" ] && [ "$(v CTRL_C)" != config.default ] \
    && [ "$(v CONFIG_DEFAULT 0)" = 1 ] && pcp_profil_varsayilan=1
pcp_eski_guard_kapat=0
[ "$eski_kurulum_karari" = otomatik ] && [ "$(v GUARD 0)" = 1 ] && [ "$(v LS_BEKCI 0)" = 1 ] && pcp_eski_guard_kapat=1
pcp_pmda_kapat=0
[ "$pmda_kapatma_karari" = uygula ] && [ "$(v PCP 0)" = 1 ] \
    && { bos_degil "$(v PMDA_AKTIF)" || bos_degil "$(v PMDA_ISARETSIZ)" || bos_degil "$(v PMDA_BEKLEYEN)"; } && pcp_pmda_kapat=1
pcp_eski_orig_tasi=0
[ "$eski_kurulum_karari" = otomatik ] && { bos_degil "$(v ESKI_ORIG)" || [ "$(v ESKI_YEDEK_DIZIN 0)" = 1 ]; } && pcp_eski_orig_tasi=1
PMDAS=$(v PMDAS /var/lib/pcp/pmdas); PMCDCONF=$(v PMCDCONF /etc/pcp/pmcd/pmcd.conf)

# R7 (playbook'a ozgu nedenler): -A, hotproc, ek PMDA ve tam kayit profili de gun boyutunu buyutur -> hesap ERTELENIR
_neden=""
[ "$pcp_a_yaz" -eq 1 ] && _neden="$_neden; proc -A eklenecek"
[ "$hotproc_karari" = uygula ] && [ "$(v PCP 0)" = 1 ] && [ "$(v HOTPROC 0)" = 0 ] && _neden="$_neden; hotproc acilacak"
[ -n "$pcp_ek_pmdalar" ] && _neden="$_neden; ek PMDA $(echo "$pcp_ek_pmdalar" | tr ' ' ',')"
[ "$pcp_profil_tam" -eq 1 ] && _neden="$_neden; tam kayit profili"
if [ "$_ham" -gt 0 ] && [ -n "$_neden" ]; then
    if [ "$_mevcut" -ge "$pcp_saklama_en_az_gun" ]; then pcp_saklama_gun=$_mevcut; else pcp_saklama_gun=$pcp_saklama_en_az_gun; fi
    pcp_saklama_notu="$pcp_saklama_notu - SAKLAMA HESABI ERTELENDI: kayit hacmi bu kosumda degisiyor (${_neden#; }), olcum onceki gunlerden; 3 tam gun sonra betik yeniden kosulmali"
fi
SAKLAMA_SATIRI="PMLOGGER_DAILY_PARAMS=\"-E -x 1 -k $pcp_saklama_gun\""

# --- durum ozeti ---
log "Tespit"
if [ "$(v PCP 0)" = 1 ]; then _p="kurulu ($(v PCP_SURUM))"; else _p="KURULU DEGIL"; fi
bilgi "PCP $_p, pcp-zeroconf $([ "$(v ZEROCONF 0)" = 1 ] && echo var || echo yok); pmcd=$(v PMCD ?), pmlogger=$(v PMLOGGER ?), pmie=$(v PMIE ?)"
bilgi "Surec gorunurlugu: surec pcp $(v GOR_PCP ?) / root $(v GOR_ROOT ?); surec basina G/C degeri pcp $_io_pcp / root $_io_root; proc -A $([ "$(v PROC_A 0)" = 1 ] && echo var || echo yok) -> $([ "$pcp_gorunurluk_eksik" -eq 1 ] && echo "EKSIK (pcp < %$pcp_gorunurluk_orani)" || echo 'yeterli ya da olculemedi'); pmcd $([ "$(v PMCD_YEREL 0)" = 1 ] && echo 'yalniz yerel (PMCD_LOCAL=1)' || echo "UZAK baglanti kabul edebilir ($pcp_ayar_dizin/pmcd PMCD_LOCAL=1 satiri $(v PMCD_LOCAL_SATIR yok))"), pmproxy $([ "$(v PMPROXY 0)" = 1 ] && echo CALISIYOR || echo calismiyor); kayitta riskli metrik: $(bos_degil "$(v RISKLI_KAYIT)" && v RISKLI_KAYIT || echo yok)"
bilgi "Kapatilacak PMDA'lar ($(echo "${pcp_kapali_pmdalar:-yok}" | tr ' ' ',')): pmcd.conf'ta etkin $(v PMDA_AKTIF | grep . || echo yok); yeniden kurulum isareti eksik $(v PMDA_ISARETSIZ | grep . || echo yok); bekleyen .NeedInstall $(v PMDA_BEKLEYEN | grep . || echo yok)"
bilgi "Kayit: birincil pmlogger -c $(v CTRL_C ? | grep . || echo ?) ($(v CTRL | grep . || echo 'kontrol satiri yok')); yonetenler: $(v KAYIT_SAHIP | grep . || echo yok)"
# 3.x kurulumundan kalan kayit yapilandirmasi (disk+ag 1 sn, tum surecler 60 sn) - playbook da dokunmaz, yalniz raporlanir
[ "$(v CTRL_C)" = config.pcp-full ] && bilgi "BILGI: kayit eski pcp-setup 3.x yapilandirmasinda (config.pcp-full: disk+ag 1 sn). Onerilen kayda donmek icin: -u -e kayit_profili=varsayilan"
# 3.x'in kosulsuz actigi, bu surumde varsayilan KAPALI olan kalemler: yalniz raporlanir (karar kullanicinin)
_iz=""
for m in lmsensors smart bonding sockets perfevent bcc bpftrace; do
    grep -qE "^${m}[[:space:]]" "$PMCDCONF" 2>/dev/null && _iz="$_iz PMDA:$m"
done
[ -d /var/lib/pcp-setup ] && _iz="$_iz /var/lib/pcp-setup"
[ "$(v CTRL_C)" != config.pcp-full ] && [ -f "$pcp_pmlogger_dizin/config.pcp-full" ] && _iz="$_iz kullanilmayan-config.pcp-full"
[ -n "$_iz" ] && bilgi "BILGI: varsayilan KAPALI kalemlerden etkin olanlar / eski izler:$_iz (dokunulmaz; PCP_EL_KITABI.md 17.9 gecis listesi)"
bilgi "Saklama: PMLOGGER_DAILY_PARAMS=\"$(v DAILY)\"; sahip: $(v SAHIP | grep . || echo yok); bu betigin kurali $pcp_saklama_gun gun ($pcp_saklama_notu)"
bilgi "Disk korumasi: log-saklama bekcisi $([ "$(v LS_BEKCI 0)" = 1 ] && echo VAR || echo yok); eski pcp-log-guard $([ "$(v GUARD 0)" = 1 ] && echo "VAR ($(v GUARD_DURUM))" || echo yok); eski pcp-setup yedekleri: $(bos_degil "$(v ESKI_ORIG)" && v ESKI_ORIG || echo yok)$([ "$(v ESKI_YEDEK_DIZIN 0)" = 1 ] && echo ' + backup.pcp-setup dizini')"

# ============================================================================
# GOMULU DOSYALAR (playbook-pcp/pcp_files ile BAYT BAYT AYNI - araclar/tutarlilik.sh denetler)
# ============================================================================
gomulu_ozel_conf() {
cat <<'OZEL_EOF'
# pcp-onlem (playbook-pcp) tarafindan kurulur; elle degistirmeyin.
# Kullanim:  pmrep -t 1s -z :canli        (canli, tek ekranda dort alt sistem)
#            pmrep -t 2s -J 10 -6 proc.hog.cpu :obur | head -12
#            pmrep -a ARSIV -Z Europe/Istanbul -S @03:00 -T @04:00 -t 5m :canli   (gecmis)

# --- :canli  CPU + RAM + Disk + Ag tek satirda -------------------------------
[canli]
header = yes
unitinfo = no
instinfo = no
globals = no
timestamp = yes
precision = 1
delimiter = " "
repeat_header = 20
kernel.cpu.util.user  = cpu_us,,,,6
kernel.cpu.util.sys   = cpu_sy,,,,6
kernel.cpu.util.wait  = cpu_wa,,,,6
kernel.all.load       = load1,1 minute,,,6
mem.util.used         = mem_use,,MB,,8
mem.util.available    = mem_free,,MB,,8
disk.all.read_bytes   = dsk_rd,,KB,,8
disk.all.write_bytes  = dsk_wr,,KB,,8
disk.all.total        = iops,,,,7
network.all.in.bytes  = net_in,,KB,,8
network.all.out.bytes = net_out,,KB,,8

# --- :obur  en cok kaynak yiyen prosesler (siralamak icin -J ve -6 gerekir) ---
[obur]
header = yes
instinfo = no
unitinfo = no
globals = no
timestamp = yes
precision = 1
delimiter = " "
repeat_header = 15
colxrow = "    PID / Komut satiri"
proc.hog.cpu = CPU_pct,,,,8

# --- :agirlik  disk cihaz basina doygunluk/gecikme ---------------------------
[agirlik]
header = yes
instinfo = no
unitinfo = no
globals = no
timestamp = yes
precision = 2
delimiter = " "
repeat_header = 20
colxrow = "     Cihaz"
disk.dev.util     = util_pct,,,,9
disk.dev.await    = await_ms,,,,9
disk.dev.avg_qlen = kuyruk,,,,8
disk.dev.read_bytes  = oku_KB,,KB,,9
disk.dev.write_bytes = yaz_KB,,KB,,9
OZEL_EOF
}

gomulu_hotproc_conf() {
cat <<'HOTPROC_EOF'
#pmdahotproc
Version 1.0
# pcp-onlem (playbook-pcp; hotproc_karari=uygula): CPU payi %10'u asan VEYA 100 MB'tan cok RSS
# kullanan prosesler "sicak" sayilir ve hotproc.* altinda ayrica izlenir.
cpuburn > 0.10 || residentsize > 102400
HOTPROC_EOF
}

# playbook-pcp/pcp_templates/config.pcp-tam.j2 ile ayni cikti (trim_blocks)
tam_config() {   # $1 devnet  $2 sys  $3 proc  $4 hw  $5 hinv (satir listeleri, sonda yeni satir yok)
    cat <<EOF
# $playbook_adi (playbook-pcp) tarafindan uretildi - elle degistirmeyin.
# Kayit profili: tam (kayit_profili=tam). Liste kurulum anindaki canli metrik
# agacindan uretilmistir. Bilerek DISLANANLAR:
#   - turetilmis metrikler (PMID domain 511): pmcd yeniden basladiginda pmlogger
#     hata dongusune girip pmlogger.log'u sisirebiliyor; analiz araclari bunlari
#     temel metriklerden hesaplar
#   - proc.psinfo.environ: sureclerin ortam degiskenleri (parola sizintisi riski)
#   - proc.memory.maps: her surecin /proc/<pid>/maps dosyasini okur (mmap_lock;
#     buyuk bellekli surecte etkisi OLCULMEDI - yuk kurali 01.10.2026)

# --- disk ve ag: her disk, bolum ve ag karti ayri ---------------------------
log mandatory on every $pcp_tam_diskag_aralik seconds {
$1
}

# --- sistem geneli: CPU, bellek, dosya sistemi, NFS -------------------------
log mandatory on every $pcp_tam_aralik seconds {
$2
}

# --- surec ayrintilari (kullanici kimlikleriyle) -----------------------------
log mandatory on every $pcp_tam_aralik seconds {
$3
}
EOF
    if bos_degil "$4"; then
        cat <<EOF

# --- donanim: sensorler, disk sagligi (SMART) -------------------------------
log advisory on every $pcp_tam_donanim_aralik seconds {
$4
}
EOF
    fi
    cat <<EOF

# --- donanim envanteri (arsiv basina bir kez) --------------------------------
log mandatory on once {
$5
}

[access]
disallow .* : all;
disallow :* : all;
allow local:* : enquire;
EOF
}

KAYNAK_DOGRULA="$BETIK_DIZIN/pcp-dogrula.sh"
# Betigin kendi kurdugu dosya kaynakla AYNIYSA yedeklenmez (ikinci kosum 0 degisiklik)
kaynak_sha() {   # DOSYA -> kaynak icerigin sha256'si (yoksa bos)
    [ "$1" = /etc/pcp/pmrep/ozel.conf ] && { gomulu_ozel_conf | sha256sum | awk '{print $1}'; return; }
    [ "$1" = "$pcp_dogrula_yol" ] && [ -f "$KAYNAK_DOGRULA" ] && { sha256sum < "$KAYNAK_DOGRULA" | awk '{print $1}'; return; }
    true
}

# ============================================================================
# YEDEK (degisiklikten ONCE; yalniz YAZILACAK dosyalar)
# ============================================================================
YOK_DOSYALAR=""   # kosum basinda var olmayan dosyalar (R13: kosum sonunda olusmussa manifeste OLUSTURULDU)
yedekle() {   # DOSYA... ; playbook 'Yedek - degistirilecek dosyalari zaman damgasiyla yedekle'
    local KOK=$yedek_kok DAMGA=$yedek_damga MANIFEST f KS h zaten y
    MANIFEST="$KOK/_kosum-$DAMGA.txt"
    for f in "$@"; do
        [ -f "$f" ] || { YOK_DOSYALAR="$YOK_DOSYALAR $f"; continue; }
        KS=$(kaynak_sha "$f")
        [ -n "$KS" ] && [ "$(sha256sum "$f" | awk '{print $1}')" = "$KS" ] && continue
        # saklama satiri zaten yazilacak degerse dosya degismeyecek: yedek yok (ikinci kosum 0 degisiklik)
        [ "$f" = "$pcp_timers_dosya" ] && grep -qxF "$SAKLAMA_SATIRI" "$f" && continue
        h="$KOK$f"
        zaten=0
        for y in $(ls -1 "$h"-* 2>/dev/null | sort -r); do
            [ -f "$y" ] || continue
            if cmp -s "$f" "$y"; then zaten=1; break; fi
        done
        [ "$zaten" -eq 1 ] && continue
        if [ "$UYGULA" -eq 0 ]; then kuru "yedek: $f -> $h-$DAMGA"; continue; fi
        # yedek alinamazsa (/var/backup dolu, salt okunur...) "yedek" denmez, manifeste satir yazilmaz (playbook ile ayni)
        if mkdir -p "$(dirname "$h")" && chmod 0700 "$KOK" && cp -aL "$f" "$h-$DAMGA" && cmp -s "$f" "$h-$DAMGA" \
            && printf '%s  %s  %s\n' "$(sha256sum "$f" | awk '{print $1}')" "$f" "$h-$DAMGA" >> "$MANIFEST"; then
            chg "yedek: $f -> $h-$DAMGA"
        else
            bilgi "SORUN: $f yedeklenemedi ($h-$DAMGA)"; YEDEK_HATA=1
        fi
    done
}

YEDEK=()
if [ "$YALNIZ_DOGRULA" -eq 0 ] && [ "$uygulama_modu" = uygula ]; then
    { [ "$pcp_a_yaz" -eq 1 ] || [ -n "$pcp_ek_pmdalar" ] || [ "$pcp_pmda_kapat" -eq 1 ]; } && YEDEK+=("$PMCDCONF")
    [ "$pcp_saklama_yaz" -eq 1 ] && YEDEK+=("$pcp_timers_dosya")
    { [ "$pcp_profil_tam" -eq 1 ] || [ "$pcp_profil_varsayilan" -eq 1 ]; } && YEDEK+=("$(v CTRL)")
    [ "$pcp_profil_tam" -eq 1 ] && YEDEK+=("$pcp_pmlogger_dizin/$pcp_tam_ad")
    [ "$hotproc_karari" = uygula ] && YEDEK+=("$PMDAS/proc/hotproc.conf")
    [ "$pmrep_sablon_karari" = uygula ] && YEDEK+=(/etc/pcp/pmrep/ozel.conf)
    [ "$pmie_karari" = uygula ] && YEDEK+=("$pcp_pmie_yapilandirma")
    [ "$dogrula_betigi_karari" = uygula ] && YEDEK+=("$pcp_dogrula_yol")
    YEDEK_HATA=0
    if [ ${#YEDEK[@]} -gt 0 ]; then log "Yedek ($yedek_kok)"; yedekle "${YEDEK[@]}"; fi
    [ "$YEDEK_HATA" -eq 0 ] || die "yedek alinamadi - bu sunucuda hicbir yapilandirma dosyasi degistirilmedi; once $yedek_kok alanini duzeltin" 3
fi

# ============================================================================
# ESKI pcp-setup 3.x KURULUMU IZLERI (taranan dizinlerden /var/backup'a tasima)
# ============================================================================
tasi() {   # YOL ETIKET
    local k=$1 etiket=$2 KOK=$yedek_kok DAMGA=$yedek_damga h OZ
    [ -e "$k" ] || return 0
    h="$KOK/eski-pcp-setup$k-$DAMGA"
    if [ "$UYGULA" -eq 0 ]; then kuru "tasi: $k -> $h"; return 0; fi
    mkdir -p "$(dirname "$h")"; chmod 0700 "$KOK"
    if [ -f "$k" ]; then OZ=$(sha256sum "$k" | awk '{print $1}'); else OZ=dizin; fi
    mv "$k" "$h" && { printf '%s  %s (%s)  %s\n' "$OZ" "$k" "$etiket" "$h" >> "$KOK/_kosum-$DAMGA.txt"; chg "tasindi: $k -> $h"; }
}
if [ "$YALNIZ_DOGRULA" -eq 0 ]; then
    if [ "$pcp_eski_orig_tasi" -eq 1 ]; then
        log "Eski pcp-setup izleri"
        for f in $(v ESKI_ORIG); do tasi "$f" "eski pcp-setup izi"; done
        tasi /etc/pcp/pmlogger/backup.pcp-setup "eski pcp-setup izi"
    fi
    if [ "$pcp_eski_guard_kapat" -eq 1 ]; then
        log "Eski pcp-log-guard (log-saklama bekcisi var - tek silici)"
        if [ "$UYGULA" -eq 1 ]; then
            systemctl disable --now pcp-log-guard.timer >/dev/null 2>&1 || true
            systemctl stop pcp-log-guard.service >/dev/null 2>&1 || true
        else kuru "systemctl disable --now pcp-log-guard.timer"; fi
        for k in /etc/systemd/system/pcp-log-guard.timer /etc/systemd/system/pcp-log-guard.service \
                 /usr/local/sbin/pcp-log-guard.sh /etc/pcp/pcp-log-guard.conf; do
            [ -f "$k" ] && tasi "$k" "eski pcp-log-guard"
        done
        [ "$UYGULA" -eq 1 ] && timeout 120 systemctl daemon-reload
    elif [ "$(v GUARD 0)" = 1 ]; then
        bilgi "BILGI: eski pcp-log-guard bekcisi bu sunucuda kaliyor ($(v GUARD_DURUM ?)) - log-saklama bekcisi yok, /var/log/pcp icin baska disk korumasi bulunmuyor. Tek silici ilkesi icin log-saklama (playbook-log-saklama) uygulandiktan sonra bu betik tekrar kosulursa bekci kapatilip tasinir."
    fi
fi

# ============================================================================
# PMDA KAPATMA (dm, kvm, nfsclient, openmetrics, opentelemetry + eski adlar)
# ============================================================================
PMDA_KALDIRILDI=0
if [ "$YALNIZ_DOGRULA" -eq 0 ] && [ "$pcp_pmda_kapat" -eq 1 ]; then
    log "PMDA kapatma ($(echo "$pcp_kapali_pmdalar" | tr ' ' ','))"
    if [ "$UYGULA" -eq 0 ]; then
        for m in $(v PMDA_AKTIF); do kuru "$m PMDA kaldirilacak ($PMDAS/$m/Remove)"; done
        for m in $(v PMDA_BEKLEYEN); do kuru "$m bekleyen .NeedInstall /var/backup agacina tasinacak"; done
        for m in $(v PMDA_ISARETSIZ); do kuru "$m icin pmcd.conf'a yeniden kurulum isareti yazilacak"; done
    else
        P=$PMDAS; C=$PMCDCONF; KOK=$yedek_kok; DAMGA=$yedek_damga
        # pmcd otomatik PMDA kurulumu suruyorsa bitmesi beklenir (sifir sunucu yarisi); ust sinir 180 sn
        for _ in $(seq 1 90); do
            [ -e "$P/pmda.auto.update" ] || ls "$P"/*/.NeedInstall.pending >/dev/null 2>&1 || break
            sleep 2
        done
        [ -e "$P/pmda.auto.update" ] && bilgi "UYARI: pmcd PMDA kurulumu 180 sn icinde bitmedi ($P/pmda.auto.update)"
        for m in $pcp_kapali_pmdalar; do
            for e in "" .pending .failed; do
                [ -e "$P/$m/.NeedInstall$e" ] || continue
                h="$KOK$P/$m/.NeedInstall$e-$DAMGA"
                mkdir -p "$(dirname "$h")"; chmod 0700 "$KOK"
                mv "$P/$m/.NeedInstall$e" "$h" && printf '%s  %s (bekleyen kurulum)  %s\n' bos "$P/$m/.NeedInstall$e" "$h" >> "$KOK/_kosum-$DAMGA.txt"
                chg "tasindi: $P/$m/.NeedInstall$e"
            done
            if grep -qE "^${m}[[:space:]]" "$C"; then
                if [ -x "$P/$m/Remove" ]; then
                    L="$KOK/_remove-$m-$DAMGA.log"; mkdir -p "$KOK"; chmod 0700 "$KOK"
                    ( cd "$P/$m" && timeout 120 ./Remove ) > "$L" 2>&1 || true
                    if grep -qE "^${m}[[:space:]]" "$C"; then
                        bilgi "SORUN: $m pmcd.conf icinden kaldirilamadi (gunluk: $L)"
                    else
                        chg "kaldirildi: $m"; PMDA_KALDIRILDI=1; rm -f "$L"
                    fi
                else
                    # paket kaldirilmis, pmcd.conf satiri kalmis. R25: gecici dosya ayni dizinde (cp -a: sahiplik/SELinux
                    # baglami korunur), mv ile tek adimda yer degistirir - 'cat >' dosyayi once kisaltiyordu
                    G="$C.pcp-onlem.$$"
                    if cp -a "$C" "$G" && { grep -vE "^${m}[[:space:]]" "$C" || true; } > "$G" && mv -f "$G" "$C" \
                        && ! grep -qE "^${m}[[:space:]]" "$C"; then
                        chg "kaldirildi: $m (Remove betigi yok - paket kaldirilmis; satir silindi)"; PMDA_KALDIRILDI=1
                    else
                        rm -f "$G"; bilgi "SORUN: $m satiri pmcd.conf icinden silinemedi ($P/$m/Remove yok)"
                    fi
                fi
            fi
            # Yeniden kurulum isareti PMDA dizini olmasa da yazilir: pcp-zeroconf paket betigi dizin yoksa da arar
            if ! grep -qE "^#.*$m/pmda$m" "$C"; then
                S="# pcp-onlem: $m/pmda$m KAPALI (yuk kurali) - bu satir pcp-zeroconf paket betiginin PMDA yi yeniden kurmasini engeller"
                if grep -qE '^\[access\]' "$C"; then
                    G="$C.pcp-onlem.$$"
                    { cp -a "$C" "$G" && awk -v s="$S" 'BEGIN{y=0} /^\[access\]/ && !y {print s; y=1} {print}' "$C" > "$G" \
                        && mv -f "$G" "$C"; } || rm -f "$G"
                else
                    printf '%s\n' "$S" >> "$C" || true
                fi
                # R25: yazim sonucu dosyadan dogrulanir - basarisizlik "isaret" diye gizlenmez
                if grep -qE "^#.*$m/pmda$m" "$C"; then chg "isaret: $m"
                else bilgi "SORUN: $m icin pmcd.conf isareti yazilamadi (dosya yazilabilir mi?)"; fi
            fi
        done
    fi
fi

# ============================================================================
# KESMELERI KAPATAN KAYIT GRUPLARI (pmlogconf force exclude)
# ============================================================================
if [ "$YALNIZ_DOGRULA" -eq 0 ] && [ "$(v PCP 0)" = 1 ] && [ "$kayit_grubu_kapatma_karari" = uygula ]; then
    log "Kayit grubu kapatma ($(echo "$pcp_kapali_kayit_gruplari" | tr ' ' ','))"
    # shellcheck disable=SC1091
    [ -f /etc/pcp.conf ] && . /etc/pcp.conf
    GD=${PCP_VAR_DIR:-/var/lib/pcp}/config/pmlogconf
    C=${PCP_VAR_DIR:-/var/lib/pcp}/config/pmlogger/config.default
    KOK=$yedek_kok; DAMGA=$yedek_damga
    if [ ! -d "$GD" ]; then
        bilgi "pmlogconf grup dizini yok - atlandi"
    else
        METRIK=""; GRUP_DEG=0; GECICI=""
        # v1.11 (P3): kesilen kosumda gecici dosya silinir (grup dizininde kalan dosyayi pmlogconf ayri grup sanardi)
        trap 'rm -f $GECICI' EXIT
        for g in $pcp_kapali_kayit_gruplari; do
            f=$(readlink -f "$GD/$g" 2>/dev/null) || continue
            [ -f "$f" ] || continue
            METRIK="$METRIK $(awk '/^[[:space:]]+[a-z]/{print $1}' "$f" | tr '\n' ' ')"
            if grep -qE '^[[:space:]]*force[[:space:]]+exclude' "$f"; then skip "$g force exclude"; continue; fi
            if [ "$UYGULA" -eq 0 ]; then kuru "$g grup dosyasi force exclude yapilacak ($f)"; GRUP_DEG=1; continue; fi
            h="$KOK$f-$DAMGA"; mkdir -p "$(dirname "$h")" "$KOK"; chmod 0700 "$KOK"
            # v1.11 (P3): yedek alinamazsa dosyaya DOKUNULMAZ; gecici dosya ayni dizinde (cp -a: sahiplik ve SELinux
            # baglami korunur), mv ile tek adimda yer degistirir; sonuc dosyadan dogrulanir (playbook ile ayni)
            if ! cp -a "$f" "$h"; then bilgi "SORUN: $f yedeklenemedi ($h) - $g grubu kapatilmadi"; continue; fi
            printf '%s  %s  %s\n' "$(sha256sum "$f" | awk '{print $1}')" "$f" "$h" >> "$KOK/_kosum-$DAMGA.txt"
            NOT="# $playbook_adi: force exclude (yuk kurali) - kesmeleri kapatan bolge kilidi okumasi kayda alinmaz"
            GT="$f.pcp-onlem.$$"; GECICI="$GECICI $GT"
            if cp -a "$f" "$GT" && awk -v n="$NOT" 'NR==1{print; print n; next}
                /^[[:space:]]*(probe|force)[[:space:]]/{if(!y){print "force exclude"; y=1}; next} {print}
                END{if(!y) print "force exclude"}' "$h" > "$GT" && mv -f "$GT" "$f" \
                && grep -qE '^[[:space:]]*force[[:space:]]+exclude' "$f"; then
                chg "kapatildi: $g"
            else
                rm -f "$GT"; bilgi "SORUN: $g grubu kapatilamadi ($f yazilamadi)"
            fi
        done
        KALAN=0
        for m in $METRIK; do grep -qE "^[[:space:]]+$m$" "$C" 2>/dev/null && KALAN=1; done
        if [ "$KALAN" -eq 1 ]; then
            if [ "$UYGULA" -eq 0 ]; then
                kuru "kayit yapilandirmasindan kapatilan grup metrikleri cikarilacak ($C), pmlogger yeniden baslatilacak"
            else
                h="$KOK$C-kayit-$DAMGA"; mkdir -p "$(dirname "$h")" "$KOK"; chmod 0700 "$KOK"
                CT="$C.pcp-onlem.$$"; GECICI="$GECICI $CT"
                # pmlogconf ACIK (y) grubu -r ile bile kapatmaz: grup 'n' yapilip blogu cikarilir (v1.11: yedek
                # alinamazsa ya da yazilamazsa kayit yapilandirmasi yenilenmez, gecici dosya + mv)
                if ! cp -a "$C" "$h"; then
                    bilgi "SORUN: $C yedeklenemedi ($h) - kayit yapilandirmasi yenilenmedi"
                elif ! { printf '%s  %s  %s\n' "$(sha256sum "$C" | awk '{print $1}')" "$C" "$h" >> "$KOK/_kosum-$DAMGA.txt" \
                    && cp -a "$C" "$CT" && awk -v g="$pcp_kapali_kayit_gruplari" 'BEGIN{n=split(g,a," "); for(i=1;i<=n;i++) h[a[i]]=1}
                    /^#\+ /{split(substr($0,4),p,":"); if(p[1] in h){print "#+ " p[1] ":n:" p[3] ":"; atla=1; next}}
                    atla&&/^#----/{atla=0} !atla{print}' "$h" > "$CT" && mv -f "$CT" "$C"; }; then
                    rm -f "$CT"; bilgi "SORUN: $C yazilamadi - kayit yapilandirmasi yenilenmedi"
                else
                # pmlogconf YALNIZ pcp kullanicisiyla (root olarak slabinfo grubunu acar - olculdu)
                timeout 120 runuser -u pcp -- pmlogconf -r -c -q "$C" </dev/null >/dev/null 2>&1 || bilgi "UYARI: pmlogconf basarisiz ya da 120 sn icinde bitmedi"
                K2=0
                for m in $METRIK; do grep -qE "^[[:space:]]+$m$" "$C" && K2=1; done
                if [ "$K2" -eq 1 ]; then
                    bilgi "SORUN: kayit yapilandirmasinda kapatilan grup metrikleri kaldi ($C)"
                else
                    chg "kayit yapilandirmasi yenilendi"
                    timeout 90 systemctl restart pmlogger || bilgi "UYARI: pmlogger yeniden baslatilamadi"
                fi
                fi
            fi
        elif [ "$GRUP_DEG" -eq 0 ]; then
            skip "kapatilan grup metrikleri kayitta yok"
        fi
    fi
fi

# ============================================================================
# GECE ISLERI YUK DAGITIMI (olcek kurali 400-1000 VM; govde playbook'tan AYNEN)
# ============================================================================
# PCP zamanlayicilari paket varsayilaninda HER SUNUCUDA AYNI DAKIKADA calisir. Sunucunun KISA ADININ ozetinden
# sabit kaydirma: gunluk isler RHEL 9/10 00:10 (RHEL 8 ailesi ve PCP < 6: 03:10) + 0..pcp_gece_pencere_dk dk, yarim
# saatlik isler 0..pcp_kontrol_pencere_dk dk. Gece raporu kapatilir; gecis kapisi uygulama anindaki daemon-reload'un
# gece isini hemen calistirmasini onler; Persistent=false toplu acilista ayni anda birlestirmeyi onler.
# Zamanlayicilar YENIDEN BASLATILMAZ (pmlogger.service BindsTo) - yalniz daemon-reload. PCP_EL_KITABI.md 17.18.
# shellcheck disable=SC1090   # govde playbook ile birebir: /etc/os-release kaynaklanir
gece_yay() (
# PCP_GECE_YAYMA (rol playbooklarinda birebir ayni)
set -o pipefail
[ -f /etc/pcp.conf ] && . /etc/pcp.conf
BIN=${PCP_BINADM_DIR:-/usr/libexec/pcp/bin}
SD=/etc/systemd/system
DOSYA=50-yuk-dagitimi.conf
KOK="$yedek_kok"
DAMGA="$yedek_damga"
PG=$pcp_gece_pencere_dk
PK=$pcp_kontrol_pencere_dk
[ -x "$BIN/pmlogger_daily" ] || { echo "PCP kurulu degil - atlandi"; exit 0; }
# Pencere 0 KABUL EDILMEZ (kalite denetimi R20): PG=0 tum sunucularin gunluk isini ayni saniyeye, PK=0 yarim
# saatlik isleri ayni dakikaya dusurur - olcek kurali bozulur. En az gece 30 dk (1000 VM icin dakikada ~33), kontrol 5 dk.
if [ "$PG" -lt 30 ] || [ "$PG" -gt 600 ] || [ "$PK" -lt 5 ] || [ "$PK" -gt 29 ]; then
    echo "SORUN: pencere degeri gecersiz (gece 30-600 dk, kontrol 5-29 dk; 0 = tum sunucular ayni anda) - dokunulmadi"; exit 0
fi
if [ -f /etc/cron.d/pcp-pmlogger ]; then
    echo "BILGI: PCP gece isleri cron ile calisiyor (/etc/cron.d/pcp-pmlogger) - systemd zamanlayicilarina dokunulmadi"; exit 0
fi
AD=$(hostname -s 2>/dev/null || true)
[ -n "$AD" ] || AD=$(cut -d. -f1 /proc/sys/kernel/hostname 2>/dev/null)
[ -n "$AD" ] || { echo "SORUN: sunucu kisa adi okunamadi - kaydirma hesaplanamaz, dokunulmadi"; exit 0; }
# Makine adi ayarlanmamis sunucu (R21): 'localhost' ozeti her yerde ayni -> bu sunucularin hepsi ayni saate duser
case "$AD" in
    localhost|localhost.localdomain|localhost4|localhost6)
        echo "SORUN: sunucu kisa adi '$AD' (makine adi ayarlanmamis) - kaydirma tum bu sunucularda ayni cikar," \
             "dokunulmadi (hostnamectl set-hostname)"; exit 0 ;;
esac
oz() { printf '%s' "$1" | md5sum | cut -c1-8; }
G=$(( 16#$(oz "$AD-gece") % (PG * 60 + 1) ))
K=$(( 16#$(oz "$AD-kontrol") % (PK * 60 + 1) ))
KI=$(( (K + 180) % (PK * 60 + 1) ))
sa() { printf '%02d:%02d:%02d' $(( $1 / 3600 )) $(( $1 % 3600 / 60 )) $(( $1 % 60 )); }
dk() { printf '%02d:%02d' $(( $1 / 60 )) $(( $1 % 60 )); }
BAS="# PCP gece isleri yuk dagitimi (olcek kurali): sunucu kisa adindan sabit kaydirma - PCP rol playbooklari yazar, elle degistirmeyin"
DEGISTI=0; RELOAD=0
# yaz/kaldir: her adim denetlenir (R26 - eski surum basarisiz yazimda da "yazildi" diyordu); yedek alinamazsa dosyaya
# DOKUNULMAZ (yedekleme ilkesi); yeni olusturulan dosya manifeste "OLUSTURULDU  <dosya>  -" satiriyla girer (R13 - geri
# almada bu dosyalar /var/backup agacina tasinir; _kosum- manifesti degisiklik ONCESI durumun tam listesidir)
yaz() {
    d="$SD/$1.d"; f="$d/${3:-$DOSYA}"
    if [ -f "$f" ] && [ "$(cat "$f")" = "$2" ]; then return 0; fi
    mkdir -p "$d" "$KOK" || { echo "SORUN: $d ya da $KOK olusturulamadi - $f yazilmadi"; return 1; }
    chmod 0700 "$KOK"
    YENI=1
    if [ -f "$f" ]; then
        YENI=0; h="$KOK$f-$DAMGA"; mkdir -p "$(dirname "$h")"
        cp -a "$f" "$h" || { echo "SORUN: $f yedeklenemedi ($h) - dosyaya dokunulmadi"; return 1; }
        printf '%s  %s  %s\n' "$(sha256sum "$f" | awk '{print $1}')" "$f" "$h" >> "$KOK/_kosum-$DAMGA.txt"
    fi
    if printf '%s\n' "$2" > "$f.tmp.$$" && chmod 0644 "$f.tmp.$$" && mv -f "$f.tmp.$$" "$f"; then
        [ "$YENI" -eq 1 ] && printf 'OLUSTURULDU  %s  -\n' "$f" >> "$KOK/_kosum-$DAMGA.txt"
        echo "yazildi: $f"; DEGISTI=1; RELOAD=1
    else
        rm -f "$f.tmp.$$"; echo "SORUN: $f yazilamadi (dosya sistemi salt okunur ya da dolu?)"; return 1
    fi
}
kaldir() {
    f="$SD/$1.d/$DOSYA"; [ -f "$f" ] || return 0
    h="$KOK$f-$DAMGA"; mkdir -p "$(dirname "$h")" "$KOK"; chmod 0700 "$KOK"
    if mv -f "$f" "$h"; then
        printf '%s  %s  %s\n' "tasindi" "$f" "$h" >> "$KOK/_kosum-$DAMGA.txt"
        echo "tasindi (artik gereksiz): $f"; DEGISTI=1; RELOAD=1
    else
        echo "SORUN: $f /var/backup agacina tasinamadi ($h) - dosya yerinde kaldi"; return 1
    fi
}
# zam <birim> <gunluk:1|0> <takvim...>. Gunluk islerde (pmlogger_daily, pmie_daily) Persistent=false yazilir: sunucu gece
# isi saatinde kapaliysa (bakim, kaza) acilista is HEMEN calismaz, ertesi gece kendi saatinde iki gunu birlestirir. Paket
# varsayilani Persistent=true toplu acilista tum sunucularda ayni anda birlestirme demektir (olculdu: paket varsayilaniyla
# kacirilan is acilistan 8 sn sonra calisti, Persistent=false ile calismadi). daemon-reload yakalamasini bu ayar ONLEMEZ - onu
# gecis kapisi karsilar. Yarim saatlik isler dokunulmaz.
zam() {
    b=$1; g=$2; shift 2
    systemctl cat "$b" >/dev/null 2>&1 || { echo "BILGI: $b yok - atlandi"; return 0; }
    i=$(printf '%s\n[Timer]\nOnCalendar=' "$BAS")
    for c in "$@"; do i=$(printf '%s\nOnCalendar=%s' "$i" "$c"); done
    [ "$g" = 1 ] && i=$(printf '%s\nPersistent=false' "$i")
    yaz "$b" "$i"
}
# Gunluk gece zaman diliminin baslangici: RHEL 9/10 00:10; RHEL 8 ailesi (PCP 5.3) 03:10 (yapilandirma karari). PCP 5.3 pmlogger yeniden
# yuklemede (SIGUSR2) arsiv adini UTC ile yazar (TZ=+03-3; olculdu: Oracle Linux 8.10): gece isi UTC gece yarisindan
# once calisirsa yeni arsiv onceki gune duser ve her gece birlestirme olur. 03:10 (+03) = 00:10 UTC.
OSR=/etc/os-release
TABAN=600
PV=$(rpm -q --qf '%{VERSION}' pcp 2>/dev/null | cut -d. -f1)
if [ "$(. "$OSR" 2>/dev/null; echo "${VERSION_ID%%.*}")" = 8 ] || { [ -n "$PV" ] && [ "$PV" -lt 6 ] 2>/dev/null; }; then
    TABAN=11400
fi
zam pmlogger_daily.timer 1 "*-*-* $(sa $(( TABAN + G )))"
zam pmie_daily.timer 1 "*-*-* $(sa $(( TABAN - 120 + G )))"
zam pmlogger_check.timer 0 "*-*-* *:$(dk "$K")" "*-*-* *:$(dk $(( K + 1800 )))"
zam pmie_check.timer 0 "*-*-* *:$(dk "$KI")" "*-*-* *:$(dk $(( KI + 1800 )))"
zam pmlogger_farm_check.timer 0 "*-*-* *:$(dk $(( K + 10 )))" "*-*-* *:$(dk $(( K + 1810 )))"
zam pmie_farm_check.timer 0 "*-*-* *:$(dk $(( KI + 10 )))" "*-*-* *:$(dk $(( KI + 1810 )))"
# Gecis kapisi: daemon-reload, yeni takvimin son tetiklemeden sonra ve simdiden once kalan saatini kacirilmis sayip
# gunluk isi HEMEN calistirir (systemd son tetiklemeyi bellekte tutar; Persistent=false da onlemez - olculdu, systemd
# 239/252/257). Uygulama aninda bu calisma 400-1000 VM dalgasinda ayni anda gece isi demektir; PCP 5.3 te UTC adli etkin
# arsivle birlestirme cakismasi da uretir ("output archive already exists": o gun birlesmez, sonraki geceler atlanir).
# Isaret varken servis CALISMAZ; zamanlayici yine tetiklenir, sonraki calisma yeni saatine kayar. Isaret /run altinda.
GECIS=/run/pcp-gece-gecis
# Onceki kosum isaret ile reload arasinda kesildiyse (AWX zaman asimi, baglanti kopmasi) isaret takili kalir ve gece
# isleri acilisa kadar CALISMAZ; her kosumda kaldirilir.
if [ -e "$GECIS" ]; then
    rm -f "$GECIS" && echo "BILGI: takili gecis isareti kaldirildi ($GECIS - onceki kosum yarida kalmis)"; DEGISTI=1
fi
for b in pmlogger_daily.service pmie_daily.service; do
    systemctl cat "$b" >/dev/null 2>&1 || continue
    yaz "$b" "$(printf '%s\n[Unit]\nConditionPathExists=!%s' "$BAS" "$GECIS")" 51-gecis-kapisi.conf
done
# RHEL 8 (PCP 5.3): gece raporu pmlogger_daily icinden degil pcp-zeroconf AYRI zamanlayicisiyla (her gece 02:00,
# tum sunucularda ayni an) calisir ve -D yoktur. Servise kosul drop-in: rapor calismaz; zamanlayici durumuna
# dokunulmaz (disable/stop yok), paket guncellemesinde kalir. Yeniden acmak: touch /etc/pcp/pmlogger_daily_report.acik
RAPOR=0
if systemctl cat pmlogger_daily_report.service >/dev/null 2>&1; then
    yaz pmlogger_daily_report.service "$(printf '%s\n[Unit]\nConditionPathExists=/etc/pcp/pmlogger_daily_report.acik' "$BAS")"
    RAPOR=1
fi
# Gece raporu: ExecStart satiri sunucudaki PAKET biriminden okunur (RHEL 9 ve 10 satirlari farkli), -D eklenir
if grep -q -- '--noreport' "$BIN/pmlogger_daily" 2>/dev/null; then
    U=$(systemctl show -p FragmentPath --value pmlogger_daily.service 2>/dev/null)
    E=$(grep -E '^ExecStart=' "$U" 2>/dev/null | tail -1)
    case "$E" in
        *" -D "*|*" -D"|*--noreport*) echo "BILGI: paket birimi gece raporunu zaten kapatiyor"; kaldir pmlogger_daily.service ;;
        ExecStart=*pmlogger_daily*)
            Y=$(printf '%s\n' "$E" | sed -E 's#^(ExecStart=[^ ]*pmlogger_daily)#\1 -D#')
            yaz pmlogger_daily.service "$(printf '%s\n[Service]\nExecStart=\n%s' "$BAS" "$Y")" ;;
        *) echo "SORUN: pmlogger_daily.service ExecStart satiri okunamadi ($U) - gece raporu kapatilamadi" ;;
    esac
elif [ "$RAPOR" -eq 0 ]; then
    echo "BILGI: kurulu pmlogger_daily -D/--noreport tanimiyor ve ayri rapor servisi yok - gece raporu bu surumde kapatilamadi"
fi
for b in pmlogger_daily.timer pmie_daily.timer pmlogger_check.timer pmie_check.timer pmlogger_farm_check.timer \
         pmie_farm_check.timer pmlogger_daily.service pmie_daily.service pmlogger_daily_report.service; do
    if [ "$RELOAD" -eq 0 ] && [ "$(systemctl show -p NeedDaemonReload --value "$b" 2>/dev/null)" = yes ]; then
        echo "BILGI: $b icin bekleyen daemon-reload (onceki kosum yuklememis)"; RELOAD=1; DEGISTI=1
    fi
done
if [ "$RELOAD" -eq 1 ]; then
    # zamanlayici YENIDEN BASLATILMAZ (pmlogger.service BindsTo); yeni saat daemon-reload ile hesaplanir.
    # Gecis kapisi isareti yalniz reload suresince; komut kesilse de cikis tuzagi kaldirir.
    touch "$GECIS"; trap 'rm -f "$GECIS"' EXIT
    # R23: takilan systemd icin sonsuz bekleme olmasin (120 sn); kesilse de isaret cikis tuzagiyla kaldirilir
    timeout 120 systemctl daemon-reload || echo "SORUN: systemctl daemon-reload basarisiz ya da 120 sn icinde bitmedi"
    sleep 5; rm -f "$GECIS"
fi
# pmlogger sure denetimi: pmlogger -T24h10m ile calisir; sure dolunca systemd ayni anda yeniden baslatir
# (Restart=always). Gece isi saati kayinca eski surenin bitisi yeni gece isinden ONCE kalir: o gece dalgadaki tum sunucular
# ayni dakikada yeniden baslar, RHEL 9/10 da (PCP 6.3/7.0 gunluk is bugunun arsivinde sinyali atlar) bu her gece 10 dk kayarak
# ~12 gece surer. Cozum: uygulama aninda, sure bir sonraki gece isinden once dolacaksa pmlogger a SIGUSR2 gonderilir (gece
# isinin kendisinin yaptigi yeniden yukleme: ayni surec, sure sifirlanir, yeni arsiv parcasi; olculen ornek boslugu 0,25 sn).
# Gece saatlerinde (00:00-05:59) gonderilmez - gece isleriyle cakismasin. Ikinci kosumda sure gece isinden sonraya kalir: sinyal yok.
# YUK NOTU: okumalar yalniz surecin komut satiri, acik dosya listesi ve arsiv etiketi (pmdumplog -l); sinyal o gece arsiv
# parcalarini birlestirmeye neden olur (sunucunun kendi gece isi saatinde, olculdu ~1,3 GB yazma / 7 sn).
sure_denetle() {
    local P T TS M L AB SIMDI BITIS GUNLUK GECE Y
    P=$(systemctl show -p MainPID --value pmlogger.service 2>/dev/null)
    case "$P" in ''|0|*[!0-9]*) echo "BILGI: pmlogger calismiyor - sure denetimi atlandi"; return 0 ;; esac
    T=$(tr '\0' '\n' < "/proc/$P/cmdline" 2>/dev/null | sed -n 's/^-T//p' | head -1)
    [ -n "$T" ] || { echo "BILGI: pmlogger -T suresi yok - sure denetimi gerekmiyor"; return 0; }
    # yalniz paketin yazdigi bicim (24h10m, 24h): baska bicimde hesap yapilmaz
    if [[ "$T" =~ ^([0-9]{1,3})h(([0-9]{1,2})m)?$ ]]; then
        TS=$(( 10#${BASH_REMATCH[1]} * 3600 + 10#${BASH_REMATCH[3]:-0} * 60 ))
    else
        echo "BILGI: pmlogger -T degeri taninmadi ($T) - sure denetimi atlandi"; return 0
    fi
    M=$(ls -l "/proc/$P/fd" 2>/dev/null | awk '{print $NF}' | grep '\.meta$' | head -1)
    [ -n "$M" ] || { echo "BILGI: pmlogger acik arsivi bulunamadi - sure denetimi atlandi"; return 0; }
    L=$(timeout 30 "${PCP_BIN_DIR:-/usr/bin}/pmdumplog" -l -Z UTC "${M%.meta}" 2>/dev/null | awk '$1=="commencing"{print $3, $4, $6, $5; exit}')
    AB=$(TZ=UTC date -d "${L%.*}" +%s 2>/dev/null)
    [ -n "$AB" ] || { echo "BILGI: arsiv baslangici okunamadi ($M) - sure denetimi atlandi"; return 0; }
    SIMDI=$(date +%s); BITIS=$(( AB + TS ))
    GUNLUK=$(( TABAN + G )); GECE=$(( $(date -d 'today 00:00' +%s) + GUNLUK ))
    [ "$GECE" -le "$SIMDI" ] && GECE=$(( $(date -d 'tomorrow 00:00' +%s) + GUNLUK ))
    if [ "$BITIS" -ge $(( GECE + 600 )) ]; then
        echo "pmlogger suresi gece isinden sonra doluyor ($(date -d "@$BITIS" '+%F %T')) - sinyal gerekmiyor"; return 0
    fi
    if [ "$(( 10#$(date +%H) ))" -lt 6 ]; then
        echo "UYARI: pmlogger suresi gece isinden once doluyor ($(date -d "@$BITIS" '+%F %T')); gece saatlerinde sinyal gonderilmez" \
             "- bu gece pmlogger kendiliginden yeniden baslayabilir; 06:00 sonrasi tekrar kosum duzeltir"; return 0
    fi
    if kill -USR2 "$P" 2>/dev/null; then
        sleep 3
        Y=$(systemctl show -p MainPID --value pmlogger.service 2>/dev/null)
        if [ "$Y" = "$P" ]; then
            echo "pmlogger yeniden yuklendi (SIGUSR2, ayni surec $P): sure $(date -d "@$BITIS" '+%F %T') yerine yarina kaydi"
        else
            echo "UYARI: SIGUSR2 sonrasi pmlogger sureci degisti ($P -> ${Y:-yok}) - systemctl status pmlogger ile denetleyin"
        fi
        DEGISTI=1
    else
        echo "SORUN: pmlogger a SIGUSR2 gonderilemedi (surec $P)"
    fi
}
sure_denetle
echo "kaydirma: gunluk +$G sn, yarim saatlik +$K sn (kisa ad $AD)"
for b in pmlogger_daily.timer pmlogger_check.timer; do
    echo "sonraki: $b $(systemctl show -p NextElapseUSecRealtime --value "$b" 2>/dev/null)"
done
[ "$DEGISTI" -eq 1 ] && echo DEGISTI || true
# PCP_GECE_YAYMA_SON (playbook-pcp'den araclar/ortak-govde.sh ile alinir; elle degistirmeyin)
)
if [ "$YALNIZ_DOGRULA" -eq 0 ] && [ "$(v PCP 0)" = 1 ] && [ "$pcp_gece_karari" = uygula ]; then
    log "Gece isleri yayma ve gece raporu (pencere $pcp_gece_pencere_dk dk, kontrol $pcp_kontrol_pencere_dk dk)"
    if [ "$UYGULA" -eq 0 ]; then
        bilgi "kuru calisma: gece isleri adimi atlandi (playbook --check ile ayni; drop-in yazimi + daemon-reload)"
    else
        while IFS= read -r s; do
            case "$s" in
                DEGISTI|"") ;;
                yazildi:*|tasindi*) chg "$s" ;;
                *) bilgi "$s" ;;
            esac
        done < <(gece_yay 2>&1)
    fi
fi

# ============================================================================
# PMCD: proc -A, hotproc, ek PMDA'lar (tek pmcd yeniden baslatmasi)
# ============================================================================
PMCD_DEGISTI=0
if [ "$YALNIZ_DOGRULA" -eq 0 ]; then
    log "proc PMDA -A"
    if [ "$pcp_a_yaz" -eq 1 ]; then
        if [ "$UYGULA" -eq 1 ]; then
            G="$PMCDCONF.pcp-onlem.$$"
            if cp -a "$PMCDCONF" "$G" && sed -E '/^proc[ \t].*pmdaproc/ s/[ \t]*$/ -A/' "$PMCDCONF" > "$G" && mv -f "$G" "$PMCDCONF"; then
                chg "-A eklendi: pcp kullanicisi surec basina G/C degerinin $_io_pcp / $_io_root kadarini goruyordu. pmcd yalniz yerel, pmproxy calismiyor; kayitta smaps/maps/environ yok."
                PMCD_DEGISTI=1
            else rm -f "$G"; bilgi "SORUN: -A pmcd.conf'a yazilamadi"; fi
        else kuru "-A eklenecek (G/C pcp $_io_pcp / root $_io_root)"; fi
    else
        if [ "$proc_tum_surec_karari" != gerekirse ]; then n="karar dokunma/rapor"
        elif [ "$(v PROC_A 0)" = 1 ]; then n="zaten var"
        elif [ "$(v PROC_SATIR 0)" != 1 ]; then n="proc satiri yok"
        elif [ "$_io_root" -eq 0 ]; then n="pmcd calismiyor, gorunurluk olculemedi"
        elif [ "$pcp_gorunurluk_eksik" -eq 0 ]; then n="gorunurluk yeterli (G/C pcp $_io_pcp / root $_io_root)"
        elif [ "$(v PMCD_YEREL 0)" != 1 ]; then n="GUVENLIK KAPISI: pmcd uzak baglanti kabul edebilir ($pcp_ayar_dizin/pmcd PMCD_LOCAL=1 satiri $(v PMCD_LOCAL_SATIR yok); acilmasi yapilandirma karari); surec G/C verisi EKSIK kalir"
        elif [ "$(v PMPROXY 0)" = 1 ]; then n="GUVENLIK KAPISI: pmproxy calisiyor (uzak istemci pmcd verisine ulasabilir); surec G/C verisi EKSIK kalir"
        else n="GUVENLIK/YUK KAPISI: kayitta $(v RISKLI_KAYIT)var; surec G/C verisi EKSIK kalir"; fi
        bilgi "-A eklenmedi: $n"
    fi

    if [ "$hotproc_karari" = uygula ] && [ "$(v PCP 0)" = 1 ]; then
        log "hotproc"
        if [ -e "$PMDAS/proc/hotproc.conf" ]; then skip "hotproc.conf var (uzerine yazilmaz)"
        elif [ "$UYGULA" -eq 1 ]; then
            gomulu_hotproc_conf > "$PMDAS/proc/hotproc.conf" && chown root:root "$PMDAS/proc/hotproc.conf" \
                && chmod 0644 "$PMDAS/proc/hotproc.conf" && { chg "hotproc.conf yazildi"; PMCD_DEGISTI=1; }
        else kuru "hotproc.conf yazilacak"; fi
    fi

    if [ -n "$pcp_ek_pmdalar" ]; then
        log "Ek PMDA'lar ($(echo "$pcp_ek_pmdalar" | tr ' ' ','))"
        for m in $pcp_ek_pmdalar; do
            if [ ! -d "$PMDAS/$m" ]; then bilgi "BILGI: PMDA $m dizin-yok (paket kurulu degil)"
            elif grep -qE "^${m}[[:space:]]" "$PMCDCONF" 2>/dev/null; then skip "PMDA $m kayitli"
            elif [ -e "$PMDAS/$m/.NeedInstall.failed" ]; then bilgi "BILGI: PMDA $m onceki-kurulum-basarisiz (donanim destegi yok olabilir, .NeedInstall.failed silinirse yeniden denenir)"
            elif [ -e "$PMDAS/$m/.NeedInstall" ]; then skip "PMDA $m .NeedInstall var"
            elif [ "$UYGULA" -eq 1 ]; then
                : > "$PMDAS/$m/.NeedInstall" && chmod 0644 "$PMDAS/$m/.NeedInstall" && { chg "PMDA $m: .NeedInstall birakildi"; PMCD_DEGISTI=1; }
            else kuru "PMDA $m: .NeedInstall birakilacak"; fi
        done
    fi

    if [ "$UYGULA" -eq 1 ] && { [ "$PMCD_DEGISTI" -eq 1 ] || [ "$PMDA_KALDIRILDI" -eq 1 ]; }; then
        log "pmcd yeniden baslatiliyor"
        # shellcheck disable=SC1091
        [ -f /etc/pcp.conf ] && . /etc/pcp.conf
        systemctl reset-failed pmcd >/dev/null 2>&1 || true
        timeout 90 systemctl restart pmcd || bilgi "UYARI: pmcd yeniden baslatma 90 sn icinde bitmedi"
        "${PCP_BINADM_DIR:-/usr/libexec/pcp/bin}/pmcd_wait" -t 60 || bilgi "UYARI: pmcd 60 sn icinde hazir olmadi"
        for _ in $(seq 1 60); do
            ls "$PMDAS"/*/.NeedInstall >/dev/null 2>&1 && { sleep 2; continue; }
            pgrep -f "$PMDAS/.*/Install" >/dev/null 2>&1 && { sleep 2; continue; }
            break
        done
        systemctl reset-failed pmlogger >/dev/null 2>&1 || true
        # PMDA kaldirildiysa pmlogger kayit listesindeki adlari yeniden cozsun
        if [ "$PMDA_KALDIRILDI" -eq 1 ]; then
            timeout 90 systemctl restart pmlogger || bilgi "UYARI: pmlogger yeniden baslatilamadi"
        fi
        systemctl is-active --quiet pmlogger || systemctl start pmlogger || bilgi "UYARI: pmlogger baslatilamadi"
        chg "pmcd yeniden baslatildi"
    fi
fi

# ============================================================================
# KAYIT PROFILI (varsayilan dokunma)
# ============================================================================
ctrl_yonlendir() {   # DOSYA HEDEF_C ; '^([^#\n]*LOCALHOSTNAME.*?)-c[ \t]+\S+' -> '\1-c HEDEF'
    awk -v yeni="$2" '
        /^[^#]*LOCALHOSTNAME/ {
            i = index($0, "LOCALHOSTNAME"); bas = substr($0, 1, i - 1); kalan = substr($0, i)
            if (match(kalan, /-c[ \t]+[^ \t]+/)) { print bas substr(kalan, 1, RSTART - 1) "-c " yeni substr(kalan, RSTART + RLENGTH); next }
        }
        { print }' "$1"
}
if [ "$YALNIZ_DOGRULA" -eq 0 ]; then
    if [ "$kayit_profili" = tam ] && [ "$pcp_profil_tam" -eq 0 ]; then
        if [ -n "$(v KAYIT_SAHIP)" ]; then n="pmlogger kayit yapilandirmasini $(v KAYIT_SAHIP) yonetiyor (pmlogconf grup eklemeleri config.default uzerinde); ayni sunucuda iki kayit sahibi olmaz"
        else n="birincil pmlogger kontrol satiri bulunamadi"; fi
        bilgi "kayit_profili=tam UYGULANMADI: $n."
    fi
    # 3.x'ten gecis: kayit config.pcp-full'dan yapildigi icin config.default HIC uretilmemis olabilir.
    # Playbook bu durumda sessizce atlar (README'ye bildirildi); betik pmlogger_check gibi pmlogconf'u
    # pcp kullanicisiyla calistirip dosyayi uretir (root olarak slabinfo grubunu acar - olculdu).
    if [ "$kayit_profili" = varsayilan ] && [ "$pcp_profil_varsayilan" -eq 0 ]; then
        if [ -z "$(v CTRL)" ]; then bilgi "kayit_profili=varsayilan UYGULANMADI: birincil pmlogger kontrol satiri bulunamadi."
        elif [ "$(v CTRL_C)" = config.default ]; then skip "kayit zaten -c config.default"
        elif [ "$UYGULA" -eq 1 ]; then
            if timeout 120 runuser -u pcp -- pmlogconf -c -q "$pcp_pmlogger_dizin/config.default" </dev/null >/dev/null 2>&1 \
               && [ -s "$pcp_pmlogger_dizin/config.default" ]; then
                chg "$pcp_pmlogger_dizin/config.default uretildi (pmlogconf, pcp kullanicisi)"; pcp_profil_varsayilan=1
            else bilgi "SORUN: config.default uretilemedi (pmlogconf); kayit yapilandirmasina DOKUNULMADI"; fi
        else kuru "$pcp_pmlogger_dizin/config.default uretilecek (pmlogconf, pcp kullanicisi), kayit ona yonlendirilecek"; fi
    fi
    if [ "$pcp_profil_tam" -eq 1 ] || [ "$pcp_profil_varsayilan" -eq 1 ]; then
        log "Kayit profili: $kayit_profili"
        PROFIL_DEGISTI=0
        if [ "$pcp_profil_tam" -eq 1 ]; then
            liste() { pminfo -m "$@" 2>/dev/null \
                | awk '$2 == "PMID:" && $3 !~ /^511\./ && $1 !~ /environ/ && $1 != "proc.memory.maps"' \
                | awk '$1 !~ /^mem\.(zoneinfo|buddyinfo|slabinfo)\./ { print "    " $1 }' \
                | sort -u || true; }
            L_DEVNET=$(liste disk network)
            L_SYS=$(liste kernel.all kernel.percpu kernel.pernode mem swap filesys vfs nfs nfs4 rpc proc.nprocs proc.runq)
            L_PROC=$(liste proc.psinfo proc.id proc.memory proc.io proc.schedstat proc.fd.count)
            L_HW=$(liste lmsensors smart)
            L_HINV=$(liste hinv kernel.uname)
            if ! bos_degil "$L_DEVNET" || ! bos_degil "$L_SYS" || ! bos_degil "$L_PROC"; then
                die "Tam profil metrik listesi uretilemedi (pmcd calismiyor ya da proc PMDA sorunlu); kayit yapilandirmasina DOKUNULMADI. 'systemctl status pmcd' ve 'pminfo proc' ile kontrol edin." 2
            fi
            HEDEF="$pcp_pmlogger_dizin/$pcp_tam_ad"
            YENI=$(mktemp) || die "mktemp basarisiz"
            tam_config "$L_DEVNET" "$L_SYS" "$L_PROC" "$L_HW" "$L_HINV" > "$YENI"
            if [ -f "$HEDEF" ] && cmp -s "$YENI" "$HEDEF" && [ "$(stat -c '%a %U %G' "$HEDEF")" = "644 root root" ]; then
                skip "$HEDEF ayni"; rm -f "$YENI"
            elif [ "$UYGULA" -eq 1 ]; then
                # 0644 sart: dar izinli yapilandirmayi pcp kullanicisi okuyamaz, pmlogger durmadan yeniden baslar
                chmod 0644 "$YENI" && chown root:root "$YENI" && mv -f "$YENI" "$HEDEF" && { chg "$HEDEF yazildi"; PROFIL_DEGISTI=1; }
            else kuru "$HEDEF yazilacak"; rm -f "$YENI"; fi
            HEDEF_C=$pcp_tam_ad
        else
            HEDEF_C=config.default
        fi
        CTRL=$(v CTRL)
        if [ "$(ctrl_yonlendir "$CTRL" "$HEDEF_C" | cmp -s - "$CTRL"; echo $?)" = 0 ]; then
            skip "$CTRL zaten -c $HEDEF_C"
        elif [ "$UYGULA" -eq 1 ]; then
            G="$CTRL.pcp-onlem.$$"
            if cp -a "$CTRL" "$G" && ctrl_yonlendir "$CTRL" "$HEDEF_C" > "$G" && mv -f "$G" "$CTRL"; then
                chg "$CTRL -> -c $HEDEF_C"; PROFIL_DEGISTI=1
            else rm -f "$G"; bilgi "SORUN: $CTRL yazilamadi"; fi
        else kuru "$CTRL -> -c $HEDEF_C"; fi
        if [ "$PROFIL_DEGISTI" -eq 1 ]; then
            systemctl reset-failed pmlogger >/dev/null 2>&1 || true
            systemctl reset-failed pmlogger_farm >/dev/null 2>&1 || true
            systemctl restart pmlogger && chg "pmlogger yeniden baslatildi"
        fi
    fi
fi

# ============================================================================
# SAKLAMA (tek sahip ilkesi)
# ============================================================================
satir_yaz() {   # DOSYA REGEX SATIR ; ansible lineinfile: son eslesen satir degisir, yoksa sona eklenir
    awk -v re="$2" -v yeni="$3" '
        { s[NR] = $0; if ($0 ~ re) son = NR }
        END { for (i = 1; i <= NR; i++) print (i == son ? yeni : s[i]); if (!son) print yeni }' "$1"
}
if [ "$YALNIZ_DOGRULA" -eq 0 ]; then
    log "Saklama"
    if [ "$pcp_saklama_yaz" -eq 1 ]; then
        F=$pcp_timers_dosya
        if satir_yaz "$F" '^#?[[:space:]]*PMLOGGER_DAILY_PARAMS=' "$SAKLAMA_SATIRI" | cmp -s - "$F" \
           && [ "$(stat -c '%a %U %G' "$F")" = "644 root root" ]; then
            skip "$SAKLAMA_SATIRI ($pcp_saklama_notu)"
        elif [ "$UYGULA" -eq 1 ]; then
            G="$F.pcp-onlem.$$"
            if cp -a "$F" "$G" && satir_yaz "$F" '^#?[[:space:]]*PMLOGGER_DAILY_PARAMS=' "$SAKLAMA_SATIRI" > "$G" && mv -f "$G" "$F"; then
                chown root:root "$F"; chmod 0644 "$F"
                chg "$SAKLAMA_SATIRI ($pcp_saklama_notu); yedek izi $yedek_kok$pcp_ayar_dizin/ altinda - log-saklama bu dosyaya dokunmaz"
            else rm -f "$G"; bilgi "SORUN: $F yazilamadi"; fi
        else kuru "$SAKLAMA_SATIRI ($pcp_saklama_notu)"; fi
    else
        if [ -n "$(v SAHIP)" ]; then n="sahip $(v SAHIP) (tek sahip ilkesi; bu betik yalniz raporlar)"
        elif [ "$(v TIMERS 0)" != 1 ]; then n="pmlogger_timers yok"
        else n="karar dokunma/rapor"; fi
        bilgi "Saklama YAZILMADI: $n. Mevcut: \"$(v DAILY)\"; bu betigin kurali $pcp_saklama_gun gun."
    fi
fi

# ============================================================================
# INCELEME SABLONLARI + DOGRULAMA BETIGI
# ============================================================================
dosya_kur() {   # URETICI HEDEF MOD ; icerik/sahip/izin ayniysa dokunmaz
    local uretici=$1 hedef=$2 mod=$3 g
    g=$(mktemp) || die "mktemp basarisiz"
    $uretici > "$g"
    if [ -f "$hedef" ] && cmp -s "$g" "$hedef" && [ "$(stat -c '%a %U %G' "$hedef")" = "$mod root root" ]; then
        skip "$hedef ayni"; rm -f "$g"; return 0
    fi
    if [ "$UYGULA" -eq 0 ]; then kuru "$hedef yazilacak"; rm -f "$g"; return 0; fi
    mkdir -p "$(dirname "$hedef")"
    chmod "$mod" "$g" && chown root:root "$g" && mv -f "$g" "$hedef" && chg "$hedef yazildi"
}
dogrula_kaynagi() { cat "$KAYNAK_DOGRULA"; }
if [ "$YALNIZ_DOGRULA" -eq 0 ]; then
    if [ "$pmrep_sablon_karari" = uygula ] && [ "$(v PMREP_DIZIN 0)" = 1 ]; then
        log "pmrep sablonlari (:canli :obur :agirlik)"
        dosya_kur gomulu_ozel_conf /etc/pcp/pmrep/ozel.conf 644
    fi
    if [ "$dogrula_betigi_karari" = uygula ] && [ "$(v PCP 0)" = 1 ]; then
        log "Dogrulama betigi ($pcp_dogrula_yol; -y secenegi YUK uretir)"
        if [ -f "$KAYNAK_DOGRULA" ]; then dosya_kur dogrula_kaynagi "$pcp_dogrula_yol" 755
        else bilgi "BILGI: $KAYNAK_DOGRULA yok - dogrulama betigi kurulmadi"; fi
    fi
fi

# ============================================================================
# PMIE ESIK ALARMLARI (varsayilan dokunma)
# ============================================================================
if [ "$YALNIZ_DOGRULA" -eq 0 ] && [ "$pmie_karari" = uygula ] && [ "$(v PCP 0)" = 1 ]; then
    log "pmie esik alarmlari"
    F=$pcp_pmie_yapilandirma
    if [ "$UYGULA" -eq 0 ]; then
        kuru "pmie kurallari: $(echo "$pcp_pmie_kurallari" | tr ' ' ','), esikler: $(echo "$pcp_pmie_esikleri" | tr ' ' ',')"
    else
        HAZIR=VAR
        if [ ! -f "$F" ]; then
            systemctl enable --now pmie >/dev/null 2>&1 || true
            for _ in $(seq 1 15); do [ -f "$F" ] && break; sleep 2; done
            [ -f "$F" ] || pmieconf -f "$F" rules >/dev/null 2>&1 || true
            if [ -f "$F" ]; then HAZIR=URETILDI; chg "pmie yapilandirmasi uretildi"; else HAZIR=YOK; bilgi "UYARI: $F uretilemedi"; fi
        fi
        if [ "$HAZIR" != YOK ]; then
            DEGISTI=0
            ETKIN=$(pmieconf -f "$F" rules enabled 2>/dev/null || true)
            for k in $pcp_pmie_kurallari; do
                if ! printf '%s\n' "$ETKIN" | grep -qE "^[[:space:]]+$(printf '%s' "$k" | sed 's/\./\\./g')[[:space:]]"; then
                    pmieconf -f "$F" enable "$k" >/dev/null 2>&1 && { chg "etkinlestirildi: $k"; DEGISTI=1; }
                fi
            done
            for e in $pcp_pmie_esikleri; do
                IFS='|' read -r kural degisken deger <<< "$e"
                M=$(pmieconf -f "$F" list "$kural" "$degisken" 2>/dev/null || true)
                deger_re=$(printf '%s' "$deger" | sed 's/[][\.*^$+?(){}|/]/\\&/g')
                if ! printf '%s\n' "$M" | grep -qE "${degisken}[[:space:]]*=[[:space:]]*${deger_re}[[:space:]]*$"; then
                    pmieconf -f "$F" modify "$kural" "$degisken" "$deger" >/dev/null 2>&1 \
                        && { chg "esik: $kural.$degisken=$deger"; DEGISTI=1; }
                fi
            done
            if [ "$DEGISTI" -eq 1 ]; then systemctl restart pmie && chg "pmie yeniden baslatildi"
            else skip "pmie kurallari ve esikleri ayni"; systemctl enable --now pmie >/dev/null 2>&1 || true; fi
        fi
    fi
fi

# ============================================================================
# DOGRULAMA (salt okuma; sapmalar kosumu DURDURMAZ - bilgi kipi)
# ============================================================================
dogrula() {
    if ! paket_var pcp; then echo "SORUN: pcp kurulu degil (rapor modu ya da depo yok)"; return 0; fi
    # shellcheck disable=SC1091
    [ -f /etc/pcp.conf ] && . /etc/pcp.conf
    SYSCONF=${PCP_SYSCONF_DIR:-/etc/pcp}
    SCD=${PCP_SYSCONFIG_DIR:-$pcp_ayar_dizin}
    for s in pmcd pmlogger; do
        d=$(systemctl is-active "$s" 2>/dev/null || true)
        if [ "$d" = active ]; then echo "$s: active"; else echo "SORUN: $s etkin degil ($d)"; fi
    done
    # pmlogger -T24h10m suresi dolunca temiz cikar ve Restart=always ile yeniden baslar: gece isi saati kaydirilinca ilk
    # gecelerde gunde bir BEKLENEN yeniden baslatmadir. SORUN = son 24 saatte basarisiz sonuc / sinyalle, dokumle ya da
    # sifir olmayan kodla cikis.
    NR=$(systemctl show pmlogger -p NRestarts --value 2>/dev/null || true)
    HATA=$(timeout 60 journalctl -u pmlogger.service --since -24h --no-pager -o cat 2>/dev/null \
        | grep -cE 'Failed with result|code=(killed|dumped)|status=[1-9]' || true)
    if [ "${HATA:-0}" -gt 0 ] || [ "$(systemctl show pmlogger -p Result --value 2>/dev/null)" != success ]; then
        echo "SORUN: pmlogger son 24 saatte hatayla cikti ($HATA kayit; NRestarts $NR) - pmlogger.log incelenmeli"
    elif [ -n "$NR" ] && [ "$NR" != "0" ]; then
        echo "BILGI: pmlogger $NR kez yeniden basladi, hata kaydi yok (-T24h10m sure sonu olabilir)"
    fi
    for t in pmlogger_daily.timer pmlogger_check.timer; do
        [ "$(systemctl is-active "$t" 2>/dev/null || true)" = active ] || echo "SORUN: $t etkin degil (gunluk dondurme/sikistirma calismaz)"
    done
    SON=$(find /var/log/pcp/pmlogger -type f -name '[0-9]*' -newermt '-15 minutes' 2>/dev/null | head -1)
    if [ -n "$SON" ]; then echo "arsiv taze: $SON"; else echo "SORUN: son 15 dakikada PCP arsivi yazilmamis"; fi
    if systemctl is-active --quiet pmcd; then
        R=$(timeout 60 pminfo -f proc.io.read_bytes 2>/dev/null | grep -c 'inst \[' || true)
        P=$(timeout 60 runuser -u pcp -- pminfo -f proc.io.read_bytes 2>/dev/null | grep -c 'inst \[' || true)
        if [ "${R:-0}" -gt 0 ] && [ $(( ${P:-0} * 100 )) -lt $(( R * pcp_gorunurluk_orani )) ]; then
            if [ "$proc_tum_surec_karari" = gerekirse ]; then D=SORUN; else D=BILGI; fi
            echo "$D: pcp kullanicisi surec basina G/C degerinin ${P:-0} / $R kadarini goruyor - arsivde surec G/C verisi eksik"
        else echo "surec G/C gorunurlugu: pcp ${P:-0} / root ${R:-0}"; fi
    fi
    if grep -E '^proc[[:space:]].*pmdaproc' "$SYSCONF/pmcd/pmcd.conf" 2>/dev/null | grep -qE '[[:space:]]-A([[:space:]]|$)'; then
        grep -qE '^[[:space:]]*PMCD_LOCAL=1' "$SCD/pmcd" 2>/dev/null \
            || echo "SORUN: proc -A var ama pmcd yalniz yerel degil (PMCD_LOCAL=1 yok) - uzak istemci tum surec ayrintilarini okuyabilir"
        systemctl is-active --quiet pmproxy 2>/dev/null \
            && echo "SORUN: proc -A var ve pmproxy calisiyor - uzak istemci pmproxy uzerinden tum surec ayrintilarini okuyabilir"
        CF=$(v CTRL_C); case "$CF" in /*|"") ;; *) CF="$pcp_pmlogger_dizin/$CF" ;; esac
        for f in "$pcp_pmlogger_dizin"/*; do
            [ -f "$f" ] || continue
            grep -qE "$pcp_a_riskli_desen" "$f" || continue
            if [ "$f" = "$CF" ]; then echo "SORUN: proc -A var ve kayit yapilandirmasi $f smaps/maps/environ iceriyor (mmap_lock / gizli bilgi)"
            else echo "BILGI: $f smaps/maps/environ iceriyor (birincil kayitta kullanilmiyor; eski dosya olabilir)"; fi
        done
    fi
    # pmproxy acilista baslayacak mi (Debian paketi etkin birakir): calisinca -A kapisi kapanir, uzak erisim acilir
    if [ "$(systemctl is-enabled pmproxy 2>/dev/null || true)" = enabled ] && ! systemctl is-active --quiet pmproxy 2>/dev/null; then
        echo "BILGI: pmproxy acilista baslayacak (enabled, su an calismiyor) - calisinca uzak istemci pmcd verisine ulasir (systemctl disable pmproxy)"
    fi
    P=${PCP_PMDAS_DIR:-/var/lib/pcp/pmdas}
    for m in $pcp_kapali_pmdalar; do
        grep -qE "^${m}[[:space:]]" "$SYSCONF/pmcd/pmcd.conf" 2>/dev/null \
            && echo "SORUN: $m PMDA etkin (kapatilacaklar listesinde) - pmda_kapatma_karari=uygula ile kaldirilir"
        ls "$P/$m"/.NeedInstall* >/dev/null 2>&1 && echo "SORUN: $m icin bekleyen kurulum isareti (pmcd baslarken PMDA kurulur)"
        [ -d "$P/$m" ] && ! grep -qE "^#.*$m/pmda$m" "$SYSCONF/pmcd/pmcd.conf" 2>/dev/null \
            && echo "BILGI: $m icin yeniden kurulum isareti yok (pcp-zeroconf guncellemesi PMDA yi geri kurabilir)"
    done
    GD=${PCP_VAR_DIR:-/var/lib/pcp}/config/pmlogconf
    for g in $pcp_kapali_kayit_gruplari; do
        f=$(readlink -f "$GD/$g" 2>/dev/null); [ -f "$f" ] || continue
        grep -qE '^[[:space:]]*force[[:space:]]+exclude' "$f" || echo "SORUN: $g grup dosyasi force exclude degil (kayda alinabilir)"
        for m in $(awk '/^[[:space:]]+[a-z]/{print $1}' "$f"); do
            grep -qE "^[[:space:]]+$m$" "$pcp_pmlogger_dizin/config.default" 2>/dev/null \
                && { echo "SORUN: $g metrigi $m kayit yapilandirmasinda"; break; }
        done
    done
    K=$(grep -E '^PMLOGGER_DAILY_PARAMS=' "$SCD/pmlogger_timers" 2>/dev/null | tail -1 | grep -oE -- '-k[ =]?[0-9]+' | tr -dc '0-9')
    if [ -z "$K" ]; then echo "BILGI: PMLOGGER_DAILY_PARAMS icinde -k yok (PCP varsayilani 14 gun)"
    elif [ "$K" -lt "$pcp_saklama_en_az_gun" ]; then echo "SORUN: pmlogger -k $K < en az $pcp_saklama_en_az_gun gun"
    else echo "saklama: -k $K gun"; fi
    for lf in /var/log/pcp/pmlogger/*/pmlogger.log; do
        [ -f "$lf" ] || continue
        S=$(stat -c %s "$lf"); [ "$S" -ge 5242880 ] && echo "SORUN: $lf $(( S / 1048576 )) MB - dogrulama dongusu olabilir"
    done
    A=$(find "$SYSCONF/pmlogger/control.d" -maxdepth 1 -type f 2>/dev/null | grep -E '\.(orig|bak|old|rpmsave|rpmnew)$|~$' | tr '\n' ' ' || true)
    [ -n "$A" ] && echo "SORUN: control.d altinda artik dosya (pmlogger_check kontrol dosyasi sanar): $A"
    if systemctl is-active --quiet pcp-log-guard.timer 2>/dev/null && [ -x /usr/local/sbin/log-saklama-bekci ]; then
        echo "SORUN: pcp-log-guard ve log-saklama bekcisi ayni anda etkin (iki silici) - eski_kurulum_karari=otomatik ile uygula"
    fi
    [ -f /root/.pcp/pmrep.conf ] && echo "SORUN: /root/.pcp/pmrep.conf /etc/pcp/pmrep altindaki hazir sablonlari gizliyor"
    [ -f "$SYSCONF/pmrep/ozel.conf" ] && echo "sablonlar: $SYSCONF/pmrep/ozel.conf var"
    true
}
# Gece isleri yayma (salt okuma): paket varsayilaninda kalan zamanlayici ya da acik gece raporu = SORUN
gece_dogrula() (
# PCP_GECE_DOGRULA (rol playbooklarinda birebir ayni)
set -o pipefail
[ -f /etc/pcp.conf ] && . /etc/pcp.conf
BIN=${PCP_BINADM_DIR:-/usr/libexec/pcp/bin}
[ -x "$BIN/pmlogger_daily" ] || { echo "PCP kurulu degil"; exit 0; }
[ -f /etc/cron.d/pcp-pmlogger ] && { echo "BILGI: PCP gece isleri cron ile calisiyor - denetlenmedi"; exit 0; }
AD=$(hostname -s 2>/dev/null || true)
case "$AD" in localhost|localhost.localdomain|localhost4|localhost6|"")
    echo "SORUN: sunucu kisa adi '${AD:-bos}' - PCP gece isi kaydirmasi hesaplanamaz, tum bu sunucular ayni saate duser" \
         "(hostnamectl set-hostname)" ;; esac
for b in pmlogger_daily.timer pmie_daily.timer pmlogger_check.timer pmie_check.timer pmlogger_farm_check.timer \
         pmie_farm_check.timer; do
    systemctl cat "$b" >/dev/null 2>&1 || continue
    [ -f "/etc/systemd/system/$b.d/50-yuk-dagitimi.conf" ] \
        || echo "SORUN: $b paket varsayilaninda (tum sunucularda ayni dakika) - pcp_gece_karari=uygula ile yayilir"
    [ "$(systemctl show -p NeedDaemonReload --value "$b" 2>/dev/null)" = yes ] \
        && echo "SORUN: $b drop-in diskte ama yuklenmemis (daemon-reload bekliyor)"
    case "$b" in pmlogger_daily.timer|pmie_daily.timer)
        [ -f "/etc/systemd/system/$b.d/50-yuk-dagitimi.conf" ] && ! grep -qx 'Persistent=false' "/etc/systemd/system/$b.d/50-yuk-dagitimi.conf" \
            && echo "SORUN: $b Persistent=false yok - sunucu gece isi saatinde kapaliysa is acilista hemen calisir (toplu acilista ayni anda)" ;;
    esac
done
for b in pmlogger_daily.service pmie_daily.service; do
    systemctl cat "$b" >/dev/null 2>&1 || continue
    grep -qs '^ConditionPathExists=!/run/pcp-gece-gecis$' "/etc/systemd/system/$b.d/51-gecis-kapisi.conf" \
        || echo "SORUN: $b gecis kapisi yok (uygulama aninda gece isi hemen calisir) - pcp_gece_karari=uygula ile yazilir"
done
[ -e /run/pcp-gece-gecis ] \
    && echo "SORUN: /run/pcp-gece-gecis takili kalmis - PCP gece isleri calismaz (rm -f /run/pcp-gece-gecis)"
if systemctl cat pmlogger_daily_report.service >/dev/null 2>&1; then
    grep -qs '^ConditionPathExists=/etc/pcp/pmlogger_daily_report.acik' \
        /etc/systemd/system/pmlogger_daily_report.service.d/50-yuk-dagitimi.conf \
        || echo "SORUN: ayri gece raporu servisi (pmlogger_daily_report, RHEL 8 / PCP 5.3) kapali degil - her gece 02:00 tum gun arsivini okur"
fi
if grep -q -- '--noreport' "$BIN/pmlogger_daily" 2>/dev/null; then
    systemctl show -p ExecStart --value pmlogger_daily.service 2>/dev/null \
        | grep -qE 'argv\[\]=[^;]*[[:space:]](-D|--noreport)([[:space:]]|;|$)' \
        || echo "SORUN: gece raporu acik (pmlogger_daily -D yok) - her gece tum gun arsivi /var/tmp altina acilir"
    U=$(systemctl show -p FragmentPath --value pmlogger_daily.service 2>/dev/null)
    PE=$(grep -E '^ExecStart=' "$U" 2>/dev/null | tail -1 | sed -E 's#^ExecStart=##')
    DE=$(grep -E '^ExecStart=.+' /etc/systemd/system/pmlogger_daily.service.d/50-yuk-dagitimi.conf 2>/dev/null \
        | tail -1 | sed -E 's#^ExecStart=##; s# -D##')
    [ -n "$DE" ] && [ "$DE" != "$PE" ] \
        && echo "SORUN: paket birimi ExecStart satiri degismis (paket: $PE / drop-in: $DE) - playbook yeniden kosulmali"
elif ! systemctl cat pmlogger_daily_report.service >/dev/null 2>&1; then
    echo "BILGI: kurulu pmlogger_daily -D/--noreport tanimiyor ve ayri rapor servisi yok"
fi
R=$(systemctl show -p Result --value pmlogger_daily.service 2>/dev/null)
[ -n "$R" ] && [ "$R" != success ] && echo "SORUN: pmlogger_daily son calisma sonucu $R"
echo "pmlogger_daily sonraki: $(systemctl show -p NextElapseUSecRealtime --value pmlogger_daily.timer 2>/dev/null)"
# PCP_GECE_DOGRULA_SON (playbook-pcp'den araclar/ortak-govde.sh ile alinir; elle degistirmeyin)
)
# PCP saklama alana sigiyor mu (salt okuma)
saklama_dogrula() (
# PCP_SAKLAMA_DOGRULA (rol playbooklarinda birebir ayni) - olcum Izleme/Logaltyapi gorevi ile AYNI kural
# (tam gunler; bugun ve en eski gun sayilmaz; 2 tam gun yoksa olcum yok); '--tags dogrula' tek basina
# kosulunca olcum olgusu tanimsiz oldugundan burada BAGIMSIZ yapilir.
set -o pipefail
ENAZ=$pcp_saklama_en_az_gun; HEDEF=$pcp_saklama_hedef_gun
ORAN=0.8
[ "$(findmnt --target /var/log/pcp -n -o TARGET 2>/dev/null)" = "/var/log/pcp" ] || ORAN=$pcp_paylasimli_oran
# pmlogger_timers yeri pcp.conf icindeki PCP_SYSCONFIG_DIR: RHEL /etc/sysconfig, Debian /etc/default; pcp.conf yoksa RHEL yolu
TM=$( [ -f /etc/pcp.conf ] && . /etc/pcp.conf; printf '%s' "${PCP_SYSCONFIG_DIR:-/etc/sysconfig}" )/pmlogger_timers
[ -f "$TM" ] || { echo "pmlogger_timers yok (PCP kurulu degil)"; exit 0; }
K=$(grep -E '^PMLOGGER_DAILY_PARAMS=' "$TM" 2>/dev/null | tail -1 | grep -oE -- '-k[ =]?[0-9]+' | tr -dc '0-9')
# systemd ortam dosyasi satir sonu yorumunu TANIMAZ: tirnaktan sonraki ek ya da tirnaksiz degerde '#' degerin
# parcasi olur (or. -k 28 # ... -> "-k value (28#)"), pmlogger_daily her gece hatayla durur (sikistirma/silme yok)
PL=$(grep -E '^PMLOGGER_DAILY_PARAMS=' "$TM" 2>/dev/null | tail -1)
DE='^PMLOGGER_DAILY_PARAMS=.*#|^PMLOGGER_DAILY_PARAMS="[^"]*"[[:space:]]*[^[:space:]]'
if printf '%s\n' "$PL" | grep -qE "$DE"; then
    echo "SORUN: PMLOGGER_DAILY_PARAMS satirinda deger disi ek var (satir sonu yorumu?) - systemd degerin"\
         "parcasi sayar, pmlogger_daily hatayla durur: $PL"
fi
[ -n "$K" ] || { echo "SORUN: PMLOGGER_DAILY_PARAMS icinde -k yok (PCP varsayilani 14 gun, alana sigdirilmadi)"; exit 0; }
[ "$K" -ge "$ENAZ" ] || echo "SORUN: pmlogger -k $K < en az $ENAZ gun"
[ "$K" -le "$HEDEF" ] || echo "SORUN: pmlogger -k $K > hedef $HEDEF gun"
LV=$(df -Pm /var/log/pcp 2>/dev/null | awk 'NR==2{print $2}')
BOS=$(df -Pm /var/log/pcp 2>/dev/null | awk 'NR==2{print $4}'); KUL=$(du -sm /var/log/pcp 2>/dev/null | cut -f1)
D=/var/log/pcp/pmlogger/$(hostname)
[ -d "$D" ] || D=$(find /var/log/pcp/pmlogger -maxdepth 2 -name '*.index*' -printf '%h\n' 2>/dev/null | head -1)
HAM=0; XZ=0; GUN=0
if [ -n "$D" ] && [ -d "$D" ]; then
    BUGUN=$(date +%Y%m%d)
    PC=/etc/pcp/pmlogger
    VOL=$(grep -hoE -- '-v[[:space:]]*[0-9]+[Mm][Bb]' $PC/control $PC/control.d/* 2>/dev/null | head -1 | tr -dc '0-9' || true)
    VOL=${VOL:-100}
    GUNLER=$(find "$D" -maxdepth 1 -mindepth 1 -printf '%f\n' | grep -oE '^[0-9]{8}' | sort -u | grep -vx "$BUGUN" || true)
    GUN=$(printf '%s\n' "$GUNLER" | grep -c . || true)
    if [ "$GUN" -ge 3 ]; then
        for p in $(printf '%s\n' "$GUNLER" | tail -n +2); do
            b=$(du -cm "$D"/"$p".* 2>/dev/null | tail -1 | cut -f1)
            PARCA=$(find "$D" -maxdepth 1 -name "$p.*" -printf '%f\n' 2>/dev/null | grep -vE '[.](index|meta)([.]|$)' \
                | grep -E '[.][0-9]+([.](xz|zst|gz|bz2|lzma))?$' || true)
            n=$(printf '%s\n' "$PARCA" | grep -c . || true)
            h=$((n * VOL)); [ "$b" -gt "$h" ] && h=$b
            [ "$h" -gt "$HAM" ] && HAM=$h
            if [ -n "$PARCA" ] && ! printf '%s\n' "$PARCA" | grep -qvE '[.](xz|zst|gz|bz2|lzma)$'; then
                [ "$b" -gt "$XZ" ] && XZ=$b
            fi
        done
    fi
fi
[ "$XZ" -gt 0 ] || XZ=$HAM
if [ "${LV:-0}" -gt 0 ] && [ "$HAM" -gt 0 ]; then
    # tavan (R2) = min(LV x pay, PCP kullanimi + bos alan - LV x 0,2): bolum yuzde 80 sinirini GECMEZ (ustun kural)
    GEREK=$((2 * HAM + (K - 2) * XZ))
    TAVAN=$(awk -v l="$LV" -v o="$ORAN" -v b="${BOS:-0}" -v k="${KUL:-0}" \
        'BEGIN{t=l*o; u=k+b-l*0.2; if ((b>0||k>0) && u<t) t=u; if (t<0) t=0; printf "%d", t}')
    if [ "$GEREK" -le "$TAVAN" ]; then
        echo "pmlogger -k $K gun sigiyor: gerek ~$GEREK MB <= tavan $TAVAN MB (LV $LV MB, pay $ORAN, bos ${BOS:-0} MB; gun ham $HAM / xz $XZ MB)"
    else
        echo "SORUN: pmlogger -k $K gun icin ~$GEREK MB gerekir, tavan $TAVAN MB (LV $LV MB, pay $ORAN, bos ${BOS:-0} MB)" \
             "- LV buyutulmeli ya da bekci silecek"
    fi
else
    echo "pmlogger -k $K gun (alan olcumu yok: $GUN tamamlanmis gun, en az 3 gerekir - sonraki kosumda olculur)"
fi
# PCP_SAKLAMA_DOGRULA_SON (playbook-pcp'den araclar/ortak-govde.sh ile alinir; elle degistirmeyin)
)
log "Dogrulama (bilgi kipi; kosum durmaz)"
DOGRULAMA=$( { dogrula; gece_dogrula; saklama_dogrula; } 2>/dev/null )
bilgi "SORUN SAYISI: $(printf '%s\n' "$DOGRULAMA" | grep -c '^SORUN')"
printf '%s\n' "$DOGRULAMA" | sed 's/^/[pcp-setup]   /'

# ============================================================================
# KOSUM SONU YEDEGI (sonraki kosum kendi ciktisini yeniden yedeklemesin; her icerik durumu yedekte kalir)
# ============================================================================
# Mantik bastaki yedekle ayni; yedek adi <dosya>-kosum-sonu-<damga>, kayit _durum-<damga>.txt (geri alma manifesti
# _kosum-<damga>.txt yalniz degisiklik ONCESI icerikleri tasir). Kosum basinda olmayip simdi var olan dosyalar
# _kosum- manifestine "OLUSTURULDU  <dosya>  -" satiriyla girer (R13; geri alma = /var/backup agacina tasima).
if [ "$UYGULA" -eq 1 ] && [ ${#YEDEK[@]} -gt 0 ]; then
    KOK=$yedek_kok; DAMGA=$yedek_damga; MANIFEST="$KOK/_durum-$DAMGA.txt"
    for f in $YOK_DOSYALAR; do
        [ -f "$f" ] || continue
        grep -qsF "OLUSTURULDU  $f  " "$KOK/_kosum-$DAMGA.txt" && continue
        if mkdir -p "$KOK" && chmod 0700 "$KOK" && printf 'OLUSTURULDU  %s  -\n' "$f" >> "$KOK/_kosum-$DAMGA.txt"; then
            chg "manifest: OLUSTURULDU $f"
        else
            bilgi "SORUN: geri alma manifestine yazilamadi ($KOK/_kosum-$DAMGA.txt: OLUSTURULDU $f)"; YEDEK_HATA=1
        fi
    done
    for f in "${YEDEK[@]}"; do
        [ -f "$f" ] || continue
        KS=$(kaynak_sha "$f")
        [ -n "$KS" ] && [ "$(sha256sum "$f" | awk '{print $1}')" = "$KS" ] && continue
        [ "$f" = "$pcp_timers_dosya" ] && grep -qxF "$SAKLAMA_SATIRI" "$f" && continue
        h="$KOK$f"
        zaten=0
        for y in $(ls -1 "$h"-* 2>/dev/null | sort -r); do
            [ -f "$y" ] || continue
            if cmp -s "$f" "$y"; then zaten=1; break; fi
        done
        [ "$zaten" -eq 1 ] && continue
        if mkdir -p "$(dirname "$h")" && chmod 0700 "$KOK" && cp -aL "$f" "$h-kosum-sonu-$DAMGA" && cmp -s "$f" "$h-kosum-sonu-$DAMGA" \
            && printf '%s  %s  %s\n' "$(sha256sum "$f" | awk '{print $1}')" "$f" "$h-kosum-sonu-$DAMGA" >> "$MANIFEST"; then
            chg "kosum sonu yedegi: $f -> $h-kosum-sonu-$DAMGA"
        else
            bilgi "SORUN: kosum sonu yedegi alinamadi: $f ($h-kosum-sonu-$DAMGA)"; YEDEK_HATA=1
        fi
    done
    [ "$YEDEK_HATA" -eq 0 ] || die "kosum sonu yedegi alinamadi - degisiklikler YAPILDI, geri alma manifesti $KOK/_kosum-$DAMGA.txt gecerli; $KOK alanini duzeltin" 3
fi

echo
if [ "$YALNIZ_DOGRULA" -eq 1 ] || [ "$uygulama_modu" != uygula ]; then
    log "Bitti (rapor modu): sistemde degisiklik yapilmadi."
elif [ "$KURU" -eq 1 ]; then
    log "Bitti (kuru calisma): $N_DEG degisiklik YAPILACAKTI, $N_AYNI adim zaten yerindeydi."
else
    log "Bitti: $N_DEG degisiklik yapildi, $N_AYNI adim zaten yerindeydi."
    [ "$N_DEG" -gt 0 ] && log "Yedek ve manifesto: $yedek_kok/_kosum-$yedek_damga.txt"
fi
exit 0
