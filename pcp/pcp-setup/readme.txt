================================================================================
 pcp-setup/ - PCP (Performance Co-Pilot) KURULUM VE ANALIZ ARACLARI (surum 4.4.1)
================================================================================

KISA OZET
---------
 * pcp-setup.sh 4.4.1 (08.11.2026), playbook-pcp v1.13 (playbook-pcp/pcp-onlem.yml)
   ile BIREBIR AYNI onerilen yapilandirmayi, ayni degisken degerleriyle
   uygulayan bagimsiz betiktir. Ansible/AWX olmayan tek RHEL ya da Debian 13 sunucusunda kullanilir;
   filo (400-2000 VM) icin playbook-pcp + AWX dalga plani (el kitabi 17.19).
 * Gece isleri, tam gun olcumu ve iki dogrulama kalemi playbook'tan AYNEN alinir
   (../araclar/ortak-govde.sh); ../araclar/tutarlilik.sh birebirligi denetler (iki arac
   gelistirme deposundadir; paylasilan pakette yok).
 * 4.2 <-> playbook v1.9 capraz testi 02.11.2026'da dort test sunucusunda temiz (asagida).
 * 4.4 (08.11.2026): Debian 13 (trixie) destegi - dpkg-query/apt-get, ayar dosyalari /etc/default
   (pcp.conf PCP_SYSCONFIG_DIR), Debian paketinin acik biraktigi pmproxy bu calistirmada kurulan PCP'de
   kapatilir ve pmie baslatilir (RHEL ile ayni son durum). Debian lab capraz testi temiz (asagida).
 * 4.4.1 (08.11.2026): yalniz yorum ve ileti dili; davranis 4.4 ile ayni.
 * 4.3 (07.11.2026): playbook v1.10 (bos alan kapisi zeroconf icin de, ek paketler kapiya bagli),
   v1.11 (pmlogger sure denetimi SIGUSR2, kayit grubu guvenli yazim) ve v1.12 tasindi; lab capraz
   testi temiz (asagida). Playbook v1.12'de yedek alinamayan sunucu ATLANIR ve digerlerine devam
   edilir; betikte (tek sunucu) karsiligi cikis 3'tur.
 * 4.2.1 (07.11.2026, yama = playbook-pcp v1.11.1 yedek denetimi): yedek alinamazsa
   (/var/backup dolu ya da salt okunur) 'yedek' yazilmaz, manifeste satir girmez, SORUN ve
   CIKIS 3; degisiklik oncesi yedekte hicbir dosyaya dokunulmaz. Diger kararlar 4.2 / v1.9.
 * Varsayilan RAPOR modudur: sistemde HICBIR degisiklik yapmaz. Uygulamak icin -u.
 * Ayrintili aciklama (faydalar, olumsuz yanlar, gereklilikler, yuk olcumleri,
   karar tablolari): ../PCP_EL_KITABI.md Bolum 17.

DOSYALAR
--------
  pcp-setup.sh        Kurulum/yapilandirma (rapor | uygula), playbook-pcp v1.13 esi
  pcp-dogrula.sh      Salt okunur dogrulama paketi v2.5 (playbook-pcp/pcp_files
                      kopyasi; pcp-setup.sh -u bunu /usr/local/bin'e kurar)
  pcp-top-apps.sh     Arsivden son N gunun en cok CPU/bellek/disk kullanan
                      uygulama ve kullanicilari (v1.2; pmlogsummary)
  pcp-top-mem.sh      En cok bellek kullanan surecler (canli / uzak / arsiv)
  pcp-top-disk.sh     En cok disk G/C yapan surecler/uygulamalar + en mesgul diskler
  pcp-top-net.sh      En cok trafik olan ag kartlari + (varsa) uygulama bazli ag
  ansible/README.md   Ansible icin playbook-pcp'ye yonlendirme (eski rol kaldirildi)
  pcp-setup-gecmis.txt  Gelistirme gecmisi (gelistirme deposunda; paylasilan pakette yok)

DESTEKLENEN SISTEMLER
---------------------
 * RHEL 8 / 9 / 10 ve turevleri (Rocky, AlmaLinux, Oracle Linux, CentOS Stream), Fedora ve
   Debian 13 (trixie; 4.4) - playbook-pcp v1.13 ile ayni. Ubuntu ve Debian 12 ve oncesi
   desteklenmez (4.1'de Ubuntu vardi; 4.2'de kaldirildi; el kitabi 17.17).
 * Debian 13 paketleri: pcp, pcp-zeroconf (Debian main; pcp-system-tools yoktur, araclar pcp
   paketinde). apt-get update yalniz kurulacak paket varsa ve liste 1 saatten eskiyse.
 * Paketler: pcp, pcp-system-tools (zorunlu), pcp-zeroconf (AppStream; yoksa bilgi
   verilir, surec basina kayit yapilmaz). Analiz betikleri icin gawk.

KULLANIM (root)
---------------
  ./pcp-setup.sh                          # RAPOR: tespit + rapor + dogrulama, degisiklik YOK
  ./pcp-setup.sh -u -n                    # uygula KURU CALISMA (playbook --check esi)
  ./pcp-setup.sh -u                       # uygula: varsayilan acik adimlar
  ./pcp-setup.sh -d                       # yalniz dogrulama (playbook --tags dogrula esi)
  ./pcp-setup.sh -u -e kayit_profili=varsayilan     # 3.x kaydindan onerilen kayda donus
  ./pcp-setup.sh -u -e hotproc_karari=uygula -e pmie_karari=uygula
  ./pcp-setup.sh -u -e pcp_ek_pmdalar=bonding,mounts -e pcp_ek_paketler=pcp-pmda-bonding

  -e AD=DEGER playbook'taki -e degiskeniyle AYNI ad ve degerleri kabul eder
  (liste degiskenlerinde virgul). Bilinmeyen ad reddedilir.

Cikti isaretleri: [+] yapildi  [=] zaten ayni  [n] kuru calismada yapilacakti.
Yedek: /var/backup/pcp-onlem/<orijinal yol>-<damga>, manifesto _kosum-<damga>.txt
(playbook ile AYNI agac: log-saklama bu izi gorup PCP saklamasina dokunmaz).

NE YAPAR (uygula modu; sira playbook ile ayni)
----------------------------------------------
On kosul: rapor modunda -e ile degisiklik karari verilirse calistirma BASTA durur; en az
gun 8'in altina yalniz -e pcp_test_ortami=true ile; gece penceresi 30-600, kontrol 5-29 dk.
Varsayilan ACIK:
 1. Kurulum: yeni kurulumda bos alan kapisi (/var/log/pcp bolumunde >= 1536 MB bos ve
    kurulum sonrasi <= %80; yoksa PCP KURULMAZ, SORUN). pcp + pcp-system-tools;
    pcp-zeroconf AYRI cagri; pmcd + pmlogger etkin.
 2. Tespit (her calistirmada, salt okuma): servisler, proc -A, surec G/C gorunurlugu
    (root ve pcp kullanicisi), PMCD_LOCAL, pmproxy, kayit -c dosyasi ve riskli
    metrikler, saklama sahipleri (rol playbook'u yalniz pmlogger_timers YEDEGI varsa;
    pcp-merkezi dizini), log-saklama bekcisi, eski pcp-setup izleri, kapatilacak
    PMDA'lar; /var/log/pcp alani (LV, bos, PCP kullanimi) ve TAM gunlerin arsiv boyutu.
 3. Eski 3.x izleri: control.d/*.pcp-setup.orig, pmcd.conf.pcp-setup.orig,
    backup.pcp-setup/ -> /var/backup/pcp-onlem/eski-pcp-setup/. pcp-log-guard
    YALNIZ log-saklama bekcisi varsa kapatilip tasinir (tek silici ilkesi).
 4. PMDA kapatma: dm, kvm, nfsclient, openmetrics, opentelemetry (+ eski adlari dmcache,
    prometheus) kendi Remove betigiyle; pmcd.conf'a yeniden kurulum isareti (gecici
    dosya + mv; yazim dosyadan dogrulanir).
 5. Kayit grubu kapatma: memory/zoneinfo, memory/buddyinfo (force exclude;
    pmlogconf yalniz pcp kullanicisiyla).
 6. Gece isleri: pmlogger_daily/pmie_daily kisa ad ozetinden sabit saate (RHEL 9/10
    00:10 + 0-120 dk, RHEL 8 ailesi 03:10 + 0-120 dk), yarim saatlik kontroller 0-29 dk;
    gece raporu kapali; gecis kapisi; Persistent=false. Yalniz daemon-reload.
 7. Saklama: PMLOGGER_DAILY_PARAMS="-E -x 1 -k K", yalniz baska sahip yoksa;
    K = min(32, max(8, 2 + (tavan - 2 x ham gun) / xz gun)),
    tavan = min(LV x pay, PCP kullanimi + bos alan - LV x 0,2); pay ayri bolumde 0,8,
    paylasilan bolumde 0,25; mevcut deger 2 gun tolerans icindeyse korunur; kayit
    hacmi bu calistirmada degisiyorsa (pcp-zeroconf, -A, hotproc, ek PMDA, tam profil)
    hesap ERTELENIR (mevcut -k ya da 8; 3 tam gun sonra yeniden calistirma).
 8. /etc/pcp/pmrep/ozel.conf (:canli :obur :agirlik) ve /usr/local/bin/pcp-dogrula.sh.
 9. Calistirma sonu yedegi (<dosya>-kosum-sonu-<damga>, _durum-<damga>.txt); ilk kez
    olusan dosyalar manifestte "OLUSTURULDU  <dosya>  -".
Varsayilan KAPALI (-e ile): proc_tum_surec_karari=gerekirse (-A: yalniz pcp kullanicisi
root'un gordugu surec G/C degerlerinin %80'inden azini goruyorsa VE PMCD_LOCAL=1 VE
pmproxy calismiyor VE kayitta smaps/maps/environ yoksa), kayit_profili=tam|varsayilan,
hotproc_karari=uygula, pmie_karari=uygula, pcp_ek_pmdalar, pcp_ek_paketler.
Ek (playbook'ta yok, yalniz gecis icin): kayit_profili=varsayilan istendiginde
config.default hic uretilmemisse (3.x kaydi) pmlogconf ile pcp kullanicisi olarak
uretilir; 3.x'in actigi ek PMDA'lar / izler yalniz RAPORLANIR.

YUK NOTU (sisteme yuk bindirmeme kurali - EN YUKSEK ONCELIK)
------------------------------------------------------------
 * pcp-setup.sh tespit: pminfo -f proc.psinfo.pid / proc.io.read_bytes root ve
   pcp ile (tum sureclerin /proc/<pid>/stat ve io okumasi; smaps YOK), du -cm
   (yalniz /var/log/pcp/pmlogger). Etkisi olculmedi, kisa.
 * Uygula: dnf (depo IO); PMDA kapatma, kayit grubu kapatma (ve istege bagli -A)
   pmcd/pmlogger'i yeniden baslatir (birkac saniye ornek kaybi).
 * Gece isleri: drop-in + daemon-reload (timeout 120), zamanlayici yeniden baslatilmaz.
   Ilk gecelerde pmlogger -T suresi dolunca gunde bir kendiliginden yeniden baslar
   (birkac sn kayip, en cok ~12 gun; RHEL 8 ailesinde ~17); eszamanli yeniden baslatma
   yuku OLCULMEDI - cok sunucuda dalgalarla uygulanir (el kitabi 17.19).
 * Varsayilan kapali adimlarin etkisi OLCULMEDI: once test sunucusunda olcun.
 * pcp-dogrula.sh -y CPU YUKU URETIR: canli ortamda kosmayin.
 * pcp-top-apps.sh: arsiv basina ~30 sn tek cekirdek + arsiv boyutu kadar disk
   okuma; analiz makinesinde kosun (canli sunucuda zorunluysa -j 1, nice/ionice).
 * pcp-top-mem.sh / pcp-top-disk.sh canli: tum sureclerin status / io dosyalari
   (mmap_lock almaz, smaps okumaz - olculdu). -t'yi 5 sn altina indirmeyin.
 * pcp-top-net.sh -P: ss -tinp (tum TCP soketleri + tum sureclerin fd dizinleri);
   buyuk sunucuda etkisi OLCULMEDI, varsayilan KAPALI.
 * Bu araclarla CALISTIRMAYIN (olculdu 26.10.2026, smaps/environ okur):
   'pcp atop -R', 'pmrep :pidstat-s', 'pmrep proc.smaps.*', 'pidstat -s',
   'pcp htop' (tum sureclerin environ dosyasi). Ayrinti: el kitabi 14.6.

ANALIZ BETIKLERI - ORNEKLER
---------------------------
  sudo ./pcp-top-disk.sh -t 30 -n 20 -g         # 30 sn, uygulama bazli disk G/C
  ./pcp-top-disk.sh -A /var/log/pcp/pmlogger/$(hostname) -S @03:00 -T @04:00
  ./pcp-top-net.sh -t 10                        # ag kartlari (+ bcc varsa surecler)
  sudo ./pcp-top-net.sh -P -g -t 10             # ss ile uygulama bazli TCP (YUK NOTU)
  sudo ./pcp-top-mem.sh -n 20 -x
  ./pcp-top-apps.sh -A <sos>/var/log/pcp/pmlogger/<makine> -d 7 -o rapor.txt
Uygulama bazli ag verisi standart PCP kaydinda YOKTUR (cekirdek surec basina ag
sayaci sunmaz); ayrinti el kitabi 17.7.

DOGRULAMA DURUMU 4.4 (08.11.2026, LAB - Debian 13)
------------------------------------------------------------------------------------
 * bash -n, shellcheck, ../araclar/tutarlilik.sh (34 degisken + 4 ortak govde v1.13 ile ayni) gecti.
 * deb13-testvm01 (Debian 13.7, PCP 6.3.8; saklama 3 gun test ek degiskenleri):
   - playbook v1.13 ile kurulan sunucuda betik -u: 0 degisiklik, SORUN 0.
   - VM sifirlandi (paketler kaldirildi, eski dizinler /root/lab-arsiv-* altina tasindi):
     rapor SORUN 1 (pcp yok) -> -u -n 2 -> -u 36 degisiklik / SORUN 0 (21 sn; pmproxy disable,
     pmie baslatildi, saklama /etc/default/pmlogger_timers) -> -u 0.
   - betikten sonra playbook --check ve uygula changed=0.
 * RHEL karsi testi (playbook v1.13; genel01, oel8test1): --check 0, uygula 0, SORUN 0. Betik 4.4
   RHEL'de ayrica calistirilmadi; RHEL yollari degismedi (PCP_SYSCONFIG_DIR=/etc/sysconfig).

DOGRULAMA DURUMU 4.3 (07.11.2026, LAB)
------------------------------------------------------------------------------------
 * bash -n, shellcheck, ../araclar/tutarlilik.sh (34 degisken + 4 ortak govde v1.12 ile ayni) gecti.
 * Lab (genel01 RHEL 9.8, oel8test1 OL 8.10 / PCP 5.3.7, rhel9-testvm02 RHEL 9.8; test ortami
   saklama 3 gun ek degiskenleriyle): playbook v1.12 uygulandiktan sonra betik rapor SORUN 0,
   -u 0 degisiklik (sure denetimi 'sinyal gerekmiyor'); betikten sonra playbook changed=0.
 * rhel9-testvm02: ozel.conf degistirilip /var/backup/pcp-onlem chattr +i iken -u -> cikis 3,
   dosya degismedi; kilit kalkinca -u yedek + ozel.conf duzeltildi (2 degisiklik).
 * Test edilmedi: sifir kurulum ve bos alan kapisinin zeroconf dali (lab sunucularinda zeroconf kurulu),
   kayit grubu kapatmanin yeni yazimi (lab sunucularinda gruplar zaten kapali).

DOGRULAMA DURUMU 4.2.1 (07.11.2026, yalniz yedek denetimi)
------------------------------------------------------------------------------------
 * bash -n, shellcheck gecti. Yedek islevi ve calistirma sonu blogu betikten AYNEN cikarilip
   gecici dizinde (root'suz; dolu alan icin unshare -rm + 64/128 KB tmpfs) calistirildi:
   yazilabilir alan -> 5 degisiklik, cikis 0; salt okunur ve dolu alan -> SORUN, cikis 3,
   hedef dosya DEGISMEDI, basarisiz kopya manifeste girmedi; calistirma sonu sigmazsa -> SORUN,
   cikis 3, _durum'a sahte satir yok.
 * Test edilmedi: test sunucusunda tam calistirma (07.11.2026 test sunucularina erisim yoktu).
 * Not: v1.10 / v1.11 degisiklikleri 4.3'te tasindi.

DOGRULAMA DURUMU 4.2 (02.11.2026)
------------------------------------------------------------------------------------
 * bash -n, shellcheck, ../araclar/tutarlilik.sh (34 degisken degeri + 4 ortak govde
   playbook-pcp v1.9 ile ayni) gecti.
 * Analiz makinesi RHEL 10.2 / PCP 7.0.3, kullanici ad alaninda (unshare -r, yetkisiz):
   rapor ve -u -n calistirildi; on kosul korumalari (rapor modunda -e karar, pencere 0, en az
   gun < 8) beklenen hatayi verdi; olcum, 32 gun, -E satiri, opentelemetry raporlandi.
 * Capraz test (test sunuculari; baslangic 26.10'daki 4.0 / v1.4 yapilandirmasi):
   - .155 RHEL 9.8: rapor 9 SORUN -> -u -n 5 -> -u 15 (SORUN 0) -> -u 0; playbook changed=0 x2
   - .166 Rocky 10.2: -u 17 (opentelemetry PMDA kaldirildi, -k 32) -> 0; playbook changed=0 x2
   - .133 RHEL 8.3 (log-saklama): -u 14 (pmlogger_daily 03:47:42, Persistent=false, ayri
     rapor servisine kosul drop-in'i; -k 7 log-saklama'nin - dokunulmadi) -> 0; playbook 0 x2
   - .173 RHEL 9.8 ters sira: playbook 6 -> 0; betik -u 0; playbook 0
   - pcp-dogrula.sh -q: .155 85/0, .173 84/0, .166 81/1 (2.4: -A yok -> surec G/C eksik HATA;
     playbook dogrulamasi BILGI der). 03.11: 2.5 (playbook v1.9.1) ile giderildi - karar
     PCP_DOGRULA_PROC_KARAR (dokunma varsayilan = BILGI/ATLA, gerekirse = HATA); .166 81/0,
     playbook v1.9.1 changed 2 -> 0, ardindan pcp-setup.sh -u 0 degisiklik,
     .133 78/6 (PCP 5.3.7 bilinen yanlis HATA'lar + -k 7).
 * Test edilmedi: sifir kurulum (paketsiz sunucu), bos alan kapisinin 'yetersiz' dali,
   tam profil / hotproc / pmie / ek PMDA ile 4.2 capraz testi; .91 kapaliydi.

DOGRULAMA DURUMU 4.0/4.1 (26.10.2026, GERCEK TEST SUNUCULARI, sifirdan; ayrinti el kitabi 17.15)
------------------------------------------------------------------------------------
 Her senaryodan once PCP paketleri kaldirildi, /etc/pcp /var/lib/pcp /var/log/pcp
 /var/backup/pcp-onlem /etc/sysconfig/pm* /var/backup altina tasindi.
 * Rocky Linux 10.2 / PCP 7.0.3:
   - sifir: rapor 0, -u -n 4 fark, -u 21 -> 1 (yedek) -> 0; playbook uygula changed=0
   - tam + hotproc + pmie + bonding: betik 13 -> 4 (yedek) -> 0; playbook ayni
     degiskenlerle changed=0 (config.pcp-tam bayt bayt ayni); varsayilana donus,
     playbook changed=0
   - ters sira: playbook (changed=9) -> betik 1 (yedek) -> 0 -> playbook changed=0
   - 3.x gecisi: eski betik -> rapor 7 SORUN -> -u 22 -> -e kayit_profili=varsayilan 4
     -> 0; playbook changed=0
   - -A eklenmedi (PCP 7.0.3 paketinde PMCD_LOCAL yorumda: guvenlik kapisi)
 * RHEL 8.3 / PCP 5.3.7 (log-saklama kurulu): betik 19 -> 0 -> 0, playbook changed=0;
   ters sira playbook 9 -> betik 0 -> playbook 0. -A eklendi. Saklama sahibi
   log-saklama -> satira dokunulmadi.
 * RHEL 9.8 / PCP 6.3.7 (3 sunucu, lab deposu duzeltildikten sonra):
   - .91 sifir: rapor 0, -u -n 4, -u 22 -> 1 (yedek) -> 0; playbook changed=0; -A eklendi
   - .155 ters sira: playbook 10 -> betik 1 (yedek) -> 0 -> playbook 0; 3.x gecisi
     rapor 6 SORUN -> -u 22 -> varsayilan 4 -> 0 (SORUN 0) -> playbook 0
   - .173 tam + hotproc + pmie + bonding: betik 14 -> 4 (yedek) -> playbook changed=0
     -> betik 0; varsayilana donus 2 -> playbook 0
   - pcp-dogrula.sh -q: 79 gecti, 0 kaldi
 * Bilinen (playbook ile ortak): tam profil + -A varken dogrulama yorum satirlarindaki
   metrik adlari yuzunden yanlis SORUN verir; tam profil -A'dan once acilirsa -A eklenmez.
 * Analiz betikleri: analiz makinesi (RHEL 10.2), RHEL 8.3, Rocky 10.2 canli/arsiv;
   200 MB dd uc sunucuda da ilk sirada. bcc PMDA yolu TEST EDILMEDI (metrik adlari
   PMDA kaynagindan).
 * Bilinen: pcp-dogrula.sh 2.1 (playbook-pcp'nin dosyasi) PCP 5.3.7'de 5 yanlis HATA
   (2.2'de :pmstat yanlis HATA'si ATLA oldu; digerleri suruyor)
   verir (--top-cpu-adv, pcp netstat, :pmstat yok; arsiv sayimi 0).

DOGRULAMA DURUMU - UBUNTU (26.10.2026, yalniz 4.1; 4.2'de Ubuntu destegi yok - tarihsel kayit)
------------------------------------------------------------------------------------
 Ubuntu 24.04.5 LTS / PCP 6.2.0, dort test sunucusu.
 A) PCP paketleri ayni gun kurulmus sunucular (192.168.3.65 spark1, .66 spark2):
 * spark2: playbook rapor (SORUN 9) -> --check 3 -> uygula 7 -> 1 (yedek) -> 0;
   ardindan betik -u: 0 degisiklik.
 * spark1: betik rapor ve -u -n (playbook ile ayni tablo) -> -u 19 -> 1 (yedek) -> 0;
   ardindan playbook uygula changed=0.
 B) SIFIRDAN kurulum: PCP paketi ve /etc/pcp yok (192.168.3.67 spark3, .68 spark4;
    arm64, DGX Spark). apt ile 14 paket kuruldu (pcp, pcp-zeroconf + bagimliliklar).
 * spark3 (once betik): rapor SORUN 1 ("pcp kurulu degil"), -u -n 4 fark,
   -u 21 -> 1 (yedek) -> 0; ardindan playbook uygula changed=0.
 * spark4 (once playbook): rapor 0, --check 2, uygula 9 -> 1 (yedek) -> 0;
   ardindan betik -u: 0 degisiklik.
 * pmlogger NRestarts 0; pcp-dogrula.sh -q (2.2): 74 gecti, 1 KALDI (-A), 6 atlandi.
 * apt paket listesi her koşumda 1 saatten yeni oldugu icin 'apt-get update'
   adimi atlandi: yenileme yolu calisarak TEST EDILMEDI.
 * spark4 once betikle de kurulmustu (test duzenegi hatasi); sonra 14 paket
   purge edilip dizinler /root/pcp-test-yedek-20261026T221535 altina alindi ve
   sifirdan yeniden kuruldu. pcp kullanicisi purge ile silinmez, kaldi.
 * Kalan tek SORUN (A ve B): -A eklenmedi (/etc/default/pmcd PMCD_LOCAL=1 yorumda).
 * Olmayan ek paket (-e pcp_ek_paketler=pcp-yok-paket): iki arac da BILGI verip surdu.
 * pcp-dogrula.sh -q: 2.1 ile 74 gecti / 2 KALDI (-A ve :pmstat sablonu yok);
   2.2 tanimsiz hazir sablonu ATLA sayar.
 * Ilk denemede bulunan hata: Ubuntu'da /bin/sh = dash; playbook kabuk gorevleri
   'set -o pipefail' ile duruyor ve tespit "PCP KURULU DEGIL" raporluyordu.
   v1.5'te gorevler /bin/bash ile kosar. Betik zaten #!/bin/bash.

GERI ALMA
---------
  cat /var/backup/pcp-onlem/_kosum-*.txt          # ne yedeklendi / tasindi
  cp -p /var/backup/pcp-onlem/etc/pcp/pmcd/pmcd.conf-<damga> /etc/pcp/pmcd/pmcd.conf && systemctl restart pmcd
  cp -p /var/backup/pcp-onlem/etc/sysconfig/pmlogger_timers-<damga> /etc/sysconfig/pmlogger_timers
  ./pcp-setup.sh -u -e kayit_profili=varsayilan   # kayit profilini onerilen kayda dondur
  Kapatilan PMDA'yi geri acmak: pmcd.conf'taki '# pcp-onlem: <ad>/pmda<ad> KAPALI'
  satirini silin, cd /var/lib/pcp/pmdas/<ad> && ./Install

--------------------------------------------------------------------------------
Tek kaynak: yapilandirma kurali degisirse ONCE playbook-pcp degisir, bu betik ona uyarlanir.
Tutarlilik denetimi: ../araclar/tutarlilik.sh (gomulu dosyalar, pcp-dogrula.sh, degisken
degerleri, ortak govdeler, pcp-top-apps.sh, bash -n, shellcheck). Govde esitleme:
../araclar/ortak-govde.sh --yaz (playbook degisince).
================================================================================
