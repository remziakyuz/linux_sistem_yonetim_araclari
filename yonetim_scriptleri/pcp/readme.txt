================================================================================
 pcp-setup.sh - PCP (Performance Co-Pilot) TAM İZLEME KURULUM KILAVUZU
================================================================================

AMAÇ
----
Tek script ile RHEL veya Ubuntu tabanlı bir sunucuda PCP'yi kurar ve şu
şekilde yapılandırır:

 * CPU, bellek, disk, filesystem, network/ethernet trafiği, prosesler
   (kullanıcı kimlikleriyle) ve donanım (envanter, sensör, disk SMART)
   verileri sürekli diske arşivlenir.
 * Arşivler günlük döner, anında sıkıştırılır, 14 gün saklanır.
 * Disk koruması: PCP logları hiçbir koşulda diski dolduramaz.
 * hotproc: ölçeklenebilir proses izleme (RHEL 9'da varsayılan olarak YOKTUR).
 * Hazır inceleme şablonları: pmrep :canli / :obur / :agirlik
 * pmie eşik alarmları (pmieconf hazır kural kütüphanesi) -> syslog
 * pcp-dogrula.sh: salt-okunur, ~80 testlik bağımsız doğrulama paketi
 * Tekrar çalıştırılabilir ("idempotent"): her adım önce mevcut durumu
   kontrol eder, aynıysa atlar;
   servisler yalnızca ilgili yapılandırma değiştiyse yeniden başlatılır.
   -n ile kuru çalışma (hiçbir şey değiştirmeden farkları göster), -f ile zorla.

Toplanan arşivler pcp-top-apps.sh rapor script'i ve tüm standart PCP
araçlarıyla (pmrep, pmstat, pcp atop -r, pmchart, pmlogsummary...) uyumludur.

DESTEKLENEN SİSTEMLER
---------------------
 * RHEL / CentOS / Rocky / AlmaLinux / Oracle Linux (dnf)
 * Ubuntu / Debian (apt)

DOĞRULAMA DURUMU
----------------
 * Fedora 44 / PCP 7.2.1 systemd konteyneri - 25 Eylül 2026 (idempotent sürüm):
   1. koşu 18 değişiklik / çıkış 0; 2. koşu 0 değişiklik, 26 adım "zaten";
   -n kuru çalışma bekleyen 3 farkı doğru listeledi; -f zorla 11 değişiklik;
   pcp-dogrula.sh -y sonucu: 78 geçti, 0 kaldı, 2 atlandı.
   Ansible rolü aynı konteynerde: ilk koşu failed=0, ikinci koşu changed=0.
 * RHEL 9.8 (Plow) / PCP 6.3.7-8 - 22 Ağustos 2026'da uçtan uca test edildi.
   Makine abonelik sunucusuna KAYITLI DEĞİLDİ (yalnızca yerel ISO reposu):
   lm_sensors, pcp-pmda-lmsensors, pcp-pmda-smart, pcp-pmda-bonding
   paketleri bulunamadı; script bunları atlayıp kuruluma devam etti.
   Kurulum çıkış kodu 0, pcp-dogrula.sh sonucu: 64 geçti, 0 kaldı.
 * Ubuntu 26.04 / PCP 7.1.1 - önceki oturumda test edildi.

ÇEVRİMDIŞI / KAYITSIZ SİSTEMLER
-------------------------------
Script paketleri iki gruba ayırır:
  ZORUNLU  : pcp, pcp-conf, pcp-system-tools  -> kurulamazsa DURUR
  OPSİYONEL: pcp-gui, pcp-doc, lm_sensors, smartmontools, gawk ve tüm
             pcp-pmda-* paketleri            -> kurulamazsa UYARI verip devam
Böylece repo erişimi olmayan sunucularda kurulum tamamlanır; yalnızca ilgili
alanlarda (sensör, SMART) izleme sınırlı olur. Sanal makinelerde sensör
metriklerinin bulunmaması zaten normaldir.

Tamamen çevrimdışı bir sunucuda önce paketleri taşıyın:
  # bağlı bir makinede
  dnf download --resolve --alldeps --destdir /tmp/pcp-rpm \
      pcp pcp-conf pcp-system-tools pcp-gui pcp-doc python3-pcp
  # hedef makinede
  dnf install --disablerepo='*' /tmp/pcp-rpm/*.rpm

KULLANIM
--------
Root olarak çalıştırılır:

  ./pcp-setup.sh -n                  # KURU ÇALIŞMA: ne değişecek, göster; dokunma
  ./pcp-setup.sh                     # varsayılanlar
  ./pcp-setup.sh -i 30               # 30 sn örnekleme
  ./pcp-setup.sh -k 30 -l 5          # 30 gün saklama, 5GB sınır
  ./pcp-setup.sh -t 85               # ayrı volümde %85 eşiği
  ./pcp-setup.sh -f                  # ZORLA: aynı olsa da yeniden yaz, servisleri yeniden başlat

Parametreler:
  -i SANİYE   Sistem+proses örnekleme aralığı        (varsayılan: 60)
  -k GÜN      Arşiv saklama süresi                   (varsayılan: 14)
  -l GB       /var/log/pcp ayrı volüm DEĞİLSE
              toplam log sınırı                      (varsayılan: 2)
  -t YÜZDE    /var/log/pcp ayrı volüm İSE temizlik
              başlatılan doluluk eşiği               (varsayılan: 80)
  -n          Kuru çalışma (dry-run)
  -f          Zorla (mevcut hotproc.conf dahil her şeyi yeniden yaz,
              sensors-detect'i tekrar çalıştır, servisleri yeniden başlat)
  -h          Yardım

TEKRAR ÇALIŞTIRILABİLİRLİK (İDEMPOTANSLIK)
------------------------------------------
"İdempotent": kaç kez çalıştırılırsa çalıştırılsın aynı sonucu verir, yapılmış
işi yeniden yapmaz. Script her adımda önce mevcut durumu okur ve çıktıda işaretler:
  [+]  yapıldı / değişti
  [=]  zaten aynı, atlandı
  [n]  (yalnızca -n) çalıştırılacak komut
Kurallar:
  * Dosyalar: içerik ve izin aynıysa dokunulmaz; farklıysa aynı dizinde geçici
    dosyaya yazılıp mv ile tek hamlede (yarım kalmadan) değiştirilir. Sistem dosyaları (pmcd.conf,
    pmlogger kontrol dosyası) ilk değişiklikten önce .pcp-setup.orig olarak
    yedeklenir; script'in kendi ürettiği dosyalar (config.pcp-full, ozel.conf,
    guard, unit'ler) parametrelerden yeniden üretilebildiği için yedeklenmez.
  * config.pcp-full artık tarih damgası TAŞIMAZ; içerik yalnızca metrik ağacı
    ya da -i değişince değişir. Böylece gereksiz pmlogger restart'ı olmaz.
  * pmcd yalnızca pmcd.conf / PMDA listesi / hotproc.conf değiştiyse,
    pmlogger yalnızca config.pcp-full / kontrol dosyası değiştiyse,
    pmie yalnızca kural/eşik değiştiyse yeniden başlatılır. Aktif değilse
    yalnızca başlatılır. daemon-reload yalnızca unit dosyaları değişince.
  * pmieconf'un enable/modify komutları her zaman başarılı döndüğü için önce
    "rules enabled" ve "list KURAL DEĞİŞKEN" okunur, yalnızca farklı olan
    uygulanır.
  * sensors-detect tek sefer çalışır: /etc/sysconfig/lm_sensors paketle de
    geldiği için varlığı kanıt sayılmaz; "# Generated by sensors-detect"
    başlığı ya da /var/lib/pcp-setup/sensors-detect.done işareti aranır.
  * Mevcut (elle ayarlanmış olabilecek) hotproc.conf'a dokunulmaz; -f yeniler.
  * Daha önce kurulumu başarısız olmuş PMDA'lar (.NeedInstall.failed) tekrar
    denenmez; -f ile denenir.
  * Temiz kurulumda pmie yapılandırması (config.default) henüz yoktur; script
    pmie'yi başlatıp dosyanın üretilmesini bekler, sonra kuralları uygular.
İkinci çalıştırma "0 degisiklik yapildi, N adim zaten yerindeydi" ile biter.

NE YAPAR (ADIM ADIM)
--------------------
 1. OS tespiti (/etc/os-release) ve paket kurulumu:
    RHEL  : pcp pcp-system-tools pcp-gui lm_sensors smartmontools gawk
            + pcp-pmda-lmsensors pcp-pmda-smart pcp-pmda-dm pcp-pmda-bonding
    Ubuntu: pcp pcp-gui lm-sensors smartmontools gawk
            (PMDA'lar pcp paketinin içindedir)
 2. proc PMDA'ya -A bayrağı ekler (pmcd.conf). BU OLMADAN pmlogger "pcp"
    kullanıcısı olarak yalnızca pcp'nin kendi proseslerini görebilir ve
    arşive postgres, java vb. hiçbir uygulama verisi yazılMAZ.
    Güvenlik notu: -A ile pmcd/pmproxy'ye erişebilen istemciler tüm proses
    adlarını/istatistiklerini okuyabilir (yazma zaten kapalıdır). İç ağ
    sunucularında genelde kabul edilebilir; hassas ortamda pmproxy portunu
    (44322) güvenlik duvarıyla sınırlayın.
 3. Ek PMDA'ları etkinleştirir (lmsensors, smart, dm, bonding) ve pmcd'yi
    yeniden başlatıp PMDA kurulumlarının bitmesini bekler.
 4. pmlogger yapılandırmasını CANLI metrik ağacından üretir:
    /var/lib/pcp/config/pmlogger/config.pcp-full
    * Sistem grubu (60 sn): kernel.all, kernel.percpu, kernel.pernode,
      mem, swap, disk, filesys, vfs, network, nfs, rpc (~1300 metrik)
    * Proses grubu (60 sn): proc.psinfo, proc.id, proc.memory, proc.io,
      proc.schedstat, proc.fd.count (112 metrik x tüm prosesler)
    * Donanım grubu (300 sn): lmsensors (sıcaklık/fan/voltaj), smart
      (disk sağlığı), dmcache/vdo
    * Envanter (arşiv başına 1 kez): hinv, kernel.uname
    BİLEREK DIŞLANANLAR:
    * Derived metrikler (PMID domain 511, örn. disk.dm.util): pmcd yeniden
      başladığında pmlogger'ı hata döngüsüne sokup pmlogger.log'u dakikada
      ~100MB şişirebiliyor. Analiz araçları bunları temel metriklerden
      otomatik hesaplar, veri kaybı yoktur.
    * proc.psinfo.environ: proseslerin environment değişkenleri (parola/
      secret sızıntısı riski).
 5. Birincil pmlogger'ı bu yapılandırmaya yönlendirir
    (/etc/pcp/pmlogger/control.d/local). Orijinalin yedeği:
    /etc/pcp/pmlogger/backup.pcp-setup/  (ASLA control.d içine yedek
    koymayın; PCP 7 pmlogger_check onu kontrol dosyası sanır ve
    "Duplicate pmlogger instances" hatasıyla pmlogger'ı düşürür.)
 5b. hotproc filtresini kurar:
    /var/lib/pcp/pmdas/proc/hotproc.conf
      cpuburn > 0.10 || residentsize > 102400
    proc PMDA yüzlerce prosesin tamamını her örnekte tarar; hotproc yalnızca
    eşiği aşanları izler ve büyük sunucularda pmcd yükünü / arşiv boyutunu
    10-20 kat düşürür. RHEL 9'da bu dosya varsayılan olarak YOKTUR ve o
    yüzden hotproc.* metrikleri hep boş döner.
    Doğrulama:  pminfo -f hotproc.control.config
    NOT: hotproc.nprocs boş sistemde 0'dır (eşiği aşan proses yok) ve yük
    başladıktan sonra dolması iki yenileme döngüsü (~20 sn) alır.
 5c. İnceleme şablonlarını kurar: /etc/pcp/pmrep/ozel.conf
      pmrep -t 1s -z :canli                       CPU+RAM+disk+ağ tek satırda
      pmrep -t 2s -J 10 -6 proc.hog.cpu :obur     en obur prosesler (PID+komut)
      pmrep -t 1s -z :agirlik                     disk doygunluk/gecikme
    DİKKAT: ~/.pcp/pmrep.conf ASLA oluşturulmaz. pmrep ilk bulduğu
    yapılandırmayı kullanır; ev dizinindeki dosya /etc/pcp/pmrep/ altındaki
    90'dan fazla hazır şablonu (:vmstat, :sar-*, :pidstat-*) erişilemez kılar.
 5d. pmie eşik alarmlarını açar (pmieconf hazır kural kütüphanesi):
      cpu.util cpu.load_average cpu.system memory.exhausted memory.swap_low
      filesys.filling filesys.vfs_files per_disk.average_wait_time
      per_netif.errors
    Eşikler: cpu.util %90, filesys.filling %90. Alarmlar syslog'a yazılır.
    Kuralları listelemek/değiştirmek:
      pmieconf -f /var/lib/pcp/config/pmie/config.default rules
      pmieconf -f ... modify cpu.util threshold 85
 6. Günlük rotasyonu ayarlar: PMLOGGER_DAILY_PARAMS="-E -x 0 -k <GÜN>"
    RHEL: /etc/sysconfig/pmlogger_timers, Ubuntu: /etc/default/pmlogger_timers
    (her gece 00:10 civarı: birleştir + xz sıkıştır + süresi dolanı sil)
 7. Disk korumasını kurar (aşağıda) ve servisleri başlatıp doğrular.

DİSK KORUMASI: pcp-log-guard
----------------------------
Dosyalar:
  /usr/local/sbin/pcp-log-guard.sh      koruma script'i
  /etc/pcp/pcp-log-guard.conf           eşik ayarları
  pcp-log-guard.service + .timer        systemd (10 dakikada bir çalışır)

Davranış:
  * /var/log/pcp ayrı bir bölüm/LV ise: doluluk >= %80 (THRESHOLD_PCT)
    olduğunda rotasyon/sıkıştırma çalıştırılır ve en eski arşiv setleri
    %70'e (TARGET_PCT) inilene kadar silinir.
  * Ayrı bölüm değilse: toplam PCP log boyutu 2GB'ı (MAX_SIZE_GB) aşarsa
    eski arşivler sınırın %90'ına inilene kadar silinir.
  * ACİL DURUM (her iki modda): dosya sistemi %90+ (EMERG_PCT) ise günün
    arşivi hariç her şey silinir; hâlâ kritikse pmlogger DURDURULUR
    (disk asla PCP yüzünden dolmaz). Doluluk TARGET_PCT altına inince
    pmlogger otomatik yeniden başlatılır.
  * pmlogger.log 200MB'ı (LOG_MAX_MB) aşarsa sıfırlanır (taşma sigortası).
  * Günün (aktif) arşivi hiçbir durumda silinmez.
  * Tüm işlemler syslog'a "pcp-log-guard" etiketiyle yazılır:
      journalctl -t pcp-log-guard

Eşikleri değiştirmek için /etc/pcp/pcp-log-guard.conf düzenlenir; servis
yeniden başlatma gerekmez (her çalışmada okunur).

BOYUT PLANLAMASI
----------------
Ölçülen değerler (~270 proses, 60 sn örnekleme):
  * Ham arşiv     : ~1.5-2 GB/gün (günün arşivi sıkıştırılmamış durur)
  * Sıkıştırılmış : ~200-250 MB/gün
  * 14 günlük toplam: ~4-5 GB
Sonuç: 2GB sınırıyla pratikte ~5-6 gün saklanabilir; guard fazlasını en
eskiden siler (disk güvenliği saklama süresinden önceliklidir).
Tam 14 gün için: /var/log/pcp'ye 6-8GB ayrı LV ayırın veya -i 120 / -i 300
ile örnekleme aralığını büyütün (boyut orantılı düşer). Proses sayısı çok
olan sunucularda (büyük DB, container host) boyut artar.

KURULUM SONRASI DOĞRULAMA
-------------------------
En kolayı bağımsız doğrulama paketidir (salt-okunur, sistemde hiçbir
değişiklik yapmaz):

  ./pcp-dogrula.sh              # 12 bölüm, ~80 test
  ./pcp-dogrula.sh -y           # + 13. bölüm: CPU yükü üretip hotproc ve top-N sıralamayı dener
  ./pcp-dogrula.sh -h web01     # uzak sunucuyu test et (pmcd erişimi gerekir)
  ./pcp-dogrula.sh -q           # yalnızca hatalar + özet
  (root değilse "pcp kullanıcısı görünürlüğü" testi atlanır; sudo ile çalıştırın)

Test ettiği alanlar: ortam, servisler (NRestarts=0, timer'lar), canlı izleme
araçları, alt sistem metrikleri, türetilmiş metrikler (/etc/pcp/derived),
proses görünürlüğü (-A), hotproc, rapor şablonları (hazır + özel; ev
dizininde gizleyici pmrep.conf yok), arşiv yeniden oynatma (proc.id.uid var,
proc.psinfo.environ YOK, pmlogger.log boyutu), pmlogger yapılandırması
(config.pcp-full izni 644, environ ve domain-511 metriği yok, kontrol dosyası
yönlendirmesi, control.d'de artık yedek yok, PMLOGGER_DAILY_PARAMS,
pmlogger_check.log'da Duplicate yok), alarm motoru, disk koruması.
Çıkış kodu: 0 = hepsi geçti, 1 = en az bir test kaldı, 2 = pcp yok.

Script sonunda otomatik doğrulama da yapılır; elle kontrol için:

  systemctl status pmcd pmlogger              # ikisi de active olmalı
  runuser -u pcp -- pminfo -f proc.psinfo.pid | grep -c inst
                                              # ~tüm proses sayısı (=-A çalışıyor)
  ls -lh /var/log/pcp/pmlogger/$(hostname)/   # arşiv büyüyor olmalı
  systemctl list-timers pcp-log-guard.timer pmlogger_daily.timer
  pcp                                         # genel özet

Rapor almak için (14 gün veri biriktikten sonra tam kapsamlı):
  ./pcp-top-apps.sh                           # top 200, son 14 gün
  ./pcp-top-apps.sh -d 7 -n 50 -o rapor.txt
  ./pcp-top-apps.sh -j 2 -c /tmp/csv          # 2 arşiv paralel, CSV de yaz
Rapor bölümleri: CPU, bellek, disk I/O (komut adına göre), KULLANICI BAZINDA
toplam (arşivde proc.id.uid varsa; adlar bu makinenin passwd'sinden çözülür,
eşleşmeyen uid:N kalır), ağ (arayüz bazlı; bcc PMDA varsa proses bazlı).
Arşivler paralel özetlenir (-j, varsayılan: çekirdek sayısı, en fazla 4);
bir günlük arşivin pmlogsummary özeti ~30 sn sürer.

SORUN GİDERME
-------------
 * "pmlogger AKTIF DEGIL" / sürekli çöküp yeniden başlama ("crashloop",
   "result 'protocol'"):
   - tail /var/log/pcp/pmlogger/$(hostname)/pmlogger.log
   - "Permission denied" görülüyorsa config dosya izni sorunudur:
     chmod 644 /var/lib/pcp/config/pmlogger/config.pcp-full
     systemctl reset-failed pmlogger && systemctl start pmlogger
     (script'in güncel sürümü bunu kendisi düzeltir)
 * Ubuntu/PCP 7'de pmlogger başlayıp hemen duruyorsa:
   - systemctl status pmlogger_farm  (BindsTo ile bağlıdır)
   - tail /var/log/pcp/pmlogger/pmlogger_check.log
   - "Duplicate pmlogger instances" varsa control.d/ altında fazladan
     dosya vardır; sadece gerçek kontrol dosyaları kalmalı.
 * Raporda sadece PCP prosesleri görünüyorsa: -A eksiktir (bkz. adım 2);
   ayrıca -A eklendikten ÖNCEKİ arşivlerde geçmişe dönük proses verisi
   oluşmaz, veri o andan itibaren birikir.
 * pmlogger.log anormal büyükse: derived metrik loglanıyor olabilir;
   config'de "511" domain'li metrik olmadığından emin olun. Guard 200MB
   üzerinde otomatik sıfırlar.
 * lmsensors uyarısı: sanal makinelerde donanım sensörü yoktur, normaldir.

DEĞİŞTİRİLEN / OLUŞTURULAN DOSYALAR
-----------------------------------
  /etc/pcp/pmcd/pmcd.conf                        (-A eklenir; yedek: .pcp-setup.orig)
  /var/lib/pcp/config/pmlogger/config.pcp-full   (üretilen izleme yapılandırması)
  /etc/pcp/pmlogger/control.d/local              (config.pcp-full'a yönlendirme)
  /etc/pcp/pmlogger/backup.pcp-setup/            (control dosyası yedekleri)
  /etc/sysconfig|/etc/default/pmlogger_timers    (rotasyon parametreleri)
  /var/lib/pcp/pmdas/proc/hotproc.conf           (sıcak proses filtresi)
  /etc/pcp/pmrep/ozel.conf                       (:canli :obur :agirlik şablonları)
  /var/lib/pcp/config/pmie/config.default        (pmieconf ile alarm kuralları)
  /etc/pcp/pcp-log-guard.conf                    (koruma eşikleri)
  /usr/local/sbin/pcp-log-guard.sh               (koruma script'i; flock ile tek kopya)
  /etc/systemd/system/pcp-log-guard.{service,timer}
  /var/lib/pcp-setup/sensors-detect.done         (sensors-detect bir kez çalıştı işareti)

GERİ ALMA
---------
  systemctl disable --now pcp-log-guard.timer
  rm /etc/systemd/system/pcp-log-guard.{service,timer} /usr/local/sbin/pcp-log-guard.sh
  cp /etc/pcp/pmlogger/backup.pcp-setup/local.orig /etc/pcp/pmlogger/control.d/local
  cp /etc/pcp/pmcd/pmcd.conf.pcp-setup.orig /etc/pcp/pmcd/pmcd.conf
  rm -f /var/lib/pcp/pmdas/proc/hotproc.conf /etc/pcp/pmrep/ozel.conf
  rm -rf /var/lib/pcp-setup
  systemctl restart pmcd pmlogger

--------------------------------------------------------------------------------
Hazırlayan: Ekip oturumu, 10 Temmuz 2026 - güncellemeler 22 Ağustos ve 25 Eylül 2026
Her dosya tek yerde: pcp-top-apps.sh ve pcp-dogrula.sh yalnızca bu dizinde,
Ansible files/ altındakiler sembolik bağlantıdır. Kontrol: ../araclar/tutarlilik.sh
Detaylı geliştirme geçmişi için: pcp-setup-gecmis.txt
PCP'nin tüm araçları ve analiz yöntemleri için: ../PCP_EL_KITABI.md
Bu dosyadaki teknik terimlerin (PMDA, arşiv, hotproc, türetilmiş metrik,
idempotent, LV/volüm, unit/timer vb.) sade açıklaması: PCP_EL_KITABI.md Ek F — Sözlük
================================================================================
