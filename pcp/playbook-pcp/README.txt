playbook-pcp

Sürüm: 1.13 - Hazırlayan: Linux sistem destek ekibi

1. Bu belge ne işe yarar

- Ne işe yarar: Bu playbook (otomatik yapılandırma dosyası) sunucuya PCP
  (Performance Co-Pilot; sunucu ölçümlerini sürekli kaydeden yazılım)
  kurar ve kaydın eksiksiz olmasını sağlar: işlemci, bellek, disk ve ağ
  ölçümleri ile süreç başına işlemci ve disk kullanımı sürekli diske
  yazılır. Bir aksaklıkta “hangi süreç ne zaman ne kadar kaynak
  kullandı” sorusu geriye dönük yanıtlanabilir.
- Nasıl kullanılır: Önce rapor (varsayılan; değişiklik yapmaz), çıktı
  okunur, sonra uygulama_modu: uygula. AWX (otomasyon arayüzü) kurulumu
  bölüm 6’dadır.
- Neden önemli: Kayıt yazılımı kurulu olsa bile kaydı yapan hesap, diğer
  kullanıcıların süreçlerinin disk okuma/yazma değerlerini göremez; bu
  durumda arşivde süreç başına disk kullanımı yalnız kayıt yazılımının
  kendi süreçleri için bulunur. Bu dosya bunu ölçer ve güvenli
  koşullarda giderir.
- Kimin ne yapması gerekiyor: Linux sistem yöneticisi önce test
  sunucusunda, sonra canlı ortamda düşük trafik saatinde, sunucuları tek
  tek seçerek çalıştırır.

2. Ne yapar

Varsayılan rapor modu sistemde hiçbir değişiklik yapmaz: durum tespiti,
rapor ve doğrulama. uygulama_modu: uygula ile aşağıdakiler yapılır:

1.  pcp, pcp-system-tools ve ayrı bir adımda pcp-zeroconf kurulur
    (depoda yoksa bilgi verilir, kurulum sürer); pmcd ve pmlogger
    etkinleştirilir. Debian 13’te pcp ve pcp-zeroconf apt ile kurulur;
    ayar dosyaları /etc/default altındadır. Debian paketinin açık
    bıraktığı pmproxy bu çalıştırmada kurulan PCP’de kapatılır, pmie
    başlatılır (RHEL ile aynı son durum).
2.  Süreç başına disk G/Ç (giriş/çıkış) görünürlüğü: kayıt kullanıcısı
    pcp, root’un gördüğü süreç G/Ç değerlerinin yüzde 80’inden azını
    görüyorsa pmcd.conf içindeki süreç ölçüm eklentisine -A eklenir ve
    pmcd yeniden başlatılır. Yalnız şu üç koşulda eklenir:
    - pmcd yalnız yerel bağlantı kabul ediyor (PMCD_LOCAL=1; RHEL 9
      varsayılanı, RHEL 10 ve Debian 13’te yorumda gelir);
    - pmproxy çalışmıyor (çalışırsa uzaktaki istemci süreç ayrıntılarına
      onun üzerinden ulaşır);
    - kayıt yapılandırmasında smaps, maps, environ metrikleri yok.

    Koşullardan biri sağlanmazsa -A eklenmez, eksiklik raporlanır.
3.  Saklama: PMLOGGER_DAILY_PARAMS="-E -x 1 -k K" yalnız bu ayarı
    yöneten başka bir playbook yoksa yazılır (-E paket varsayılanıdır:
    aynı günün arşivleri birleştirilirken tanımı tutarsız bir metrik
    birleştirmeyi durdurmaz, yalnız o metrik o gün için atlanır). K günü
    /var/log/pcp alanına sığdırılır: hedef 32 gün, en az 8 gün; alan
    ayrı bölümse yüzde 80’i, paylaşılan bölümse yüzde 25’i kullanılır.
4.  İnceleme şablonları: /etc/pcp/pmrep/ozel.conf (pmrep :canli, :obur,
    :agirlik).
5.  Doğrulama betiği: /usr/local/bin/pcp-dogrula.sh (salt okunur).
6.  Eski kurulum izleri: önceki elle kurulumdan kalan yedek dosyalar
    /var/backup/pcp-onlem/ altına taşınır; eski pcp-log-guard bekçisi,
    log-saklama bekçisi varsa kapatılıp taşınır.
7.  Ölçüm eklentisi kapatma: dm, kvm, nfsclient, openmetrics ve
    opentelemetry eklentileri kendi kaldırma betikleriyle kaldırılır.
    Neden: dm eklentisi kuruluyken, pcp-zeroconf ile gelen hazır alarm
    kuralları 10 dakikada bir dmsetup status çalıştırıyor ve sunucudaki
    her device-mapper aygıtına (multipath LUN’ları dahil) sorgu
    gönderiyordu; SAN üzerindeki etkisi ölçülmemiştir. Playbook
    uygulandıktan sonra bu sorgu artık yapılmaz: eklenti kaldırılınca
    alarm kuralı okuyacak ölçü bulamaz ve hiçbir aygıta komut gitmez
    (ölçüm: PCP’den disk ve LUN’a giden komut 0). Diğer eklentilerin
    etkisi ölçülmemiştir ve analizde kullanılmaz. pcp-zeroconf paketi
    güncellendiğinde bu eklentileri kendiliğinden yeniden kurar; bunu
    önlemek için pmcd.conf içine işaret yorum satırı yazılır.
    Kaldırmadan önce pcp-zeroconf’un arka planda başlattığı eklenti
    kurulumunun bitmesi en çok 180 saniye beklenir. Doğrulama, eklenti
    yeniden etkinleşirse ya da bekleyen kurulum işareti kalırsa SORUN
    bildirir.
8.  Kesmeleri kapatan kayıt grupları: /proc/zoneinfo ve /proc/buddyinfo
    okuması çekirdekte bellek bölgesi kilidini kesmeler kapalıyken
    tutar; süre çekirdek sayısıyla büyür ve analizde kullanılmaz. Bu iki
    kayıt grubu pmlogconf grup dosyasında force exclude yapılır (paket
    güncellemesinde korunur) ve kayıt yapılandırmasından çıkarılır;
    pmlogconf yalnız pcp kullanıcısıyla çalıştırılır.

Varsayılan kapalı adımlar (bölüm 4): proc -A (proc_tum_surec_karari),
kayit_profili (tam / varsayilan), hotproc_karari, pmie_karari,
pcp_ek_pmdalar, pcp_ek_paketler.

3. Komut satırından kullanım

    cp envanter.ini.ornek envanter.ini      # sunucuları yazın; grup adı pcp_sunucular OLMALI
    ansible-playbook -i envanter.ini pcp-onlem.yml                                 # rapor
    ansible-playbook -i envanter.ini pcp-onlem.yml -e uygulama_modu=uygula --check --diff
    ansible-playbook -i envanter.ini pcp-onlem.yml -e uygulama_modu=uygula -l <sunucu>
    ansible-playbook -i envanter.ini pcp-onlem.yml --tags dogrula

  ----------------------------------------------------------------------------------------------------------------------------
  Değişken                     Varsayılan                                                              Anlamı
  ---------------------------- ----------------------------------------------------------------------- -----------------------
  uygulama_modu                rapor                                                                   rapor / uygula

  kurulum_karari,              uygula                                                                  paket kurulumu (dokunma
  zeroconf_karari                                                                                      ile kapatılır)

  proc_tum_surec_karari        dokunma                                                                 -A eklenmez, süreç G/Ç
                                                                                                       eksikliği BİLGİ olarak
                                                                                                       raporlanır. gerekirse:
                                                                                                       -A yalnız ölçülen
                                                                                                       eksiklikte ve güvenlik
                                                                                                       koşullarında (-A ile
                                                                                                       root olmayan yerel
                                                                                                       hesaplar tüm süreçlerin
                                                                                                       ortam değişkenlerini
                                                                                                       okuyabilir)

  pcp_kurulum_bos_alan_mb      1536                                                                    PCP kurulu değilse:
                                                                                                       bölümde bu kadar boş
                                                                                                       alan yoksa ya da
                                                                                                       kurulum sonrası bölüm
                                                                                                       %80’i aşacaksa PCP
                                                                                                       kurulmaz

  pcp_test_ortami              false                                                                   yalnız test ortamı:
                                                                                                       saklamanın 8 günün
                                                                                                       altına inmesine izin
                                                                                                       verir; canlı ortamda
                                                                                                       tanımlanmaz

  saklama_karari               uygula                                                                  PMLOGGER_DAILY_PARAMS
                                                                                                       (başka sahip yoksa)

  pmrep_sablon_karari,         uygula                                                                  şablon dosyası,
  dogrula_betigi_karari                                                                                doğrulama betiği

  eski_kurulum_karari          otomatik                                                                eski kurulum izlerini
                                                                                                       taşı (dokunma ile
                                                                                                       kapatılır)

  kayit_profili                dokunma                                                                 tam = ayrıntılı kayıt
                                                                                                       profili; varsayilan =
                                                                                                       pcp-zeroconf profiline
                                                                                                       dönüş

  hotproc_karari, pmie_karari  dokunma                                                                 süreç filtresi, eşik
                                                                                                       alarmları

  pcp_ek_pmdalar               []                                                                      ek ölçüm eklentileri
                                                                                                       (örnek ['bonding'];
                                                                                                       kapatılan eklentiler
                                                                                                       burada kullanılamaz)

  pmda_kapatma_karari          uygula                                                                  pcp_kapali_pmdalar
                                                                                                       listesindeki
                                                                                                       eklentileri kaldırır
                                                                                                       (dokunma ile kapatılır)

  pcp_kapali_pmdalar           [dm, dmcache, kvm, nfsclient, openmetrics, opentelemetry, prometheus]   kaldırılacak ölçüm
                                                                                                       eklentileri (dmcache,
                                                                                                       prometheus eski adlar)

  kayit_grubu_kapatma_karari   uygula                                                                  kesmeleri kapatan kayıt
                                                                                                       gruplarını kapatır
                                                                                                       (dokunma ile kapatılır)

  pcp_kapali_kayit_gruplari    [memory/zoneinfo, memory/buddyinfo]                                     kayda alınmayacak
                                                                                                       gruplar

  pcp_gece_karari              uygula                                                                  PCP gece işlerini
                                                                                                       (pmlogger_daily,
                                                                                                       pmie_daily,
                                                                                                       pmlogger_check,
                                                                                                       pmie_check,
                                                                                                       pmlogger_farm_check,
                                                                                                       pmie_farm_check)
                                                                                                       sunucunun kısa adından
                                                                                                       hesaplanan sabit saate
                                                                                                       yayar ve gece raporunu
                                                                                                       kapatır; dokunma ile
                                                                                                       paket varsayılanı kalır
                                                                                                       (doğrulama SORUN
                                                                                                       yazar).

  pcp_gece_pencere_dk          120                                                                     Günlük gece işlerinin
                                                                                                       yayma aralığı (dakika):
                                                                                                       gece işi 00:10’dan
                                                                                                       (RHEL 8 ailesinde ve
                                                                                                       PCP 6 öncesinde
                                                                                                       03:10’dan) başlayıp bu
                                                                                                       kadar dakika içine
                                                                                                       sunucuya özgü sabit
                                                                                                       saatle dağıtılır;
                                                                                                       30-600, 0 kabul
                                                                                                       edilmez.

  pcp_kontrol_pencere_dk       29                                                                      Yarım saatlik işlerin
                                                                                                       yayma aralığı (dakika);
                                                                                                       5-29, 0 kabul edilmez.
  ----------------------------------------------------------------------------------------------------------------------------

Bir ayarı başka bir playbook yönetiyorsa (couchbase, temel, proxy,
patroni, postgresql rol playbook’ları, merkezi PCP toplama betiği
pcp-merkezi ya da log-saklama) bu playbook o ayara dokunmaz, yalnız
raporlar. Yedekler ve her çalıştırmanın dökümü sunucuda
/var/backup/pcp-onlem/ altındadır; hiçbir dosya silinmez.

4. YÜK NOTU

- Tespit (her çalıştırma): paket ve servis durumu, df; süreç listesi ve
  süreç G/Ç değerleri root ve pcp kullanıcısıyla birer kez okunur (smaps
  okunmaz); /var/log/pcp/pmlogger altında gün başına boyut. Kısa sürer;
  etkisi ölçülmedi.
- Uygulama: paket kurulumu (depo indirmesi); -A gerekirse pmcd yeniden
  başlatılır, kayıtta birkaç saniyelik boşluk olur (etkisi ölçülmedi).
- -A ve büyük bellekli sunucular - ölçüldü: -A’nın açtığı okumalar
  (/proc/<pid>/io, wchan) ve kaydın okuduğu süreç dosyaları sürecin
  bellek boyutundan bağımsızdır; bellek tablosunu taramazlar. Test
  ortamında 96 GB bellek, 8 çekirdek ve yüzde 80 bellek doluluğu altında
  30 GB’lık bir sürecin bellek işlemlerinin süresi, kaydın süreç ölçüm
  seti dakikadaki sıklığın yaklaşık 400 katı hızla okunurken bile
  değişmedi. Karşılaştırma için okunan smaps ise aynı süreçte işi yüzde
  95 düşürdü; bu nedenle -A yalnız kayıtta smaps / maps yoksa eklenir,
  varsa engellenir. /proc/zoneinfo ve /proc/buddyinfo kayıt grupları bu
  sürümde kapatılır (madde 8); kapatma öncesi ölçüm 8 çekirdekte en çok
  1-2 ms, 32 çekirdekte 53-127 mikrosaniye idi; 128’den fazla çekirdekli
  sunucuda ölçülmedi.
- Varsayılan kapalı adımlar (etkisi ölçülmedi): kayit_profili=tam (çok
  sayıda ek metrik, arşiv belirgin büyür), hotproc, ek ölçüm eklentileri
  (smart disklere smartctl komutu gönderir - SAN disklerinde etkisi
  bilinmiyor; sockets ss komutu çalıştırır; perfevent donanım
  sayaçlarını kullanır), pmie (syslog’a alarm yazar).
- Gece işleri yayma (yük azaltan adım): PCP zamanlayıcıları paket
  varsayılanında her sunucuda aynı dakikada çalışır; 400-1000 sunucuda
  bu ortak depolamaya aynı anda biner. Playbook günlük işleri
  (pmlogger_daily, pmie_daily) 00:10’dan itibaren 0-120 dakikaya (RHEL 8
  ailesinde 03:10’dan itibaren: bu sürümde arşiv adı UTC saatiyle
  verilir), yarım saatlik işleri (pmlogger_check, pmie_check,
  pmlogger_farm_check, pmie_farm_check) 0-29 dakikaya sunucunun kısa
  adından hesaplanan sabit bir saate yayar
  (/etc/systemd/system/<birim>.d/50-yuk-dagitimi.conf). Gece raporu
  (pmlogger_daily_report) her gece günün tüm arşivini /var/tmp altına
  açıyordu (ölçüldü: işletim sistemi diski 60 saniye dolu, yazma
  beklemesi 2,7 saniye); pmlogger_daily -D ile kapatılır (yalnız sürüm
  destekliyorsa). RHEL 8’de rapor ayrı bir zamanlayıcıyla her gece
  02:00’de çalışır; servisine bir koşul eklenerek çalışması durdurulur.
  Zamanlayıcılar yeniden başlatılmaz (pmlogger’ı da durdururdu), yalnız
  daemon-reload yapılır. Geçiş: kaydırması 10 dakikayı aşan sunucuda ilk
  gecelerde pmlogger kendi süresi dolunca günde bir yeniden başlar
  (birkaç saniye örnek kaybı, en çok ~12 gün). Uygulamanın ertesi gecesi
  bu yeniden başlatmalar sunucuların çoğunda aynı dakikaya (~00:20)
  düşer; bu yüzden uygulama dalgalarla yapılır: önce küçük bir test
  grubu, 2-3 gece gözlem, sonra dalgalar (dalga boyu ortama göre
  seçilir).
- pcp-dogrula.sh -y iki çekirdekte yaklaşık 40 saniye işlemci yükü
  üretir: canlı ortamda kullanılmaz.

5. Sonuçlar

  -----------------------------------------------------------------------
  Durum                               Anlamı
  ----------------------------------- -----------------------------------
  çalıştırma başarılı,                kayıt eksiksiz
  SORUN SAYISI: 0                     

  çalıştırma başarılı, SORUN          doğrulama sapması; çalıştırma
  satırları                           durmaz, çıktı okunmalı

  iş başarısız                        ön koşul (yanlış envanter grubu,
                                      desteklenmeyen sistem, geçersiz
                                      değişken) ya da bağlantı

  changed                             yalnız uygula modunda; ikinci
                                      çalıştırmada 0 (playbook’un kendi
                                      kurduğu dosyalar kaynakla aynıysa
                                      yedeklenmez; tam kayıt profili
                                      açıkken ikinci çalıştırmada yalnız
                                      o dosyanın yedeği)
  -----------------------------------------------------------------------

6. AWX kurulumu

1.  Proje: kaynak denetimi Git, bu paketin bulunduğu depo; “Clean” ve
    “Update Revision on Launch” işaretli; dal yerine sürüm etiketi
    kullanılması önerilir.
2.  Envanter: yeni bir envanter, içinde pcp_sunucular grubu; sunucular
    bu gruba eklenir (ansible_host, ansible_user). Playbook başka
    gruptaki sunucuda başta durur.
3.  Kimlik: sunuculara SSH ile bağlanan makine kimliği (root ya da sudo
    yetkili kullanıcı).
4.  Şablon: playbook pcp-onlem.yml, iş tipi Check, “Prompt on launch”
    işaretli alanlar: iş tipi, değişkenler, limit. Varsayılan Job
    Slicing 1, Concurrent Jobs kapalı: sunucular tek tek işlenir. Büyük
    filoda dalga uygulamasında eşzamanlılık bilerek iş dilimleme (Job
    Slicing N) ya da N ayrı limit ile verilir; forks eşzamanlılığı
    değiştirmez (serial: 1). Dalga boyu ve dur koşulları için PCP el
    kitabı 17.19’a bakın.
5.  Çalıştırma: önce Check (rapor); sonra Run + değişken
    uygulama_modu: uygula + limit ile tek sunucu.

7. Paket içeriği

    pcp-onlem.yml                    playbook
    pcp_files/hotproc.conf           hotproc filtresi (hotproc_karari=uygula)
    pcp_files/ozel.conf              pmrep inceleme şablonları
    pcp_files/pcp-dogrula.sh         salt okunur doğrulama betiği
    pcp_templates/config.pcp-tam.j2  tam kayıt profili (kayit_profili=tam)
    envanter.ini.ornek               örnek envanter
    README.md, SURUM-NOTLARI.md      kullanım ve sürüm notları
