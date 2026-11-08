================================================================================
 pcp-merkezi.sh 1.2 - PCP ARSIVLERINI MERKEZDE TOPLAMA - KULLANIM
================================================================================
Ayrintili plan ve kararlar: PLAN.txt. Betik yonetim makinesinde calisir;
merkeze ve istemcilere root ile SSH (anahtar, BatchMode) yapar.

Merkez : pcplogger.lab.example.com  172.16.211.246 (SSH) / 172.16.16.246 (ic ag)
Arsiv  : /var/log/pcp/merkez/<istemci-kisa-adi>/   (ayri LV, 60 GB, 32 gun: -K)

1. ISTEMCI EKLEME (ornek rh442-node3)
------------------------------------
  # 1) Rapor: ne yapilacagini gosterir, HICBIR SEY DEGISTIRMEZ
  ./pcp-merkezi.sh -i 172.16.210.83

  # 2) Uygula (test ortami: yerelde 3 gun)
  ./pcp-merkezi.sh -i 172.16.210.83 -u

  # 3) Ikinci kosu: "degisiklik sayisi: 0" beklenir
  ./pcp-merkezi.sh -i 172.16.210.83 -u

  # 4) Sonradan denetim (salt okuma)
  ./pcp-merkezi.sh -i 172.16.210.83 -d -k 3

  Merkez saklamasi (-K, varsayilan 32 gun): farkliysa rapor/uyari;
  -M kur -u ile merkeze PMLOGGER_DAILY_PARAMS -k 32 yazilir (yedekli).
  32 gun: aylik periyodik yukler bir onceki ayin ayni gunuyle
  karsilastirilir (ay 28-31 gun + 1 gun pay). Yerel tampon 8 gun oldugu
  icin aylik desen yalniz merkezde yakalanir.

  Canli ortamda yerel saklama 8 gun, gecmis once merkeze (K8):
                               ./pcp-merkezi.sh -i <adres> -k 8 -Y -u
  -Y: istemcinin mevcut yerel arsivleri merkezde
      /var/log/pcp/merkez/<ad>/yerel-gecmis/ altina kopyalanir (yalniz
      merkezde olmayan dosyalar; istemcide nice/ionice ile en dusuk oncelik).
      Saklama ancak kopya basariliysa kisaltilir. Varsayilan KAPALI: yuku
      olculmedi (lab: istemci basina ~160 MB, 3 istemci ~5 dk).
      yerel-gecmis gece bakiminin (pmlogger_daily) kapsami DISINDADIR:
      birlestirilmez, silinmez; elle temizlenir.
  Birden cok istemci: -i 172.16.210.80,172.16.210.82,172.16.210.83

  -k 8'in altinda betik her kosuda UYARI basar ve cikis kodu 1 olur (onerilen
  alt siniri 8 gun). playbook-pcp dogrulamasi da "pmlogger -k 3 < en az 8
  gun" SORUN'u yazar. Test ortaminda beklenen durumdur.

2. NE YAPAR
-----------
  Merkez denetimi (-M kontrol, varsayilan): pcp 7.x, pmlogger_farm, gece
    bakimi zamanlayicilari, saat esitlemesi, arsiv koku (sahip pcp:pcp,
    SELinux pcp_log_t, istemci basina 2 GB bos). Hazir degilse istemcilere
    dokunmaz. -M kur -u: eksik PCP paketlerini/servisleri merkezde kurar.
  Istemci:
    - /var/backup/pcp-merkezi olusturulur: yerel saklamanin sahibinin
      pcp-merkezi oldugunu gosterir (playbook-pcp v1.5 ve log-saklama 1.11
      bu dizini gorunce -k'ye dokunmaz).
    - Guvenlik duvari: yalniz 172.16.16.246/32 -> 44321/tcp (rich rule,
      calisan + kalici; firewall-cmd --reload yapilmaz).
    - Merkez kaydi basarili olduktan SONRA PMLOGGER_DAILY_PARAMS -k N.
    - pmcd erisim kurallari, PMCD_LOCAL ve proc -A DEGISMEZ.
  Merkez kaydi:
    - Ilk kayitta uyum kapisi: 2 dk deneme kaydi, metrik adlari istemcinin
      yerel arsiviyle karsilastirilir (%95 alti -> durur, -k yazilmaz).
      Deneme arsivi /var/backup/pcp-merkezi/deneme-<ad>-<damga> altinda kalir.
    - /var/lib/pcp/config/pmlogger/config.<ad> = istemcinin config.default'u
      + aciklama ilk satiri (pmlogger_check bu dosyayi pmlogconf ile yeniden
      uretmez; istemcide kapatilan zoneinfo/buddyinfo merkezde acilmaz).
    - /etc/pcp/pmlogger/control.d/<ad>, arsiv dizini, pmlogger baslatma.
  Her degisiklikten once yedek: /var/backup/pcp-merkezi/<yol>-<damga> ve
  manifest-<damga>.txt (merkezde ve istemcide). Betik dosya silmez.

3. DIKKAT
---------
  - YEREL ARSIV SILINMESI: uzun yerel -k (onerilen 32) -> N sonrasi ilk gece pmlogger_daily N
    gunden eski yerel arsivleri siler. Merkezde yalniz kayit baslangicindan
    sonraki veri vardir. Betik en eski yerel arsiv gununu raporlar. Gecmisi
    korumak icin -Y ile once merkeze kopyalayin (K8).
  - Istemcinin kayit listesi (config.default) degisirse (playbook-pcp kayit
    profili, PMDA ekleme) betigi yeniden -u ile kosun; merkez kopyasi
    yenilenir, uyum kapisi yeniden calisir, o istemcinin merkez pmlogger'i
    yeniden baslar.
  - Saat dilimi: merkez ve tum istemciler AYNI saat diliminde olmali
    (Europe/Istanbul) ve NTP ile esit olmali; aksi halde arsiv adlari, gece
    bakimi ve sunucular arasi karsilastirma kayar.
  - Olcek: bu betik lab olcegindedir (sirali; ilk kayitta 2 dk kapi). Buyuk olcek
    yayginlastirmasi AWX rolu ile yapilir (PLAN.txt bolum 12-13).

4. GERI ALMA
------------
  ./pcp-merkezi.sh -i 172.16.210.83 -G      # rapor
  ./pcp-merkezi.sh -i 172.16.210.83 -G -u   # uygula
  Merkez : control.d/<ad> ve config.<ad> yedek agacina tasinir, o istemcinin
           pmlogger'i durur; arsivler /var/log/pcp/merkez/<ad> altinda KALIR.
  Istemci: kural kaldirilir; pmlogger_timers ilk yedekten geri gelir;
           /var/backup/pcp-merkezi -> /var/backup/pcp-merkezi-geri-alindi-<damga>
           (playbook-pcp yeniden saklamanin sahibi olur).

5. ANALIZ (merkezde)
--------------------
  pmlogsummary -a /var/log/pcp/merkez/rh442-base/<arsiv> kernel.all.load
  pmrep -a /var/log/pcp/merkez/rh442-base/<arsiv> :sar-u -t 1m
  pmlogctl status                 # merkezdeki tum pmlogger'lar

6. YUK NOTU
-----------
  Istemcide merkez pmlogger'i yerel pmlogger ile ayni okuma kumesini ikinci
  kez ceker (proc PMDA: surec stat/status/io; smaps/maps/environ okunmaz).
  Olcum (29.10.2026): ek pmcd + PMDA CPU tek cekirdegin ~%0,02si (PLAN.txt 8).
  Betik tespitleri kisadir; buyuk find/du ve smaps okumasi yoktur. Uyum
  kapisi yalniz ilk kayitta istemci basina 2 dk ek kayit yapar.
================================================================================
