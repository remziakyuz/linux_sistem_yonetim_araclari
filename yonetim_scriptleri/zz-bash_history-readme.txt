=============================================================================
BASH HISTORY ANINDA KAYIT VE AUDITD ILE KOMUT DENETIMI
=============================================================================
Tarih  : 2026-07-22
Kapsam : RHEL 8/9/10, RHEL turevleri, Fedora

Bu dokuman iki konuyu kapsar:

  1. Bash komutlarinin, komut biter bitmez (senkron/anlik) history dosyasina
     yazilmasi.
  2. Tum komutlarin kernel seviyesinde, kurcalanamaz sekilde audit
     kayitlarina yazilmasi.

Birinci bolum gunluk kullanim/pratiklik icindir ve kullanici tarafindan
atlatilabilir. Ikinci bolum (auditd) denetim/adli analiz icin guvenilir olan
yontemdir. Ikisi birlikte kullanilmalidir.

-----------------------------------------------------------------------------
1. BASH HISTORY: ANINDA YAZMA VE PROFIL DUZELTMELERI
-----------------------------------------------------------------------------

~/.bashrc (tek kullanici) veya /etc/profile.d/zz-history-sync.sh (tum
kullanicilar):

NOT - dosya adi neden "zz-" ile basliyor?
    /etc/profile.d/*.sh dosyalari alfabetik sirayla source edilir. Baska bir
    profil PROMPT_COMMAND/HIST* degiskenlerini yeniden tanimlarsa ayarimiz
    ezilir. "zz-" oneki dosyayi en sona siralayarak son sozun bizde kalmasini
    saglar. Rakam oneki (ornegin "99-") ise yaramaz: ASCII siralamasinda
    rakamlar harflerden once geldigi icin 99-* cogu paket profilinden once
    yuklenir. Kullanicinin kendi ~/.bashrc dosyasi her durumda profile.d'den
    sonra calisir; oradaki toptan PROMPT_COMMAND atamasi denetlenemez.

    export HISTSIZE=999999
    export HISTFILESIZE=999999
    export HISTTIMEFORMAT="%Y/%h/%d - %H:%M:%S  : "
    export HISTFILE="$HOME/.bash_history-$(date +%Y%m)"

    shopt -s histappend      # kapanista dosyayi ezme, ekle
    shopt -s histreedit
    shopt -s histverify

    # komut biter bitmez HISTFILE'a yaz (anlik/senkron kayit)
    PROMPT_COMMAND="history -a${PROMPT_COMMAND:+; $PROMPT_COMMAND}"

    # Ayarladigimiz degerler sonradan degistirilmesin
    readonly HISTSIZE HISTFILESIZE HISTTIMEFORMAT HISTFILE PROMPT_COMMAND


Etkinlestirme: source ~/.bashrc (veya yeniden login).

Aciklamalar
---------------

- history -a : her prompt ciziminde (yani komut tamamlanir tamamlanmaz)
  bellekteki yeni satirlari HISTFILE'a ekler. Anlik yazmayi saglayan satir
  budur.
- shopt -s histappend : kabuk kapanirken history dosyasinin truncate edilip
  diger oturumlarin satirlarinin silinmesini onler.
- HISTTIMEFORMAT : zaman damgalari dosyaya #epoch yorum satiri olarak
  yazilir, "history" komutu bunlari bicimlendirerek gosterir.
- Aylik HISTFILE rotasyonu (date +%Y%m) history -a ile uyumludur; ay
  degisince acilan yeni oturumlar yeni dosyaya yazar.
- Oturumlar arasi tam senkron istenirse (bir terminalde yazilan komut
  digerinde gorunsun):
      PROMPT_COMMAND="history -a; history -n; ..."
  (history -n dosyadaki yeni satirlari bellege okur.)


- history bir denetim (audit) mekanizmasi DEGILDIR. Guvenilir kayit
icin 2. bolumdeki auditd yapilandirmasi gereklidir.

UYARILAR:

- PROMPT_COMMAND kilidi, prompt'a ekleme yapan araclari (starship, direnv,
  vte terminal basligi) bozabilir; sunucu ortaminda genelde kabul
  edilebilir, gelistirici makinelerinde dusunulmelidir.

- readonly bile KESIN ENGEL DEGILDIR: bash --noprofile, farkli bir kabuk
  (zsh/sh), set +o history ile kacilabilir (readonly degiskenleri korur,
  set seceneklerini kilitleyemez). Kesin denetim 2. bolumdeki auditd execve
  kuralidir; readonly yalnizca citayi yukseltir.

-----------------------------------------------------------------------------
2. TUM KOMUTLARIN AUDIT'E YAZILMASI (AUDITD)
-----------------------------------------------------------------------------

Kernel seviyesinde execve/execveat sistem cagrilari izlenir; kullanici hicbir
kabuk ayariyla bunu atlatamaz. RHEL 8/9/10 ve Fedora'da aynidir.

Kural dosyasi
-----------------

/etc/audit/rules.d/99-komut-kaydi.rules :

    -a always,exit -F arch=b64 -S execve,execveat -F auid!=unset -k komutlar
    -a always,exit -F arch=b32 -S execve,execveat -F auid!=unset -k komutlar

- auid (audit uid) sudo/su sonrasinda bile orijinal kullanicida kalir;
  "komutu kim calistirdi" sorusu her zaman cevaplanir.
- b32 satiri 32-bit binary'lerin gozden kacmamasi icin sarttir.

Yukleme ve dogrulama
------------------------

    augenrules --load     # kurallari derle ve yukle
    auditctl -l           # aktif kurallari dogrula

Kurallarin degistirilememesi icin kural dosyalarinin en sonuna "-e 2"
eklenir (immutable mod). DIKKAT: -e 2 sonrasi kural degisikligi ancak reboot
ile mumkundur; once kurallarin dogru calistigindan emin olun.

Sorgulama
-------------

    ausearch -k komutlar -i               # tum kayitlar, cozumlenmis
    ausearch -k komutlar -ts today -i     # bugunku kayitlar
    ausearch -k komutlar -ui 1000 -i      # belirli kullanici (uid=1000)
    aureport -x --summary                 # calistirilan programlarin ozeti

Kapasite ve dayaniklilik (/etc/audit/auditd.conf)
-----------------------------------------------------

- max_log_file ve num_logs buyutulmelidir; execve izleme gunde yuz binlerce
  kayit uretebilir, disk plani yapin.
- flush = incremental_async ve freq = 50 : performans/dayaniklilik dengesi.
  Tam senkron kayit icin flush = sync (I/O maliyeti yuksektir).
- Kurcalamaya karsi kayitlar uzak log sunucusuna tasinmalidir:
  /etc/audit/plugins.d/syslog.conf icinde active = yes yapip auditd'yi
  yeniden baslatin; ardindan rsyslog ile uzak sunucuya forward edin.

Yerlesik komutlar dahil tam kayit: pam_tty_audit (SSH)
----------------------------------------------------------

NEDEN GEREKLI? execve kurali yalnizca HARICI programlari yakalar
(ls, cat, rm...). echo, cd, pwd, ulimit, export gibi KABUK YERLESIKLERI
execve cagirmadigi icin o kurala hic gorunmez. SSH oturumunda yazilan HER
SEYIN (yerlesikler dahil) kayda gecmesi icin pam_tty_audit kullanilir:
TTY'de yazilan her tusu audit'e yazar.

SSH oturumlarina ozel olarak /etc/pam.d/sshd dosyasinin sonuna (once yedek
alin):

    session     required     pam_tty_audit.so enable=*

- Yeni SSH oturumlarinda etkindir; mevcut oturumlar etkilenmez.
- Goruntuleme: aureport --tty -ts today  veya  ausearch -m TTY -i
  Kayitlar oturum kapaninca / tampon dolunca gorunur.
- log_passwd secenegini EKLEMEYIN: parolalar da (echo'suz girisler) kayda
  gecer. Varsayilan halde parola girisleri kaydedilmez.
- Yalnizca root izlenecekse: disable=* enable=root
- Tum kullanicilarda hacim + mahremiyet/KVKK etkisinden dolayi  kayitlari uzak log sunuculara iletilecek
- Konsol/su dahil tum girisler icin SSH yerine /etc/pam.d/system-auth ve  /etc/pam.d/password-auth kullanilabilir.

Uc katman birlikte tam resmi verir: history (pratik okuma) + execve kurali
(harici komutlar, atlatilamaz) + pam_tty_audit (yerlesikler dahil tus kaydi).

-----------------------------------------------------------------------------
OZET
-----------------------------------------------------------------------------

  Yontem                  Amac                          Guvenilirlik
  ----------------------  ----------------------------  ----------------------
  history + history -a    Gunluk kullanim, pratiklik    Atlatilabilir
  auditd execve kurali    Denetim, adli analiz          Kernel, atlatilamaz
  pam_tty_audit           Yerlesikler dahil tus kaydi   Kernel; mahremiyet etkisi

Ikisi birlikte kullanilmalidir: history gunluk is akisi icin, auditd gercek
denetim kaydi icin.
