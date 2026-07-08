# ssl-trust-unified — Kurumsal TLS/SSL Güven Dağıtım Araçları

Yerel/kurumsal sertifikalı uygulamalara (FreeIPA, Satellite/Foreman, Git,
container registry vb.) güvenli erişimi **tek adımda** sağlayan iki script:

| Script | Platform | Sürüm | Tarih |
|---|---|---|---|
| `ssl-trust-unified.sh` | Linux (RHEL/Fedora/OEL/Rocky/Alma, Debian/Ubuntu, SUSE, Arch, Alpine, Gentoo) | 2.0 | 2026-07-07 |
| `ssl-trust-unified.ps1` | Windows (PowerShell 5.1 ve 7+) | 1.0 | 2026-07-07 |

İki script de aynı iş akışını uygular:

1. Hedef host'lardan TLS sertifika zincirini çeker
2. Zincirdeki CA (`CA:TRUE`) sertifikalarından `ca-bundle` üretir
3. İşletim sistemi güven deposuna (trust store) kurar
4. Container (Podman/Docker) registry güvenini ayarlar
5. Tarayıcı güvenini ayarlar (Linux: NSS DB'leri, Windows: sertifika deposu + Firefox enterprise-roots)
6. Java truststore'larına (`cacerts`) import eder
7. Terminal/CLI kullanıcıları için PEM/CRT/DER/P7B + birleşik bundle üretir

---

## 1. Linux — `ssl-trust-unified.sh`

### Ne yapar?

- **Zincir çekme:** `openssl s_client -showcerts` ile hedeften tam zinciri alır;
  yalnızca PEM blokları ayıklanır (özet satırları `chain.pem`'e sızmaz).
- **OS trust store:** Dağıtım ailesini otomatik tespit eder ve doğru dizine kurar:

  | Aile | Anchor dizini | Güncelleme komutu |
  |---|---|---|
  | RHEL/Fedora/CentOS/Rocky/Alma/OEL/Amazon | `/etc/pki/ca-trust/source/anchors/` | `update-ca-trust extract` |
  | Debian/Ubuntu/Mint/Kali/Alpine, Gentoo | `/usr/local/share/ca-certificates/` | `update-ca-certificates` |
  | SUSE/openSUSE/SLES | `/etc/pki/trust/anchors/` | `update-ca-certificates` |
  | Arch/Manjaro/EndeavourOS | `/etc/ca-certificates/trust-source/anchors/` | `update-ca-trust` |

  SELinux varsa `restorecon` otomatik uygulanır.
- **Container registry:** `podman`/`docker` tespit edilirse
  `/etc/containers/certs.d/<host[:port]>/ca.crt` ve
  `/etc/docker/certs.d/<host[:port]>/ca.crt` yazılır.
- **Tarayıcı NSS DB'leri** (`--install-nss` veya `--all` veya `--user-mode`):
  - Chrome / Chromium / Edge / Brave: `~/.pki/nssdb` (yoksa otomatik oluşturulur)
    + snap Chromium + flatpak Chrome/Edge/Chromium/Brave DB'leri (varsa)
  - Firefox: klasik (`~/.mozilla/firefox`), snap (`~/snap/firefox/...`) ve
    flatpak (`~/.var/app/org.mozilla.firefox/...`) profillerinin tamamı
    (`cert9.db` sql ve `cert8.db` dbm)
  - Root modunda `/root` + `/home/*` (uid ≥ 1000) altındaki **tüm kullanıcılar**
    güncellenir; işlemler dosya sahibi kullanıcı kimliğiyle (`runuser`/`sudo -u`)
    yapılır, sahiplik bozulmaz.
- **Java truststore** (varsayılan: açık): `/usr/lib/jvm`, `/usr/java`, `/opt`,
  `JAVA_HOME` ve SDKMAN altındaki `cacerts` dosyalarına `keytool` ile import.
  RHEL/Debian'da OS trust ile otomatik senkron olan cacerts'ler
  (`/etc/pki/ca-trust/extracted/java/`, `/etc/ssl/certs/java/` vb.) atlanır.
- **İdempotent:** NSS/Java'da aynı takma ad varsa yenilenir; kurulan dosya
  aynı içerikteyse atlanır, farklıysa `--force` olmadan **dokunulmaz**
  (`--force` ile önce yedek alınır).

### Gereksinimler

| Amaç | Gerekli |
|---|---|
| Her mod | `openssl`, `awk` (genelde kurulu gelir) |
| NSS import | `certutil` → `nss-tools` (RHEL) / `libnss3-tools` (Debian) / `mozilla-nss-tools` (SUSE) / `nss` (Arch) |
| Java import | `keytool` (JDK ile gelir) |
| Sistem kurulumu | root veya `sudo` |

`certutil`/`keytool` yoksa ilgili adım uyarıyla atlanır, script durmaz.

### Modlar

- **Varsayılan (root/sudo):** OS trust + Podman/Docker certs.d + Java truststore.
  NSS için ayrıca `--install-nss` (veya `--all`) gerekir.
- **`--user-mode`:** sudo **gerektirmez**. Yalnızca çalışan kullanıcının
  tarayıcı NSS DB'leri ve kullanıcıya ait Java kurulumları (JAVA_HOME, SDKMAN)
  güncellenir. OS trust ve container kayıtları yapılmaz.

### Hızlı kullanım

```bash
# 1) Root/sudo: OS trust + container + Java (+ tarayıcılar için --install-nss)
sudo ./ssl-trust-unified.sh --target git.sirket.local --install-nss

# 2) Tam kurulum kısa yolu (system + containers + nss + java)
sudo ./ssl-trust-unified.sh --all \
  --target freeipa.example.com \
  --target satellite.example.com \
  --target registry.example.com:5000

# 3) Normal kullanıcı (sudo YOK): tarayıcılar + kullanıcı Java
./ssl-trust-unified.sh --user-mode --target git.sirket.local

# 4) Sadece dosya üret, hiçbir yere kurma
./ssl-trust-unified.sh --no-install --target git.lab.local --out ./out

# 5) Hedef listesini dosyadan oku (satır başına host[:port]; # yorum desteklenir)
sudo ./ssl-trust-unified.sh --all --from-file targets.txt

# 6) Makinedeki bilinen CA dosyalarını otomatik ekle
#    (/etc/ipa/ca.crt, katello, foreman-proxy ...)
sudo ./ssl-trust-unified.sh --all --auto-local-ca

# 7) Profil modu: --base-domain'den host üretir
sudo ./ssl-trust-unified.sh --all \
  --profile all --base-domain example.com \
  --svc registry=myregistry.lab:5000

# 8) Yerel CA dosyasıyla
./ssl-trust-unified.sh --user-mode --add-local-ca ~/Downloads/sirket-ca.pem

# 9) Önce güvenli deneme: analiz yapılır, kalıcı hiçbir şey değişmez
sudo ./ssl-trust-unified.sh --dry-run --target freeipa.sirket.local

# 10) IPv6 ve şema destekli hedefler
./ssl-trust-unified.sh --user-mode --target "[2001:db8::1]:8443"
./ssl-trust-unified.sh --user-mode --target https://git.sirket.local
```

### Seçenekler

```
HEDEF
  --target <host[:port]>      Hedef (port yoksa 443). Birden çok kez verilebilir.
                              IPv6: "[addr]:port". https:// öneki kabul edilir.
  --from-file <dosya>         Satır başına bir host[:port] (# yorum, boş satır OK)
  --profile <liste>           all veya virgüllü: freeipa,satellite,foreman,git,registry
                              (--base-domain zorunlu)
  --base-domain <domain>      Profil host'ları için domain (örn: example.com)
  --svc <ad>=<host[:port]>    Servis host ataması; port yoksa servis varsayılanı
                              (registry=5000, diğerleri 443)
  --out <dizin>               Çıkış dizini (varsayılan: ./ssl-trust-out)

KURULUM
  --no-install                Hiç kurulum yapma; yalnızca dosya üret
  --install-system            OS trust store'a kur          (varsayılan: AÇIK)
  --no-install-system         OS trust'ı atla
  --install-containers        Podman/Docker certs.d kur     (varsayılan: AÇIK)
  --no-install-containers     Container certs.d'yi atla
  --install-nss               Tarayıcı NSS DB'lerine ekle   (varsayılan: KAPALI)
  --install-java              Java truststore'lara ekle     (varsayılan: AÇIK)
  --no-install-java           Java'yı atla
  --java-storepass <parola>   Java keystore parolası (varsayılan: changeit)
  --all                       Kısa yol: system + containers + nss + java
  --user-mode                 sudo gerektirmeyen kullanıcı modu (NSS otomatik açılır)

YEREL CA
  --add-local-ca <dosya>      Yerel CA dosyasını da işle (birden çok kez verilebilir)
  --auto-local-ca             Bilinen yerel CA dosyalarını otomatik ekle

DİĞER
  --timeout <sn>              openssl s_client bekleme süresi (varsayılan: 12)
  --dry-run                   Analiz et, yapılacakları yaz; KALICI DEĞİŞİKLİK YAPMA
  --force                     Farklı içerikli mevcut dosyayı yedekleyip üstüne yaz
  --version                   Sürümü yazdır
  -h, --help                  Yardım
```

Tüm değerli seçenekler `--secenek deger` ve `--secenek=deger` biçimlerini destekler.

### v2.0 değişiklikleri (v1.2 üzerine)

- **[GÜVENLİK]** `eval` tamamen kaldırıldı; tüm komutlar argüman dizisiyle çalışır.
- **[BUGFIX]** `--dry-run` artık gerçekten çalışır: zincir çekilir/analiz edilir,
  kalıcı hiçbir değişiklik yapılmaz (dosyalar geçici dizinde).
- **[BUGFIX]** `s_client` çıktısındaki PEM dışı satırlar `chain.pem`'e sızmıyor.
- **[BUGFIX]** Root modunda NSS işlemleri hedef kullanıcı kimliğiyle yapılır —
  root sahipli `cert9.db` oluşmaz.
- **[BUGFIX]** Çoklu sertifikalı bundle'larda certutil/keytool'a sertifikalar
  **tek tek** import edilir (önceden yalnız ilki eklenirdi).
- **[BUGFIX]** `~/.pki/nssdb` "her zaman true" koşul hatası; die-in-subshell;
  bash 4.2 (RHEL7) boş dizi + `set -u` uyumluluğu düzeltildi.
- **[BUGFIX]** Var olan dosya: içerik aynıysa atlanır (idempotent); farklıysa
  `--force` olmadan dokunulmaz, `--force` ile yedek alınıp yazılır.
- **[BUGFIX]** `--profile`, `--base-domain` olmadan verilirse artık hata verir.
- **[YENİ]** Java truststore desteği (`--install-java`, `--java-storepass`).
- **[YENİ]** SUSE, Arch, Alpine aileleri; SELinux `restorecon`.
- **[YENİ]** snap/flatpak Chromium/Chrome/Edge/Brave NSS yolları.
- **[YENİ]** NSS/Java importları idempotent (aynı takma ad yenilenir).
- **[YENİ]** `chain.p7b`, `cas/ca-NN.pem`, `all-ca-bundle.pem`, `env-hints.sh` çıktıları.
- **[YENİ]** Sertifika özeti loglanır; süresi dolmuş sertifika uyarısı.
- **[YENİ]** IPv6 (`[addr]:port`), `https://` öneki, port/host doğrulaması.
- **[YENİ]** Başarı/başarısızlık özeti; hata varsa `exit 2` (CI dostu).
- **[KALDIRILDI]** `csplit` bağımlılığı (awk ile taşınabilir bölme).

---

## 2. Windows — `ssl-trust-unified.ps1`

Linux scriptiyle aynı görevi Windows'ta yapar; **openssl gerektirmez**
(zincir .NET `SslStream` ile çekilir, tamamen yerel/offline çalışır).

### Ne yapar?

- **Windows sertifika deposu:** Zincirdeki CA'ları kurar —
  kök (self-signed) CA'lar → `Root` (Güvenilen Kök Sertifika Yetkilileri),
  ara CA'lar → `CA` (Ara Sertifika Yetkilileri).
  Konum: `LocalMachine` (yönetici) veya `CurrentUser` (`-UserMode`, yönetici
  **gerekmez**). Bu adım **Chrome, Edge, IE ve çoğu .NET/CLI aracını kapsar**.
- **Firefox:** her profilin `user.js` dosyasına
  `security.enterprise_roots.enabled=true` yazılır — Firefox böylece Windows
  deposunu kullanır; NSS `certutil` gerekmez. Yönetici modunda `C:\Users\*`
  altındaki tüm kullanıcı profilleri, `-UserMode`'da yalnızca geçerli kullanıcı.
- **Java:** `Program Files` altındaki yaygın JDK dağıtımları (Oracle, Adoptium,
  Corretto, Microsoft, Zulu, BellSoft, RedHat) + `JAVA_HOME` taranır;
  bulunan `cacerts` dosyalarına `keytool` ile import edilir (idempotent).
- **Container:** Docker Desktop Windows `Root` deposunu kullandığı için
  yukarıdaki adımla kapsanır; podman/WSL için `certs.d\<host>\ca.crt` üretilir
  ve WSL'e kurulum komutu loglanır.
- **DryRun:** dosyalar geçici dizine yazılır, depo/Firefox/Java'ya dokunulmaz.

### Parametreler

```
HEDEF
  -Target <host[:port]>[,...]   Hedef(ler); port yoksa 443. IPv6: "[addr]:port",
                                https:// öneki kabul edilir.
  -FromFile <dosya>             Satır başına bir host[:port] (# yorum desteklenir)
  -Profiles <liste>             all veya freeipa,satellite,foreman,git,registry
                                (-BaseDomain zorunlu; PowerShell'de $Profile
                                otomatik değişken olduğu için adı -Profiles)
  -BaseDomain <domain>          Profil host'ları için domain
  -Svc <ad>=<host[:port]>       Servis host ataması (registry=5000 varsayılanı)
  -Out <dizin>                  Çıkış dizini (varsayılan: .\ssl-trust-out)

KURULUM
  -UserMode                     CurrentUser deposu; yönetici GEREKMEZ
                                (container adımı atlanır)
  -NoInstall                    Hiç kurulum yapma; yalnızca dosya üret
  -NoInstallSystem              Windows deposu kurulumunu atla
  -NoFirefox                    Firefox yapılandırmasını atla
  -NoJava                       Java importunu atla
  -NoContainers                 Container adımını atla
  -JavaStorePass <parola>       Java keystore parolası (varsayılan: changeit)

YEREL CA
  -AddLocalCa <dosya>[,...]     Yerel CA dosyası (PEM/DER, çoklu PEM destekli)
  -AutoLocalCa                  Bilinen konumlardaki CA dosyalarını otomatik ekle
                                (ProgramData\ipa, ProgramData\katello, Downloads)

DİĞER
  -TimeoutSec <sn>              Bağlantı zaman aşımı (varsayılan: 12)
  -DryRun                       Analiz et; kalıcı değişiklik yapma
  -Force                        Depodaki mevcut sertifikayı yenile
  -Version                      Sürümü yazdır
```

### Hızlı kullanım

```powershell
# Normal kullanıcı (yönetici yok): CurrentUser deposu + Firefox + kullanıcı Java
.\ssl-trust-unified.ps1 -UserMode -Target git.sirket.local

# Yönetici (tüm makine): LocalMachine deposu + Firefox (tüm kullanıcılar) + sistem Java
.\ssl-trust-unified.ps1 -Target git.sirket.local, registry.sirket.local:5000

# Profil ile
.\ssl-trust-unified.ps1 -Profiles all -BaseDomain sirket.local `
    -Svc registry=reg.sirket.local:5000

# Önce güvenli deneme
.\ssl-trust-unified.ps1 -DryRun -Target freeipa.sirket.local

# Yerel CA dosyası
.\ssl-trust-unified.ps1 -UserMode -AddLocalCa C:\certs\sirket-ca.pem
```

Not: `LocalMachine` deposuna yazan varsayılan mod **yönetici** ister; yönetici
değilseniz script net bir hatayla durur ve `-UserMode` önerir.

---

## Üretilen dosyalar (iki script için ortak)

Her hedef için `<out>/<host_port>/` altında:

```
chain.pem        Sunucunun gönderdiği tüm zincir
chain.p7b        Zincirin PKCS#7 hali (Java/Windows import için)
ca-bundle.pem    CA:TRUE sertifikalar (zincirde CA yoksa leaf) 
ca-bundle.crt    ca-bundle.pem'in kopyası
ca-bundle.der    Bundle'daki İLK sertifikanın DER hali (tek sertifika!)
cas/ca-NN.pem    Her CA sertifikası ayrı dosya (NSS/Java importları bunları kullanır)
```

Ek olarak `<out>/` altında:

```
all-ca-bundle.pem   Tüm hedeflerden benzersiz CA'ların birleşimi
env-hints.sh        (Linux, --user-mode)  CLI ortam değişkeni önerileri
env-hints.ps1       (Windows, -UserMode)  CLI ortam değişkeni önerileri
certs.d/<host>/     (Windows) podman/WSL için ca.crt referans yapısı
```

`env-hints` dosyası `NODE_EXTRA_CA_CERTS` (güvenli, ekleme yapar) tanımını içerir;
`GIT_SSL_CAINFO`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`
(sistem deposunun **yerine geçen** değişkenler) yorum satırı olarak sunulur.

### Tarayıcıya elle import (gerekirse)

- **Firefox:** Ayarlar → Gizlilik ve Güvenlik → Sertifikalar → İçe Aktar →
  `ca-bundle.pem` veya `.crt`
- **Chrome:** Ayarlar → Gizlilik → Sertifikaları Yönet → Yetkililer → `.pem`
- **Edge:** Ayarlar → Gizlilik → Sertifikaları Yönet → Güvenilen Kök CA → `.der`

---

## Çıkış kodları (iki script için ortak)

| Kod | Anlamı |
|---|---|
| 0 | Tüm hedefler başarılı |
| 1 | Kullanım/ön koşul hatası (geçersiz argüman, yetki eksik vb.) |
| 2 | En az bir hedef başarısız (özet logda listelenir) — CI dostu |

---

## Notlar

- **Linux'ta tarayıcılar OS trust store'u değil kendi NSS DB'lerini kullanır**;
  `curl`, `git`, Python `requests` vb. için OS trust yeterlidir ama tarayıcıda
  da görünsün istiyorsanız `--install-nss` (veya `--all` / `--user-mode`) gerekir.
- **Windows'ta tersine**, Chrome/Edge doğrudan Windows deposunu kullanır;
  Firefox da `enterprise_roots` ayarıyla aynı depoya bağlanır — bu yüzden
  Windows scriptinde ayrı NSS adımı yoktur.
- Zincirde `CA:TRUE` sertifika yoksa (self-signed sunucu) leaf sertifika
  uyarıyla kullanılır/kurulur.
- Sunucu kök CA'yı göndermiyorsa bundle intermediate CA içerir; modern
  doğrulayıcılar için bu yeterlidir (Linux scripti bunu bilgi olarak loglar).
- Süresi dolmuş sertifikalar import sırasında **uyarıyla** bildirilir.
- `--auto-local-ca` (Linux) şu dosyaları arar: `/etc/ipa/ca.crt`,
  `/etc/pki/katello/certs/katello-default-ca.crt` ve
  `foreman-proxy` `ca.pem` konumları.
- Servis adı eşanlamlıları: `ipa`→`freeipa`, `katello`→`satellite`,
  `gitrepo`→`git`.
