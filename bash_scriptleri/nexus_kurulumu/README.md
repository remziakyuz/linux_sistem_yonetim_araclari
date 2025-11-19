# Nexus Repository Manager Kurulum Scripti v2.2

## 📋 İçindekiler

- [Genel Bakış](#genel-bakış)
- [v2.2 Yenilikleri](#v22-yenilikleri)
- [Özellikler](#özellikler)
- [Sistem Gereksinimleri](#sistem-gereksinimleri)
- [Disk Alanı Gereksinimleri](#disk-alanı-gereksinimleri)
- [Kurulum Öncesi Hazırlık](#kurulum-öncesi-hazırlık)
- [Hızlı Başlangıç](#hızlı-başlangıç)
- [Detaylı Kullanım](#detaylı-kullanım)
- [Yapılandırma Detayları](#yapılandırma-detayları)
- [Kurulum Sonrası İşlemler](#kurulum-sonrası-işlemler)
- [Sorun Giderme](#sorun-giderme)
- [Güvenlik Notları](#güvenlik-notları)
- [Sık Sorulan Sorular](#sık-sorulan-sorular)
- [Yedekleme ve Geri Yükleme](#yedekleme-ve-geri-yükleme)
- [Kaldırma](#kaldırma)
- [Versiyon Geçmişi](#versiyon-geçmişi)

---

## 🎯 Genel Bakış

Bu script, **Nexus Repository Manager 3.86.2-01** versiyonunu RHEL 9 tabanlı Linux dağıtımlarına otomatik olarak kurmak için geliştirilmiştir. Script, production ortamları için optimize edilmiş, kapsamlı hata kontrolü ve disk alanı yönetimi içeren profesyonel bir kurulum çözümüdür.

### Nexus Repository Manager Nedir?

Nexus Repository Manager, Maven, npm, Docker, PyPI ve diğer paket formatları için merkezi bir repository yönetim çözümüdür. Yazılım bileşenlerini saklamak, versiyon kontrolü yapmak ve organizasyonunuzda tekrar kullanılabilirliği artırmak için kullanılır.

---

## 🆕 v2.2 Yenilikleri

### 1. 🔐 Basitleştirilmiş Custom Encryption Key

**Önceki Versiyon (v2.1):**
- Karmaşık `custom-encryption.json` formatı
- fixedEncryption, salt, iv gibi ek alanlar

**Yeni Versiyon (v2.2):**
```json
{
  "active": "alibaba33442",
  "keys": [
    {
      "id": "alibaba33442",
      "key": "d2lsbGluZ3BsYW5lc3RvcnlncmFiYmVkaGVscGZ1bGM="
    }
  ]
}
```
- Daha basit ve temiz yapı
- Kolay debug ve yönetim
- Dosya: `/app/nexus/etc/custom-key.json`

### 2. 📝 Modern Property Desteği

**nexus.secrets.file** property desteği eklendi:

```properties
# /app/nexus/etc/default-application.properties
secret.nexusSecret.enabled=true
nexus.secrets.file=/app/nexus/etc/custom-key.json
```

**Avantajları:**
- Nexus 3.x için önerilen yöntem
- Tırnak kullanımı gerektirmez
- Daha güvenli ve modern

### 3. 🤖 Otomatik API Re-encryption

Kurulum tamamlandıktan sonra otomatik olarak:
- ⏱️ 90 saniye bekleme (geri sayım ile)
- 🔄 API re-encryption endpoint çağrısı
- ✅ Başarı/başarısızlık raporlaması
- 📝 Manuel komut önerisi (gerekirse)

**API Çağrısı:**
```bash
curl -X 'PUT' \
  'https://nexus.lab.akyuz.tech/service/rest/v1/secrets/encryption/re-encrypt' \
  -u 'admin:INITIAL_PASSWORD' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'NX-ANTI-CSRF-TOKEN: 0.6199265331343733' \
  -H 'X-Nexus-UI: true' \
  -d '{
  "secretKeyId": "alibaba33442",
  "notifyEmail": "string"
}'
```

### 4. 🛠️ Systemd Stop Hatası Düzeltildi

**Problem:**
```bash
$ systemctl stop nexus
$ systemctl status nexus
× nexus.service - Nexus Repository Manager
     Active: failed (Result: exit-code)
   Main PID: 1428 (code=exited, status=143)
```

**Çözüm:**
```ini
[Service]
...
SuccessExitStatus=143  # SIGTERM artık başarılı sayılır
```

**Sonuç:**
```bash
$ systemctl stop nexus
$ systemctl status nexus
○ nexus.service - Nexus Repository Manager
     Active: inactive (dead)
```

---

## ✨ Özellikler

### Temel Özellikler

- ✅ **Otomatik Kurulum**: Tek komutla tam otomatik kurulum
- ✅ **JDK 17 Kurulumu**: Gerekli Java sürümünün otomatik kurulumu ve doğrulaması
- ✅ **Özel Kullanıcı**: Güvenlik için özel nexus kullanıcısı (UID: 30033, GID: 30033)
- ✅ **Systemd Entegrasyonu**: Otomatik başlatma ve servis yönetimi
- ✅ **Firewall Yapılandırması**: Port 8081 için otomatik firewall kuralı
- ✅ **Özelleştirilebilir Dizinler**: İhtiyaca göre dizin yapısı ayarlanabilir
- ✅ **SSL/HTTPS Desteği**: Let's Encrypt ve Self-Signed sertifika desteği
- ✅ **Verbose Mode**: Detaylı debug çıktısı

### v2.2 İyileştirmeleri

#### 🔐 Gelişmiş Şifreleme
- Custom encryption key otomatik oluşturma
- "Default Secret Encryption Key" uyarısını baştan önleme
- Basitleştirilmiş JSON formatı
- Otomatik backup oluşturma

#### 🤖 Akıllı Kurulum
- Otomatik API re-encryption
- 90 saniye bekleme mekanizması
- Başarı/başarısızlık bildirimi
- Manuel komut önerisi

#### 🛠️ Sistem Entegrasyonu
- Düzeltilmiş systemd service (exit code 143)
- Geliştirilmiş stop/start yönetimi
- Detaylı durum raporlaması

#### 1. Kapsamlı Hata Kontrolü

- 🔍 **Dosya İndirme Kontrolü**: İndirme başarısız olursa anında algılama
- 🔍 **Dosya Varlık Kontrolü**: Tüm kritik dosyaların varlığı doğrulanır
- 🔍 **Komut Başarı Kontrolü**: Her komutun çıkış kodu kontrol edilir
- 🔍 **Boş Dosya Kontrolü**: İndirilen dosyaların içerik kontrolü
- 🔍 **Servis Durum Kontrolü**: Nexus servisinin doğru başlatıldığı doğrulanır
- 🔍 **JSON Format Doğrulama**: Encryption key dosyalarının format kontrolü

#### 2. İşletim Sistemi Kontrolü

Script aşağıdaki işletim sistemlerini destekler:

- Rocky Linux 9.x
- Red Hat Enterprise Linux (RHEL) 9.x
- AlmaLinux 9.x
- CentOS Stream 9

Desteklenmeyen sistemlerde çalıştırılmaya çalışıldığında açıklayıcı hata mesajı verir ve kurulumu durdurur.

#### 3. Disk Alanı Yönetimi

Kurulum öncesi disk alanı kontrolleri:

| Dizin | Minimum Alan | Açıklama |
|-------|--------------|----------|
| INSTALL_DIR | 2 GB | Nexus uygulama dosyaları |
| REPO_DIR | 10 GB | Repository ve artifact depolama |
| WORK_DIR | 5 GB | Çalışma ve log dosyaları |

Yeterli alan yoksa kurulum başlamaz ve kullanıcı bilgilendirilir.

#### 4. Kullanıcı Dostu Arayüz

- 🎨 **Renkli Çıktılar**: Hata (kırmızı), başarı (yeşil), uyarı (sarı), güvenlik (magenta) mesajları
- 📊 **İlerleme Göstergeleri**: Her adımda detaylı bilgilendirme
- ⏱️ **Geri Sayım Göstergesi**: API re-encryption öncesi bekleme
- 📝 **Kurulum Özeti**: Kurulum sonunda tüm önemli bilgiler

---

## 💻 Sistem Gereksinimleri

### İşletim Sistemi

- Rocky Linux 9.x (Test edildi: 9.6)
- RHEL 9.x
- AlmaLinux 9.x
- CentOS Stream 9

### Donanım Gereksinimleri

#### Minimum

- **CPU**: 2 Core
- **RAM**: 4 GB
- **Disk**: 20 GB boş alan

#### Önerilen

- **CPU**: 4+ Core
- **RAM**: 8+ GB
- **Disk**: 100+ GB (SSD önerilir)

#### Production Ortamı

- **CPU**: 8+ Core
- **RAM**: 16+ GB
- **Disk**: 500+ GB (SSD şart)
- **Network**: 1 Gbps+

### Yazılım Gereksinimleri

- Root erişimi
- İnternet bağlantısı (ilk kurulum için)
- wget, tar, sed, awk, openssl (script tarafından kontrol edilir)
- systemd
- firewalld (opsiyonel)

---

## 💾 Disk Alanı Gereksinimleri

### Dizin Yapısı

```
/app/
├── nexus/                    # INSTALL_DIR (2 GB minimum)
│   ├── bin/
│   ├── etc/
│   │   ├── custom-key.json           # 🆕 v2.2
│   │   └── default-application.properties
│   ├── lib/
│   └── ...
└── data/
    ├── nexus-repo/          # REPO_DIR (10 GB minimum)
    └── nexus/
        └── sonatype-work/   # WORK_DIR (5 GB minimum)
            └── nexus3/      # DATA_DIR
                ├── db/
                ├── etc/
                ├── log/
                ├── tmp/
                └── blobs/
```

### Depolama Planlaması

Repository boyutu, kullanım senaryonuza bağlı olarak hızla büyüyebilir:

- **Küçük Ekip** (5-10 geliştirici): 50-100 GB
- **Orta Ekip** (10-50 geliştirici): 200-500 GB
- **Büyük Ekip** (50+ geliştirici): 1+ TB
- **Enterprise**: 5+ TB

**Not**: Maven Central proxy kullanıyorsanız, disk alanı ihtiyacı çok daha hızlı artacaktır.

---

## 🔧 Kurulum Öncesi Hazırlık

### 1. Sistem Güncellemesi

```bash
sudo yum update -y
```

### 2. Gerekli Araçların Kontrolü

```bash
# wget kontrolü
wget --version

# tar kontrolü
tar --version

# systemctl kontrolü
systemctl --version

# openssl kontrolü (v2.2 için gerekli)
openssl version
```

### 3. Disk Alanı Kontrolü

```bash
# Disk kullanımını görüntüle
df -h

# /app dizini için kullanılabilir alan
df -h /app 2>/dev/null || df -h /
```

### 4. Port Kontrolü

```bash
# 8081 portunu kullanan süreç var mı kontrol et
sudo ss -tulpn | grep 8081

# veya
sudo lsof -i :8081
```

Port kullanımda ise, scriptteki `NEXUS_PORT` değişkenini değiştirin.

### 5. SELinux Kontrolü (Opsiyonel)

```bash
# SELinux durumunu kontrol et
sestatus

# Geçici olarak devre dışı bırak (gerekirse)
sudo setenforce 0

# Kalıcı olarak devre dışı bırak
sudo sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
```

---

## 🚀 Hızlı Başlangıç

### Senaryo 1: Basit HTTP Kurulum

```bash
# 1. Script'i çalıştırılabilir yap
chmod +x install-nexus.sh

# 2. Kurulumu başlat
sudo ./install-nexus.sh
```

**Sonuç:** `http://YOUR_IP:8081`

### Senaryo 2: Let's Encrypt ile SSL

```bash
sudo ./install-nexus.sh \
  --enable-ssl \
  --domain nexus.lab.akyuz.tech \
  --email admin@akyuz.tech
```

**Sonuç:** `https://nexus.lab.akyuz.tech`

**Gereksinimler:**
- Domain'in DNS kaydı sunucuya işaret etmeli
- Port 80 ve 443 açık olmalı
- Geçerli email adresi

### Senaryo 3: Self-Signed SSL

```bash
sudo ./install-nexus.sh \
  --enable-ssl \
  --domain nexus.lab.akyuz.tech \
  --self-signed
```

**Sonuç:** `https://nexus.lab.akyuz.tech` (tarayıcı uyarısı verecek)

### Senaryo 4: Verbose Mode ile Kurulum

```bash
sudo ./install-nexus.sh --verbose
```

**Sonuç:** Detaylı debug çıktısı ile kurulum

### Kurulum Adımları

Script otomatik olarak:
1. ✅ İşletim sistemini kontrol eder
2. ✅ Disk alanını kontrol eder
3. ✅ JDK 17'yi kurar
4. ✅ Nexus kullanıcısı oluşturur
5. ✅ Nexus'u indirir ve kurar
6. ✅ Custom encryption key oluşturur (v2.2)
7. ✅ Yapılandırmaları yapar
8. ✅ Systemd service oluşturur (SuccessExitStatus=143 ile)
9. ✅ Firewall kuralları ekler
10. ✅ Servisi başlatır
11. ✅ 90 saniye bekler (v2.2)
12. ✅ API re-encryption çağrısı yapar (v2.2)
13. ✅ Doğrulama testleri yapar
14. ✅ Kurulum özeti gösterir

---

## 📖 Detaylı Kullanım

### Komut Satırı Parametreleri

```bash
Kullanım: ./install-nexus.sh [OPTIONS]

SEÇENEKLER:
    --enable-ssl           Nginx reverse proxy ve SSL/HTTPS'i etkinleştir
    --domain DOMAIN        SSL için domain adı (örn: nexus.example.com)
    --email EMAIL          Let's Encrypt için email adresi
    --self-signed          Let's Encrypt yerine self-signed sertifika kullan
    --verbose              Detaylı çıktı göster (debug modu)
    --help                 Yardım mesajını göster
```

### Özelleştirilmiş Kurulum

Script başındaki değişkenleri düzenleyerek kurulumu özelleştirebilirsiniz:

```bash
# Script'i düzenleyin
nano install-nexus.sh
```

#### Özelleştirilebilir Değişkenler

```bash
# Nexus versiyonu
NEXUS_VERSION="3.86.2-01"

# Java versiyonu
JAVA_VERSION="17"

# Nexus kullanıcı bilgileri
NEXUS_USER="nexus"
NEXUS_UID=30033
NEXUS_GID=30033

# Kurulum dizinleri
INSTALL_DIR="/app/nexus"
REPO_DIR="/app/data/nexus-repo"
WORK_DIR="/app/data/nexus/sonatype-work"

# Port numarası
NEXUS_PORT=8081

# API yapılandırması (v2.2)
API_WAIT_TIME=90  # Saniye cinsinden bekleme süresi

# Disk alanı gereksinimleri (MB)
MIN_INSTALL_SPACE=2048  # 2GB
MIN_REPO_SPACE=10240    # 10GB
MIN_WORK_SPACE=5120     # 5GB
```

### Offline Kurulum

İnternet bağlantısı olmayan sistemlerde:

1. **Nexus tar dosyasını manuel olarak indirin:**
```bash
curl -L -O https://cdn.download.sonatype.com/repository/downloads-prod-group/3/nexus-3.86.2-01-linux-x86_64.tar.gz
```

2. **Tar dosyasını /tmp dizinine koyun**

3. **Script'i normal şekilde çalıştırın**

Script, mevcut tar dosyasını otomatik olarak algılayacak ve kullanacaktır.

### Sessiz Kurulum

Kurulum sırasında tüm çıktıları bir log dosyasına kaydetmek için:

```bash
sudo ./install-nexus.sh 2>&1 | tee nexus-install.log
```

---

## ⚙️ Yapılandırma Detayları

### v2.2 Özel Yapılandırma Dosyaları

#### 1. custom-key.json (🆕 v2.2)
**Konum**: `/app/nexus/etc/custom-key.json`

```json
{
  "active": "alibaba33442",
  "keys": [
    {
      "id": "alibaba33442",
      "key": "d2lsbGluZ3BsYW5lc3RvcnlncmFiYmVkaGVscGZ1bGM="
    }
  ]
}
```

**Özellikler:**
- Basitleştirilmiş format
- Otomatik oluşturulur
- Güvenli izinler (600)
- Nexus kullanıcısına ait

**Güvenlik:**
```bash
# İzinleri kontrol et
ls -la /app/nexus/etc/custom-key.json
# Çıktı: -rw------- 1 nexus nexus

# JSON formatını doğrula
python3 -m json.tool /app/nexus/etc/custom-key.json
```

#### 2. default-application.properties (🔄 v2.2)
**Konum**: `/app/nexus/etc/default-application.properties`

```properties
# Nexus Repository Manager Configuration
# Auto-generated by installation script v2.2

# Logging Configuration
logging.config=./etc/logback/logback.xml

# Custom Secrets File Configuration
secret.nexusSecret.enabled=true
nexus.secrets.file=/app/nexus/etc/custom-key.json

# DO NOT UNCOMMENT OR ADD THESE LINES:
# nexus.security.encryptionKey=...
# They will conflict with nexus.secrets.file
```

**Önemli Notlar:**
- ✅ Tırnak kullanmayın
- ✅ `nexus.secrets.file` kullanın (v2.2)
- ❌ Inline `nexus.security.encryptionKey` kullanmayın

### Standart Nexus Yapılandırma Dosyaları

#### 3. nexus.rc
**Konum**: `/app/nexus/bin/nexus.rc`

```bash
run_as_user="nexus"
```

Bu dosya, Nexus'un hangi kullanıcı ile çalışacağını belirtir.

#### 4. nexus.vmoptions
**Konum**: `/app/nexus/bin/nexus.vmoptions`

JVM parametrelerini içerir:

```bash
-XX:LogFile=/app/data/nexus/sonatype-work/nexus3/log/jvm.log
-Dkaraf.data=/app/data/nexus/sonatype-work/nexus3
-Dkaraf.log=/app/data/nexus/sonatype-work/nexus3/log
-Djava.io.tmpdir=/app/data/nexus/sonatype-work/nexus3/tmp
-Xms2G          # Minimum heap boyutu
-Xmx4G          # Maksimum heap boyutu
-XX:MaxDirectMemorySize=4G
```

**Bellek Ayarlaması:**

Sistem RAM'ine göre önerilen değerler:

| Sistem RAM | -Xms | -Xmx | MaxDirectMemorySize |
|------------|------|------|---------------------|
| 4 GB | 1G | 2G | 2G |
| 8 GB | 2G | 4G | 4G |
| 16 GB | 4G | 8G | 8G |
| 32 GB | 8G | 16G | 16G |

#### 5. nexus-default.properties
**Konum**: `/app/nexus/etc/nexus-default.properties`

Nexus'un temel yapılandırma dosyası:

```properties
nexus-work=/app/data/nexus/sonatype-work
data-dir=/app/data/nexus/sonatype-work/nexus3
application-port=8081
application-host=0.0.0.0
```

### Systemd Servis Yapılandırması (🔄 v2.2)

**Konum**: `/etc/systemd/system/nexus.service`

```ini
[Unit]
Description=Nexus Repository Manager
After=network.target

[Service]
Type=forking
LimitNOFILE=65536
Environment="NEXUS_HOME=/app/nexus"
Environment="NEXUS_DATA=/app/data/nexus/sonatype-work/nexus3"
Environment="HOME=/app/data/nexus/sonatype-work/nexus3"
Environment="JAVA_TOOL_OPTIONS=-Duser.home=/app/data/nexus/sonatype-work/nexus3"
Environment="INSTALL4J_ADD_VM_PARAMS=-Dkaraf.data=/app/data/nexus/sonatype-work/nexus3 -Dkaraf.home=/app/nexus -Dkaraf.base=/app/nexus -Djava.io.tmpdir=/app/data/nexus/sonatype-work/nexus3/tmp"
ExecStart=/app/nexus/bin/nexus start
ExecStop=/app/nexus/bin/nexus stop
User=nexus
Restart=on-abort
SuccessExitStatus=143    # 🆕 v2.2: SIGTERM başarılı sayılır

[Install]
WantedBy=multi-user.target
```

**v2.2 İyileştirmesi:**
- `SuccessExitStatus=143` eklendi
- Exit code 143 (SIGTERM) artık başarılı
- `systemctl stop nexus` artık "failed" göstermez

---

## ✅ Kurulum Sonrası İşlemler

### 1. Servis Durumu Kontrolü

```bash
# Servis durumu
systemctl status nexus

# Beklenen çıktı:
● nexus.service - Nexus Repository Manager
     Active: active (running)
```

### 2. Stop/Start Testi (v2.2)

```bash
# Durdur
systemctl stop nexus
systemctl status nexus
# Beklenen: Active: inactive (dead) - ARTIK "failed" DEĞİL!

# Başlat
systemctl start nexus
systemctl status nexus
# Beklenen: Active: active (running)
```

### 3. Custom Key Doğrulama (v2.2)

```bash
# Dosya var mı?
ls -la /app/nexus/etc/custom-key.json

# JSON geçerli mi?
python3 -m json.tool /app/nexus/etc/custom-key.json

# Property tanımlı mı?
grep "nexus.secrets.file" /app/nexus/etc/default-application.properties
```

### 4. İlk Giriş

```bash
# Admin şifresini al
sudo cat /app/data/nexus/sonatype-work/nexus3/admin.password
```

**Web Arayüzüne Erişim:**
- URL: `http://YOUR_IP:8081` veya `https://YOUR_DOMAIN`
- Kullanıcı: `admin`
- Şifre: Yukarıdaki komuttan alınan değer

### 5. Setup Wizard

1. Sign in ile giriş yapın
2. Yeni admin şifresini belirleyin
3. Anonymous access'i yapılandırın (Production'da Disable önerilir)
4. Repository'leri yapılandırın

### 6. Encryption Key Doğrulama

**Web Arayüzünden:**
1. Support → Status
2. "Default Secret Encryption Key" uyarısı OLMAMALI ✅
3. Custom encryption kullanıldığını görmelisiniz

**Komut Satırından:**
```bash
# Nexus loglarında custom key kullanımı
grep -i "secrets.file" /app/data/nexus/sonatype-work/nexus3/log/nexus.log

# Default key uyarısı olmamalı
grep -i "Default Secret Encryption Key" /app/data/nexus/sonatype-work/nexus3/log/nexus.log
```

### 7. API Re-encryption Kontrolü (v2.2)

```bash
# Kurulum logunu kontrol et
cat /var/log/nexus-installation-*.log | grep -A 10 "API RE-ENCRYPTION"

# Nexus loglarını kontrol et
tail -100 /app/data/nexus/sonatype-work/nexus3/log/nexus.log | grep -i encrypt
```

### 8. Backup Dosyasını Güvenli Yere Kopyalayın

```bash
# Backup dosyasını bul
ls -lh /root/nexus-encryption-key-*.txt

# Güvenli yere kopyala
cp /root/nexus-encryption-key-*.txt /güvenli/yedek/dizini/

# İçeriği görüntüle (encryption key içerir - dikkatli olun!)
cat /root/nexus-encryption-key-*.txt
```

**⚠️ ÇOK ÖNEMLİ:** Bu dosya kaybolursa, şifrelenmiş veriler kurtarılamaz!

---

## 🔧 Sorun Giderme

### 1. Servis Başlamıyor

**Semptom:**
```bash
systemctl status nexus
# Active: failed (Result: exit-code)
```

**Çözüm:**
```bash
# Logları kontrol et
sudo journalctl -u nexus -f

# Nexus logları
sudo tail -f /app/data/nexus/sonatype-work/nexus3/log/nexus.log

# JVM logları
sudo tail -f /app/data/nexus/sonatype-work/nexus3/log/jvm.log

# Dosya izinlerini kontrol et
ls -la /app/nexus
sudo chown -R nexus:nexus /app/nexus /app/data/nexus

# Port kontrolü
sudo ss -tulpn | grep 8081
```

### 2. "Out of Memory" Hatası

**Semptom:**
```
java.lang.OutOfMemoryError: Java heap space
```

**Çözüm:**
```bash
# nexus.vmoptions'ı düzenle
sudo nano /app/nexus/bin/nexus.vmoptions

# Heap boyutunu artır
-Xms4G
-Xmx8G
-XX:MaxDirectMemorySize=8G

# Servisi yeniden başlat
sudo systemctl restart nexus
```

### 3. Stop Komutu "Failed" Gösteriyor (v2.1 ve öncesi)

**Semptom:**
```bash
systemctl stop nexus
systemctl status nexus
# Active: failed (Result: exit-code)
```

**Çözüm (v2.2'de otomatik):**
```bash
# Service dosyasını düzenle
sudo nano /etc/systemd/system/nexus.service

# Bu satırı [Service] bölümüne ekle:
SuccessExitStatus=143

# Daemon'ı reload et
sudo systemctl daemon-reload

# Test et
sudo systemctl stop nexus
sudo systemctl status nexus
# Active: inactive (dead) olmalı
```

### 4. API Re-encryption Başarısız (v2.2)

**Semptom:**
```
API re-encryption isteği gönderilirken bir sorun oluştu
```

**Çözüm:**
```bash
# Manuel olarak çalıştır
ADMIN_PASS=$(sudo cat /app/data/nexus/sonatype-work/nexus3/admin.password)

curl -X 'PUT' \
  'http://localhost:8081/service/rest/v1/secrets/encryption/re-encrypt' \
  -u "admin:${ADMIN_PASS}" \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'NX-ANTI-CSRF-TOKEN: 0.6199265331343733' \
  -H 'X-Nexus-UI: true' \
  -d '{
  "secretKeyId": "alibaba33442",
  "notifyEmail": "string"
}'
```

### 5. Custom Key Dosyası Bulunamıyor

**Semptom:**
```
custom-key.json bulunamadı
```

**Çözüm:**
```bash
# Dosya var mı kontrol et
ls -la /app/nexus/etc/custom-key.json

# Manuel oluştur (gerekirse)
sudo cat > /app/nexus/etc/custom-key.json <<'EOF'
{
  "active": "alibaba33442",
  "keys": [
    {
      "id": "alibaba33442",
      "key": "YOUR_BASE64_KEY_HERE"
    }
  ]
}
EOF

# İzinleri ayarla
sudo chmod 600 /app/nexus/etc/custom-key.json
sudo chown nexus:nexus /app/nexus/etc/custom-key.json

# Servisi yeniden başlat
sudo systemctl restart nexus
```

### 6. Port Zaten Kullanımda

**Semptom:**
```
Address already in use
```

**Çözüm:**
```bash
# 8081 portunu kim kullanıyor?
sudo lsof -i :8081

# Değiştirmek için
sudo nano /app/nexus/etc/nexus-default.properties
# application-port=8081  →  application-port=9999

# Firewall'u güncelle
sudo firewall-cmd --permanent --remove-port=8081/tcp
sudo firewall-cmd --permanent --add-port=9999/tcp
sudo firewall-cmd --reload

# Servisi yeniden başlat
sudo systemctl restart nexus
```

### 7. Disk Alanı Yetersiz

**Semptom:**
```
No space left on device
```

**Çözüm:**
```bash
# Disk kullanımını kontrol et
df -h /app

# Büyük dosyaları bul
sudo du -sh /app/data/nexus/sonatype-work/nexus3/* | sort -h

# Log dosyalarını temizle
sudo rm -rf /app/data/nexus/sonatype-work/nexus3/log/*.log.*
sudo rm -rf /app/data/nexus/sonatype-work/nexus3/tmp/*

# Cleanup policy ayarla (Web UI'dan)
# Admin → Repository → Cleanup Policies

# Compact işlemi (Web UI'dan)
# Admin → Repository → Blob Stores → Compact
```

### 8. SSL Sertifika Hataları

**Semptom:**
```
SSL certificate problem
```

**Çözüm:**
```bash
# Let's Encrypt sertifikası yenile
sudo certbot renew

# Self-signed sertifika yenile
sudo openssl req -new -x509 -days 365 -key /etc/ssl/nexus/nexus.key \
  -out /etc/ssl/nexus/nexus.crt

# Nginx'i yeniden başlat
sudo systemctl restart nginx
```

### 9. Repository'e Upload Edilemiyor

**Çözümler:**
1. **Kullanıcı yetkileri kontrol edin**
   - Security → Users → admin → Check privileges

2. **Repository policy kontrol edin**
   - Repository → Select repo → Configuration
   - Deployment policy: Allow redeploy

3. **Disk alanı kontrol edin**
   ```bash
   df -h /app/data/nexus/sonatype-work/nexus3
   ```

4. **Nexus loglarını kontrol edin**
   ```bash
   sudo tail -f /app/data/nexus/sonatype-work/nexus3/log/nexus.log
   ```

---

## 🔒 Güvenlik Notları

### 1. Encryption Key Güvenliği (v2.2)

```bash
# ✅ YAPILMASI GEREKENLER:

# Backup dosyasını güvenli yere kopyala
cp /root/nexus-encryption-key-*.txt /secure/offsite/backup/

# İzinleri koru
chmod 600 /app/nexus/etc/custom-key.json
chmod 600 /root/nexus-encryption-key-*.txt

# Düzenli yedekleme
# - custom-key.json
# - default-application.properties
# - Database

# ❌ YAPILMAMASI GEREKENLER:

# Backup dosyasını silme
# Custom key'i değiştirme (data kaybı!)
# İzinleri gevşetme (chmod 644 gibi)
```

### 2. Admin Şifresi

```bash
# İlk giriş sonrası şifreyi DEĞİŞTİRİN
# admin.password dosyası kurulumdan sonra silinir

# Güçlü şifre kullanın:
# - Minimum 12 karakter
# - Büyük/küçük harf
# - Rakam
# - Özel karakter
```

### 3. Anonymous Access

```bash
# Production'da KAPATIN
# Web UI: Security → Anonymous Access → Disable
```

### 4. HTTPS Kullanımı

```bash
# Production'da HTTPS şart!
# Kurulumda --enable-ssl kullanın

sudo ./install-nexus.sh \
  --enable-ssl \
  --domain nexus.yourdomain.com \
  --email admin@yourdomain.com
```

### 5. Firewall Yapılandırması

```bash
# Sadece gerekli portları açın
sudo firewall-cmd --list-ports

# Gereksiz portları kapatın
sudo firewall-cmd --permanent --remove-port=XXXX/tcp
sudo firewall-cmd --reload
```

### 6. Düzenli Güncellemeler

```bash
# Nexus güncellemeleri
# https://www.sonatype.com/products/repository-oss-download

# Sistem güncellemeleri
sudo yum update -y

# Java güncellemeleri
sudo yum update java-17-openjdk
```

### 7. Güvenlik Denetimi

```bash
# Nexus güvenlik durumu
# Support → Status → Security

# Log denetimi
grep -i "authentication failed" /app/data/nexus/sonatype-work/nexus3/log/nexus.log

# Başarısız giriş denemeleri
grep -i "login" /app/data/nexus/sonatype-work/nexus3/log/request.log
```

---

## ❓ Sık Sorulan Sorular

### Genel Sorular

**S: Nexus ne kadar sürede açılır?**

**C**: Normal şartlarda 2-3 dakika. İlk açılış biraz daha uzun sürebilir. Kurulum scripti 90 saniye bekler (v2.2).

---

**S: Nexus hangi portları kullanır?**

**C**: 
- HTTP: 8081 (varsayılan)
- Docker Registry: 8082-8090 (manuel yapılandırma gerekir)
- HTTPS: 443 (Nginx kullanıyorsanız)

---

**S: v2.1'den v2.2'ye nasıl geçiş yaparım?**

**C**: 
```bash
# Yeni kurulum için direk v2.2 kullanın
# Mevcut kurulum için:

# 1. Backup alın
sudo tar -czf /backup/nexus-full-$(date +%Y%m%d).tar.gz \
  /app/nexus /app/data/nexus

# 2. Nexus'u durdurun
sudo systemctl stop nexus

# 3. custom-key.json oluşturun
# (Script'teki generate_custom_key_file fonksiyonunu kullanın)

# 4. default-application.properties güncelleyin
# nexus.secrets.file=/app/nexus/etc/custom-key.json

# 5. nexus.service güncelleyin
# SuccessExitStatus=143 ekleyin

# 6. Daemon reload ve başlatın
sudo systemctl daemon-reload
sudo systemctl start nexus

# 7. API re-encryption yapın
# (Script'teki komutu kullanın)
```

---

**S: Custom key dosyasını kaybedersem ne olur?**

**C**: 
- ⚠️ Şifrelenmiş veriler ASLA kurtarılamaz!
- Kullanıcı şifreleri erişilemez hale gelir
- Repository credentials kaybolur
- Bu yüzden backup ÇOK önemli!

---

**S: Nexus çok fazla disk alanı kullanıyor**

**C**: 
- Cleanup policies ayarlayın
- Proxy cache ayarlarını kontrol edin
- Gereksiz snapshot'ları temizleyin
- Blob store compact işlemi yapın
- Log rotasyon yapılandırın

---

### v2.2 Spesifik Sorular

**S: API re-encryption neden 90 saniye bekliyor?**

**C**: Nexus'un tam olarak başlaması ve API'nin hazır olması için gereken süre. Daha kısa/uzun süre için `API_WAIT_TIME` değişkenini değiştirin.

---

**S: API re-encryption başarısız oldu, ne yapmalıyım?**

**C**: Manuel olarak çalıştırın:
```bash
ADMIN_PASS=$(sudo cat /app/data/nexus/sonatype-work/nexus3/admin.password)

curl -X 'PUT' \
  'http://localhost:8081/service/rest/v1/secrets/encryption/re-encrypt' \
  -u "admin:${ADMIN_PASS}" \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'NX-ANTI-CSRF-TOKEN: 0.6199265331343733' \
  -H 'X-Nexus-UI: true' \
  -d '{
  "secretKeyId": "alibaba33442",
  "notifyEmail": "string"
}'
```

---

**S: "Default Secret Encryption Key" uyarısı alıyorum**

**C**: 
1. custom-key.json dosyası var mı kontrol edin
2. nexus.secrets.file property tanımlı mı kontrol edin
3. API re-encryption yapıldı mı kontrol edin
4. Nexus'u yeniden başlatın

```bash
ls -la /app/nexus/etc/custom-key.json
grep "nexus.secrets.file" /app/nexus/etc/default-application.properties
sudo systemctl restart nexus
```

---

## 💾 Yedekleme ve Geri Yükleme

### Manuel Backup

#### 1. Database Backup

```bash
# Nexus'u durdurun
sudo systemctl stop nexus

# Database'i yedekleyin
sudo tar -czf /backup/nexus-db-$(date +%Y%m%d).tar.gz \
  /app/data/nexus/sonatype-work/nexus3/db

# Nexus'u başlatın
sudo systemctl start nexus
```

#### 2. Blob Store Backup

```bash
# Blob store'u yedekleyin (Nexus çalışırken yapılabilir)
sudo tar -czf /backup/nexus-blobs-$(date +%Y%m%d).tar.gz \
  /app/data/nexus/sonatype-work/nexus3/blobs
```

#### 3. Encryption Key Backup (🆕 v2.2)

```bash
# Custom key dosyasını yedekle
sudo cp /app/nexus/etc/custom-key.json \
  /backup/custom-key-$(date +%Y%m%d).json

# Otomatik oluşturulan backup'ı kopyala
sudo cp /root/nexus-encryption-key-*.txt /backup/

# Yapılandırma dosyalarını yedekle
sudo tar -czf /backup/nexus-config-$(date +%Y%m%d).tar.gz \
  /app/nexus/etc/custom-key.json \
  /app/nexus/etc/default-application.properties \
  /app/nexus/bin/nexus.vmoptions \
  /app/nexus/bin/nexus.rc \
  /etc/systemd/system/nexus.service
```

### Otomatik Backup Script (v2.2 Enhanced)

```bash
#!/bin/bash
# /usr/local/bin/nexus-backup.sh

BACKUP_DIR="/backup/nexus"
DATE=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS=30

# Backup dizinini oluştur
mkdir -p ${BACKUP_DIR}

# Database export (Nexus API kullanarak)
ADMIN_PASS=$(cat /app/data/nexus/sonatype-work/nexus3/admin.password 2>/dev/null)
if [ -n "$ADMIN_PASS" ]; then
    curl -u admin:${ADMIN_PASS} -X POST \
      "http://localhost:8081/service/rest/v1/tasks/run/db.backup"
fi

# Encryption key backup (v2.2)
cp /app/nexus/etc/custom-key.json \
  ${BACKUP_DIR}/custom-key-${DATE}.json 2>/dev/null

# Konfigürasyon backup
tar -czf ${BACKUP_DIR}/nexus-config-${DATE}.tar.gz \
  /app/nexus/etc \
  /app/nexus/bin/nexus.vmoptions \
  /etc/systemd/system/nexus.service 2>/dev/null

# Database backup
tar -czf ${BACKUP_DIR}/nexus-db-${DATE}.tar.gz \
  /app/data/nexus/sonatype-work/nexus3/db 2>/dev/null

# Eski backup'ları temizle
find ${BACKUP_DIR} -name "nexus-*" -mtime +${RETENTION_DAYS} -delete
find ${BACKUP_DIR} -name "custom-key-*" -mtime +${RETENTION_DAYS} -delete

echo "Backup completed: ${DATE}"
```

**Cron Job ile Otomatikleştirme:**

```bash
# Crontab'ı düzenle
sudo crontab -e

# Her gün saat 02:00'de backup al
0 2 * * * /usr/local/bin/nexus-backup.sh >> /var/log/nexus-backup.log 2>&1
```

### Geri Yükleme (Restore) - v2.2

#### 1. Database Restore

```bash
# Nexus'u durdurun
sudo systemctl stop nexus

# Mevcut database'i yedekleyin
sudo mv /app/data/nexus/sonatype-work/nexus3/db \
  /app/data/nexus/sonatype-work/nexus3/db.old

# Backup'tan geri yükleyin
sudo tar -xzf /backup/nexus-db-YYYYMMDD.tar.gz -C /

# İzinleri düzeltin
sudo chown -R nexus:nexus /app/data/nexus/sonatype-work/nexus3/db

# Nexus'u başlatın
sudo systemctl start nexus
```

#### 2. Encryption Key Restore (v2.2)

```bash
# Custom key'i geri yükle
sudo cp /backup/custom-key-YYYYMMDD.json \
  /app/nexus/etc/custom-key.json

# İzinleri ayarla
sudo chmod 600 /app/nexus/etc/custom-key.json
sudo chown nexus:nexus /app/nexus/etc/custom-key.json

# Property dosyasını kontrol et
grep "nexus.secrets.file" /app/nexus/etc/default-application.properties
```

#### 3. Disaster Recovery (Tam Sistem)

```bash
# 1. v2.2 Script ile Nexus'u kurun
sudo ./install-nexus.sh

# 2. Nexus'u durdurun
sudo systemctl stop nexus

# 3. Database ve blob store'u geri yükleyin
sudo tar -xzf /backup/nexus-db-YYYYMMDD.tar.gz -C /
sudo tar -xzf /backup/nexus-blobs-YYYYMMDD.tar.gz -C /

# 4. Custom key'i geri yükleyin (v2.2)
sudo cp /backup/custom-key-YYYYMMDD.json /app/nexus/etc/custom-key.json
sudo chmod 600 /app/nexus/etc/custom-key.json

# 5. Yapılandırmaları geri yükleyin
sudo tar -xzf /backup/nexus-config-YYYYMMDD.tar.gz -C /

# 6. İzinleri düzeltin
sudo chown -R nexus:nexus /app/nexus /app/data/nexus

# 7. Daemon reload
sudo systemctl daemon-reload

# 8. Nexus'u başlatın
sudo systemctl start nexus

# 9. Durumu kontrol edin
systemctl status nexus
curl -I http://localhost:8081
```

---

## 🗑️ Kaldırma

### Tam Kaldırma

```bash
#!/bin/bash
# nexus-uninstall.sh

echo "Nexus kaldırılıyor..."

# Servisi durdur ve devre dışı bırak
sudo systemctl stop nexus
sudo systemctl disable nexus

# Servis dosyasını sil
sudo rm -f /etc/systemd/system/nexus.service
sudo systemctl daemon-reload

# Firewall kuralını kaldır
sudo firewall-cmd --permanent --remove-port=8081/tcp
sudo firewall-cmd --reload

# Nexus kullanıcısını sil
sudo userdel -r nexus 2>/dev/null

# Kurulum dizinlerini sil
sudo rm -rf /app/nexus
sudo rm -rf /app/data/nexus-repo
sudo rm -rf /app/data/nexus

# Encryption key backup'larını sil (dikkatli!)
# sudo rm -f /root/nexus-encryption-key-*.txt
# sudo rm -f /backup/custom-key-*.json

# JDK'yı kaldırmak isterseniz (opsiyonel)
# sudo yum remove -y java-17-openjdk java-17-openjdk-devel

echo "Nexus başarıyla kaldırıldı."
```

### Kısmi Kaldırma (Sadece Uygulama)

```bash
# Data'yı koruyarak sadece uygulamayı sil
sudo systemctl stop nexus
sudo rm -rf /app/nexus

# Yeniden kurulum için
sudo ./install-nexus.sh
```

### Data Temizleme

```bash
# Tüm repository data'sını sil
sudo rm -rf /app/data/nexus-repo/*

# Sadece geçici dosyaları temizle
sudo rm -rf /app/data/nexus/sonatype-work/nexus3/tmp/*
sudo rm -rf /app/data/nexus/sonatype-work/nexus3/log/*.log.*
```

---

## 📊 Versiyon Geçmişi

### v2.2 (2025-11-19) - 🆕 CURRENT

**Yeni Özellikler:**
- ✅ Basitleştirilmiş `custom-key.json` formatı
- ✅ `nexus.secrets.file` property desteği
- ✅ Otomatik API re-encryption (90 saniye sonra)
- ✅ `SuccessExitStatus=143` ile düzeltilmiş systemd service
- ✅ Key ID: `alibaba33442` (sabit, özelleştirilebilir)
- ✅ Geliştirilmiş doğrulama mekanizması
- ✅ Detaylı güvenlik loglaması

**İyileştirmeler:**
- Systemd stop komutu artık "failed" göstermiyor
- Custom key dosyası daha basit ve anlaşılır
- API re-encryption otomatik yapılıyor
- Geri sayım göstergesi eklendi
- Manuel komut önerileri geliştirildi

**Düzeltilen Hatalar:**
- Exit code 143 artık başarılı sayılıyor
- Stop işlemi doğru çalışıyor
- Property dosyası tırnak hatasız

---

### v2.1 (2024)

**Yeni Özellikler:**
- ✅ Custom encryption key desteği
- ✅ "Default Secret Encryption Key" uyarısını önleme
- ✅ Detaylı güvenlik loglaması
- ✅ Encryption key backup'ı otomatik oluşturma
- ✅ Kurulum sonrası doğrulama testleri
- ✅ Geliştirilmiş tırnak kontrolü

**İyileştirmeler:**
- custom-encryption.json formatı
- Otomatik backup oluşturma
- JSON format doğrulama
- Verbose mode eklendi

---

### v2.0 (2024)

**Yeni Özellikler:**
- ✅ Kapsamlı hata kontrolü mekanizması
- ✅ İşletim sistemi uyumluluk kontrolü
- ✅ Disk alanı yönetimi ve kontrolleri
- ✅ Renkli ve kullanıcı dostu çıktılar
- ✅ Modüler fonksiyon yapısı
- ✅ Detaylı loglama ve hata mesajları
- ✅ Firewalld servisi kontrolü
- ✅ SELinux uyumluluğu

**İyileştirmeler:**
- Tüm kritik işlemlerde hata kontrolü
- Dosya indirme doğrulaması
- Boş dosya kontrolü
- Servis durum doğrulaması
- Otomatik offline kurulum desteği

**Desteklenen Sistemler:**
- Rocky Linux 9.x
- RHEL 9.x
- AlmaLinux 9.x
- CentOS Stream 9

---

### v1.0 (2023)

**Özellikler:**
- Temel Nexus kurulum işlevselliği
- JDK 17 kurulumu
- Systemd entegrasyonu
- Firewall yapılandırması
- Özel kullanıcı oluşturma

---

## 📞 Destek ve Katkıda Bulunma

### Sorun Bildirimi

Bir sorun yaşadıysanız:

1. **Log dosyalarını toplayın:**
```bash
# Systemd logları
sudo journalctl -u nexus > nexus-systemd.log

# Nexus logları
sudo cp /app/data/nexus/sonatype-work/nexus3/log/nexus.log ./
sudo cp /app/data/nexus/sonatype-work/nexus3/log/jvm.log ./

# Kurulum logu
sudo cp /var/log/nexus-installation-*.log ./
```

2. **Sistem bilgilerini toplayın:**
```bash
cat /etc/os-release > system-info.txt
df -h >> system-info.txt
free -h >> system-info.txt
uname -a >> system-info.txt
```

3. **v2.2 spesifik bilgiler:**
```bash
# Custom key durumu
ls -la /app/nexus/etc/custom-key.json >> system-info.txt
grep "nexus.secrets.file" /app/nexus/etc/default-application.properties >> system-info.txt

# Systemd service durumu
systemctl status nexus >> system-info.txt
```

4. Issue açın ve log dosyalarını ekleyin

### Katkıda Bulunma

1. Repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'i push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

### Test Checklist

PR açmadan önce:
- [ ] Rocky Linux 9.x üzerinde test edildi
- [ ] HTTP kurulum çalışıyor
- [ ] SSL kurulum çalışıyor (Let's Encrypt veya Self-Signed)
- [ ] Custom key oluşturuluyor
- [ ] API re-encryption çalışıyor
- [ ] Systemd stop düzgün çalışıyor (failed göstermiyor)
- [ ] Verbose mode çalışıyor
- [ ] Dokümantasyon güncellendi

---

## 📄 Lisans

Bu script MIT Lisansı altında dağıtılmaktadır.

## 🙏 Teşekkürler

- Sonatype ekibine Nexus Repository Manager için
- Rocky Linux topluluğuna
- Tüm katkıda bulunanlara
- Beta testerlar için

---

## 🔗 Faydalı Linkler

### Resmi Dokümantasyon

- [Nexus Repository Manager Documentation](https://help.sonatype.com/repomanager3)
- [Nexus Security Guide](https://help.sonatype.com/repomanager3/nexus-repository-administration/configuring-ssl)
- [Sonatype Learning](https://learn.sonatype.com/)
- [Nexus Repository Manager Downloads](https://www.sonatype.com/products/repository-oss-download)

### API Dokümantasyonu

- [Nexus REST API](https://help.sonatype.com/repomanager3/integrations/rest-and-integration-api)
- [Secrets Encryption API](https://help.sonatype.com/repomanager3/nexus-repository-administration/configuring-ssl#ConfiguringSSL-CustomSecretEncryption)

### Topluluk Kaynakları

- [Nexus Community](https://community.sonatype.com/)
- [Stack Overflow - Nexus Tag](https://stackoverflow.com/questions/tagged/nexus)
- [GitHub - Sonatype](https://github.com/sonatype)

### Security ve Best Practices

- [Repository Management Best Practices](https://www.sonatype.com/resources/repository-management-best-practices)
- [Nexus Security Best Practices](https://help.sonatype.com/repomanager3/planning-your-implementation/security-best-practices)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)

---

## 🎯 Hızlı Referans

### Önemli Komutlar

```bash
# Servis yönetimi
systemctl status nexus
systemctl start nexus
systemctl stop nexus
systemctl restart nexus
systemctl enable nexus
systemctl disable nexus

# Log görüntüleme
journalctl -u nexus -f
tail -f /app/data/nexus/sonatype-work/nexus3/log/nexus.log
tail -f /app/data/nexus/sonatype-work/nexus3/log/jvm.log

# Yapılandırma
nano /app/nexus/etc/default-application.properties
nano /app/nexus/bin/nexus.vmoptions
nano /etc/systemd/system/nexus.service

# v2.2 spesifik
cat /app/nexus/etc/custom-key.json
grep "nexus.secrets.file" /app/nexus/etc/default-application.properties
cat /root/nexus-encryption-key-*.txt
```

### Önemli Dosyalar

```
/app/nexus/etc/custom-key.json              # 🆕 v2.2 Encryption key
/app/nexus/etc/default-application.properties
/app/nexus/bin/nexus.vmoptions
/etc/systemd/system/nexus.service
/root/nexus-encryption-key-*.txt            # Backup
/app/data/nexus/sonatype-work/nexus3/admin.password
```

### Kurulum Kontrol Listesi

- [ ] Script çalıştırıldı ve başarıyla tamamlandı
- [ ] Servis çalışıyor (`systemctl status nexus`)
- [ ] Stop testi başarılı (failed göstermiyor)
- [ ] Web arayüzü erişilebilir
- [ ] Custom key dosyası mevcut
- [ ] nexus.secrets.file property tanımlı
- [ ] Admin şifresi değiştirildi
- [ ] Anonymous access yapılandırıldı
- [ ] Encryption key backup alındı
- [ ] API re-encryption yapıldı
- [ ] "Default Secret Encryption Key" uyarısı yok

---

**Son Güncelleme:** 19 Kasım 2025  
**Script Versiyonu:** 2.2  
**Nexus Versiyonu:** 3.86.2-01  
**Test Edildiği Sistem:** Rocky Linux 9.6 (Blue Onyx)

---

**Hazırlayan:** Enhanced Installation Script Team  
**Katkıda Bulunanlar:** Community Contributors  
**Lisans:** MIT License  
**Repository:** [https://github.com/remziakyuz/linux_sistem_yonetim_araclari/tree/main/bash_scriptleri/nexus_kurulumu]

---

**🎉 İyi kullanımlar! Happy Nexusing! 🚀**
