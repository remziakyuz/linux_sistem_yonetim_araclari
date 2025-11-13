# Nexus Repository Manager Kurulum Scripti

## 📋 İçindekiler

- [Genel Bakış](#genel-bakış)
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

## 🎯 Genel Bakış

Bu script, **Nexus Repository Manager 3.86.2-01** versiyonunu RHEL 9 tabanlı Linux dağıtımlarına otomatik olarak kurmak için geliştirilmiştir. Script, production ortamları için optimize edilmiş, kapsamlı hata kontrolü ve disk alanı yönetimi içeren profesyonel bir kurulum çözümüdür.

### Nexus Repository Manager Nedir?

Nexus Repository Manager, Maven, npm, Docker, PyPI ve diğer paket formatları için merkezi bir repository yönetim çözümüdür. Yazılım bileşenlerini saklamak, versiyon kontrolü yapmak ve organizasyonunuzda tekrar kullanılabilirliği artırmak için kullanılır.

## ✨ Özellikler

### Temel Özellikler

- ✅ **Otomatik Kurulum**: Tek komutla tam otomatik kurulum
- ✅ **JDK 17 Kurulumu**: Gerekli Java sürümünün otomatik kurulumu ve doğrulaması
- ✅ **Özel Kullanıcı**: Güvenlik için özel nexus kullanıcısı (UID: 30033, GID: 30033)
- ✅ **Systemd Entegrasyonu**: Otomatik başlatma ve servis yönetimi
- ✅ **Firewall Yapılandırması**: Port 8081 için otomatik firewall kuralı
- ✅ **Özelleştirilebilir Dizinler**: İhtiyaca göre dizin yapısı ayarlanabilir

### İyileştirilmiş Özellikler

#### 1. Kapsamlı Hata Kontrolü

- 🔍 **Dosya İndirme Kontrolü**: İndirme başarısız olursa anında algılama
- 🔍 **Dosya Varlık Kontrolü**: Tüm kritik dosyaların varlığı doğrulanır
- 🔍 **Komut Başarı Kontrolü**: Her komutun çıkış kodu kontrol edilir
- 🔍 **Boş Dosya Kontrolü**: İndirilen dosyaların içerik kontrolü
- 🔍 **Servis Durum Kontrolü**: Nexus servisinin doğru başlatıldığı doğrulanır

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

- 🎨 **Renkli Çıktılar**: Hata (kırmızı), başarı (yeşil), uyarı (sarı) mesajları
- 📊 **İlerleme Göstergeleri**: Her adımda detaylı bilgilendirme
- 📝 **Kurulum Özeti**: Kurulum sonunda tüm önemli bilgiler

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

### Yazılım Gereksinimleri

- Root erişimi
- İnternet bağlantısı (ilk kurulum için)
- curl (genellikle varsayılan olarak yüklü)
- tar (genellikle varsayılan olarak yüklü)
- systemd
- firewalld (opsiyonel)

## 💾 Disk Alanı Gereksinimleri

### Dizin Yapısı

```
/app/
├── nexus/                    # INSTALL_DIR (2 GB minimum)
│   ├── bin/
│   ├── etc/
│   ├── lib/
│   └── ...
└── data/
    ├── nexus-repo/          # REPO_DIR (10 GB minimum)
    └── nexus/
        └── sonatype-work/   # WORK_DIR (5 GB minimum)
            └── nexus3/      # DATA_DIR
                ├── log/
                ├── tmp/
                └── ...
```

### Depolama Planlaması

Repository boyutu, kullanım senaryonuza bağlı olarak hızla büyüyebilir:

- **Küçük Ekip** (5-10 geliştirici): 50-100 GB
- **Orta Ekip** (10-50 geliştirici): 200-500 GB
- **Büyük Ekip** (50+ geliştirici): 1+ TB

**Not**: Maven Central proxy kullanıyorsanız, disk alanı ihtiyacı çok daha hızlı artacaktır.

## 🔧 Kurulum Öncesi Hazırlık

### 1. Sistem Güncellemesi

```bash
sudo yum update -y
```

### 2. Gerekli Araçların Kontrolü

```bash
# curl kontrolü
curl --version

# tar kontrolü
tar --version

# systemctl kontrolü
systemctl --version
```

### 3. Disk Alanı Kontrolü

```bash
# Disk kullanımını görüntüle
df -h

# /app dizini için kullanılabilir alan
df -h /app
```

### 4. Port Kontrolü

```bash
# 8081 portunu kullanan süreç var mı kontrol et
sudo ss -tulpn | grep 8081
```

Port kullanımda ise, scriptteki `NEXUS_PORT` değişkenini değiştirin.

### 5. SELinux Kontrolü (Opsiyonel)

```bash
# SELinux durumunu kontrol et
sestatus

# Geçici olarak devre dışı bırak (gerekirse)
sudo setenforce 0
```

## 🚀 Hızlı Başlangıç

### Adım 1: Script'i İndirin

```bash
# Script'i indirin (örnek URL)
curl -O https://your-server.com/install-nexus-improved.sh

# veya wget kullanarak
wget https://your-server.com/install-nexus-improved.sh
```

### Adım 2: Çalıştırma İzni Verin

```bash
chmod +x install-nexus-improved.sh
```

### Adım 3: Script'i Çalıştırın

```bash
sudo ./install-nexus-improved.sh
```

### Adım 4: Kurulum Tamamlanmasını Bekleyin

Script otomatik olarak:
1. İşletim sistemini kontrol eder
2. Disk alanını kontrol eder
3. JDK 17'yi kurar
4. Nexus'u indirir ve kurar
5. Yapılandırmaları yapar
6. Servisi başlatır

### Adım 5: Nexus'a Erişin

```bash
# Kurulum sonunda gösterilen URL'yi kullanın
http://sunucu-ip-adresi:8081
```

## 📖 Detaylı Kullanım

### Özelleştirilmiş Kurulum

Script başındaki değişkenleri düzenleyerek kurulumu özelleştirebilirsiniz:

```bash
# Script'i düzenleyin
nano install-nexus-improved.sh
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

# Disk alanı gereksinimleri (MB)
MIN_INSTALL_SPACE=2048  # 2GB
MIN_REPO_SPACE=10240    # 10GB
MIN_WORK_SPACE=5120     # 5GB
```

### Offline Kurulum

İnternet bağlantısı olmayan sistemlerde:

1. Nexus tar dosyasını manuel olarak indirin:
```bash
curl -L -O https://cdn.download.sonatype.com/repository/downloads-prod-group/3/nexus-3.86.2-01-linux-x86_64.tar.gz
```

2. Tar dosyasını script ile aynı dizine koyun

3. Script'i normal şekilde çalıştırın

Script, mevcut tar dosyasını otomatik olarak algılayacak ve kullanacaktır.

### Sessiz Kurulum

Kurulum sırasında tüm çıktıları bir log dosyasına kaydetmek için:

```bash
sudo ./install-nexus-improved.sh 2>&1 | tee nexus-install.log
```

## ⚙️ Yapılandırma Detayları

### Nexus Yapılandırma Dosyaları

#### 1. nexus.rc
**Konum**: `/app/nexus/bin/nexus.rc`

```bash
run_as_user="nexus"
```

Bu dosya, Nexus'un hangi kullanıcı ile çalışacağını belirtir.

#### 2. nexus.vmoptions
**Konum**: `/app/nexus/bin/nexus.vmoptions`

JVM parametrelerini içerir:

```bash
-XX:LogFile=/app/data/nexus/sonatype-work/nexus3/log/jvm.log
-Dkaraf.data=/app/data/nexus/sonatype-work/nexus3
-Dkaraf.log=/app/data/nexus/sonatype-work/nexus3/log
-Djava.io.tmpdir=/app/data/nexus/sonatype-work/nexus3/tmp
```

**Bellek Ayarları** (opsiyonel olarak eklenebilir):

```bash
-Xms2G          # Minimum heap boyutu
-Xmx4G          # Maksimum heap boyutu
-XX:MaxDirectMemorySize=2G
```

#### 3. nexus-default.properties
**Konum**: `/app/nexus/etc/nexus-default.properties`

Nexus'un temel yapılandırma dosyası:

```properties
nexus-work=/app/data/nexus/sonatype-work
data-dir=/app/data/nexus/sonatype-work/nexus3
application-port=8081
```

### Systemd Servis Yapılandırması

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
ExecStart=/app/nexus/bin/nexus start
ExecStop=/app/nexus/bin/nexus stop
User=nexus
Restart=on-abort

[Install]
WantedBy=multi-user.target
```

### Firewall Yapılandırması

```bash
# Firewall kuralını görüntüle
sudo firewall-cmd --list-ports

# Kuralı manuel olarak ekle (script otomatik yapar)
sudo firewall-cmd --permanent --add-port=8081/tcp
sudo firewall-cmd --reload
```

## 🎓 Kurulum Sonrası İşlemler

### 1. İlk Giriş

1. Web tarayıcınızda Nexus'a erişin:
```
http://sunucu-ip-adresi:8081
```

2. Sağ üst köşedeki **Sign In** butonuna tıklayın

3. Varsayılan kullanıcı adı: `admin`

4. Şifreyi aşağıdaki dosyadan alın:
```bash
sudo cat /app/data/nexus/sonatype-work/nexus3/admin.password
```

### 2. İlk Kurulum Sihirbazı

İlk girişte karşınıza çıkacak adımlar:

1. **Şifre Değiştirme**: Yeni admin şifrenizi belirleyin
2. **Anonymous Access**: Anonim erişime izin vermek isteyip istemediğinizi seçin
   - Production ortamlar için: Devre dışı bırakın
   - Test ortamları için: İhtiyaca göre ayarlayın

### 3. İlk Repository Oluşturma

#### Maven Repository

1. **Settings** → **Repository** → **Repositories**
2. **Create repository** butonuna tıklayın
3. **maven2 (hosted)** seçin
4. Repository bilgilerini doldurun:
   - Name: `maven-releases`
   - Version policy: `Release`
   - Layout policy: `Strict`
   - Blob store: `default`

#### npm Repository

1. **Create repository** → **npm (hosted)**
2. Repository bilgilerini doldurun:
   - Name: `npm-private`
   - Blob store: `default`

#### Docker Repository

1. **Create repository** → **docker (hosted)**
2. Repository bilgilerini doldurun:
   - Name: `docker-private`
   - HTTP port: `8082`
   - Enable Docker V1 API: Hayır (güvenlik için)

**Not**: Docker için ek port açmanız gerekebilir:
```bash
sudo firewall-cmd --permanent --add-port=8082/tcp
sudo firewall-cmd --reload
```

### 4. LDAP/AD Entegrasyonu (Opsiyonel)

1. **Settings** → **Security** → **LDAP**
2. **Create connection** butonuna tıklayın
3. LDAP/AD bilgilerinizi girin
4. Bağlantıyı test edin
5. User ve Group mapping yapılandırmasını yapın

### 5. Backup Görevini Ayarlama

1. **Settings** → **System** → **Tasks**
2. **Create task** → **Admin - Export databases for backup**
3. Zamanlamayı ayarlayın (örn: Günlük 02:00)
4. Backup lokasyonunu belirleyin

### 6. Cleanup Policies

Disk alanını yönetmek için:

1. **Settings** → **Repository** → **Cleanup Policies**
2. **Create cleanup policy**
3. Kural tanımlayın:
   - Son kullanım: 30 gün
   - En son indirme: 90 gün

4. Policy'yi repository'lere uygulayın

## 🔍 Sorun Giderme

### Kurulum Sorunları

#### Sorun: "İşletim sistemi desteklenmiyor" Hatası

**Çözüm**:
```bash
# İşletim sisteminizi kontrol edin
cat /etc/os-release

# Eğer RHEL 9 tabanlı bir sistem kullanıyorsanız ancak hata alıyorsanız,
# script'teki check_os fonksiyonunu kontrol edin
```

#### Sorun: "Yetersiz Disk Alanı" Hatası

**Çözüm**:
```bash
# Disk kullanımını kontrol edin
df -h

# Gereksiz dosyaları temizleyin
sudo yum clean all

# Eski log dosyalarını temizleyin
sudo journalctl --vacuum-time=7d

# Daha fazla disk ekleyin veya script'teki dizin yollarını değiştirin
```

#### Sorun: "Nexus İndirilemedi" Hatası

**Çözüm**:
```bash
# İnternet bağlantınızı kontrol edin
ping -c 4 google.com

# Proxy ayarlarını kontrol edin
echo $http_proxy
echo $https_proxy

# Manuel indirmeyi deneyin
curl -L -O https://cdn.download.sonatype.com/repository/downloads-prod-group/3/nexus-3.86.2-01-linux-x86_64.tar.gz

# İndirilen dosyayı script ile aynı dizine koyun ve tekrar çalıştırın
```

#### Sorun: JDK Kurulum Hatası

**Çözüm**:
```bash
# Repository'leri güncelle
sudo yum clean all
sudo yum makecache

# Manuel JDK kurulumu
sudo yum install -y java-17-openjdk java-17-openjdk-devel

# Java versiyonunu kontrol et
java -version
```

### Servis Sorunları

#### Sorun: Nexus Başlamıyor

**Çözüm 1: Logları kontrol edin**
```bash
# Systemd logları
sudo journalctl -u nexus -f

# Nexus logları
sudo tail -f /app/data/nexus/sonatype-work/nexus3/log/nexus.log

# JVM logları
sudo tail -f /app/data/nexus/sonatype-work/nexus3/log/jvm.log
```

**Çözüm 2: Port kontrolü**
```bash
# 8081 portu kullanımda mı?
sudo ss -tulpn | grep 8081

# Eğer kullanımdaysa, süreci sonlandırın
sudo kill -9 $(sudo lsof -t -i:8081)
```

**Çözüm 3: Dosya izinlerini kontrol edin**
```bash
# Sahiplik kontrolü
ls -la /app/nexus
ls -la /app/data/nexus

# İzinleri düzelt
sudo chown -R nexus:nexus /app/nexus
sudo chown -R nexus:nexus /app/data/nexus
```

**Çözüm 4: Bellek sorunları**
```bash
# Sisteminizin bellek durumunu kontrol edin
free -h

# nexus.vmoptions dosyasındaki bellek ayarlarını azaltın
sudo nano /app/nexus/bin/nexus.vmoptions

# Örnek: -Xmx değerini düşürün
# -Xmx4G yerine -Xmx2G
```

#### Sorun: Nexus Yavaş Çalışıyor

**Çözüm**:
```bash
# 1. Bellek artırın (nexus.vmoptions)
sudo nano /app/nexus/bin/nexus.vmoptions

# Şu satırları ekleyin/güncelleyin:
-Xms4G
-Xmx8G
-XX:MaxDirectMemorySize=4G

# 2. Cleanup policy uygulayın (web arayüzünden)

# 3. Blob store compact işlemi yapın (web arayüzünden)

# 4. Servisi restart edin
sudo systemctl restart nexus
```

### Ağ Sorunları

#### Sorun: Nexus'a Dışarıdan Erişilemiyor

**Çözüm**:
```bash
# 1. Servis çalışıyor mu?
sudo systemctl status nexus

# 2. Port dinleniyor mu?
sudo ss -tulpn | grep 8081

# 3. Firewall açık mı?
sudo firewall-cmd --list-ports

# 4. Firewall kuralını ekle
sudo firewall-cmd --permanent --add-port=8081/tcp
sudo firewall-cmd --reload

# 5. SELinux kontrol
sudo setenforce 0  # Geçici olarak devre dışı bırak
# Eğer bu çözerse, SELinux policy'sini düzelt
```

#### Sorun: SSL/HTTPS Yapılandırması

**Çözüm**:
```bash
# Nginx kullanarak reverse proxy oluşturun

# 1. Nginx kurulumu
sudo yum install -y nginx

# 2. Nexus için yapılandırma
sudo nano /etc/nginx/conf.d/nexus.conf

# İçeriği:
server {
    listen 80;
    server_name nexus.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name nexus.example.com;

    ssl_certificate /etc/ssl/certs/nexus.crt;
    ssl_certificate_key /etc/ssl/private/nexus.key;

    location / {
        proxy_pass http://localhost:8081/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto "https";
    }
}

# 3. Nginx'i başlat
sudo systemctl enable nginx
sudo systemctl start nginx
```

### Database Sorunları

#### Sorun: OrientDB Bozulması

**Çözüm**:
```bash
# 1. Nexus'u durdur
sudo systemctl stop nexus

# 2. Database'i yedekle
sudo cp -r /app/data/nexus/sonatype-work/nexus3/db /backup/db-backup-$(date +%Y%m%d)

# 3. Database repair
cd /app/nexus/bin
sudo -u nexus ./nexus repair-orient

# 4. Nexus'u başlat
sudo systemctl start nexus
```

## 🔒 Güvenlik Notları

### Temel Güvenlik Önlemleri

#### 1. Varsayılan Şifreyi Değiştirin

İlk girişte admin şifresini mutlaka değiştirin ve güçlü bir şifre kullanın:
- Minimum 12 karakter
- Büyük/küçük harf, rakam ve özel karakter içermeli

#### 2. Anonymous Access'i Kapatın

Production ortamlarda anonim erişimi devre dışı bırakın:
```
Settings → Security → Anonymous Access → Disable
```

#### 3. HTTPS Kullanın

Reverse proxy (Nginx/Apache) ile HTTPS yapılandırması yapın.

#### 4. Firewall Kuralları

Sadece gerekli portları açın:
```bash
# Yalnızca belirli IP'lerden erişim
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port protocol="tcp" port="8081" accept'
sudo firewall-cmd --reload
```

#### 5. Regular Backup

Otomatik backup görevini mutlaka kurun ve test edin.

#### 6. Güvenlik Güncellemeleri

Nexus ve sistem güncellemelerini düzenli takip edin:
```bash
# Sistem güncellemeleri
sudo yum update -y

# Nexus güncellemeleri için Sonatype web sitesini takip edin
```

#### 7. Audit Logging

Tüm aktiviteleri loglamak için:
```
Settings → System → Capabilities → Audit
```

#### 8. Role-Based Access Control (RBAC)

Kullanıcılara sadece ihtiyaç duydukları yetkileri verin:
- Developer: Sadece okuma ve deploy yetkisi
- Build Server: Deploy yetkisi
- Admin: Tam yetki

### SELinux Yapılandırması

Production ortamlarda SELinux'u devre dışı bırakmak yerine doğru yapılandırın:

```bash
# SELinux context'leri ayarla
sudo semanage fcontext -a -t bin_t "/app/nexus/bin(/.*)?"
sudo restorecon -R /app/nexus/bin

sudo semanage fcontext -a -t usr_t "/app/nexus(/.*)?"
sudo restorecon -R /app/nexus

# Port etiketleme
sudo semanage port -a -t http_port_t -p tcp 8081
```

## ❓ Sık Sorulan Sorular

### Genel Sorular

**S: Nexus ne kadar RAM kullanır?**

**C**: Varsayılan olarak 2-4 GB arası. Kullanım senaryonuza göre artırabilirsiniz. nexus.vmoptions dosyasında -Xms ve -Xmx parametreleri ile ayarlayın.

---

**S: Birden fazla Nexus instance'ı aynı sunucuda çalışabilir mi?**

**C**: Evet, ancak her instance için farklı portlar ve dizinler kullanmanız gerekir. Script'i kopyalayıp değişkenleri düzenleyin.

---

**S: Nexus'u Docker container olarak çalıştırmalı mıyım?**

**C**: Her iki yöntem de geçerlidir. Bu script, bare-metal veya VM kurulumları için optimize edilmiştir. Docker daha kolay yönetim sunar, ancak daha fazla resource kullanabilir.

---

**S: Script Windows veya Mac'te çalışır mı?**

**C**: Hayır. Bu script RHEL 9 tabanlı Linux dağıtımları için tasarlanmıştır. Windows/Mac için Sonatype'ın resmi Docker image'ını kullanın.

---

### Kurulum Soruları

**S: Kurulum ne kadar sürer?**

**C**: İnternet hızınıza bağlı olarak 5-15 dakika arası. Offline kurulumda 2-5 dakika.

---

**S: Mevcut Nexus kurulumu üzerine çalıştırılabilir mi?**

**C**: Hayır, önce mevcut kurulumu temizlemeniz önerilir. Yoksa konflikt oluşabilir.

---

**S: Farklı bir Java versiyonu kullanabilir miyim?**

**C**: Nexus 3.x için JDK 8, 11 veya 17 kullanılabilir. Ancak JDK 17 önerilir ve script bu versiyonu kurar.

---

### Yapılandırma Soruları

**S: Nexus portunu nasıl değiştiririm?**

**C**: Script'teki NEXUS_PORT değişkenini düzenleyin. Ayrıca /app/nexus/etc/nexus-default.properties dosyasında da application-port değerini değiştirin.

---

**S: Nexus'u LDAP ile entegre edebilir miyim?**

**C**: Evet, web arayüzünden Settings → Security → LDAP bölümünden yapılandırabilirsiniz.

---

**S: Proxy arkasında nasıl çalışır?**

**C**: Settings → System → HTTP bölümünden HTTP ve HTTPS proxy ayarlarını yapın.

---

### Yedekleme ve Güvenlik

**S: Backup stratejisi nasıl olmalı?**

**C**: 
- Günlük: Database export task (export işlemi)
- Haftalık: Blob store backup
- Aylık: Full sistem snapshot

---

**S: Nexus şifresi kaybolursa ne yapmalıyım?**

**C**: 
1. Nexus'u durdurun
2. /app/data/nexus/sonatype-work/nexus3/admin.password dosyasını silin
3. Nexus'u başlatın
4. Bu dosya yeniden oluşacak ve içinde yeni şifre olacak

---

**S: SSL sertifikası nasıl eklerim?**

**C**: İki yöntem:
1. Reverse proxy (Nginx/Apache) kullanarak (önerilir)
2. Nexus'un kendi SSL yapılandırması (jetty-https.xml)

---

### Performans

**S: Nexus çok yavaş, ne yapmalıyım?**

**C**: 
1. RAM artırın (nexus.vmoptions)
2. Cleanup policy uygulayın
3. Blob store compact yapın
4. SSD kullanın

---

**S: Çok fazla disk alanı kullanıyor**

**C**: 
- Cleanup policies ayarlayın
- Proxy cache ayarlarını kontrol edin
- Gereksiz snapshot'ları temizleyin
- Blob store compact işlemi yapın

---

### Sorun Giderme

**S: "Out of Memory" hatası alıyorum**

**C**: nexus.vmoptions dosyasında heap boyutunu artırın:
```bash
-Xms4G
-Xmx8G
```

---

**S: Nexus başlamıyor, ne yapmalıyım?**

**C**: 
```bash
# Logları kontrol edin
sudo journalctl -u nexus -f
sudo tail -f /app/data/nexus/sonatype-work/nexus3/log/nexus.log

# Dosya izinlerini kontrol edin
ls -la /app/nexus
sudo chown -R nexus:nexus /app/nexus /app/data/nexus
```

---

**S: Repository'e artifact upload edemiyorum**

**C**: 
1. Kullanıcı yetkileri kontrol edin
2. Repository policy kontrol edin (Release/Snapshot)
3. Disk alanı kontrol edin
4. Nexus loglarını kontrol edin

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

#### 3. Yapılandırma Backup

```bash
# Yapılandırma dosyalarını yedekleyin
sudo tar -czf /backup/nexus-config-$(date +%Y%m%d).tar.gz \
  /app/nexus/etc \
  /app/nexus/bin/nexus.vmoptions \
  /app/nexus/bin/nexus.rc \
  /etc/systemd/system/nexus.service
```

### Otomatik Backup Script

```bash
#!/bin/bash
# /usr/local/bin/nexus-backup.sh

BACKUP_DIR="/backup/nexus"
DATE=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS=30

# Backup dizinini oluştur
mkdir -p ${BACKUP_DIR}

# Database export (Nexus API kullanarak)
curl -u admin:admin123 -X POST \
  "http://localhost:8081/service/rest/v1/tasks/run/db.backup"

# Konfigürasyon backup
tar -czf ${BACKUP_DIR}/nexus-config-${DATE}.tar.gz \
  /app/nexus/etc \
  /app/nexus/bin/nexus.vmoptions

# Eski backup'ları temizle
find ${BACKUP_DIR} -name "nexus-*" -mtime +${RETENTION_DAYS} -delete

echo "Backup completed: ${DATE}"
```

Cron job ile otomatikleştirin:

```bash
# Crontab'ı düzenle
sudo crontab -e

# Her gün saat 02:00'de backup al
0 2 * * * /usr/local/bin/nexus-backup.sh >> /var/log/nexus-backup.log 2>&1
```

### Geri Yükleme (Restore)

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

#### 2. Blob Store Restore

```bash
# Nexus'u durdurun (önerilir)
sudo systemctl stop nexus

# Blob store'u geri yükleyin
sudo tar -xzf /backup/nexus-blobs-YYYYMMDD.tar.gz -C /

# İzinleri düzeltin
sudo chown -R nexus:nexus /app/data/nexus/sonatype-work/nexus3/blobs

# Nexus'u başlatın
sudo systemctl start nexus
```

#### 3. Disaster Recovery

Tamamen yeni bir sunucuda geri yükleme:

```bash
# 1. Script ile Nexus'u kurun
sudo ./install-nexus-improved.sh

# 2. Nexus'u durdurun
sudo systemctl stop nexus

# 3. Database ve blob store'u geri yükleyin
sudo tar -xzf /backup/nexus-db-YYYYMMDD.tar.gz -C /
sudo tar -xzf /backup/nexus-blobs-YYYYMMDD.tar.gz -C /

# 4. Yapılandırmaları geri yükleyin
sudo tar -xzf /backup/nexus-config-YYYYMMDD.tar.gz -C /

# 5. İzinleri düzeltin
sudo chown -R nexus:nexus /app/nexus /app/data/nexus

# 6. Nexus'u başlatın
sudo systemctl start nexus
```

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

# JDK'yı kaldırmak isterseniz (opsiyonel)
# sudo yum remove -y java-17-openjdk java-17-openjdk-devel

echo "Nexus başarıyla kaldırıldı."
```

### Kısmi Kaldırma (Sadece Uygulama)

```bash
# Data'yı koruyarak sadece uygulamayı sil
sudo systemctl stop nexus
sudo rm -rf /app/nexus
```

### Data Temizleme

```bash
# Tüm repository data'sını sil
sudo rm -rf /app/data/nexus-repo/*

# Sadece geçici dosyaları temizle
sudo rm -rf /app/data/nexus/sonatype-work/nexus3/tmp/*
sudo rm -rf /app/data/nexus/sonatype-work/nexus3/log/*
```

## 📊 Versiyon Geçmişi

### v2.0.0 (Mevcut)
**Tarih**: 2024

**Yeni Özellikler**:
- ✅ Kapsamlı hata kontrolü mekanizması
- ✅ İşletim sistemi uyumluluk kontrolü
- ✅ Disk alanı yönetimi ve kontrolleri
- ✅ Renkli ve kullanıcı dostu çıktılar
- ✅ Modüler fonksiyon yapısı
- ✅ Detaylı loglama ve hata mesajları
- ✅ Firewalld servisi kontrolü
- ✅ SELinux uyumluluğu

**İyileştirmeler**:
- Tüm kritik işlemlerde hata kontrolü
- Dosya indirme doğrulaması
- Boş dosya kontrolü
- Servis durum doğrulaması
- Otomatik offline kurulum desteği

**Desteklenen Sistemler**:
- Rocky Linux 9.x
- RHEL 9.x
- AlmaLinux 9.x
- CentOS Stream 9

---

### v1.0.0 (Orijinal)
**Tarih**: 2023

**Özellikler**:
- Temel Nexus kurulum işlevselliği
- JDK 17 kurulumu
- Systemd entegrasyonu
- Firewall yapılandırması
- Özel kullanıcı oluşturma

---

## 📞 Destek ve Katkıda Bulunma

### Sorun Bildirimi

Bir sorun yaşadıysanız:

1. Log dosyalarını toplayın:
```bash
sudo journalctl -u nexus > nexus-systemd.log
sudo cp /app/data/nexus/sonatype-work/nexus3/log/nexus.log ./
sudo cp /app/data/nexus/sonatype-work/nexus3/log/jvm.log ./
```

2. Sistem bilgilerini toplayın:
```bash
cat /etc/os-release > system-info.txt
df -h >> system-info.txt
free -h >> system-info.txt
```

3. Issue açın ve log dosyalarını ekleyin

### Katkıda Bulunma

1. Repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'i push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

### İletişim

- 📧 Email: nexus-support@example.com
- 🌐 Website: https://example.com/nexus
- 📚 Dokümantasyon: https://docs.example.com/nexus

## 📄 Lisans

Bu script MIT Lisansı altında dağıtılmaktadır.

## 🙏 Teşekkürler

- Sonatype ekibine Nexus Repository Manager için
- Rocky Linux topluluğuna
- Tüm katkıda bulunanlara

## 🔗 Faydalı Linkler

### Resmi Dokümantasyon

- [Nexus Repository Manager Documentation](https://help.sonatype.com/repomanager3)
- [Sonatype Learning](https://learn.sonatype.com/)
- [Nexus Repository Manager Downloads](https://www.sonatype.com/products/repository-oss-download)

### Topluluk Kaynakları

- [Nexus Community](https://community.sonatype.com/)
- [Stack Overflow - Nexus Tag](https://stackoverflow.com/questions/tagged/nexus)
- [GitHub - Sonatype](https://github.com/sonatype)

### Security ve Best Practices

- [Nexus Security](https://help.sonatype.com/repomanager3/nexus-repository-administration/configuring-ssl)
- [Repository Management Best Practices](https://www.sonatype.com/resources/repository-management-best-practices)

---

**Son Güncelleme**: 2024  
**Script Versiyonu**: 2.0.0  
**Nexus Versiyonu**: 3.86.2-01  
**Test Edildiği Sistem**: Rocky Linux 9.6 (Blue Onyx)
