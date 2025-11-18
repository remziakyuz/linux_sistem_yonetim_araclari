# FİREWALLD ve DBUS
# OPERASYONEL DÖKÜMAN

**Mühendisler ve Mimarlar için Kapsamlı Teknik Referans**

---

## İçindekiler

1. [Firewalld Mimarisi](#1-firewalld-mimarisi)
2. [Firewall-cmd Detaylı Kullanım](#2-firewall-cmd-detayli-kullanim)
3. [Detaylı Örnekler ve Senaryolar](#3-detayli-ornekler-ve-senaryolar)
4. [Performans Optimizasyonu ve Tuning](#4-performans-optimizasyonu-ve-tuning)
5. [DBus Mimarisi ve Entegrasyon](#5-dbus-mimarisi-ve-entegrasyon)
6. [İleri Seviye Konular](#6-ileri-seviye-konular)
7. [Gerçek Dünya Senaryoları](#7-gercek-dunya-senaryolari)
8. [Sorun Giderme ve Debug](#8-sorun-giderme-ve-debug)
9. [Referans ve Hızlı Erişim](#9-referans-ve-hizli-erisim)

---

## 1. FİREWALLD MİMARİSİ

### 1.1 Genel Bakış ve Temel Kavramlar

Firewalld, Linux sistemlerde dinamik güvenlik duvarı yönetimi sağlayan bir servistir. Iptables/nftables'ın üzerine inşa edilmiş, kullanıcı dostu bir arayüz sunar ve mevcut bağlantıları kesmeden kural değişikliği yapılmasına olanak tanır.

#### Firewalld'nin Temel Özellikleri

- **Dinamik Kural Yönetimi**: Servis yeniden başlatılmadan kural değişikliği
- **Zone Tabanlı Yönetim**: Ağ arayüzlerini güvenlik bölgelerine atama
- **DBus API**: Programatik erişim ve otomatik yapılandırma
- **Runtime ve Permanent Kurallar**: Geçici ve kalıcı konfigürasyon
- **Rich Rules**: Gelişmiş ve esnek kural tanımlama
- **ipset Desteği**: Yüksek performanslı IP listesi yönetimi

### 1.2 Mimari Bileşenler

#### 1.2.1 Katman Yapısı

| Katman | Açıklama |
|--------|----------|
| **Kullanıcı Katmanı** | firewall-cmd, firewall-config, firewall-applet |
| **DBus Katmanı** | org.fedoraproject.FirewallD1 - IPC ve API erişim noktası |
| **Daemon Katmanı** | firewalld daemon - Kural yönetimi ve çeviri mantığı |
| **Backend Katmanı** | nftables/iptables - Kernel-level paket filtreleme |

#### 1.2.2 Zone (Güvenlik Bölgeleri)

Zone'lar, ağ arayüzlerini ve bağlantıları güvenlik seviyelerine göre gruplandırır. Her zone farklı güvenlik politikalarına sahiptir.

| Zone | Kullanım Amacı ve Özellikler |
|------|------------------------------|
| **drop** | En kısıtlayıcı. Tüm gelen paketler reddedilir, cevap verilmez. Sadece giden bağlantılara izin verilir. |
| **block** | Gelen paketler reddedilir ancak icmp-host-prohibited mesajı ile yanıt verilir. |
| **public** | Varsayılan zone. Güvensiz ağlar için. Seçili servislere izin verilir (ssh, dhcpv6-client). |
| **external** | Masquerading aktif. Router yapılandırması için uygun. |
| **dmz** | DMZ bölgesi için. Sınırlı servislere erişim (genelde ssh). |
| **work** | İş ortamı için. Güvenilir ağ ile çalışma senaryoları. |
| **home** | Ev ağı için. Daha fazla servise izin verilir. |
| **internal** | İç ağ için. Güvenilir sistemler arasında. |
| **trusted** | En az kısıtlayıcı. Tüm bağlantılara izin verilir. |

### 1.3 Çalışma Akışı

Firewalld, paket akışını şu adımlarla işler:

1. **Paket Alımı**: Ağ arayüzüne gelen paket kernel tarafından yakalanır
2. **Zone Belirleme**: Kaynak IP ve interface bilgisine göre ilgili zone belirlenir
3. **Kural Kontrolü**: Zone'un kuralları sırasıyla kontrol edilir (service, port, source, rich rules)
4. **Karar Verme**: Eşleşen kural bulunursa aksiyon alınır (accept/reject/drop)
5. **Backend Uygulaması**: Karar nftables/iptables kurallarına çevrilerek kernel'de uygulanır

```
[Paket Gelişi] → [Zone Seçimi] → [Kural Kontrolü] → [Karar] → [Backend]
     eth0            public          rich rules        ACCEPT    nftables
```

---

## 2. FIREWALL-CMD DETAYLI KULLANIM

### 2.1 Temel Komutlar

#### 2.1.1 Durum Kontrol Komutları

```bash
# Firewalld durumunu kontrol et
firewall-cmd --state

# Varsayılan zone'u göster
firewall-cmd --get-default-zone

# Aktif zone'ları listele
firewall-cmd --get-active-zones

# Tüm zone'ları listele
firewall-cmd --get-zones

# Belirli zone'un detaylarını göster
firewall-cmd --zone=public --list-all

# Tüm zone'ların detaylarını göster
firewall-cmd --list-all-zones
```

#### 2.1.2 Runtime vs Permanent Kurallar

Firewalld'de iki tip konfigürasyon vardır:

- **Runtime**: Anında etkili olur ancak reload veya restart sonrası kaybolur
- **Permanent**: Kalıcı olarak kaydedilir, --reload ile aktif edilir

```bash
# Runtime kural ekleme (geçici)
firewall-cmd --zone=public --add-service=http

# Permanent kural ekleme (kalıcı)
firewall-cmd --permanent --zone=public --add-service=http

# Permanent kuralları runtime'a yükle
firewall-cmd --reload

# Runtime kuralları permanent yap
firewall-cmd --runtime-to-permanent
```

### 2.2 Zone Yönetimi

#### 2.2.1 Zone Oluşturma ve Yapılandırma

```bash
# Yeni zone oluştur
firewall-cmd --permanent --new-zone=webservers

# Zone'a açıklama ekle
firewall-cmd --permanent --zone=webservers --set-description='Web Sunucuları için Zone'

# Zone'un hedef politikasını ayarla
firewall-cmd --permanent --zone=webservers --set-target=DROP
# Target değerleri: default, ACCEPT, REJECT, DROP

# Interface'i zone'a ata
firewall-cmd --zone=webservers --add-interface=eth1

# Interface'i zone'dan çıkar
firewall-cmd --zone=webservers --remove-interface=eth1

# Interface'in zone'unu değiştir
firewall-cmd --zone=dmz --change-interface=eth1

# Varsayılan zone'u değiştir
firewall-cmd --set-default-zone=dmz
```

#### 2.2.2 Source Bazlı Zone Yönetimi

Kaynak IP adreslerine göre zone ataması yapılabilir. Bu özellik özellikle multi-tenant ortamlarda veya ağ segmentasyonunda kritik öneme sahiptir.

```bash
# Belirli IP'yi zone'a ekle
firewall-cmd --zone=trusted --add-source=192.168.1.100

# IP bloğunu zone'a ekle
firewall-cmd --zone=internal --add-source=10.0.0.0/8

# Zone'daki source'ları listele
firewall-cmd --zone=trusted --list-sources

# Source'u zone'dan kaldır
firewall-cmd --zone=trusted --remove-source=192.168.1.100
```

---

## 3. DETAYLI ÖRNEKLER VE SENARYOLAR

### 3.1 Servis ve Port Yönetimi

#### 3.1.1 Temel Servis İşlemleri

```bash
# Mevcut servisleri listele
firewall-cmd --get-services

# Zone'a servis ekle
firewall-cmd --zone=public --add-service=http

# Birden fazla servis ekle
firewall-cmd --zone=public --add-service={http,https,ssh}

# Servis detaylarını görüntüle
firewall-cmd --info-service=http

# Servisi kaldır
firewall-cmd --zone=public --remove-service=http
```

#### 3.1.2 Port Yönetimi

```bash
# Tek port ekle
firewall-cmd --zone=public --add-port=8080/tcp

# Port aralığı ekle
firewall-cmd --zone=public --add-port=5000-5100/tcp

# Birden fazla port ekle
firewall-cmd --zone=public --add-port={8080/tcp,8443/tcp,9000/udp}

# Port'u kaldır
firewall-cmd --zone=public --remove-port=8080/tcp

# Zone'daki portları listele
firewall-cmd --zone=public --list-ports
```

#### 3.1.3 Özel Servis Tanımlama

```bash
# Yeni servis oluştur
firewall-cmd --permanent --new-service=myapp

# Servis açıklaması ekle
firewall-cmd --permanent --service=myapp --set-description='Özel Uygulama Servisi'

# Servis kısa adı ekle
firewall-cmd --permanent --service=myapp --set-short='MyApp'

# Servise port ekle
firewall-cmd --permanent --service=myapp --add-port=8888/tcp

# Servise protokol ekle
firewall-cmd --permanent --service=myapp --add-protocol=esp

# Servisi aktif et
firewall-cmd --reload
firewall-cmd --zone=public --add-service=myapp
```

### 3.2 Rich Rules (Zengin Kurallar)

Rich rules, firewalld'nin en güçlü özelliğidir ve karmaşık senaryolar için esneklik sağlar. Source, destination, port, protocol, service ve logging gibi birçok parametreyi birleştirir.

#### 3.2.1 Temel Rich Rule Yapısı

```bash
rule family="ipv4|ipv6"
  [source address="IP/CIDR" [invert="true"]]
  [destination address="IP/CIDR" [invert="true"]]
  [service name="SERVICE"] | [port port="PORT" protocol="tcp|udp"]
  [log [prefix="TEXT"] [level="LEVEL"] [limit value="RATE"]]
  [audit]
  accept|reject|drop
```

#### 3.2.2 Source Bazlı Kurallar

```bash
# Belirli IP'den gelen SSH bağlantılarını kabul et
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" 
  source address="192.168.1.100" service name="ssh" accept'

# Belirli subnet'ten gelen trafiği engelle
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" 
  source address="10.10.10.0/24" reject'

# Belirli IP hariç herkesi engelle
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" 
  source address="192.168.1.100" invert="true" drop'
```

#### 3.2.3 Port ve Protokol Bazlı Kurallar

```bash
# Belirli kaynak ve porta izin ver
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" 
  source address="192.168.1.0/24" port port="8080" protocol="tcp" accept'

# Port aralığı için kural
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" 
  source address="10.0.0.0/8" port port="5000-5100" protocol="tcp" accept'

# UDP protokolü ile çalışan özel port
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" 
  port port="9000" protocol="udp" accept'
```

#### 3.2.4 Logging ve Audit

```bash
# Belirli kaynaktan gelen trafiği logla ve kabul et
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" 
  source address="192.168.1.0/24" service name="http" 
  log prefix="HTTP-ACCESS: " level="info" limit value="10/m" accept'

# Reddedilen paketleri logla
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" 
  source address="10.10.10.0/24" 
  log prefix="BLOCKED: " level="warning" reject'

# Audit log ile güvenlik izleme
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" 
  source address="172.16.0.0/12" service name="ssh" 
  audit limit value="5/m" accept'
```

#### 3.2.5 Rate Limiting (Hız Sınırlama)

```bash
# SSH brute force saldırılarını önle (dakikada 5 bağlantı)
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" 
  service name="ssh" limit value="5/m" accept'

# HTTP isteklerini sınırla (saniyede 100 istek)
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" 
  service name="http" limit value="100/s" accept'
```

### 3.3 NAT (Network Address Translation) İşlemleri

NAT, IP adres çevirimi yaparak farklı ağlar arasında iletişim sağlar. Firewalld, SNAT, DNAT, masquerading ve port forwarding gibi NAT tekniklerini destekler.

#### 3.3.1 Masquerading (IP Maskeleme)

Masquerading, iç ağdan çıkan paketlerin kaynak IP adresini gateway'in dış IP'sine çeviren özel bir SNAT türüdür. Dinamik IP adresleri için idealdir.

```bash
# Zone'da masquerading'i etkinleştir
firewall-cmd --zone=external --add-masquerade

# Masquerading durumunu kontrol et
firewall-cmd --zone=external --query-masquerade

# Masquerading'i kaldır
firewall-cmd --zone=external --remove-masquerade
```

**Pratik Senaryo: Internet Paylaşımı**

```bash
# eth0: WAN (İnternet bağlantısı)
# eth1: LAN (İç ağ - 192.168.1.0/24)

# External zone'u eth0'a ata
firewall-cmd --zone=external --change-interface=eth0

# Internal zone'u eth1'e ata
firewall-cmd --zone=internal --change-interface=eth1

# Masquerading'i etkinleştir
firewall-cmd --zone=external --add-masquerade

# IP forwarding'i etkinleştir (kernel parameter)
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Kuralları kalıcı yap
firewall-cmd --runtime-to-permanent
```

#### 3.3.2 Port Forwarding (Port Yönlendirme)

Port forwarding, dış ağdan gelen belirli bir porta yapılan istekleri iç ağdaki farklı bir IP ve porta yönlendirir.

```bash
# Temel port forwarding
firewall-cmd --zone=external --add-forward-port=port=80:proto=tcp:toport=8080

# Farklı IP'ye port forwarding
firewall-cmd --zone=external --add-forward-port=port=443:proto=tcp:toaddr=192.168.1.10:toport=443

# Port forwarding'i listele
firewall-cmd --zone=external --list-forward-ports
```

**Pratik Senaryo: Web Sunucusu Yönlendirme**

```bash
# Public IP: 203.0.113.50
# İç Web Server: 192.168.1.10

# Masquerading aktif olmalı
firewall-cmd --zone=external --add-masquerade --permanent

# HTTP trafiğini yönlendir
firewall-cmd --zone=external --permanent \
  --add-forward-port=port=80:proto=tcp:toaddr=192.168.1.10:toport=80

# HTTPS trafiğini yönlendir
firewall-cmd --zone=external --permanent \
  --add-forward-port=port=443:proto=tcp:toaddr=192.168.1.10:toport=443

firewall-cmd --reload
```

#### 3.3.3 SNAT (Source NAT) ile Rich Rules

SNAT, kaynak IP adresini değiştirir. Masquerading'den farkı, statik bir IP adresine çevirmesidir.

```bash
# Belirli subnet'ten çıkan trafiğin kaynak IP'sini değiştir
firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 \
  -s 192.168.1.0/24 -o eth0 -j SNAT --to-source 203.0.113.50

# Rich rule ile SNAT
firewall-cmd --permanent --zone=external --add-rich-rule='
  rule family="ipv4"
  source address="192.168.1.0/24"
  forward-port port="80" protocol="tcp" to-port="8080" to-addr="10.0.0.5"'
```

#### 3.3.4 DNAT (Destination NAT) ile Rich Rules

DNAT, hedef IP adresini değiştirir. Port forwarding'in daha gelişmiş versiyonudur.

```bash
# Direct rule ile DNAT
firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 \
  -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.10:80

# Belirli kaynaktan gelen DNAT
firewall-cmd --permanent --direct --add-rule ipv4 nat PREROUTING 0 \
  -s 10.0.0.0/8 -p tcp --dport 3306 -j DNAT --to-destination 192.168.1.20:3306
```

**Kompleks NAT Senaryosu: Multi-Tier Uygulama**

```bash
# Mimari:
# - Public IP: 203.0.113.50 (eth0)
# - Web Server: 192.168.1.10 (eth1)
# - App Server: 192.168.1.20 (eth1)
# - DB Server: 192.168.1.30 (eth1)

# 1. Masquerading için gerekli
firewall-cmd --permanent --zone=external --add-masquerade

# 2. HTTP/HTTPS -> Web Server
firewall-cmd --permanent --zone=external \
  --add-forward-port=port=80:proto=tcp:toaddr=192.168.1.10:toport=80
firewall-cmd --permanent --zone=external \
  --add-forward-port=port=443:proto=tcp:toaddr=192.168.1.10:toport=443

# 3. Sadece Web Server'dan App Server'a erişim
firewall-cmd --permanent --zone=internal --add-rich-rule='
  rule family="ipv4"
  source address="192.168.1.10"
  destination address="192.168.1.20"
  port port="8080" protocol="tcp" accept'

# 4. Sadece App Server'dan DB'ye erişim
firewall-cmd --permanent --zone=internal --add-rich-rule='
  rule family="ipv4"
  source address="192.168.1.20"
  destination address="192.168.1.30"
  port port="3306" protocol="tcp" accept'

firewall-cmd --reload
```

### 3.4 IPSet Kullanımı (Yüksek Performanslı IP Listeleri)

IPSet, büyük miktarda IP adresini veya ağı yönetmek için kernel-level bir mekanizmadır. Binlerce kural yerine tek bir kural ile yüksek performans sağlar. Hash tabanlı yapısı sayesinde O(1) zaman karmaşıklığı ile arama yapar.

#### 3.4.1 IPSet Temelleri

```bash
# IPSet yüklü mü kontrol et
ipset --version
yum install ipset -y  # Yoksa yükle

# Yeni ipset oluştur (IP adresleri için)
ipset create blacklist hash:ip

# IP ekle
ipset add blacklist 192.168.1.100
ipset add blacklist 10.0.0.50

# IPSet'i listele
ipset list blacklist

# IP sil
ipset del blacklist 192.168.1.100

# IPSet'i tamamen sil
ipset destroy blacklist
```

#### 3.4.2 IPSet Türleri

| IPSet Türü | Açıklama ve Kullanım |
|------------|----------------------|
| **hash:ip** | Tek IP adresleri için. Örnek: 192.168.1.1 |
| **hash:net** | Network/CIDR blokları için. Örnek: 192.168.1.0/24 |
| **hash:ip,port** | IP ve port kombinasyonu. Örnek: 192.168.1.1,80 |
| **hash:net,port** | Network ve port kombinasyonu. Örnek: 192.168.1.0/24,tcp:80 |
| **hash:ip,port,ip** | Kaynak IP, port, hedef IP kombinasyonu |

#### 3.4.3 Firewalld ile IPSet Entegrasyonu

```bash
# Firewalld için ipset oluştur
firewall-cmd --permanent --new-ipset=blacklist --type=hash:ip
firewall-cmd --reload

# IPSet'e entry ekle
firewall-cmd --permanent --ipset=blacklist --add-entry=192.168.1.100
firewall-cmd --permanent --ipset=blacklist --add-entry=10.0.0.0/8
firewall-cmd --reload

# IPSet'teki IP'leri engelle
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source ipset="blacklist"
  drop'
firewall-cmd --reload

# IPSet'leri listele
firewall-cmd --permanent --get-ipsets

# IPSet içeriğini görüntüle
firewall-cmd --permanent --ipset=blacklist --get-entries
```

**Pratik Senaryo: Bulk IP Bloklama**

```bash
# 1. Kara liste ipset'i oluştur
firewall-cmd --permanent --new-ipset=blacklist --type=hash:net

# 2. Toplu IP ekleme için script
cat << 'EOF' > /tmp/add_blacklist.sh
#!/bin/bash
while read ip; do
  firewall-cmd --permanent --ipset=blacklist --add-entry="$ip"
done < blacklist.txt
firewall-cmd --reload
EOF

# 3. Blacklist dosyası oluştur
cat << EOF > /tmp/blacklist.txt
192.168.1.100
10.10.10.0/24
172.16.5.50
203.0.113.0/24
EOF

# 4. Script'i çalıştır
bash /tmp/add_blacklist.sh

# 5. IPSet'i kullanarak engelle
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4" source ipset="blacklist" drop'
firewall-cmd --reload
```

#### 3.4.4 Dinamik IPSet Güncellemeleri

```bash
# Runtime ipset güncelleme (firewalld reload'a gerek yok)
ipset add blacklist 192.168.50.25
ipset del blacklist 192.168.1.100

# Permanent ipset için
firewall-cmd --permanent --ipset=blacklist --add-entry=192.168.50.25
firewall-cmd --permanent --ipset=blacklist --remove-entry=192.168.1.100

# Timeout ile geçici ekleme (3600 saniye = 1 saat)
ipset add blacklist 192.168.99.99 timeout 3600
```

### 3.5 GeoIP ile Coğrafi Konum Bazlı Filtreleme

GeoIP, IP adreslerini coğrafi konumlara göre sınıflandırarak ülke bazında erişim kontrolü yapılmasına olanak tanır. Özellikle DDoS saldırıları ve coğrafi kısıtlamalar için kritik önem taşır.

#### 3.5.1 GeoIP Kurulumu

```bash
# GeoIP veritabanı ve araçları yükle (RHEL/CentOS)
yum install -y geoipupdate xtables-addons

# MaxMind hesabı oluştur ve lisans anahtarı al
# https://www.maxmind.com/en/geolite2/signup

# GeoIP yapılandırması
cat << EOF > /etc/GeoIP.conf
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-Country GeoLite2-City
DatabaseDirectory /usr/share/GeoIP
EOF

# Veritabanını güncelle
geoipupdate

# Otomatik güncelleme için cron
echo '0 2 * * 3 /usr/bin/geoipupdate' >> /etc/crontab
```

#### 3.5.2 GeoIP IPSet Oluşturma

```bash
# Script: Ülke bazında IPSet oluşturma
cat << 'EOF' > /usr/local/bin/create_geoip_ipset.sh
#!/bin/bash

COUNTRY_CODE="$1"
IPSET_NAME="geoip-${COUNTRY_CODE}"

# IPSet oluştur
ipset create $IPSET_NAME hash:net family inet hashsize 4096 maxelem 65536

# GitHub'dan ülke IP listesini al (alternatif kaynak)
wget -q "https://github.com/herrbischoff/country-ip-blocks/raw/master/ipv4/${COUNTRY_CODE}.cidr" -O "/tmp/${COUNTRY_CODE}.cidr"

# firewalld'ye ekle
firewall-cmd --permanent --new-ipset=$IPSET_NAME --type=hash:net
firewall-cmd --permanent --ipset=$IPSET_NAME --add-entries-from-file="/tmp/${COUNTRY_CODE}.cidr"
firewall-cmd --reload

echo "IPSet $IPSET_NAME oluşturuldu"
EOF

chmod +x /usr/local/bin/create_geoip_ipset.sh
```

**Pratik Senaryo: Belirli Ülkeleri Engelleme**

```bash
# 1. Çin (CN) ve Rusya (RU) için IPSet oluştur
/usr/local/bin/create_geoip_ipset.sh CN
/usr/local/bin/create_geoip_ipset.sh RU

# 2. Bu ülkelerden gelen trafiği engelle
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4" source ipset="geoip-CN" drop'

firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4" source ipset="geoip-RU" drop'

# 3. Loglamayı etkinleştir
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4" source ipset="geoip-CN"
  log prefix="GEOBLOCK-CN: " level="info" limit value="10/m" drop'

firewall-cmd --reload
```

#### 3.5.3 Whitelist Yaklaşımı (Sadece İzin Verilen Ülkeler)

```bash
# Sadece Türkiye (TR) ve ABD (US)'den erişime izin ver

# 1. Whitelist ipset'leri oluştur
/usr/local/bin/create_geoip_ipset.sh TR
/usr/local/bin/create_geoip_ipset.sh US

# 2. Zone hedefini DROP yap
firewall-cmd --permanent --zone=public --set-target=DROP

# 3. Sadece whitelist ülkelerden gelen trafiğe izin ver
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4" source ipset="geoip-TR" accept'

firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4" source ipset="geoip-US" accept'

firewall-cmd --reload
```

#### 3.5.4 Servis Bazlı GeoIP Filtreleme

```bash
# SSH'a sadece Türkiye'den erişim
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source ipset="geoip-TR"
  service name="ssh" accept'

# Web servislerine global erişim, ancak admin paneline sadece TR
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https

firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source ipset="geoip-TR"
  destination address="203.0.113.50"
  port port="8443" protocol="tcp" accept'

firewall-cmd --reload
```

---

## 4. PERFORMANS OPTİMİZASYONU VE TUNING

### 4.1 Firewalld Backend Seçimi

Firewalld iki farklı backend kullanabilir: iptables ve nftables. Nftables, daha yeni ve performanslı bir alternatiftir.

#### Backend Karşılaştırma

| Özellik | iptables | nftables |
|---------|----------|----------|
| **Performans** | Doğrusal arama O(n) | Set/Map yapısı, daha hızlı |
| **Atomik İşlem** | Hayır - Tüm kurallar reload | Evet - Tek kural güncellenebilir |
| **Büyük Kural Seti** | Yavaş reload (10000+ kural) | Hızlı, ölçeklenebilir |
| **Önerilen** | Eski sistemler için | Yeni sistemler için (RHEL 8+) |

#### nftables'a Geçiş

```bash
# Mevcut backend'i kontrol et
firewall-cmd --get-backend

# nftables'a geçiş
# /etc/firewalld/firewalld.conf dosyasını düzenle
sed -i 's/^FirewallBackend=.*/FirewallBackend=nftables/' /etc/firewalld/firewalld.conf

# Firewalld'yi yeniden başlat
systemctl restart firewalld

# Backend'i kontrol et
firewall-cmd --get-backend
```

### 4.2 Kural Optimizasyonu Stratejileri

#### 4.2.1 Kural Sıralamasının Önemi

Firewalld kuralları sırayla işlenir. En sık eşleşen kuralların başta olması performansı artırır.

- **Sık Kullanılan Kurallar**: En çok kullanılan servislerin kuralları ilk sırada
- **Spesifik Kurallar**: Genel kurallardan önce spesifik kurallar
- **Drop Kuralları**: Engelleme kuralları accept kurallarından önce

#### 4.2.2 IPSet Kullanımı (Binlerce IP için)

Çok sayıda IP adresi için IPSet kullanımı kritik performans artışı sağlar:

```bash
# KÖTÜ ÖRNEK: Her IP için ayrı kural (1000 IP = 1000 kural)
for ip in $(cat blacklist.txt); do
  firewall-cmd --zone=public --add-rich-rule="rule source address=$ip drop"
done
# Sonuç: Yavaş işlem, yüksek memory kullanımı

# İYİ ÖRNEK: IPSet kullanımı (1000 IP = 1 kural)
firewall-cmd --permanent --new-ipset=blacklist --type=hash:net
for ip in $(cat blacklist.txt); do
  firewall-cmd --permanent --ipset=blacklist --add-entry=$ip
done
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule source ipset="blacklist" drop'
firewall-cmd --reload
# Sonuç: Hızlı işlem, düşük memory
```

#### 4.2.3 Kural Sayısı Performans Etkisi

| Kural Sayısı | Reload Süresi | Memory | Öneri |
|--------------|---------------|---------|-------|
| < 100 | < 1 saniye | Minimal | Herhangi bir yöntem |
| 100-1000 | 1-3 saniye | Orta | IPSet tercih et |
| 1000-10000 | 5-30 saniye | Yüksek | IPSet zorunlu |
| > 10000 | > 1 dakika | Çok yüksek | IPSet+nftables |

### 4.3 Kernel Parametreleri

```bash
# /etc/sysctl.d/99-firewall-hardening.conf

# IP Forwarding (router senaryoları için)
net.ipv4.ip_forward = 1

# SYN flood koruması
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2

# IP spoofing koruması
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ICMP redirect kabul etme
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# Source routing devre dışı
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# ICMP broadcast koruması
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Connection tracking tablosu boyutu
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# TCP/IP stack tuning
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Buffer boyutları
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Uygula
sysctl -p /etc/sysctl.d/99-firewall-hardening.conf
```

### 4.4 Performans Monitoring

```bash
# Aktif bağlantı sayısı
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max

# Connection tracking tablosunu görüntüle
conntrack -L | wc -l
conntrack -L -o extended | head -20

# Tablo doluluk oranı
COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
USAGE=$((COUNT * 100 / MAX))
echo "Connection tracking usage: $USAGE%"

# Eğer %80'in üzerindeyse max değeri artır
if [ $USAGE -gt 80 ]; then
  echo 'net.netfilter.nf_conntrack_max=262144' >> /etc/sysctl.conf
  sysctl -p
fi

# Firewall reload süresi ölç
time firewall-cmd --reload

# Aktif kural sayısı
firewall-cmd --list-all-zones | grep -c 'rule\|port\|service'
```

---

## 5. DBUS MİMARİSİ VE ENTEGRASYON

### 5.1 DBus Nedir ve Neden Önemlidir?

DBus (Desktop Bus), Linux sistemlerde süreçler arası iletişim (IPC - Inter-Process Communication) için kullanılan bir mesaj bus sistemidir. Firewalld, DBus üzerinden tüm işlemlerini gerçekleştirir ve bu sayede hem komut satırı araçları (firewall-cmd) hem de GUI uygulamaları aynı API'yi kullanır.

#### DBus'ın Avantajları

- **Güvenlik**: PolicyKit entegrasyonu ile yetkilendirme
- **Asenkron İletişim**: Non-blocking operasyonlar
- **Signal/Event Sistemi**: Değişikliklerin otomatik bildirilmesi
- **Çoklu İstemci**: Aynı anda birden fazla uygulama firewalld'ye erişebilir
- **Otomatik Aktivasyon**: Servis ihtiyaç duyulduğunda otomatik başlatılır

### 5.2 DBus Mimarisi

#### DBus Bileşenleri

| Bileşen | Görev |
|---------|-------|
| **dbus-daemon** | Merkezi mesaj bus. Tüm DBus mesajlarını yönlendirir. |
| **System Bus** | Sistem çapında servisler için (firewalld, NetworkManager, systemd) |
| **Session Bus** | Kullanıcı oturumu için (masaüstü uygulamaları) |
| **PolicyKit** | Yetkilendirme mekanizması. Root yetkisi gerektiren işlemleri kontrol eder. |

#### Firewalld DBus Interface

Firewalld, `org.fedoraproject.FirewallD1` isimli DBus servisi üzerinden erişilebilir.

```bash
# DBus interface'ini keşfet

# Firewalld DBus servisini listele
busctl list | grep firewalld

# Firewalld DBus metodlarını göster
busctl introspect org.fedoraproject.FirewallD1 /org/fedoraproject/FirewallD1

# DBus üzerinden zone listesini al
busctl call org.fedoraproject.FirewallD1 \
  /org/fedoraproject/FirewallD1 \
  org.fedoraproject.FirewallD1.zone \
  getZones
```

### 5.3 DBus Yapılandırması ve Optimizasyonu

#### 5.3.1 DBus Timeout Ayarları

DBus timeout sorunları, özellikle büyük kural setlerinde veya yavaş sistemlerde ortaya çıkabilir. Firewalld işlemleri uzun sürdüğünde DBus varsayılan 25 saniyelik timeout'u aşabilir.

```bash
# System bus timeout ayarı
# /etc/dbus-1/system.d/firewalld.conf dosyasını düzenle
cat << 'EOF' > /etc/dbus-1/system.d/firewalld.conf
<?xml version="1.0"?>
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.fedoraproject.FirewallD1"/>
    <allow send_destination="org.fedoraproject.FirewallD1"/>
    <allow send_interface="org.fedoraproject.FirewallD1"/>
  </policy>

  <policy context="default">
    <allow send_destination="org.fedoraproject.FirewallD1"/>
    <allow send_interface="org.freedesktop.DBus.Introspectable"/>
    <allow send_interface="org.freedesktop.DBus.Properties"/>
  </policy>

  <!-- Timeout ayarları (milisaniye) -->
  <limit name="max_replies_per_connection">512</limit>
  <limit name="max_match_rules_per_connection">512</limit>
</busconfig>
EOF

# DBus'ı yeniden yükle
systemctl reload dbus

# Firewall-cmd için timeout ayarı
# Ortam değişkeni ile timeout artırma
export DBUS_SYSTEM_BUS_DEFAULT_TIMEOUT=120000  # 120 saniye
firewall-cmd --reload

# Kalıcı olarak ayarlama
echo 'export DBUS_SYSTEM_BUS_DEFAULT_TIMEOUT=120000' >> /etc/profile.d/dbus-timeout.sh
```

#### 5.3.2 DBus Performans Optimizasyonu

```bash
# DBus daemon ayarları
# /etc/dbus-1/system.conf dosyasını düzenle
# Önemli parametreler:

<busconfig>
  <!-- Maksimum aktif bağlantı sayısı -->
  <limit name="max_incoming_connections">1000</limit>
  <limit name="max_outgoing_connections">1000</limit>

  <!-- Bağlantı başına mesaj limiti -->
  <limit name="max_match_rules_per_connection">512</limit>
  <limit name="max_replies_per_connection">512</limit>

  <!-- Mesaj boyutu limitleri (byte) -->
  <limit name="max_incoming_bytes">134217728</limit>  <!-- 128 MB -->
  <limit name="max_outgoing_bytes">134217728</limit>
  <limit name="max_message_size">134217728</limit>

  <!-- Servis aktivasyon timeout (ms) -->
  <limit name="service_start_timeout">120000</limit>  <!-- 120 saniye -->
</busconfig>
```

### 5.4 DBus Troubleshooting

#### 5.4.1 Yaygın DBus Hataları ve Çözümleri

**Hata 1: Timeout Hatası**

```bash
Error: 'org.freedesktop.DBus.Error.NoReply: Did not receive a reply'

Çözüm:
# 1. Timeout'u artır
export DBUS_SYSTEM_BUS_DEFAULT_TIMEOUT=120000

# 2. Firewalld loglama seviyesini kontrol et
firewall-cmd --get-log-denied
firewall-cmd --set-log-denied=off  # Loglamayı azalt

# 3. İşlemi parça parça yap
# Tüm kuralları tek seferde değil, küçük gruplar halinde ekle
```

**Hata 2: Permission Denied**

```bash
Error: 'PERMISSION_DENIED: Failed to acquire org.fedoraproject.FirewallD1'

Çözüm:
# 1. PolicyKit yapılandırmasını kontrol et
cat /usr/share/polkit-1/actions/org.fedoraproject.FirewallD1.policy

# 2. Kullanıcı yetkilerini kontrol et
pkaction --action-id org.fedoraproject.firewalld1.zone.add --verbose

# 3. Root olarak çalıştır veya sudo kullan
sudo firewall-cmd --reload
```

**Hata 3: DBus Service Başlatılamıyor**

```bash
Error: 'Failed to connect to D-Bus: Connection refused'

Çözüm:
# 1. DBus daemon'unun çalıştığını kontrol et
systemctl status dbus
systemctl start dbus

# 2. Firewalld servisini kontrol et
systemctl status firewalld
systemctl start firewalld

# 3. DBus soket dosyasını kontrol et
ls -la /var/run/dbus/system_bus_socket

# 4. SELinux kontrol (varsa)
getenforce
setenforce 0  # Geçici olarak devre dışı bırak
# Kalıcı çözüm için SELinux policy düzeltilmeli
```

#### 5.4.2 DBus Monitoring ve Debugging

```bash
# DBus mesajlarını izle (tüm system bus)
dbus-monitor --system

# Sadece firewalld mesajlarını izle
dbus-monitor --system "type='signal',sender='org.fedoraproject.FirewallD1'"

# Method call'ları izle
dbus-monitor --system "type='method_call',path='/org/fedoraproject/FirewallD1'"

# DBus servis durumunu detaylı kontrol

# Firewalld DBus aktivasyon durumu
systemctl status dbus-org.fedoraproject.FirewallD1.service

# DBus bağlantılarını listele
busctl list | grep -i firewall

# Firewalld DBus propertylerini göster
busctl get-property org.fedoraproject.FirewallD1 \
  /org/fedoraproject/FirewallD1 \
  org.fedoraproject.FirewallD1 \
  version
```

#### 5.4.3 DBus Log Analizi

```bash
# System log'da DBus hatalarını ara
journalctl -u dbus -n 100 --no-pager

# Firewalld DBus mesajlarını filtrele
journalctl -u firewalld | grep -i dbus

# Timeout hatalarını bul
journalctl -u dbus | grep -i timeout

# Belirli zaman aralığında logları incele
journalctl -u dbus --since "2024-01-01 10:00:00" --until "2024-01-01 11:00:00"
```

---

## 6. İLERİ SEVİYE KONULAR VE EN İYİ PRATİKLER

### 6.1 Yüksek Performanslı Firewall Mimarisi

#### 6.1.1 Multi-Interface Senaryosu

Karmaşık ağ topolojilerinde birden fazla interface'in farklı zone'larda yönetimi:

```bash
# Senaryo: Web sunucusu ile 4 interface
# eth0: WAN (Internet)
# eth1: LAN (İç ağ)
# eth2: DMZ (Web sunucuları)
# eth3: Management (Yönetim ağı)

# 1. Zone atamaları
firewall-cmd --zone=external --change-interface=eth0 --permanent
firewall-cmd --zone=internal --change-interface=eth1 --permanent
firewall-cmd --zone=dmz --change-interface=eth2 --permanent
firewall-cmd --zone=trusted --change-interface=eth3 --permanent

# 2. External zone (WAN) - Sadece HTTP/HTTPS
firewall-cmd --zone=external --permanent --add-masquerade
firewall-cmd --zone=external --permanent \
  --add-forward-port=port=80:proto=tcp:toaddr=192.168.2.10:toport=80
firewall-cmd --zone=external --permanent \
  --add-forward-port=port=443:proto=tcp:toaddr=192.168.2.10:toport=443

# 3. DMZ zone - Web sunucuları
firewall-cmd --zone=dmz --permanent --add-service=http
firewall-cmd --zone=dmz --permanent --add-service=https
# DMZ'den internal'a database erişimi
firewall-cmd --zone=dmz --permanent --add-rich-rule='
  rule family="ipv4"
  source address="192.168.2.0/24"
  destination address="192.168.1.20"
  port port="3306" protocol="tcp" accept'

# 4. Internal zone - İç ağ servisleri
firewall-cmd --zone=internal --permanent --add-service=ssh
firewall-cmd --zone=internal --permanent --add-service=mysql
firewall-cmd --zone=internal --permanent --add-service=dns

# 5. Management zone - Sadece yönetim
firewall-cmd --zone=trusted --permanent --add-service=ssh
firewall-cmd --zone=trusted --permanent --add-rich-rule='
  rule family="ipv4"
  source address="10.0.0.0/24"
  log prefix="MGMT-ACCESS: " level="info"
  accept'

firewall-cmd --reload
```

#### 6.1.2 Direct Rules ile Özel Filtreleme

Direct rules, firewalld'nin sağlamadığı özel iptables/nftables kuralları için kullanılır. Ancak dikkatli kullanılmalıdır çünkü firewalld'nin kural yönetimini bypass eder.

```bash
# Connection tracking optimizasyonu
firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 \
  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# SYN flood koruması
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
  -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
  -p tcp --syn -j DROP

# Port scan koruması
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
  -p tcp --tcp-flags ALL NONE -j DROP
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
  -p tcp --tcp-flags ALL ALL -j DROP

# Invalid paket engelleme
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
  -m conntrack --ctstate INVALID -j DROP

firewall-cmd --reload
```

### 6.2 Monitoring ve Alerting

#### 6.2.1 Firewall Log Analizi

```bash
# Reddedilen paketleri logla
firewall-cmd --set-log-denied=all

# Log seviyelerini kontrol et
firewall-cmd --get-log-denied
# Seçenekler: all, unicast, broadcast, multicast, off

# Kernel log'larında firewall mesajlarını izle
tail -f /var/log/messages | grep -i 'REJECT\|DROP'

# journalctl ile firewall logları
journalctl -k | grep -i firewall
```

#### 6.2.2 Gerçek Zamanlı İzleme Scripti

```bash
#!/bin/bash
# /usr/local/bin/firewall-monitor.sh

LOG_FILE="/var/log/firewall-monitor.log"
ALERT_THRESHOLD=100  # Dakikada kaç drop/reject

while true; do
  # Son 1 dakikada reddedilen paket sayısı
  DROPS=$(journalctl -k --since "1 minute ago" | \
          grep -c 'DROP\|REJECT')
  
  if [ $DROPS -gt $ALERT_THRESHOLD ]; then
    # Alert gönder
    echo "[$(date)] ALERT: $DROPS packets dropped in last minute" >> $LOG_FILE
    
    # En çok drop edilen IP'leri bul
    journalctl -k --since "1 minute ago" | \
      grep 'SRC=' | \
      grep -oP 'SRC=\K[0-9.]+' | \
      sort | uniq -c | sort -rn | head -10 >> $LOG_FILE
    
    # Email veya Slack notification (opsiyonel)
    # mail -s "Firewall Alert" admin@example.com < $LOG_FILE
  fi
  
  sleep 60
done
```

#### 6.2.3 Performans Metrikleri

```bash
# Aktif bağlantı sayısı
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max

# Connection tracking tablosunu görüntüle
conntrack -L | wc -l
conntrack -L -o extended | head -20

# Tablo doluluk oranı
COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
USAGE=$((COUNT * 100 / MAX))
echo "Connection tracking usage: $USAGE%"

# Eğer %80'in üzerindeyse max değeri artır
if [ $USAGE -gt 80 ]; then
  echo 'net.netfilter.nf_conntrack_max=262144' >> /etc/sysctl.conf
  sysctl -p
fi
```

### 6.3 Yedekleme ve Disaster Recovery

#### 6.3.1 Konfigürasyon Yedekleme

```bash
#!/bin/bash
# /usr/local/bin/backup-firewall.sh

BACKUP_DIR="/var/backups/firewalld"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/firewalld_backup_$DATE.tar.gz"

mkdir -p $BACKUP_DIR

# Firewalld konfigürasyonunu yedekle
tar -czf $BACKUP_FILE \
  /etc/firewalld/ \
  /etc/dbus-1/system.d/firewalld.conf \
  /etc/sysctl.conf

# Runtime kuralları kaydet
firewall-cmd --list-all-zones > "$BACKUP_DIR/runtime_rules_$DATE.txt"
iptables-save > "$BACKUP_DIR/iptables_rules_$DATE.txt"

# IPSet'leri kaydet
ipset save > "$BACKUP_DIR/ipsets_$DATE.txt"

# Eski yedekleri temizle (30 günden eski)
find $BACKUP_DIR -name "firewalld_backup_*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

#### 6.3.2 Konfigürasyon Geri Yükleme

```bash
#!/bin/bash
# /usr/local/bin/restore-firewall.sh

BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
  echo "Usage: $0 <backup_file.tar.gz>"
  exit 1
fi

# Mevcut konfigürasyonu yedekle
/usr/local/bin/backup-firewall.sh

# Firewalld'yi durdur
systemctl stop firewalld

# Yedekten geri yükle
tar -xzf $BACKUP_FILE -C /

# IPSet'leri geri yükle
IPSET_FILE=$(dirname $BACKUP_FILE)/ipsets_*.txt
if [ -f "$IPSET_FILE" ]; then
  ipset restore < $IPSET_FILE
fi

# Firewalld'yi başlat
systemctl start firewalld
firewall-cmd --reload

echo "Restore completed from: $BACKUP_FILE"
```

### 6.4 Security Hardening

#### 6.4.1 DDoS Koruması

```bash
# Rate limiting ile DDoS koruması

# 1. SYN flood koruması
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
  -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
  -p tcp --syn -j DROP

# 2. ICMP flood koruması
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
  -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
  -p icmp --icmp-type echo-request -j DROP

# 3. HTTP flood koruması (connlimit ile)
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
  -p tcp --dport 80 -m connlimit --connlimit-above 20 \
  --connlimit-mask 32 -j REJECT --reject-with tcp-reset

# 4. Port scan koruması (recent modül ile)
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
  -m recent --name portscan --rcheck --seconds 86400 -j DROP
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
  -m recent --name portscan --remove
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 2 \
  -p tcp --tcp-flags ALL NONE -m recent --name portscan --set -j DROP

firewall-cmd --reload
```

---

## 7. GERÇEK DÜNYA SENARYOLARI VE ÇÖZÜMLER

### 7.1 Kubernetes Cluster Güvenliği

Kubernetes node'larında firewalld yapılandırması:

```bash
# Master Node Firewall Yapılandırması

# 1. Kubernetes API Server
firewall-cmd --permanent --zone=public --add-port=6443/tcp

# 2. etcd server client API
firewall-cmd --permanent --zone=public --add-port=2379-2380/tcp

# 3. Kubelet API
firewall-cmd --permanent --zone=public --add-port=10250/tcp

# 4. kube-scheduler
firewall-cmd --permanent --zone=public --add-port=10259/tcp

# 5. kube-controller-manager
firewall-cmd --permanent --zone=public --add-port=10257/tcp

# Worker Node için ek portlar
# Kubelet API
firewall-cmd --permanent --zone=public --add-port=10250/tcp

# NodePort Services (varsayılan aralık)
firewall-cmd --permanent --zone=public --add-port=30000-32767/tcp

# CNI plugin portları (Calico örneği)
firewall-cmd --permanent --zone=public --add-port=179/tcp  # BGP
firewall-cmd --permanent --zone=public --add-port=4789/udp # VXLAN

# Sadece cluster içinden erişime izin ver
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source address="10.0.0.0/8"  # Pod CIDR
  port port="10250" protocol="tcp" accept'

firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source address="192.168.0.0/16"  # Service CIDR
  accept'

firewall-cmd --reload
```

### 7.2 Load Balancer Arkasında Web Sunucu

```bash
# Senaryo: HAProxy/Nginx load balancer arkasında web sunucular
# Load Balancer IP: 192.168.1.10
# Web Sunucu: Bu sunucu

# 1. Sadece load balancer'dan gelen trafiğe izin ver
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source address="192.168.1.10"
  port port="80" protocol="tcp" accept'

firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source address="192.168.1.10"
  port port="443" protocol="tcp" accept'

# 2. Diğer tüm web trafiğini engelle
firewall-cmd --permanent --zone=public --remove-service=http
firewall-cmd --permanent --zone=public --remove-service=https

# 3. X-Forwarded-For header kontrolü için log
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source address="192.168.1.10"
  port port="80" protocol="tcp"
  log prefix="LB-HTTP: " level="info" limit value="10/m"
  accept'

# 4. Health check portuna izin ver
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source address="192.168.1.10"
  port port="8080" protocol="tcp" accept'

firewall-cmd --reload
```

### 7.3 Database Sunucu Sıkılaştırma

```bash
# PostgreSQL/MySQL için güvenli firewall yapılandırması

# 1. Sadece uygulama sunucularından erişim
firewall-cmd --permanent --new-ipset=app-servers --type=hash:net
firewall-cmd --permanent --ipset=app-servers --add-entry=192.168.1.20
firewall-cmd --permanent --ipset=app-servers --add-entry=192.168.1.21
firewall-cmd --permanent --ipset=app-servers --add-entry=192.168.1.22

# 2. PostgreSQL port (5432) sadece app-servers'a açık
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source ipset="app-servers"
  port port="5432" protocol="tcp"
  log prefix="PG-ACCESS: " level="info" limit value="5/m"
  accept'

# 3. Brute force koruması
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source ipset="app-servers"
  port port="5432" protocol="tcp"
  limit value="10/m" accept'

# 4. Monitoring/backup sunucusu için ayrı kural
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source address="192.168.1.30"  # Monitoring server
  port port="5432" protocol="tcp"
  accept'

# 5. SSH sadece management ağından
firewall-cmd --permanent --zone=public --remove-service=ssh
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule family="ipv4"
  source address="10.0.0.0/24"  # Management network
  service name="ssh" accept'

firewall-cmd --reload

# 6. Tüm diğer database portlarını kapat
firewall-cmd --permanent --zone=public --remove-service=mysql
firewall-cmd --permanent --zone=public --remove-service=postgresql
```

### 7.4 VPN Gateway Yapılandırması

```bash
# OpenVPN/WireGuard gateway için firewall yapılandırması

# 1. VPN zone oluştur
firewall-cmd --permanent --new-zone=vpn
firewall-cmd --permanent --zone=vpn --set-target=ACCEPT

# 2. VPN interface'i zone'a ata (OpenVPN örneği)
firewall-cmd --zone=vpn --add-interface=tun0 --permanent

# 3. External zone'da VPN portunu aç
firewall-cmd --permanent --zone=external --add-port=1194/udp  # OpenVPN
# veya
firewall-cmd --permanent --zone=external --add-port=51820/udp # WireGuard

# 4. Masquerading etkinleştir
firewall-cmd --permanent --zone=external --add-masquerade
firewall-cmd --permanent --zone=vpn --add-masquerade

# 5. VPN kullanıcıları için internal kaynaklara erişim
firewall-cmd --permanent --zone=vpn --add-rich-rule='
  rule family="ipv4"
  source address="10.8.0.0/24"  # VPN subnet
  destination address="192.168.1.0/24"  # Internal network
  accept'

# 6. Split tunneling için routing
firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 \
  -s 10.8.0.0/24 -o eth0 -j MASQUERADE

# 7. VPN kullanıcı bazlı access control
firewall-cmd --permanent --new-ipset=vpn-admin --type=hash:net
firewall-cmd --permanent --ipset=vpn-admin --add-entry=10.8.0.2
firewall-cmd --permanent --ipset=vpn-admin --add-entry=10.8.0.3

firewall-cmd --permanent --zone=vpn --add-rich-rule='
  rule family="ipv4"
  source ipset="vpn-admin"
  destination address="192.168.1.10"  # Admin server
  service name="ssh" accept'

# 8. IP forwarding etkinleştir
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

firewall-cmd --reload
```

---

## 8. SORUN GİDERME VE DEBUG

### 8.1 Yaygın Sorunlar ve Çözümleri

#### 8.1.1 Servis Başlatma Hataları

**Sorun:** Firewalld başlamıyor veya hemen kapanıyor

```bash
# 1. Detaylı log kontrolü
journalctl -xeu firewalld.service
systemctl status firewalld -l

# 2. Konfigürasyon dosyası sözdizimi kontrolü
firewall-cmd --check-config

# 3. XML dosyalarını doğrula
for file in /etc/firewalld/zones/*.xml; do
  xmllint --noout "$file" 2>&1 || echo "Error in $file"
done

# 4. Backend kontrolü
firewall-cmd --get-backend
# nftables kullanıyorsa ve kernel desteği yoksa
lsmod | grep nf_tables
modprobe nf_tables

# 5. Bozuk konfigürasyonu sıfırla
systemctl stop firewalld
mv /etc/firewalld /etc/firewalld.backup
yum reinstall firewalld -y
systemctl start firewalld
```

#### 8.1.2 Kurallar Çalışmıyor

**Sorun:** Eklenen kurallar beklendiği gibi çalışmıyor

```bash
# 1. Kuralın aktif olduğunu doğrula
firewall-cmd --zone=public --list-all
firewall-cmd --permanent --zone=public --list-all

# 2. Runtime ve permanent farkını kontrol et
diff <(firewall-cmd --list-all) <(firewall-cmd --permanent --list-all)

# 3. Backend'de gerçek kuralları kontrol et
# nftables için:
nft list ruleset | grep -A 10 'chain filter_INPUT'

# iptables için:
iptables -L -n -v --line-numbers
iptables -t nat -L -n -v

# 4. Paket akışını trace et
nft add table raw
nft add chain raw trace { type filter hook prerouting priority -300 \; }
nft add rule raw trace ip daddr 192.168.1.10 meta nftrace set 1
# Log'ları izle
nft monitor trace

# 5. Connection tracking kontrolü
conntrack -L | grep <IP_ADDRESS>

# 6. Logging aktif et ve kontrol et
firewall-cmd --set-log-denied=all
tail -f /var/log/messages | grep -i 'REJECT\|DROP'
```

#### 8.1.3 Performans Problemleri

**Sorun:** Firewall yavaş, yüksek CPU kullanımı

```bash
# 1. Kural sayısını kontrol et
firewall-cmd --list-all-zones | grep -c 'rule\|port\|service'

# 2. Backend performansını kontrol et
time firewall-cmd --reload

# 3. nftables'a geç (daha performanslı)
sed -i 's/^FirewallBackend=.*/FirewallBackend=nftables/' /etc/firewalld/firewalld.conf
systemctl restart firewalld

# 4. IPSet kullan (binlerce IP için)
# Her IP için ayrı kural yerine
firewall-cmd --permanent --new-ipset=blocklist --type=hash:net
for ip in $(cat blocklist.txt); do
  firewall-cmd --permanent --ipset=blocklist --add-entry=$ip
done
firewall-cmd --permanent --zone=public --add-rich-rule='
  rule source ipset="blocklist" drop'

# 5. Gereksiz loglamayı kapat
firewall-cmd --set-log-denied=off

# 6. Connection tracking limitlerini artır
echo 'net.netfilter.nf_conntrack_max=262144' >> /etc/sysctl.conf
sysctl -p

# 7. Firewalld CPU kullanımını izle
top -p $(pgrep -f firewalld)
```

### 8.2 Debug Teknikleri

#### 8.2.1 Paket Trace

```bash
# tcpdump ile paket analizi
tcpdump -i eth0 -n host 192.168.1.100
tcpdump -i eth0 -n port 80
tcpdump -i any -n -vv 'tcp[tcpflags] & tcp-syn != 0'

# nftables trace
nft add table ip trace_table
nft add chain ip trace_table trace_chain { \
  type filter hook prerouting priority -300\; }
nft add rule ip trace_table trace_chain \
  ip saddr 192.168.1.100 meta nftrace set 1

# Trace logları
nft monitor trace

# Temizlik
nft delete table ip trace_table
```

#### 8.2.2 Debug Modu

```bash
# Firewalld debug seviyesi
# /etc/firewalld/firewalld.conf
LogDenied=all
AutomaticHelpers=no
FirewallBackend=nftables
MinimalMark=0x00000100
IndividualCalls=no
LogTarget=syslog
RFC3964_IPv4=yes

# Python debug
PYTHONPATH=/usr/lib/python3.9/site-packages \
  python3 -m pdb /usr/sbin/firewalld --nofork --debug=10

# Systemd servisi debug
systemctl edit firewalld
# Ekle:
[Service]
Environment="PYTHONDEBUG=1"

systemctl daemon-reload
systemctl restart firewalld
```

---

## 9. REFERANS ve HIZLI ERİŞİM

### 9.1 Sık Kullanılan Komutlar (Cheat Sheet)

#### Temel İşlemler

```bash
# Durum ve Bilgi
firewall-cmd --state
firewall-cmd --get-default-zone
firewall-cmd --get-active-zones
firewall-cmd --list-all
firewall-cmd --list-all-zones

# Reload ve Restart
firewall-cmd --reload
firewall-cmd --complete-reload
systemctl restart firewalld

# Runtime ↔ Permanent
firewall-cmd --runtime-to-permanent
firewall-cmd --permanent <komut>
```

#### Servis ve Port

```bash
# Servis
firewall-cmd --add-service=http
firewall-cmd --remove-service=http
firewall-cmd --list-services

# Port
firewall-cmd --add-port=8080/tcp
firewall-cmd --add-port=5000-5100/tcp
firewall-cmd --remove-port=8080/tcp
firewall-cmd --list-ports
```

#### Rich Rules

```bash
# Ekle/Sil/Listele
firewall-cmd --add-rich-rule='rule ...'
firewall-cmd --remove-rich-rule='rule ...'
firewall-cmd --list-rich-rules

# Örnekler
firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.1.100" accept'
firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="22" protocol="tcp" accept'
firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.1.100" log prefix="TEST: " level="info" accept'
```

#### NAT ve Forwarding

```bash
# Masquerading
firewall-cmd --add-masquerade
firewall-cmd --query-masquerade

# Port Forwarding
firewall-cmd --add-forward-port=port=80:proto=tcp:toport=8080
firewall-cmd --add-forward-port=port=443:proto=tcp:toaddr=192.168.1.10:toport=443
firewall-cmd --list-forward-ports
```

#### IPSet

```bash
# IPSet Yönetimi
firewall-cmd --permanent --new-ipset=myipset --type=hash:net
firewall-cmd --permanent --ipset=myipset --add-entry=192.168.1.0/24
firewall-cmd --permanent --ipset=myipset --get-entries
firewall-cmd --permanent --delete-ipset=myipset

# IPSet Kullanımı
firewall-cmd --permanent --add-rich-rule='rule source ipset="myipset" drop'
```

### 9.2 Performans Benchmark Değerleri

| Senaryo | Kötü Yöntem | İyi Yöntem | İyileştirme |
|---------|-------------|------------|-------------|
| 1000 IP bloklama | ~30 saniye | ~2 saniye | 15x |
| Reload süresi (500 kural) | ~5 saniye | ~1 saniye | 5x |
| Paket işleme (1M pkt/s) | ~15% CPU | ~5% CPU | 3x |

*İyi Yöntem: nftables backend + IPSet kullanımı

### 9.3 Güvenlik Kontrol Listesi

- ✅ Varsayılan zone politikası DROP veya REJECT olmalı
- ✅ SSH portu değiştirilmeli veya rate limiting uygulanmalı
- ✅ Gereksiz servisler kapatılmalı
- ✅ Log monitoring aktif olmalı
- ✅ Düzenli yedekleme yapılmalı
- ✅ GeoIP filtering kritik servisler için uygulanmalı
- ✅ Connection tracking limitleri uygun şekilde ayarlanmalı
- ✅ DDoS koruması için rate limiting aktif olmalı
- ✅ Kernel security parametreleri hardening yapılmalı
- ✅ DBus timeout değerleri yüksek kural sayısı için artırılmalı

### 9.4 Önemli Dosya ve Dizinler

```bash
# Konfigürasyon Dosyaları
/etc/firewalld/firewalld.conf           # Ana konfigürasyon
/etc/firewalld/zones/                   # Zone tanımları
/etc/firewalld/services/                # Servis tanımları
/etc/firewalld/ipsets/                  # IPSet tanımları
/etc/dbus-1/system.d/firewalld.conf    # DBus konfigürasyonu

# Log Dosyaları
/var/log/messages                       # Kernel firewall logları
/var/log/firewalld                     # Firewalld logları

# Runtime Bilgileri
/proc/sys/net/netfilter/               # Kernel netfilter parametreleri
```

### 9.5 Faydalı Linkler ve Kaynaklar

- **Resmi Dokümantasyon**: https://firewalld.org/documentation/
- **Red Hat Dokümantasyonu**: https://access.redhat.com/documentation/
- **nftables Wiki**: https://wiki.nftables.org/
- **DBus Specification**: https://dbus.freedesktop.org/doc/
- **MaxMind GeoIP**: https://www.maxmind.com/en/geoip2-services-and-databases

---

## SONUÇ

Bu döküman, firewalld ve dbus konularında kapsamlı bir referans kaynağı sunmaktadır. Sahada karşılaşılabilecek tüm senaryolar için pratik çözümler ve best practice'ler içerir. Düzenli olarak güncellenmesi ve organizasyonunuzun özel ihtiyaçlarına göre özelleştirilmesi önerilir.

### Önemli Hatırlatmalar

1. **Test Ortamı**: Yeni kuralları önce test ortamında deneyin
2. **Yedekleme**: Her değişiklik öncesi mevcut konfigürasyonu yedekleyin
3. **Dokümantasyon**: Yapılan tüm değişiklikleri dokümante edin
4. **Monitoring**: Firewall loglarını düzenli olarak izleyin
5. **Güncelleme**: Güvenlik yamalarını düzenli olarak uygulayın

---

**Döküman Versiyonu**: 1.0  
**Son Güncelleme**: Kasım 2024  
**Yazar**: Firewalld/DBus Operasyonel Ekibi

---

*Bu döküman, production ortamlarda güvenli ve performanslı firewall yapılandırması için hazırlanmıştır.*
