# Büyük Dosya Upload ve Container Image Desteği

## 📦 Genel Bakış

Bu dokümantasyon, Nexus Repository Manager üzerinde **3GB+** boyutundaki dosyaların (özellikle Docker/container image'lar) güvenli ve hızlı bir şekilde yüklenmesi için gerekli tüm yapılandırmaları açıklar.

## 🔍 Mevcut Yapılandırma

Script ile otomatik olarak yapılandırılan değerler:

### Nginx Tarafı

| Parametre | Değer | Açıklama |
|-----------|-------|----------|
| `client_max_body_size` | **10GB** | Maximum upload boyutu |
| `client_body_timeout` | **300s** | Client'ın body göndermesi için timeout |
| `proxy_connect_timeout` | **900s** (15 dk) | Backend'e bağlantı timeout |
| `proxy_send_timeout` | **1800s** (30 dk) | Backend'e data gönderme timeout |
| `proxy_read_timeout` | **1800s** (30 dk) | Backend'den cevap okuma timeout |
| `proxy_request_buffering` | **off** | Streaming mode (bellekte tampon yok) |
| `proxy_buffering` | **off** | Download'lar için buffering kapalı |

### Nexus Tarafı

| Parametre | Değer | Açıklama |
|-----------|-------|----------|
| `-Xms` | **2GB** | Minimum heap memory |
| `-Xmx` | **4GB** | Maximum heap memory |
| `-XX:MaxDirectMemorySize` | **4GB** | Direct memory buffer |

## 📊 Gerçek Dünya Senaryoları

### Senaryo 1: Docker Image Push (3.5GB)

**Problem:**
```bash
$ docker push nexus.example.com:8082/myapp:latest
error pushing image: 413 Request Entity Too Large
```

**Çözüm:**
✅ Script otomatik olarak `client_max_body_size 10G` ayarlar
✅ Timeout'lar 30 dakikaya ayarlıdır
✅ Streaming mode sayesinde memory-efficient

**Test:**
```bash
# 3.5GB image push test
docker tag myapp:latest nexus.example.com:8082/myapp:latest
docker push nexus.example.com:8082/myapp:latest

# Başarılı output:
# latest: digest: sha256:abc123... size: 3758096384
```

---

### Senaryo 2: Maven Artifact Upload (5GB JAR)

**Problem:**
```bash
$ mvn deploy
[ERROR] Failed to execute goal: connection timeout
```

**Çözüm:**
✅ `proxy_send_timeout 1800s` ile 30 dakika timeout
✅ `proxy_request_buffering off` ile streaming

**Maven pom.xml:**
```xml
<distributionManagement>
  <repository>
    <id>nexus</id>
    <url>https://nexus.example.com/repository/maven-releases/</url>
  </repository>
</distributionManagement>

<!-- settings.xml timeout settings -->
<servers>
  <server>
    <id>nexus</id>
    <username>admin</username>
    <password>your-password</password>
    <configuration>
      <timeout>1800000</timeout> <!-- 30 minutes in ms -->
      <httpConfiguration>
        <all>
          <connectionTimeout>900000</connectionTimeout> <!-- 15 minutes -->
        </all>
      </httpConfiguration>
    </configuration>
  </server>
</servers>
```

---

### Senaryo 3: NPM Package Upload (2GB)

**Problem:**
```bash
$ npm publish
npm ERR! code E413
npm ERR! 413 Request Entity Too Large
```

**Çözüm:**
✅ Nginx yapılandırması 10GB'a kadar destekler

**.npmrc:**
```ini
registry=https://nexus.example.com/repository/npm-private/
_auth=YWRtaW46cGFzc3dvcmQ=
email=admin@example.com
always-auth=true
```

---

## ⚙️ Manuel Yapılandırma (Gerekirse)

### 1. Nginx Ayarlarını Değiştirme

Eğer **10GB üzeri** dosyalara ihtiyacınız varsa:

```bash
# Nginx config'i düzenle
sudo nano /etc/nginx/conf.d/nexus.conf

# Değiştir:
client_max_body_size 20G;  # veya 0 (unlimited)

# Timeout'ları artır (60 dakika için)
proxy_connect_timeout 1800;
proxy_send_timeout 3600;
proxy_read_timeout 3600;
send_timeout 3600;

# Kaydet ve test et
sudo nginx -t

# Reload (zero downtime)
sudo systemctl reload nginx
```

---

### 2. Nexus Memory Ayarları

Çok büyük dosyalar için Nexus memory'sini artırın:

```bash
# nexus.vmoptions düzenle
sudo nano /app/nexus/bin/nexus.vmoptions

# Değiştir:
-Xms4G                      # Minimum heap: 4GB
-Xmx8G                      # Maximum heap: 8GB
-XX:MaxDirectMemorySize=8G  # Direct memory: 8GB

# Nexus'u restart et
sudo systemctl restart nexus
```

**Önerilen RAM değerleri:**

| Upload Boyutu | Sistem RAM | Nexus Xmx | Direct Memory |
|---------------|------------|-----------|---------------|
| < 5GB | 8GB | 4GB | 4GB |
| 5-10GB | 16GB | 8GB | 8GB |
| 10-20GB | 32GB | 16GB | 16GB |
| > 20GB | 64GB+ | 32GB | 32GB |

---

### 3. Nexus Web UI Ayarları

Kurulum sonrası Nexus web arayüzünden:

1. **Settings** → **System** → **Capabilities**
2. **HTTP** capability'sini bul
3. **Request Timeout**: `3600` saniye (60 dakika)
4. **Connection Timeout**: `900` saniye (15 dakika)
5. Save

---

### 4. Docker Repository Özel Ayarları

Docker registry kullanıyorsanız ek yapılandırma:

```bash
sudo nano /etc/nginx/conf.d/nexus.conf

# Docker registry için özel location ekle
server {
    listen 443 ssl http2;
    server_name nexus.example.com;
    
    # ... mevcut ayarlar ...
    
    # Docker registry için özel konfigürasyon
    location /v2/ {
        proxy_pass http://127.0.0.1:8082/v2/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Docker için ÖZEL ayarlar
        client_max_body_size 0;           # Unlimited
        client_body_timeout 600s;
        
        # Chunked transfer encoding
        chunked_transfer_encoding on;
        
        # Disable buffering
        proxy_request_buffering off;
        proxy_buffering off;
        
        # Extended timeouts
        proxy_connect_timeout 900;
        proxy_send_timeout 3600;
        proxy_read_timeout 3600;
    }
}
```

**Docker Daemon Yapılandırması:**

```bash
# /etc/docker/daemon.json
{
  "registry-mirrors": [],
  "insecure-registries": [],
  "max-concurrent-uploads": 5,
  "max-concurrent-downloads": 10
}

sudo systemctl restart docker
```

---

## 🔧 Sorun Giderme

### Problem 1: "413 Request Entity Too Large"

**Belirtiler:**
```
HTTP 413 Request Entity Too Large
nginx/1.20.1
```

**Çözüm Adımları:**

```bash
# 1. Nginx config'i kontrol et
sudo grep -r "client_max_body_size" /etc/nginx/

# 2. Eğer bulunamazsa veya çok küçükse ekle/güncelle
sudo nano /etc/nginx/conf.d/nexus.conf
# client_max_body_size 10G;

# 3. Syntax kontrolü
sudo nginx -t

# 4. Reload
sudo systemctl reload nginx

# 5. Test
curl -I -X POST https://nexus.example.com/test
```

---

### Problem 2: "504 Gateway Timeout"

**Belirtiler:**
```
HTTP 504 Gateway Timeout
```

**Yavaş network veya büyük dosya upload'unda görülür.**

**Çözüm:**

```bash
# Nginx timeout'ları artır
sudo nano /etc/nginx/conf.d/nexus.conf

# Şu değerleri ekle/güncelle:
proxy_connect_timeout 1800;    # 30 dakika
proxy_send_timeout 3600;       # 60 dakika
proxy_read_timeout 3600;       # 60 dakika
send_timeout 3600;             # 60 dakika
client_body_timeout 600;       # 10 dakika

# Reload
sudo systemctl reload nginx
```

**Nexus timeout'larını kontrol et:**

```bash
# Web UI → Settings → System → HTTP
# Request Timeout: 3600 saniye
```

---

### Problem 3: "Connection Reset" veya "Broken Pipe"

**Belirtiler:**
```
curl: (56) Recv failure: Connection reset by peer
```

**Nedeni:** Streaming sırasında connection kopuyor.

**Çözüm:**

```bash
# Nginx keepalive artır
sudo nano /etc/nginx/conf.d/nexus.conf

# Server block içine ekle:
keepalive_timeout 600s;
keepalive_requests 1000;

# Proxy block içine ekle:
proxy_http_version 1.1;
proxy_set_header Connection "";

# Reload
sudo systemctl reload nginx
```

---

### Problem 4: Nexus "Out of Memory"

**Belirtiler:**
```
java.lang.OutOfMemoryError: Java heap space
```

**Çözüm:**

```bash
# 1. Mevcut memory kullanımını kontrol et
free -h

# 2. Nexus memory artır
sudo nano /app/nexus/bin/nexus.vmoptions

# Heap size artır (sistemin %50-60'ı)
-Xms4G
-Xmx8G
-XX:MaxDirectMemorySize=8G

# 3. Nexus restart
sudo systemctl restart nexus

# 4. Memory kullanımını izle
sudo watch -n 5 'free -h; echo "---"; ps aux | grep nexus | head -1'
```

---

### Problem 5: Disk Doldu

**Belirtiler:**
```
No space left on device
```

**Çözüm:**

```bash
# 1. Disk kullanımı kontrol
df -h

# 2. Nexus blob store cleanup
# Web UI → Settings → Repository → Cleanup Policies
# Create policy: Delete unused after 30 days

# 3. Compact blob store
# Web UI → Settings → Repository → Blob Stores
# Select blob store → Compact

# 4. Eski log temizle
sudo find /app/data/nexus/sonatype-work/nexus3/log -type f -mtime +7 -delete

# 5. Docker prune (eğer Docker kullanıyorsanız)
docker system prune -a --volumes -f
```

---

## 📈 Performance Optimizasyonu

### 1. Nginx Worker Processes

```bash
# CPU çekirdek sayısına göre ayarla
sudo nano /etc/nginx/nginx.conf

# CPU sayısını bul
nproc

# Worker sayısını ayarla (genellikle CPU count = worker count)
worker_processes auto;
worker_connections 2048;

# Reload
sudo systemctl reload nginx
```

---

### 2. Nginx Buffer Optimizasyonu

Büyük dosyalar için buffer'ları artırın:

```bash
sudo nano /etc/nginx/conf.d/nexus.conf

# Proxy buffer settings ekle:
proxy_buffer_size 128k;
proxy_buffers 8 128k;
proxy_busy_buffers_size 256k;

# Client buffer
client_body_buffer_size 512k;
```

---

### 3. File System Optimizasyonu

```bash
# XFS veya EXT4 mount options
# /etc/fstab
/dev/sdb1  /app/data  xfs  defaults,noatime,nodiratime  0 0

# Remount
sudo mount -o remount /app/data
```

---

### 4. Nexus Blob Store Optimizasyonu

Web UI'dan:

1. **Settings** → **Repository** → **Blob Stores**
2. Her blob store için:
   - **Type**: File (en hızlısı)
   - **Path**: SSD disk üzerinde
   - **Soft Quota**: Disk dolmasını önlemek için set et

---

## 📊 Monitoring ve Alerting

### 1. Upload İstatistikleri

```bash
# Real-time upload monitoring
sudo tail -f /var/log/nginx/nexus-access.log | grep -E "POST|PUT"

# Upload boyutlarını analiz et
sudo awk '$9 ~ /^(201|204)$/ {sum+=$10} END {print "Total uploaded:", sum/1024/1024/1024, "GB"}' \
  /var/log/nginx/nexus-access.log
```

---

### 2. Timeout İzleme

```bash
# 504 gateway timeout sayısı
sudo grep "504" /var/log/nginx/nexus-error.log | wc -l

# Son 1 saatteki timeout'lar
sudo grep "504" /var/log/nginx/nexus-error.log | grep "$(date '+%d/%b/%Y:%H')"
```

---

### 3. Disk Doluluk Alerting

```bash
# Cron job ekle
sudo crontab -e

# Her saat disk kontrolü
0 * * * * df -h /app/data | awk 'NR==2 {if ($5+0 > 80) print "Disk usage:", $5}' | mail -s "Nexus Disk Alert" admin@example.com
```

---

## 🎯 Best Practices

### ✅ Yapılması Gerekenler

1. **Streaming Mode Kullanın**
   - `proxy_request_buffering off`
   - `proxy_buffering off`
   - Memory efficient

2. **Yeterli Timeout Ayarlayın**
   - Minimum 30 dakika upload timeout
   - Network hızınıza göre ayarlayın

3. **Disk Alanını İzleyin**
   - Minimum %20 boş tutun
   - Cleanup policy uygulayın

4. **Memory'yi Doğru Ayarlayın**
   - Nexus heap: Sistem RAM'in %50-60'ı
   - Direct memory = Heap memory

5. **SSD Kullanın**
   - Blob store için SSD şart
   - 10x daha hızlı I/O

### ❌ Yapılmaması Gerekenler

1. **Buffering Açık Bırakmayın**
   - `proxy_request_buffering on` ❌
   - Büyük dosyalar için memory explosion

2. **Çok Küçük Timeout Kullanmayın**
   - 60 saniye timeout ❌
   - Büyük dosyalar için yetersiz

3. **Unlimited Boyut Kullanmayın (Production)**
   - `client_max_body_size 0` ❌ (production'da)
   - DoS attack riski

4. **RAM'den Fazla Heap Vermeyin**
   - Xmx > Sistem RAM ❌
   - System instability

---

## 🔍 Debug ve Troubleshooting

### Detaylı Logging

```bash
# Nginx debug modu
sudo nano /etc/nginx/conf.d/nexus.conf

# Error log level artır
error_log /var/log/nginx/nexus-error.log debug;

# Reload
sudo systemctl reload nginx

# Real-time log monitoring
sudo tail -f /var/log/nginx/nexus-error.log
```

---

### Request Trace

```bash
# Curl ile detaylı upload test
curl -v -X POST \
  -H "Authorization: Basic $(echo -n admin:password | base64)" \
  -F "file=@large-file.tar.gz" \
  https://nexus.example.com/repository/raw-hosted/

# Output'ta kontrol edin:
# - Upload progress
# - HTTP response codes
# - Timing information
```

---

## 📞 Destek ve Yardım

### Log Lokasyonları

```bash
# Nginx logs
/var/log/nginx/nexus-access.log
/var/log/nginx/nexus-error.log

# Nexus logs
/app/data/nexus/sonatype-work/nexus3/log/nexus.log
/app/data/nexus/sonatype-work/nexus3/log/jvm.log

# System logs
sudo journalctl -u nginx -f
sudo journalctl -u nexus -f
```

---

### Test Script

```bash
#!/bin/bash
# test-large-upload.sh

echo "Testing large file upload configuration..."

# 1. Nginx config check
echo "[1/5] Checking Nginx configuration..."
nginx -t && echo "✓ Nginx config OK" || echo "✗ Nginx config ERROR"

# 2. Client max body size
echo "[2/5] Checking max body size..."
MAX_SIZE=$(grep -r "client_max_body_size" /etc/nginx/ | grep -v "#" | awk '{print $2}' | head -1)
echo "Max body size: $MAX_SIZE"

# 3. Timeout check
echo "[3/5] Checking timeouts..."
grep -E "proxy_read_timeout|proxy_send_timeout" /etc/nginx/conf.d/nexus.conf

# 4. Nexus memory
echo "[4/5] Checking Nexus memory..."
grep -E "^-Xm" /app/nexus/bin/nexus.vmoptions

# 5. Disk space
echo "[5/5] Checking disk space..."
df -h /app/data

echo ""
echo "Test completed!"
```

---

## 📚 Referanslar

- [Nexus Upload Limits](https://help.sonatype.com/repomanager3)
- [Nginx Large File Uploads](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size)
- [Docker Registry Best Practices](https://docs.docker.com/registry/)

---

**Son Güncelleme**: 2024  
**Test Edildi**: Rocky Linux 9.6, Nexus 3.86.2-01, Nginx 1.20+
