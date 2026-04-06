# GeoIP Firewall Setup v3.0 — Kullanım Kılavuzu

## 📋 Genel Bakış

Bu script, `firewalld` kullanarak ülke bazlı erişim kontrolü (whitelist) sağlar. İzin
verilen ülkeler dışındaki tüm bağlantılar engellenir. v3.0 ile birlikte yerel / özel
ağlar için ayrı bir ipset grubu eklenerek LAN ve loopback trafiğinin hiçbir zaman
yanlışlıkla bloklanmaması güvence altına alınmıştır.

---

## ✨ Özellikler

- Fedora, RHEL/CentOS ve Ubuntu/Debian desteği
- Otomatik paket kurulumu (`firewalld`, `ipset`, `geoipupdate`)
- GeoLite2 veritabanı yönetimi
- IPv4 ve IPv6 desteği
- **Yerel ağ ipset'leri** — LAN/loopback/VPN trafiği her zaman kabul edilir
- `--account-id` / `--license-key` CLI parametreleriyle otomatik yapılandırma
- `--local-networks` ile özel ağ aralıkları ekleme
- Detaylı loglama (`/var/log/allowcntry.log`)
- Kapsamlı hata yönetimi

---

## 🚀 Hızlı Başlangıç

```bash
# Sadece Türkiye
sudo python3 geoip_firewall_setup.py --allow TR

# Birden fazla ülke
sudo python3 geoip_firewall_setup.py --allow TR,DE,US

# Credential'larla birlikte (interaktif prompt atlanır)
sudo python3 geoip_firewall_setup.py \
  --allow TR \
  --account-id YOUR_ACCOUNT_ID \
  --license-key YOUR_LICENSE_KEY

# Ekstra VPN subnet'i ile
sudo python3 geoip_firewall_setup.py \
  --allow TR \
  --local-networks 10.8.0.0/24,172.20.0.0/14
```

---

## 📝 Parametreler

| Parametre | Açıklama | Varsayılan |
|-----------|----------|------------|
| `--allow` | İzin verilen ülke kodları (virgülle ayrılmış ISO 3166-1 alpha-2) | `TR` |
| `--account-id` | MaxMind Account ID | *(interaktif)* |
| `--license-key` | MaxMind License Key | *(interaktif)* |
| `--edition-ids` | GeoIP Edition ID'leri | `GeoLite2-Country` |
| `--skip-update` | Veritabanı güncellemesini atla | `False` |
| `--local-networks` | Yerel ipset'e eklenecek ek CIDR'ler (virgülle) | — |
| `--no-local` | Yerel ağ ipset'lerini devre dışı bırak *(önerilmez)* | `False` |

---

## 🔧 Detaylı Çalışma Mantığı

### Adım 1 & 2 — Sistem Hazırlığı

- OS tespit edilir (Fedora/RHEL → `dnf`; Ubuntu/Debian → `apt`)
- Root yetkisi kontrol edilir
- `firewalld`, `ipset`, `python3`, `geoipupdate` kurulur
- `firewalld` servisi etkinleştirilir ve başlatılır

### Adım 3 — GeoIP Yapılandırması

`/etc/GeoIP.conf` dosyası yazılır:

```
AccountID  <sizin_id>
LicenseKey <sizin_key>
EditionIDs GeoLite2-Country
DatabaseDirectory /usr/share/GeoIP
```

`--account-id` ve `--license-key` parametreleri verilmişse interaktif
sormadan doğrudan bu değerler kullanılır. Dosya izinleri `0600` olarak
ayarlanır.

### Adım 4 — Veritabanı Güncelleme

`geoipupdate -v` çalıştırılır. Ardından `.tar.gz` / `.zip` arşivlerinden
CSV dosyaları çıkarılır:

- `GeoLite2-Country-Locations-en.csv`
- `GeoLite2-Country-Blocks-IPv4.csv`
- `GeoLite2-Country-Blocks-IPv6.csv`

### Adım 5 — Veritabanı Ayrıştırma

CSV dosyaları `GeoIPParser` ile işlenir; `geoname_id → ISO kodu` ve
`ISO kodu → CIDR listesi` eşlemeleri bellekte tutulur.

### Adım 6 — IPSet Dosyaları

**Ülke bazlı ipset'ler** (`/etc/firewalld/ipsets/`):

```
geoip4-tr.xml          # TR IPv4 (bireysel referans)
geoip6-tr.xml          # TR IPv6 (bireysel referans)
geoip4-notblock.xml    # Tüm izinli ülkeler — IPv4 (kural tarafından kullanılır)
geoip6-notblock.xml    # Tüm izinli ülkeler — IPv6 (kural tarafından kullanılır)
```

**Yerel ağ ipset'leri** (v3.0 — yeni):

```
ipset4-local.xml       # Loopback + link-local + kullanıcı tanımlı subnet'ler (IPv4)
ipset6-local.xml       # Loopback + link-local + kullanıcı tanımlı subnet'ler (IPv6)
```

Varsayılan IPv4 içeriği (minimal — yalnızca evrensel adresler):

| CIDR | Açıklama |
|------|----------|
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local (APIPA) |

Varsayılan IPv6 içeriği:

| CIDR | Açıklama |
|------|----------|
| `::1/128` | Loopback |
| `fe80::/10` | Link-local |

> **Not:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` gibi geniş RFC 1918 blokları
> artık varsayılanda **yoktur**. Bu bloklar eklenirse alt subnet'ler çakışma hatası verir
> (nftables overlapping intervals). LAN subnet'lerinizi `--local-networks` ile açıkça belirtin:

```bash
sudo python3 geoip_firewall_setup.py --allow TR \
  --local-networks 10.253.10.0/24,10.255.255.0/24,192.168.5.0/24
```

### Adım 7 — Firewalld Kuralları

Eklenen rich rule'lar ve öncelikleri:

```bash
# Yerel ağlar — en yüksek öncelik (LAN asla bloklanmaz)
rule priority="-32768" family="ipv4" source ipset="ipset4-local" accept
rule priority="-32768" family="ipv6" source ipset="ipset6-local" accept

# İzinli ülkeler — kabul et
rule priority="-32767" family="ipv4" source ipset="geoip4-notblock" accept
rule priority="-32767" family="ipv6" source ipset="geoip6-notblock" accept

# Diğer her şey — engelle
rule priority="-32767" family="ipv4" drop
rule priority="-32767" family="ipv6" drop
```

**Öncelik mantığı:** firewalld'de öncelik sayısı ne kadar küçükse o kural
o kadar önce işlenir. `-32768 < -32767` olduğundan yerel ağ accept kuralları,
drop kurallarından önce değerlendirilir.

### Adım 8 — Doğrulama

Aktif kurallar kontrol edilir; eksik kural varsa log'a yazılır ve uyarı gösterilir.

---

## 📊 Log Dosyası

```bash
/var/log/allowcntry.log

# Canlı takip
sudo tail -f /var/log/allowcntry.log

# Sadece hatalar
sudo grep ERROR /var/log/allowcntry.log
```

---

## 🔍 Durum Kontrolü ve IPSet İnceleme

### Yüklü ipset'leri listele

```bash
sudo firewall-cmd --get-ipsets
```

Örnek çıktı:
```
geoip4-notblock geoip4-tr geoip6-notblock geoip6-tr ipset4-local ipset6-local
```

---

### Belirli bir ipset'in detaylarını gör

```bash
# firewalld'nin XML tanımı (family, type, entry sayısı)
sudo firewall-cmd --info-ipset=ipset4-local
sudo firewall-cmd --info-ipset=geoip4-notblock

# Kernel'deki ham ipset içeriği (tüm entry'ler)
sudo ipset list ipset4-local
sudo ipset list ipset6-local
sudo ipset list geoip4-notblock | head -30
```

---

### Entry sayısını öğren

```bash
# Kernel üzerinden (en güvenilir)
sudo ipset list geoip4-notblock | grep -c "^[0-9]"
sudo ipset list ipset4-local    | grep -c "^[0-9]"

# XML dosyası üzerinden
grep -c "<entry>" /etc/firewalld/ipsets/geoip4-notblock.xml
grep -c "<entry>" /etc/firewalld/ipsets/ipset4-local.xml
```

---

### Belirli bir IP'nin ipset'te olup olmadığını test et

```bash
# IP izinli ülkeler listesinde mi?
sudo ipset test geoip4-notblock 1.2.3.4 && echo "İZİNLİ" || echo "BLOKLU"

# IP yerel ağ listesinde mi?
sudo ipset test ipset4-local 10.253.10.5 && echo "YEREL" || echo "Yerel değil"
```

---

### XML dosyalarını doğrudan incele

```bash
# Tüm entry'leri listele
grep "<entry>" /etc/firewalld/ipsets/ipset4-local.xml

# Entry'ler olmadan sadece başlığı gör (family, type, description)
grep -v "<entry>" /etc/firewalld/ipsets/ipset4-local.xml

# Belirli bir subnet var mı?
grep "10.253.10.0" /etc/firewalld/ipsets/ipset4-local.xml
```

---

### Aktif rich rule'ları gör

```bash
sudo firewall-cmd --list-rich-rules
```

Beklenen çıktı:
```
rule priority="-32768" family="ipv4" source ipset="ipset4-local" accept
rule priority="-32768" family="ipv6" source ipset="ipset6-local" accept
rule priority="-32767" family="ipv4" source ipset="geoip4-notblock" accept
rule priority="-32767" family="ipv4" drop
rule priority="-32767" family="ipv6" source ipset="geoip6-notblock" accept
rule priority="-32767" family="ipv6" drop
```

---

### Tüm firewalld durumunu bir arada gör

```bash
sudo firewall-cmd --list-all
```

---

### Tüm ipset'lerin özet tablosu

```bash
for s in $(sudo firewall-cmd --get-ipsets); do
  count=$(sudo ipset list "$s" 2>/dev/null | grep -c "^[0-9a-f]" || echo "?")
  printf "%-25s : %s entry\n" "$s" "$count"
done
```

Örnek çıktı:
```
geoip4-notblock           : 14823 entry
geoip4-tr                 : 12105 entry
geoip6-notblock           : 3201 entry
geoip6-tr                 : 2984 entry
ipset4-local              : 4 entry
ipset6-local              : 2 entry
```

---

### Firewalld ve sistem durumu

```bash
sudo systemctl status firewalld
sudo firewall-cmd --state
```

---

## 🛠️ Bakım ve Güncelleme

### Veritabanını Manuel Güncelleme

```bash
sudo geoipupdate -v
# Ardından kural yenileme
sudo python3 geoip_firewall_setup.py --allow TR --skip-update
```

### Otomatik Güncelleme (Cron)

```bash
sudo crontab -e
```

Önerilen zamanlama (her Pazar 03:00):

```cron
# GeoIP veritabanı güncelle
0 3 * * 0 /usr/bin/geoipupdate -v >> /var/log/geoipupdate.log 2>&1

# Kuralları yenile (güncelleme bittikten 30 dk sonra)
30 3 * * 0 /usr/bin/python3 /root/geoip_firewall_setup.py \
  --allow TR --skip-update >> /var/log/allowcntry-cron.log 2>&1
```

### Yeni Ülke / Ağ Ekleme

```bash
# Ülke ekle
sudo python3 geoip_firewall_setup.py --allow TR,DE

# VPN subnet ekle
sudo python3 geoip_firewall_setup.py --allow TR --local-networks 10.8.0.0/24
```

### Kuralları Tamamen Kaldırma

```bash
sudo firewall-cmd --list-rich-rules | grep -E "geoip|ipset.-local" | \
  while IFS= read -r rule; do
    sudo firewall-cmd --remove-rich-rule="$rule"
    sudo firewall-cmd --permanent --remove-rich-rule="$rule"
  done
sudo firewall-cmd --reload
```

---

## 📋 Sistem Gereksinimleri

| Gereksinim | Minimum |
|------------|---------|
| İşletim sistemi | Fedora 30+, RHEL/CentOS 8+, Ubuntu 20.04+, Debian 10+ |
| Python | 3.6+ |
| Disk alanı | ~500 MB (GeoIP veritabanı) |
| RAM | 512 MB+ |
| Ağ | İnternet erişimi (GeoIP indirme için) |
| Yetki | root |

---

## 📚 Ülke Kodları (ISO 3166-1 alpha-2)

| Kod | Ülke | Kod | Ülke |
|-----|------|-----|------|
| TR | Türkiye | US | ABD |
| DE | Almanya | GB | İngiltere |
| FR | Fransa | IT | İtalya |
| ES | İspanya | NL | Hollanda |
| BE | Belçika | SE | İsveç |
| NO | Norveç | DK | Danimarka |
| FI | Finlandiya | PL | Polonya |
| GR | Yunanistan | RO | Romanya |
| BG | Bulgaristan | HU | Macaristan |
| CZ | Çekya | AT | Avusturya |
| CH | İsviçre | CA | Kanada |
| AU | Avustralya | JP | Japonya |
| GE | Gürcistan | AZ | Azerbaycan |

Tam liste: <https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2>

---

## 💡 En İyi Uygulamalar

1. **Düzenli güncelleme** — GeoIP veritabanını haftada bir güncelleyin (cron ile otomatik)
2. **Log izleme** — `journalctl -u firewalld -f` ile trafiği takip edin
3. **Yedekleme** — Konfigürasyon değişikliklerinden önce yedek alın
4. **Test ortamı** — Değişiklikleri önce test sunucusunda doğrulayın
5. **Yerel ağ kontrolü** — `ipset list ipset4-local` ile yerel ağ ipset içeriğini doğrulayın
6. **Minimal izin** — Yalnızca gerçekten ihtiyaç duyulan ülkeleri ekleyin

---

## 📄 Lisans

Bu script sistem güvenliği için geliştirilmiş profesyonel bir araçtır. Üretim
ortamında kullanmadan önce test ortamında doğrulama yapmanız önerilir.
