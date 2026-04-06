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
ipset4-local.xml       # RFC 1918 + loopback + link-local (IPv4)
ipset6-local.xml       # RFC 4193 + loopback + link-local (IPv6)
```

Varsayılan IPv4 içeriği:

| CIDR | Açıklama |
|------|----------|
| `10.0.0.0/8` | RFC 1918 Class-A özel |
| `172.16.0.0/12` | RFC 1918 Class-B özel |
| `192.168.0.0/16` | RFC 1918 Class-C özel |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local (APIPA) |

Varsayılan IPv6 içeriği:

| CIDR | Açıklama |
|------|----------|
| `::1/128` | Loopback |
| `fc00::/7` | Unique local (RFC 4193) |
| `fe80::/10` | Link-local |
| `::ffff:0:0/96` | IPv4-mapped |

Özel bir VPN veya yönetim ağı eklemek için:

```bash
sudo python3 geoip_firewall_setup.py --allow TR \
  --local-networks 10.8.0.0/24,2001:db8::/32
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

## 🔍 Durum Kontrolü

```bash
# Aktif kurallar
sudo firewall-cmd --list-rich-rules

# IPSet listesi
sudo firewall-cmd --get-ipsets

# Belirli bir ipset'in içeriği
sudo ipset list geoip4-notblock | head -50
sudo ipset list ipset4-local

# Firewalld genel durum
sudo firewall-cmd --list-all
sudo systemctl status firewalld
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
