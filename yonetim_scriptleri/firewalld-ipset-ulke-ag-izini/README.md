# GeoIP Firewall Setup v3.0 — Hızlı Başlangıç

## 🚀 3 Adımda Kurulum

### 1️⃣ MaxMind Hesabı (2 dakika)
1. <https://www.maxmind.com/en/geolite2/signup> — ücretsiz hesap oluşturun
2. <https://www.maxmind.com/en/accounts/current/license-key> — License Key alın
3. **Account ID** ve **License Key** değerlerini not edin

### 2️⃣ Script'i Çalıştırın

```bash
chmod +x geoip_firewall_setup.py

# Sadece Türkiye'ye izin ver (varsayılan)
sudo python3 geoip_firewall_setup.py --allow TR

# Credential'ları doğrudan verin (interaktif prompt'u atlar)
sudo python3 geoip_firewall_setup.py \
  --allow TR \
  --account-id 123456 \
  --license-key "AbCd1234EfGh5678"
```

### 3️⃣ Kontrol Edin

```bash
sudo firewall-cmd --list-rich-rules
sudo firewall-cmd --get-ipsets
sudo tail -f /var/log/allowcntry.log
```

---

## 📝 Sık Kullanılan Örnekler

| Amaç | Komut |
|------|-------|
| Sadece TR | `sudo python3 geoip_firewall_setup.py --allow TR` |
| TR + DE | `sudo python3 geoip_firewall_setup.py --allow TR,DE` |
| Veritabanı güncellemesini atla | `--skip-update` |
| Ekstra yerel ağ ekle | `--local-networks 10.10.0.0/16,172.20.0.0/14` |
| Yerel ağ kurallarını devre dışı bırak | `--no-local` *(önerilmez)* |
| Tüm parametreler | `python3 geoip_firewall_setup.py --help` |

---

## ⚙️ Script Ne Yapıyor?

Script 8 adımda çalışır:

1. **Sistem tespiti** — OS ve paket yöneticisi belirlenir
2. **Paket kurulumu** — `firewalld`, `ipset`, `geoipupdate` yüklenir
3. **GeoIP yapılandırması** — MaxMind ayarları `/etc/GeoIP.conf`'a yazılır
4. **Veritabanı indirme** — GeoLite2-Country güncellenir
5. **Veritabanı ayrıştırma** — CSV dosyaları işlenir
6. **IPSet dosyaları** — Ülke ve yerel ağ ipset'leri oluşturulur
7. **Firewalld kuralları** — Rich rule'lar eklenir
8. **Doğrulama** — Kurallar kontrol edilir

### Oluşturulan IPSet'ler

| Dosya | İçerik | Öncelik |
|-------|--------|---------|
| `ipset4-local.xml` | RFC 1918 + loopback IPv4 | -32768 (en yüksek) |
| `ipset6-local.xml` | RFC 4193 + loopback IPv6 | -32768 (en yüksek) |
| `geoip4-notblock.xml` | Tüm izinli ülkeler — IPv4 | -32767 |
| `geoip6-notblock.xml` | Tüm izinli ülkeler — IPv6 | -32767 |
| `geoip4-tr.xml` | TR IPv4 (ayrı referans) | — |
| `geoip6-tr.xml` | TR IPv6 (ayrı referans) | — |

### Kural Sırası (öncelik düşükten yükseğe)

```
-32768  ipset4-local / ipset6-local  →  ACCEPT  (yerel ağ, asla bloklanmaz)
-32767  geoip4-notblock              →  ACCEPT  (izinli ülkeler)
-32767  DROP                                     (diğer her şey)
-32767  geoip6-notblock              →  ACCEPT  (izinli ülkeler - IPv6)
-32767  DROP                                     (diğer her şey - IPv6)
```

---

## 🔒 Yerel Ağ IPSet'i (`ipset4-local` / `ipset6-local`)

**v3.0'da eklendi.** Yerel ağ trafiği `-32768` önceliğiyle **her zaman kabul edilir**
ve GeoIP drop kurallarından etkilenmez. Bu sayede:

- LAN erişimi (SSH, yönetim vb.) kesinlikle bloklanmaz
- Loopback adresleri (`127.0.0.1`, `::1`) korunur
- VPN / management subnet'leri `--local-networks` ile eklenebilir

Varsayılan IPv4 ağları: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`

Varsayılan IPv6 ağları: `::1/128`, `fc00::/7`, `fe80::/10`, `::ffff:0:0/96`

```bash
# Örnek: VPN subnet'ini ekle
sudo python3 geoip_firewall_setup.py --allow TR --local-networks 10.8.0.0/24
```

---

## ⚠️ Kritik Uyarılar

> **1. Kendi ülkenizi ekleyin!** SSH bağlantınızın kesilmemesi için `--allow` listesine
> bağlandığınız ülkeyi mutlaka ekleyin.

> **2. Test sunucusunda deneyin.** İlk kurulumu üretim ortamı yerine test sunucusunda yapın.

> **3. Yedeğini alın.** Mevcut firewall ayarlarınızı yedekleyin:
> `sudo firewall-cmd --list-all > firewall-backup-$(date +%Y%m%d).txt`

> **4. Console erişimi.** KVM/console erişiminiz olmadan çalıştırmayın.

---

## 🎯 Popüler Ülke Kombinasyonları

```bash
# TR + AB
sudo python3 geoip_firewall_setup.py --allow TR,DE,FR,IT,ES,NL,BE,AT,CH

# TR + İngilizce konuşulan ülkeler
sudo python3 geoip_firewall_setup.py --allow TR,US,GB,CA,AU

# TR + Komşu ülkeler
sudo python3 geoip_firewall_setup.py --allow TR,GR,BG,GE,AZ,IQ

# Sadece Avrupa
sudo python3 geoip_firewall_setup.py --allow TR,DE,FR,IT,ES,GB,NL,BE,AT,CH,SE,NO,DK,FI,PL
```

---

## 📚 Daha Fazla Bilgi

| Doküman | İçerik |
|---------|--------|
| `KULLANIM_KILAVUZU.md` | Tüm parametreler, mimari, bakım |
| `SORUN_GIDERME.md` | Hata kodları ve çözümleri |
| `ornekler.sh` | Hazır komut örnekleri |
