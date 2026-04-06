# GeoIP Firewall Setup v3.0 — Sorun Giderme Rehberi

## 🔍 Hızlı Tanı

Bir hatayla karşılaştığınızda önce şunları çalıştırın:

```bash
# Son 50 log satırı
sudo tail -50 /var/log/allowcntry.log | grep -E "ERROR|WARNING|FATAL"

# Firewalld durumu
sudo systemctl status firewalld

# Aktif kurallar
sudo firewall-cmd --list-rich-rules

# IPSet listesi
sudo firewall-cmd --get-ipsets
```

---

## ❌ Hata Kataloğu

---

### 1. "This script must be run as root"

**Neden:** Script root yetkisi olmadan çalıştırılmış.

**Çözüm:**

```bash
sudo python3 geoip_firewall_setup.py --allow TR
```

---

### 2. "Package installation failed"

**Neden:** Paket yöneticisi erişilemiyor (kilitleme, ağ sorunu, repo hatası).

**Fedora/RHEL çözümü:**

```bash
# Kilidi kaldır
sudo killall dnf 2>/dev/null; sudo rm -f /var/lib/dnf/locks/*

# Cache temizle ve yenile
sudo dnf clean all && sudo dnf makecache

# Manuel kurulum
sudo dnf install -y firewalld ipset python3 geoipupdate

sudo systemctl enable --now firewalld
```

**Ubuntu/Debian çözümü:**

```bash
# Kilidi kaldır
sudo killall apt apt-get 2>/dev/null
sudo rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*

# Güncelle ve kur
sudo apt-get update
sudo apt-get install -y firewalld ipset python3 geoipupdate

sudo systemctl enable --now firewalld
```

---

### 3. "GeoIP database update failed"

**Neden:** Yanlış credential, ağ sorunu veya MaxMind hesap limiti.

**Adımlar:**

```bash
# 1. Credential'ları kontrol et
sudo cat /etc/GeoIP.conf

# 2. Bağlantıyı test et
ping -c 3 www.maxmind.com
curl -I https://download.maxmind.com

# 3. Manuel güncelleme
sudo geoipupdate -v

# 4. Credential'ları el ile düzelt
sudo nano /etc/GeoIP.conf
```

Doğru `/etc/GeoIP.conf` formatı:

```
AccountID  123456
LicenseKey AbCd1234EfGh5678
EditionIDs GeoLite2-Country
DatabaseDirectory /usr/share/GeoIP
```

**Alternatif — Manuel indirme:**

```bash
# MaxMind panelinden indir:
# https://www.maxmind.com/en/accounts/current/geoip/downloads

sudo cp GeoLite2-Country_*.tar.gz /usr/share/GeoIP/
cd /usr/share/GeoIP/
sudo tar -xzf GeoLite2-Country_*.tar.gz
sudo mv GeoLite2-Country_*/GeoLite2-Country-*.csv .

# Script'i güncelleme olmadan çalıştır
sudo python3 geoip_firewall_setup.py --allow TR --skip-update
```

---

### 4. "Country code not found in database"

**Neden:** Geçersiz veya küçük harfli ülke kodu.

```bash
# Doğru format: büyük harf, 2 karakter
# ✓  TR   DE   US   GB
# ✗  tr   tur  turkey  TUR

# Veritabanındaki tüm kodları listele
sudo cut -d',' -f5 /usr/share/GeoIP/GeoLite2-Country-Locations-en.csv | sort -u

# Belirli ülkeyi ara
sudo grep -i "turkey" /usr/share/GeoIP/GeoLite2-Country-Locations-en.csv
```

---

### 5. "Failed to create ipset file"

**Neden:** Dizin yok, izin hatası veya disk dolmuş.

```bash
# Dizin kontrolü
ls -ld /etc/firewalld/ipsets/

# Gerekirse oluştur
sudo mkdir -p /etc/firewalld/ipsets
sudo chmod 755 /etc/firewalld/ipsets

# Disk alanı
df -h /etc/

# Firewalld yeniden başlat
sudo systemctl restart firewalld

# Tekrar çalıştır
sudo python3 geoip_firewall_setup.py --allow TR
```

---

### 6. "Firewalld service not running"

```bash
# Başlat ve etkinleştir
sudo systemctl enable --now firewalld

# Hata devam ederse log'a bak
sudo journalctl -xeu firewalld

# iptables ile çakışma varsa
sudo systemctl disable --now iptables
sudo systemctl mask iptables
sudo systemctl start firewalld
```

---

### 7. "Failed to add rule" / IPSet yüklenmemiş

**Neden:** Firewalld ipset XML dosyalarını henüz okumamış.

```bash
# IPSet dosyaları var mı?
ls -la /etc/firewalld/ipsets/geoip*-notblock.xml
ls -la /etc/firewalld/ipsets/ipset*-local.xml   # v3.0 — yerel ağ

# Reload et
sudo firewall-cmd --reload

# IPSet'leri kontrol et
sudo firewall-cmd --get-ipsets

# Eski GeoIP kurallarını temizle
sudo firewall-cmd --list-rich-rules | grep -E "geoip|ipset.-local" | \
  while IFS= read -r rule; do
    sudo firewall-cmd --remove-rich-rule="$rule"
    sudo firewall-cmd --permanent --remove-rich-rule="$rule"
  done

# Tekrar çalıştır
sudo python3 geoip_firewall_setup.py --allow TR --skip-update
```

---

### 8. SSH Bağlantısı Koptu / Sunucuya Erişemiyorum

> **Bu en kritik senaryodur!**

**Önleme (script çalıştırmadan önce):**

- `--allow` listesine kendi ülkenizi ekleyin
- KVM/console erişiminiz olduğundan emin olun
- Önce test sunucusunda çalıştırın
- Mevcut kuralları yedekleyin: `sudo firewall-cmd --list-all > backup.txt`

**Console/KVM erişiminiz varsa:**

```bash
# Tüm GeoIP ve yerel kuralları kaldır
sudo firewall-cmd --list-rich-rules | grep -E "geoip|ipset.-local" | \
  while IFS= read -r rule; do
    sudo firewall-cmd --remove-rich-rule="$rule"
    sudo firewall-cmd --permanent --remove-rich-rule="$rule"
  done
sudo firewall-cmd --reload

# Hâlâ erişemiyorsanız firewalld'yi geçici durdur
sudo systemctl stop firewalld
```

**Console erişiminiz yoksa:** Hosting sağlayıcınızdan rescue/recovery console isteyin.

---

### 9. Yerel Ağ Trafiği Bloklanıyor (v3.0)

**Neden:** `ipset4-local` / `ipset6-local` oluşturulmamış veya kurallar yanlış öncelikte.

```bash
# Yerel ipset'ler var mı?
sudo firewall-cmd --get-ipsets | grep local

# İçerik kontrolü
sudo ipset list ipset4-local

# Kural önceliklerini kontrol et
# Şunlar görünmeli:  priority="-32768" ... ipset="ipset4-local"
sudo firewall-cmd --list-rich-rules

# Eksikse yeniden oluştur
sudo python3 geoip_firewall_setup.py --allow TR --skip-update

# Özel ağınız varsayılan aralıklarda değilse ekleyin
sudo python3 geoip_firewall_setup.py --allow TR \
  --local-networks 10.10.0.0/16 --skip-update
```

---

### 10. Script Yarıda Kaldı / Zaman Aşımı

```bash
# Log'dan kaldığı yeri bul
sudo tail -200 /var/log/allowcntry.log

# Yarım kalan ipset dosyalarını temizle
sudo rm -f /etc/firewalld/ipsets/geoip*.xml
sudo rm -f /etc/firewalld/ipsets/ipset*-local.xml

sudo firewall-cmd --reload

# Tekrar çalıştır
sudo python3 geoip_firewall_setup.py --allow TR
```

---

### 11. "Permission denied" / SELinux Hataları

```bash
# Script'i root olarak çalıştırın
sudo python3 geoip_firewall_setup.py --allow TR

# SELinux aktifse
sudo getenforce          # Enforcing / Permissive / Disabled
sudo setenforce 0        # Geçici: Permissive moda al
sudo journalctl -t setroubleshoot   # SELinux engellemelerini gör

# Kalıcı çözüm — firewalld için politika gevşetme
sudo setsebool -P logging_syslogd_can_sendmail on
```

---

### 12. IPv6 Desteği Yok

Script hem IPv4 hem IPv6 kuralları ekler. IPv6 kullanmıyorsanız kurulduktan sonra:

```bash
# IPv6 rich rule'ları kaldır
sudo firewall-cmd --list-rich-rules | grep ipv6 | \
  while IFS= read -r rule; do
    sudo firewall-cmd --remove-rich-rule="$rule"
    sudo firewall-cmd --permanent --remove-rich-rule="$rule"
  done
sudo firewall-cmd --reload
```

---

## 🔍 Genel Tanı Komutları

```bash
# --- Sistem ---
cat /etc/os-release
python3 --version
firewall-cmd --version
df -h && free -h

# --- Firewalld ---
sudo firewall-cmd --state
sudo firewall-cmd --list-all
sudo firewall-cmd --list-rich-rules

# --- IPSet listesi ---
sudo firewall-cmd --get-ipsets

# --- IPSet detayı (firewalld tanımı) ---
sudo firewall-cmd --info-ipset=ipset4-local
sudo firewall-cmd --info-ipset=geoip4-notblock

# --- Ham ipset içeriği (kernel) ---
sudo ipset list ipset4-local
sudo ipset list ipset6-local
sudo ipset list geoip4-notblock | head -20

# --- Entry sayısı ---
sudo ipset list geoip4-notblock | grep -c "^[0-9]"
sudo ipset list ipset4-local    | grep -c "^[0-9]"

# --- Belirli bir IP izinli mi? ---
sudo ipset test geoip4-notblock 1.2.3.4 && echo "İZİNLİ" || echo "BLOKLU"
sudo ipset test ipset4-local 10.253.10.5 && echo "YEREL" || echo "Yerel değil"

# --- XML dosyaları ---
grep "<entry>" /etc/firewalld/ipsets/ipset4-local.xml
grep -c "<entry>" /etc/firewalld/ipsets/geoip4-notblock.xml
grep "10.253.10.0" /etc/firewalld/ipsets/ipset4-local.xml  # subnet var mı?

# --- Tüm ipset'lerin özet tablosu ---
for s in $(sudo firewall-cmd --get-ipsets); do
  count=$(sudo ipset list "$s" 2>/dev/null | grep -c "^[0-9a-f]" || echo "?")
  printf "%-25s : %s entry\n" "$s" "$count"
done

# --- Log ---
sudo tail -100 /var/log/allowcntry.log
sudo grep -E "ERROR|FATAL" /var/log/allowcntry.log
sudo journalctl -u firewalld -n 100 --no-pager

# --- GeoIP ---
sudo cat /etc/GeoIP.conf
ls -lh /usr/share/GeoIP/
```

---

## 📁 Destek İçin Log Toplama

```bash
# Tüm tanı bilgilerini tek dosyaya topla
{
  echo "=== OS ===" && cat /etc/os-release
  echo "=== Firewalld ===" && sudo firewall-cmd --list-all
  echo "=== Rich Rules ===" && sudo firewall-cmd --list-rich-rules
  echo "=== IPSets ===" && sudo firewall-cmd --get-ipsets
  echo "=== Script Log (son 200 satır) ===" && sudo tail -200 /var/log/allowcntry.log
  echo "=== Firewalld Journal ===" && sudo journalctl -u firewalld -n 100 --no-pager
} > geoip-firewall-diag-$(date +%Y%m%d-%H%M%S).txt

echo "Tanı dosyası oluşturuldu: geoip-firewall-diag-*.txt"
```

---

## 🆘 Acil Durum — Firewalld'yi Tamamen Kaldırma

> **Yalnızca son çare olarak kullanın!**

```bash
# Firewalld'yi durdur ve devre dışı bırak
sudo systemctl stop firewalld
sudo systemctl disable firewalld

# Gerekirse iptables'a geri dön
sudo systemctl enable --now iptables
```

---

## ✅ Kurulum Öncesi Kontrol Listesi

- [ ] Root yetkisiyle çalıştırıyorum (`sudo`)
- [ ] İnternet bağlantım var (`ping www.maxmind.com`)
- [ ] MaxMind hesabım ve credential'larım hazır
- [ ] **Kendi ülkem** `--allow` listesinde
- [ ] KVM/console erişimim var
- [ ] Önce test sunucusunda deneyeceğim
- [ ] Mevcut firewall ayarlarını yedekledim
- [ ] Disk alanı yeterli: en az 500 MB (`df -h /usr/share`)
- [ ] Firewalld kurulu ve çalışıyor (`systemctl status firewalld`)
