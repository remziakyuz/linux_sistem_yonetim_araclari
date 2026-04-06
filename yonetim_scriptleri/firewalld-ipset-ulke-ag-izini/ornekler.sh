#!/bin/bash
# GeoIP Firewall Setup v3.0 — Örnek Kullanım ve Yönetim Komutları

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

header() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"; }
section() { echo -e "\n${YELLOW}▶ $1${NC}"; }
cmd()     { echo -e "  ${GREEN}\$${NC} $1"; }
note()    { echo -e "  ${RED}⚠  $1${NC}"; }

header "GeoIP Firewall Setup v3.0 — Örnek Komutlar"

# ──────────────────────────────────────────────────────────────────────────────
section "1. Temel Kurulum"

cmd "sudo python3 geoip_firewall_setup.py --allow TR"
echo "     Sadece Türkiye'den gelen trafiğe izin ver."
echo ""

cmd "sudo python3 geoip_firewall_setup.py --allow TR,DE"
echo "     Türkiye ve Almanya'ya izin ver."
echo ""

cmd "sudo python3 geoip_firewall_setup.py --allow TR,DE,US,GB"
echo "     Birden fazla ülkeye izin ver."
echo ""

# ──────────────────────────────────────────────────────────────────────────────
section "2. Credential ile Kurulum (İnteraktif Prompt'u Atlar)"

cmd "sudo python3 geoip_firewall_setup.py \\"
cmd "  --allow TR \\"
cmd "  --account-id 123456 \\"
cmd "  --license-key 'AbCd1234EfGh5678'"
echo ""

# ──────────────────────────────────────────────────────────────────────────────
section "3. Yerel Ağ IPSet Yönetimi (v3.0 — YENİ)"

cmd "sudo python3 geoip_firewall_setup.py --allow TR"
echo "     Varsayılan yerel ağlar otomatik eklenir:"
echo "     IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16"
echo "     IPv6: ::1/128, fc00::/7, fe80::/10, ::ffff:0:0/96"
echo ""

cmd "sudo python3 geoip_firewall_setup.py --allow TR \\"
cmd "  --local-networks 10.8.0.0/24"
echo "     VPN subnet ekle (varsayılan aralıklara ek olarak)."
echo ""

cmd "sudo python3 geoip_firewall_setup.py --allow TR \\"
cmd "  --local-networks 10.8.0.0/24,172.20.0.0/14,2001:db8::/32"
echo "     IPv4 ve IPv6 özel ağları birlikte ekle."
echo ""

cmd "sudo python3 geoip_firewall_setup.py --allow TR --no-local"
note "Yerel ağ kurallarını devre dışı bırakır — LAN/loopback erişimi engellenebilir!"
echo ""

# ──────────────────────────────────────────────────────────────────────────────
section "4. Güncelleme Seçenekleri"

cmd "sudo python3 geoip_firewall_setup.py --allow TR --skip-update"
echo "     GeoIP veritabanı güncellenmeden mevcut veriyle kurallar yenilenir."
echo ""

cmd "sudo geoipupdate -v"
echo "     GeoIP veritabanını sadece güncelle (kuralları değiştirme)."
echo ""

# ──────────────────────────────────────────────────────────────────────────────
section "5. Popüler Ülke Kombinasyonları"

cmd "# TR + AB ülkeleri"
cmd "sudo python3 geoip_firewall_setup.py --allow TR,DE,FR,IT,ES,NL,BE,AT,CH"
echo ""

cmd "# TR + İngilizce konuşulan ülkeler"
cmd "sudo python3 geoip_firewall_setup.py --allow TR,US,GB,CA,AU"
echo ""

cmd "# TR + Komşu ülkeler"
cmd "sudo python3 geoip_firewall_setup.py --allow TR,GR,BG,GE,AZ,IQ"
echo ""

cmd "# Geniş Avrupa"
cmd "sudo python3 geoip_firewall_setup.py --allow TR,DE,FR,IT,ES,GB,NL,BE,AT,CH,SE,NO,DK,FI,PL"
echo ""

# ──────────────────────────────────────────────────────────────────────────────
section "6. Durum Kontrol Komutları"

cmd "sudo firewall-cmd --list-rich-rules"
echo "     Tüm aktif rich rule'ları göster."
echo ""

cmd "sudo firewall-cmd --get-ipsets"
echo "     Yüklü IPSet'leri listele."
echo ""

cmd "sudo ipset list ipset4-local"
echo "     Yerel IPv4 ağlarını göster."
echo ""

cmd "sudo ipset list ipset6-local"
echo "     Yerel IPv6 ağlarını göster."
echo ""

cmd "sudo ipset list geoip4-notblock | head -20"
echo "     İzinli ülkeler IPv4 ipset'ini önizle."
echo ""

cmd "sudo firewall-cmd --list-all"
echo "     Tüm firewalld yapılandırmasını göster."
echo ""

cmd "sudo systemctl status firewalld"
echo "     Firewalld servis durumunu kontrol et."
echo ""

# ──────────────────────────────────────────────────────────────────────────────
section "7. Log Komutları"

cmd "sudo tail -f /var/log/allowcntry.log"
echo "     Canlı log takibi."
echo ""

cmd "sudo grep -E 'ERROR|FATAL' /var/log/allowcntry.log"
echo "     Sadece hata satırlarını filtrele."
echo ""

cmd "sudo journalctl -u firewalld -n 100 --no-pager"
echo "     Firewalld sistem logları."
echo ""

# ──────────────────────────────────────────────────────────────────────────────
section "8. Temizlik ve Yönetim"

cmd "# Tüm GeoIP ve yerel ipset kurallarını kaldır"
cmd "sudo firewall-cmd --list-rich-rules | grep -E 'geoip|ipset.-local' | \\"
cmd "  while IFS= read -r rule; do"
cmd "    sudo firewall-cmd --remove-rich-rule=\"\$rule\""
cmd "    sudo firewall-cmd --permanent --remove-rich-rule=\"\$rule\""
cmd "  done"
cmd "sudo firewall-cmd --reload"
echo ""

cmd "# Mevcut kuralları yedekle"
cmd "sudo firewall-cmd --list-all > firewall-backup-\$(date +%Y%m%d).txt"
echo ""

# ──────────────────────────────────────────────────────────────────────────────
section "9. Otomatik Güncelleme — Cron Örneği"

echo "     Aşağıdakileri 'sudo crontab -e' ile ekleyin:"
echo ""
echo '     # Her Pazar 03:00 — GeoIP güncelle'
echo '     0 3 * * 0 /usr/bin/geoipupdate -v >> /var/log/geoipupdate.log 2>&1'
echo ""
echo '     # Her Pazar 03:30 — Kuralları yenile (güncelleme bittikten sonra)'
echo '     30 3 * * 0 /usr/bin/python3 /root/geoip_firewall_setup.py \'
echo '       --allow TR --skip-update >> /var/log/allowcntry-cron.log 2>&1'
echo ""

# ──────────────────────────────────────────────────────────────────────────────
section "10. Yardım"

cmd "python3 geoip_firewall_setup.py --help"
echo ""
echo "  Dokümantasyon:"
echo "    README.md            — Hızlı başlangıç"
echo "    KULLANIM_KILAVUZU.md — Detaylı kılavuz"
echo "    SORUN_GIDERME.md     — Hata çözümleri"
echo ""

header "Ülke Kodları (ISO 3166-1 alpha-2)"
echo ""
printf "  %-6s %-15s  %-6s %-15s  %-6s %-15s\n" \
  "TR" "Türkiye"    "DE" "Almanya"     "US" "ABD"
printf "  %-6s %-15s  %-6s %-15s  %-6s %-15s\n" \
  "GB" "İngiltere"  "FR" "Fransa"      "IT" "İtalya"
printf "  %-6s %-15s  %-6s %-15s  %-6s %-15s\n" \
  "ES" "İspanya"    "NL" "Hollanda"    "BE" "Belçika"
printf "  %-6s %-15s  %-6s %-15s  %-6s %-15s\n" \
  "GR" "Yunanistan" "BG" "Bulgaristan" "RO" "Romanya"
printf "  %-6s %-15s  %-6s %-15s  %-6s %-15s\n" \
  "PL" "Polonya"    "SE" "İsveç"       "NO" "Norveç"
printf "  %-6s %-15s  %-6s %-15s  %-6s %-15s\n" \
  "CA" "Kanada"     "AU" "Avustralya"  "JP" "Japonya"
printf "  %-6s %-15s  %-6s %-15s  %-6s %-15s\n" \
  "GE" "Gürcistan"  "AZ" "Azerbaycan"  "CH" "İsviçre"
echo ""
echo "  Tam liste: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2"
echo ""
