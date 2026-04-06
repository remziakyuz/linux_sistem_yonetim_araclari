# CPU Güç Yönetimi Scripti - Kullanım Kılavuzu

## Özellikler

Bu script Fedora için tasarlanmış bir CPU güç yönetim aracıdır:

✅ Pil %40'ın altına düştüğünde otomatik olarak CPU çekirdeklerini kapatır
✅ Sadece 2 çekirdek aktif bırakır (CPU0 ve CPU1)
✅ Güç tasarrufu profili ve CPU frekans yönetimini optimize eder
✅ Normal durumda tüm çekirdekleri tekrar açabilir

## Kurulum

### 1. Script'i Uygun Konuma Kopyalayın

```bash
sudo cp cpu_power_manager.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/cpu_power_manager.sh
```

### 2. Manuel Kullanım

Script'i istediğiniz zaman manuel olarak çalıştırabilirsiniz:

```bash
sudo /usr/local/bin/cpu_power_manager.sh
```

### 3. Otomatik Çalıştırma (Önerilen)

#### Seçenek A: Systemd Servisi (Sürekli İzleme)

Sürekli pil seviyesini izleyen bir systemd servisi oluşturun:

```bash
sudo nano /etc/systemd/system/cpu-power-monitor.service
```

Aşağıdaki içeriği ekleyin:

```ini
[Unit]
Description=CPU Power Management Monitor
After=multi-user.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /usr/local/bin/cpu_power_manager.sh; sleep 300; done'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

Servisi etkinleştirin:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cpu-power-monitor.service
sudo systemctl start cpu-power-monitor.service
```

Servis durumunu kontrol edin:

```bash
sudo systemctl status cpu-power-monitor.service
```

#### Seçenek B: Cron Job (Periyodik Kontrol)

Her 5 dakikada bir kontrol etmek için:

```bash
sudo crontab -e
```

Şu satırı ekleyin:

```
*/5 * * * * /usr/local/bin/cpu_power_manager.sh > /dev/null 2>&1
```

#### Seçenek C: Udev Kuralı (Pil Olayında)

Pil durumu değiştiğinde tetiklenen bir kural:

```bash
sudo nano /etc/udev/rules.d/99-battery-power.rules
```

İçeriği ekleyin:

```
SUBSYSTEM=="power_supply", ATTR{status}=="Discharging", RUN+="/usr/local/bin/cpu_power_manager.sh"
```

Udev kurallarını yeniden yükleyin:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

## Script Nasıl Çalışır?

1. **Pil Kontrolü**: Pil seviyesini ve durumunu (şarj oluyor/boşalıyor) kontrol eder
2. **%40 Eşiği**: Pil %40'ın altındaysa ve boşalıyorsa enerji tasarrufu moduna geçer
3. **Çekirdek Yönetimi**: 
   - CPU0: Her zaman açık (sistem gereksinimi)
   - CPU1: Açık bırakılır
   - CPU2, CPU3, vb.: Kapatılır
4. **Güç Optimizasyonu**: 
   - Güç profilini `power-saver` yapar
   - CPU frekans yönetimini `powersave` yapar

## Çekirdekleri Tekrar Açma

Script manuel çalıştırıldığında ve pil seviyesi yeterliyse, tüm çekirdekleri açma seçeneği sunar:

```bash
sudo /usr/local/bin/cpu_power_manager.sh
```

Veya manuel olarak tüm çekirdekleri açmak için:

```bash
# Tüm CPU çekirdeklerini aç
for cpu in /sys/devices/system/cpu/cpu*/online; do
    echo 1 | sudo tee $cpu > /dev/null 2>&1
done
```

## Sorun Giderme

### Problem: "Pil bulunamadı" Hatası
**Çözüm**: Dizüstü bilgisayarda çalıştığınızdan emin olun. Masaüstü sistemlerde pil olmadığı için bu hata normaldir.

### Problem: Çekirdekler Kapatılamıyor
**Çözüm**: Script'i root yetkisiyle çalıştırın: `sudo /usr/local/bin/cpu_power_manager.sh`

### Problem: CPU0 Kapatılamıyor
**Çözüm**: Bu normal bir durumdur. CPU0 sistem tarafından korunur ve kapatılamaz.

### Problem: Performans Çok Düşük
**Çözüm**: Tüm çekirdekleri tekrar açın:
```bash
sudo /usr/local/bin/cpu_power_manager.sh
# Sonra 'e' tuşuna basın
```

## Log Kontrolü

Systemd servisi kullanıyorsanız logları görmek için:

```bash
sudo journalctl -u cpu-power-monitor.service -f
```

## Özelleştirme

Script içinde değiştirebileceğiniz parametreler:

- **Pil eşiği**: `[ "$BAT_LEVEL" -lt 40 ]` satırındaki 40 değerini değiştirin
- **Aktif çekirdek sayısı**: Script'te CPU0 ve CPU1 aktif kalıyor. Daha fazla çekirdek için döngüyü düzenleyin
- **Kontrol sıklığı**: Systemd servisinde `sleep 300` (5 dakika) değerini değiştirin

## Servisi Durdurma

Otomatik izlemeyi durdurmak için:

```bash
sudo systemctl stop cpu-power-monitor.service
sudo systemctl disable cpu-power-monitor.service
```

## Güvenlik Notu

Bu script root yetkisi gerektirir çünkü sistem seviyesinde CPU yönetimi yapar. Scripti çalıştırmadan önce içeriğini incelemeniz önerilir.

## Lisans

Bu script eğitim ve kişisel kullanım için özgürce kullanılabilir.
