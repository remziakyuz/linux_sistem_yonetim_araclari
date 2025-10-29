#!/bin/bash

# Fedora CPU Güç Yönetimi Scripti
# Pil %40'ın altına düştüğünde sadece 2 enerji tasarruflu çekirdek aktif bırakır

# Root kontrolü
if [ "$EUID" -ne 0 ]; then 
    echo "Bu scripti root olarak çalıştırmalısınız: sudo $0"
    exit 1
fi

# Pil durumunu kontrol et
check_battery() {
    # Pil dosyasını bul
    BAT_PATH=$(ls /sys/class/power_supply/BAT*/capacity 2>/dev/null | head -1)
    STATUS_PATH=$(ls /sys/class/power_supply/BAT*/status 2>/dev/null | head -1)
    
    if [ -z "$BAT_PATH" ]; then
        echo "HATA: Pil bulunamadı!"
        exit 1
    fi
    
    BAT_LEVEL=$(cat "$BAT_PATH")
    BAT_STATUS=$(cat "$STATUS_PATH")
    
    echo "Pil seviyesi: %$BAT_LEVEL"
    echo "Pil durumu: $BAT_STATUS"
    
    # Şarjda değilse ve %40'ın altındaysa
    if [ "$BAT_STATUS" = "Discharging" ] && [ "$BAT_LEVEL" -lt 40 ]; then
        return 0  # True
    else
        return 1  # False
    fi
}

# CPU çekirdeklerini kapat (CPU0 hariç, o kapatılamaz)
disable_cores() {
    echo "=== CPU Çekirdekleri Kapatılıyor ==="
    
    # Toplam CPU sayısını al
    TOTAL_CPUS=$(nproc --all)
    echo "Toplam CPU çekirdeği: $TOTAL_CPUS"
    
    # CPU0 ve CPU1 hariç tüm çekirdekleri kapat
    # CPU0 sistem tarafından kapatılamaz, CPU1'i de aktif tutuyoruz
    for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
        cpu_num=$(echo $cpu | grep -o '[0-9]*$')
        
        # CPU0 ve CPU1'i atla
        if [ "$cpu_num" -eq 0 ] || [ "$cpu_num" -eq 1 ]; then
            echo "CPU$cpu_num: Aktif (zorunlu/seçili)"
            continue
        fi
        
        # Çekirdeği kapat
        if [ -f "$cpu/online" ]; then
            echo 0 > "$cpu/online" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "CPU$cpu_num: Kapatıldı ✓"
            else
                echo "CPU$cpu_num: Kapatılamadı"
            fi
        fi
    done
    
    echo ""
    echo "Aktif çekirdek sayısı: $(nproc)"
}

# Tüm CPU çekirdeklerini aç
enable_cores() {
    echo "=== Tüm CPU Çekirdekleri Açılıyor ==="
    
    for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
        cpu_num=$(echo $cpu | grep -o '[0-9]*$')
        
        # CPU0'ı atla (zaten her zaman açık)
        if [ "$cpu_num" -eq 0 ]; then
            continue
        fi
        
        # Çekirdeği aç
        if [ -f "$cpu/online" ]; then
            echo 1 > "$cpu/online" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "CPU$cpu_num: Açıldı ✓"
            fi
        fi
    done
    
    echo ""
    echo "Aktif çekirdek sayısı: $(nproc)"
}

# Ana fonksiyon
main() {
    echo "================================"
    echo "CPU Güç Yönetimi Scripti"
    echo "================================"
    echo ""
    
    if check_battery; then
        echo ""
        echo "⚠️  Pil seviyesi düşük! Enerji tasarrufu modu etkinleştiriliyor..."
        echo ""
        disable_cores
        
        # Güç profili ayarla (eğer power-profiles-daemon varsa)
        if command -v powerprofilesctl &> /dev/null; then
            echo ""
            echo "Güç profili 'power-saver' olarak ayarlanıyor..."
            powerprofilesctl set power-saver
        fi
        
        # CPU frekansını düşür
        if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
            echo ""
            echo "CPU frekans yönetimi 'powersave' olarak ayarlanıyor..."
            for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                if [ -f "$cpu" ]; then
                    echo "powersave" > "$cpu" 2>/dev/null
                fi
            done
        fi
        
    else
        echo ""
        echo "✓ Pil seviyesi yeterli veya şarj oluyor. Normal mod aktif."
        echo ""
        
        # Kullanıcıya seçenek sun
        read -p "Tüm çekirdekleri açmak ister misiniz? (e/h): " answer
        if [ "$answer" = "e" ] || [ "$answer" = "E" ]; then
            enable_cores
            
            # Güç profilini dengeli yap
            if command -v powerprofilesctl &> /dev/null; then
                echo ""
                echo "Güç profili 'balanced' olarak ayarlanıyor..."
                powerprofilesctl set balanced
            fi
            
            # CPU frekans yönetimini dengeli yap
            if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
                echo ""
                echo "CPU frekans yönetimi 'schedutil' olarak ayarlanıyor..."
                for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                    if [ -f "$cpu" ]; then
                        echo "schedutil" > "$cpu" 2>/dev/null || echo "ondemand" > "$cpu" 2>/dev/null
                    fi
                done
            fi
        fi
    fi
    
    echo ""
    echo "================================"
    echo "İşlem tamamlandı!"
    echo "================================"
}

# Scripti çalıştır
main
