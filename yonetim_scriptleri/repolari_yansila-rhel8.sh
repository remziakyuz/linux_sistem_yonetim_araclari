#!/bin/bash

#######################################
# RHEL Repository Sync Script
# Tüm binary ve source paketleri senkronize eder
#######################################

set -euo pipefail  # Hatalarda dur

# Değişkenler
LOCK_FILE="/var/run/repguncelle.lock"
BASEDIR="/arsiv/repo/rhel/rhel8"
REPOLIST_FILE="/root/bin/repolist.txt"
LOG_DIR="/root/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MAIN_LOG="${LOG_DIR}/sync_${TIMESTAMP}.log"

# Fonksiyonlar
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$MAIN_LOG"
}

cleanup() {
    log_message "Script sonlandırılıyor, lock kaldırılıyor..."
    rm -f "$LOCK_FILE"
    subscription-manager repos --disable='*' 2>/dev/null || true
}

# Trap ile cleanup
trap cleanup EXIT INT TERM

# Lock kontrolü
if [ -f "$LOCK_FILE" ]; then
    log_message "HATA: Script zaten çalışıyor! Lock dosyası mevcut: $LOCK_FILE"
    exit 1
fi

# Lock dosyası oluştur
touch "$LOCK_FILE"
log_message "Script başlatıldı - PID: $$"

# Log dizini oluştur
mkdir -p "$LOG_DIR"
mkdir -p "$BASEDIR"

# Eski logları arşivle (silme)
if [ -n "$(ls -A $LOG_DIR/*.txt 2>/dev/null)" ]; then
    mkdir -p "${LOG_DIR}/archive"
    mv "$LOG_DIR"/*.txt "${LOG_DIR}/archive/" 2>/dev/null || true
fi

# Tüm repoları devre dışı bırak
log_message "Tüm repolar devre dışı bırakılıyor..."
subscription-manager repos --disable='*'

# Repo listesini kontrol et
if [ ! -f "$REPOLIST_FILE" ]; then
    log_message "HATA: $REPOLIST_FILE bulunamadı!"
    exit 1
fi

# Her repo için senkronizasyon
while IFS= read -r repo_name || [ -n "$repo_name" ]; do
    # Boş satır ve yorum kontrolü
    [[ -z "$repo_name" || "$repo_name" =~ ^[[:space:]]*# ]] && continue
    
    log_message "=========================================="
    log_message "REPO: $repo_name işleniyor..."
    log_message "=========================================="
    
    REPO_LOG="${LOG_DIR}/sync_${repo_name}_${TIMESTAMP}.txt"
    
    # Repo'yu aktifleştir
    if ! subscription-manager repos --enable="$repo_name" 2>&1 | tee -a "$REPO_LOG"; then
        log_message "UYARI: $repo_name aktifleştirilemedi, atlanıyor..."
        continue
    fi
    
    # Binary paketleri senkronize et (tüm paket tipleri)
    log_message "Binary paketler indiriliyor..."
    if reposync \
        --remote-time \
        --noautoremove \
        --nogpgcheck \
        --bugfix \
        --enhancement \
        --newpackage \
        --security \
        --downloadcomps \
        --download-metadata \
        --setopt="${repo_name}.module_hotfixes=1" \
        --repo="$repo_name" \
        -p "$BASEDIR/" 2>&1 | tee -a "$REPO_LOG"; then
        log_message "✓ Binary paketler başarılı: $repo_name"
    else
        log_message "✗ HATA: Binary paketler başarısız: $repo_name"
    fi
    
    # Source paketleri senkronize et (tüm paket tipleri)
    log_message "Source paketler indiriliyor..."
    if reposync \
        --remote-time \
        --source \
        --noautoremove \
        --nogpgcheck \
        --bugfix \
        --enhancement \
        --newpackage \
        --security \
        --downloadcomps \
        --download-metadata \
        --setopt="${repo_name}.module_hotfixes=1" \
        --repo="$repo_name" \
        -p "$BASEDIR/" 2>&1 | tee -a "$REPO_LOG"; then
        log_message "✓ Source paketler başarılı: $repo_name"
    else
        log_message "✗ UYARI: Source paketler başarısız (bazı repolarda source olmayabilir): $repo_name"
    fi
    
    # Metadata oluştur
    log_message "Metadata oluşturuluyor..."
    REPO_PATH="${BASEDIR}/${repo_name}"
    if [ -d "$REPO_PATH" ]; then
        createrepo --update "$REPO_PATH" 2>&1 | tee -a "$REPO_LOG" || \
            log_message "UYARI: Metadata oluşturulamadı: $repo_name"
    fi
    
    # Repo'yu devre dışı bırak
    subscription-manager repos --disable="$repo_name"
    
    log_message "✓ $repo_name tamamlandı"
    
done < "$REPOLIST_FILE"

# Tüm repoları devre dışı bırak
subscription-manager repos --disable='*'

log_message "=========================================="
log_message "TÜM SENKRONIZASYON TAMAMLANDI!"
log_message "Log dosyası: $MAIN_LOG"
log_message "=========================================="
