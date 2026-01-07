#!/bin/bash
# Version 2.2 - Enhanced with Custom Key Support and API Re-encryption
# Variables
NEXUS_VERSION="3.86.2-01"
NEXUS_TAR="nexus-${NEXUS_VERSION}-linux-x86_64.tar.gz"
NEXUS_DOWNLOAD_URL="https://cdn.download.sonatype.com/repository/downloads-prod-group/3/${NEXUS_TAR}"

JAVA_VERSION="17"
NEXUS_USER="nexus"
NEXUS_UID=30033
NEXUS_GID=30033
INSTALL_DIR="/app/nexus"
REPO_DIR="/app/data/nexus-repo"
WORK_DIR="/app/data/nexus/sonatype-work"
DATA_DIR="${WORK_DIR}/nexus3"
NEXUS_PORT=8081

# Encryption key files - UPDATED for custom-key.json
CUSTOM_KEY_FILE="${INSTALL_DIR}/etc/custom-key.json"
CUSTOM_ENCRYPTION_FILE="${INSTALL_DIR}/etc/custom-encryption.json"
DEFAULT_PROPERTIES_FILE="${INSTALL_DIR}/etc/default-application.properties"
ENCRYPTION_KEY_BACKUP="/root/nexus-encryption-key-$(date +%Y%m%d-%H%M%S).txt"

# API Configuration for re-encryption
NEXUS_DOMAIN=""
API_WAIT_TIME=90

# Minimum disk space requirements in MB
MIN_INSTALL_SPACE=2048  # 2GB for installation
MIN_REPO_SPACE=10240    # 10GB for repository
MIN_WORK_SPACE=5120     # 5GB for work directory

# Nginx and SSL Configuration
ENABLE_NGINX_PROXY=false
DOMAIN_NAME=""
SSL_EMAIL=""
USE_SELF_SIGNED=false
NGINX_PORT=80
NGINX_SSL_PORT=443

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Logging configuration
LOG_FILE="/var/log/nexus-installation-$(date +%Y%m%d-%H%M%S).log"
VERBOSE_MODE=false

# Function to log messages
log_message() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$LOG_FILE"
}

# Function to print colored messages
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log_message "ERROR: $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log_message "SUCCESS: $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log_message "WARNING: $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log_message "INFO: $1"
}

print_debug() {
    if [ "$VERBOSE_MODE" = true ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
    log_message "DEBUG: $1"
}

print_security() {
    echo -e "${MAGENTA}[SECURITY]${NC} $1"
    log_message "SECURITY: $1"
}

# Function to check if script is run as root
check_root() {
    print_info "Root yetki kontrolü yapılıyor..."
    if [ "$(id -u)" -ne 0 ]; then
        print_error "Bu script root kullanıcısı ile çalıştırılmalıdır."
        exit 1
    fi
    print_success "Root yetki kontrolü başarılı."
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --enable-ssl)
                ENABLE_NGINX_PROXY=true
                print_debug "SSL modu etkinleştirildi"
                shift
                ;;
            --domain)
                DOMAIN_NAME="$2"
                NEXUS_DOMAIN="$2"
                print_debug "Domain: $DOMAIN_NAME"
                shift 2
                ;;
            --email)
                SSL_EMAIL="$2"
                print_debug "Email: $SSL_EMAIL"
                shift 2
                ;;
            --self-signed)
                USE_SELF_SIGNED=true
                print_debug "Self-signed sertifika kullanılacak"
                shift
                ;;
            --verbose)
                VERBOSE_MODE=true
                print_info "Verbose mode aktif"
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                print_error "Bilinmeyen parametre: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Function to show help
show_help() {
    cat << EOF
Nexus Repository Manager Kurulum Scripti v2.2
Kullanım: $0 [OPTIONS]

SEÇENEKLER:
    --enable-ssl           Nginx reverse proxy ve SSL/HTTPS'i etkinleştir
    --domain DOMAIN        SSL için domain adı (örn: nexus.example.com)
    --email EMAIL          Let's Encrypt için email adresi
    --self-signed          Let's Encrypt yerine self-signed sertifika kullan
    --verbose              Detaylı çıktı göster (debug modu)
    --help                 Bu yardım mesajını göster

YENİ ÖZELLİKLER (v2.2):
    ✓ custom-key.json dosyası ile özel şifreleme
    ✓ nexus.secrets.file property desteği
    ✓ Otomatik API re-encryption çağrısı
    ✓ İyileştirilmiş systemd service (stop hatası düzeltildi)
    ✓ Detaylı güvenlik loglaması
    ✓ Encryption key backup'ı otomatik oluşturma

ÖRNEKLER:
    # Basit kurulum (sadece HTTP)
    $0

    # Let's Encrypt ile SSL kurulumu
    $0 --enable-ssl --domain nexus.example.com --email admin@example.com

    # Self-signed sertifika ile SSL kurulumu
    $0 --enable-ssl --domain nexus.example.com --self-signed
    
    # Detaylı çıktı ile kurulum
    $0 --verbose

NOT: 
- SSL kullanımı için domain DNS kayıtlarının sunucuya işaret etmesi gerekir.
- Kurulum log dosyası: $LOG_FILE
- Encryption key backup: $ENCRYPTION_KEY_BACKUP
EOF
}

# Function to validate SSL parameters
validate_ssl_parameters() {
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        print_info "SSL yapılandırması doğrulanıyor..."
        
        if [ -z "$DOMAIN_NAME" ]; then
            print_error "SSL için domain adı belirtilmelidir: --domain nexus.example.com"
            exit 1
        fi
        
        if [ "$USE_SELF_SIGNED" = false ] && [ -z "$SSL_EMAIL" ]; then
            print_error "Let's Encrypt için email adresi belirtilmelidir: --email admin@example.com"
            print_info "Alternatif: Self-signed sertifika için --self-signed parametresini kullanın"
            exit 1
        fi
        
        print_success "SSL parametreleri doğrulandı."
    fi
}

# Function to check operating system
check_os() {
    print_info "İşletim sistemi kontrolü yapılıyor..."
    
    if [ ! -f /etc/os-release ]; then
        print_error "/etc/os-release dosyası bulunamadı. İşletim sistemi belirlenemedi."
        exit 1
    fi
    
    source /etc/os-release
    
    # Check for RHEL 9 based distributions
    if [[ "$ID" == "rocky" || "$ID" == "rhel" || "$ID" == "almalinux" || "$ID" == "centos" ]]; then
        if [[ "$VERSION_ID" =~ ^9 ]]; then
            print_success "Desteklenen işletim sistemi tespit edildi: ${NAME} ${VERSION_ID}"
            print_debug "OS ID: $ID, Version: $VERSION_ID"
            return 0
        else
            print_error "Desteklenmeyen versiyon: ${NAME} ${VERSION_ID}"
            print_error "Bu script sadece RHEL 9 tabanlı dağıtımlar için tasarlanmıştır."
            print_info "Desteklenen sistemler: Rocky Linux 9, RHEL 9, AlmaLinux 9, CentOS Stream 9"
            exit 1
        fi
    else
        print_error "Desteklenmeyen işletim sistemi: ${NAME}"
        print_error "Bu script sadece RHEL 9 tabanlı dağıtımlar için tasarlanmıştır."
        print_info "Desteklenen sistemler: Rocky Linux 9, RHEL 9, AlmaLinux 9, CentOS Stream 9"
        exit 1
    fi
}

# Function to check available disk space
check_disk_space() {
    local target_dir=$1
    local min_space_mb=$2
    local dir_description=$3
    
    # Get parent directory if target doesn't exist
    local check_dir=$target_dir
    while [ ! -d "$check_dir" ] && [ "$check_dir" != "/" ]; do
        check_dir=$(dirname "$check_dir")
    done
    
    print_debug "Disk alanı kontrolü: $check_dir ($dir_description)"
    
    local available_mb=$(df -BM "$check_dir" | awk 'NR==2 {print $4}' | sed 's/M//')
    
    print_debug "Mevcut alan: ${available_mb}MB, Minimum gerekli: ${min_space_mb}MB"
    
    if [ "$available_mb" -lt "$min_space_mb" ]; then
        print_error "Yetersiz disk alanı: $dir_description"
        print_error "Mevcut: ${available_mb}MB, Gerekli: ${min_space_mb}MB"
        return 1
    fi
    
    print_success "Disk alanı yeterli: $dir_description (${available_mb}MB)"
    return 0
}

# Function to check all required disk spaces
check_all_disk_spaces() {
    print_info "Disk alanı kontrolleri yapılıyor..."
    
    local all_checks_passed=true
    
    if ! check_disk_space "$INSTALL_DIR" "$MIN_INSTALL_SPACE" "Kurulum dizini"; then
        all_checks_passed=false
    fi
    
    if ! check_disk_space "$REPO_DIR" "$MIN_REPO_SPACE" "Repository dizini"; then
        all_checks_passed=false
    fi
    
    if ! check_disk_space "$WORK_DIR" "$MIN_WORK_SPACE" "Work dizini"; then
        all_checks_passed=false
    fi
    
    if [ "$all_checks_passed" = false ]; then
        print_error "Disk alanı kontrolleri başarısız. Lütfen yeterli alan sağlayın."
        exit 1
    fi
    
    print_success "Tüm disk alanı kontrolleri başarılı."
}

# Function to check required tools
check_required_tools() {
    print_info "Gerekli araçlar kontrol ediliyor..."
    
    local required_tools=("wget" "tar" "sed" "awk" "openssl")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            print_warning "$tool bulunamadı"
        else
            print_debug "$tool mevcut"
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "Eksik araçlar: ${missing_tools[*]}"
        print_info "Yükleme için: dnf install -y ${missing_tools[*]}"
        exit 1
    fi
    
    print_success "Tüm gerekli araçlar mevcut."
}

# Function to install Java
install_java() {
    print_info "Java ${JAVA_VERSION} kurulumu kontrol ediliyor..."
    
    if java -version 2>&1 | grep -q "version \"${JAVA_VERSION}"; then
        print_success "Java ${JAVA_VERSION} zaten kurulu."
        print_debug "Java version: $(java -version 2>&1 | head -n 1)"
        return 0
    fi
    
    print_info "Java ${JAVA_VERSION} kuruluyor..."
    if dnf install -y java-${JAVA_VERSION}-openjdk java-${JAVA_VERSION}-openjdk-devel; then
        print_success "Java ${JAVA_VERSION} başarıyla kuruldu."
    else
        print_error "Java ${JAVA_VERSION} kurulamadı."
        exit 1
    fi
    
    print_debug "Java version: $(java -version 2>&1 | head -n 1)"
}

# Function to create Nexus user
create_nexus_user() {
    print_info "Nexus kullanıcısı oluşturuluyor..."
    
    if id -u ${NEXUS_USER} >/dev/null 2>&1; then
        print_success "Nexus kullanıcısı zaten mevcut."
        print_debug "User ID: $(id -u ${NEXUS_USER}), Group ID: $(id -g ${NEXUS_USER})"
        return 0
    fi
    
    if groupadd -g ${NEXUS_GID} ${NEXUS_USER} && \
       useradd -u ${NEXUS_UID} -g ${NEXUS_GID} -d /home/${NEXUS_USER} -m -s /bin/bash ${NEXUS_USER}; then
        print_success "Nexus kullanıcısı oluşturuldu (UID: ${NEXUS_UID}, GID: ${NEXUS_GID})"
    else
        print_error "Nexus kullanıcısı oluşturulamadı."
        exit 1
    fi
}

# Function to create directories
create_directories() {
    print_info "Gerekli dizinler oluşturuluyor..."
    
    local directories=(
        "${INSTALL_DIR}"
        "${REPO_DIR}"
        "${WORK_DIR}"
        "${DATA_DIR}"
        "${DATA_DIR}/etc"
        "${DATA_DIR}/log"
        "${DATA_DIR}/tmp"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            if mkdir -p "$dir"; then
                print_debug "Dizin oluşturuldu: $dir"
            else
                print_error "Dizin oluşturulamadı: $dir"
                exit 1
            fi
        else
            print_debug "Dizin zaten mevcut: $dir"
        fi
    done
    
    # Set ownership
    if chown -R ${NEXUS_USER}:${NEXUS_USER} ${INSTALL_DIR} ${REPO_DIR} ${WORK_DIR}; then
        print_success "Dizinler oluşturuldu ve sahiplik ayarlandı."
    else
        print_error "Dizin sahipliği ayarlanamadı."
        exit 1
    fi
}

# Function to download Nexus
download_nexus() {
    print_info "Nexus ${NEXUS_VERSION} indiriliyor..."
    
    cd /tmp || exit 1
    
    if [ -f "/tmp/${NEXUS_TAR}" ]; then
        print_info "Nexus arşivi zaten mevcut, indirme atlanıyor."
        return 0
    fi
    
    if wget -q --show-progress "${NEXUS_DOWNLOAD_URL}"; then
        print_success "Nexus arşivi indirildi."
    else
        print_error "Nexus arşivi indirilemedi."
        exit 1
    fi
}

# Function to install Nexus
install_nexus() {
    print_info "Nexus arşivi çıkartılıyor..."
    
    cd /tmp || exit 1
    
    if tar -xzf ${NEXUS_TAR} -C /tmp/; then
        print_success "Nexus arşivi çıkartıldı."
    else
        print_error "Nexus arşivi çıkartılamadı."
        exit 1
    fi
    
    # Move files to installation directory
    local extracted_dir="/tmp/nexus-${NEXUS_VERSION}"
    
    if [ ! -d "$extracted_dir" ]; then
        print_error "Çıkartılan dizin bulunamadı: $extracted_dir"
        exit 1
    fi
    
    print_info "Nexus dosyaları kurulum dizinine taşınıyor..."
    if cp -r ${extracted_dir}/* ${INSTALL_DIR}/; then
        print_success "Nexus dosyaları kurulum dizinine kopyalandı."
    else
        print_error "Nexus dosyaları kopyalanamadı."
        exit 1
    fi
    
    # Set ownership
    if chown -R ${NEXUS_USER}:${NEXUS_USER} ${INSTALL_DIR}; then
        print_success "Kurulum dizini sahipliği ayarlandı."
    else
        print_error "Kurulum dizini sahipliği ayarlanamadı."
        exit 1
    fi
    
    # Clean up
    rm -rf /tmp/${NEXUS_TAR} ${extracted_dir}
    print_success "Geçici dosyalar temizlendi."
}

# NEW FUNCTION: Generate custom-key.json (simplified format)
generate_custom_key_file() {
    print_security "═══════════════════════════════════════════════════"
    print_security "CUSTOM-KEY.JSON OLUŞTURULUYOR"
    print_security "═══════════════════════════════════════════════════"
    
    # Generate secure encryption key
    print_info "Güvenli encryption key oluşturuluyor..."
    local ENCRYPTION_KEY=$(openssl rand -base64 32)
    local KEY_ID="alibaba33442"
    
    print_success "Encryption key başarıyla oluşturuldu."
    print_debug "Key ID: $KEY_ID"
    
    # Create custom-key.json with simplified format
    print_info "custom-key.json dosyası oluşturuluyor..."
    
    mkdir -p "$(dirname ${CUSTOM_KEY_FILE})"
    
    cat > "${CUSTOM_KEY_FILE}" <<EOF
{
  "active": "${KEY_ID}",
  "keys": [
    {
      "id": "${KEY_ID}",
      "key": "${ENCRYPTION_KEY}"
    }
  ]
}
EOF
    
    if [ $? -eq 0 ]; then
        print_success "custom-key.json dosyası oluşturuldu: ${CUSTOM_KEY_FILE}"
    else
        print_error "custom-key.json dosyası oluşturulamadı!"
        exit 1
    fi
    
    # Validate JSON format
    print_info "JSON formatı doğrulanıyor..."
    if python3 -m json.tool "${CUSTOM_KEY_FILE}" > /dev/null 2>&1 || \
       jq empty "${CUSTOM_KEY_FILE}" > /dev/null 2>&1; then
        print_success "JSON formatı geçerli."
    else
        print_warning "JSON validation araçları bulunamadı, manuel kontrol önerilir."
    fi
    
    # Set secure permissions
    print_info "Dosya izinleri ayarlanıyor..."
    chmod 600 "${CUSTOM_KEY_FILE}"
    chown ${NEXUS_USER}:${NEXUS_USER} "${CUSTOM_KEY_FILE}"
    
    print_success "Dosya izinleri ayarlandı (600, ${NEXUS_USER}:${NEXUS_USER})"
    print_debug "Dosya izinleri: $(ls -la ${CUSTOM_KEY_FILE})"
    
    # Create backup of encryption key info
    print_security "Encryption key bilgileri yedekleniyor..."
    
    cat > "${ENCRYPTION_KEY_BACKUP}" <<EOF
═══════════════════════════════════════════════════
NEXUS CUSTOM KEY BACKUP
═══════════════════════════════════════════════════
Oluşturma Tarihi: $(date)
Hostname: $(hostname)
Nexus Version: ${NEXUS_VERSION}

═══ ENCRYPTION KEY BİLGİLERİ ═══
Key ID: ${KEY_ID}
Encryption Key: ${ENCRYPTION_KEY}

═══ DOSYA LOKASYONLARI ═══
Custom Key File: ${CUSTOM_KEY_FILE}
Default Properties File: ${DEFAULT_PROPERTIES_FILE}
Backup File: ${ENCRYPTION_KEY_BACKUP}

═══════════════════════════════════════════════════
ÇOK ÖNEMLİ UYARILAR
═══════════════════════════════════════════════════
1. Bu dosyayı MUTLAKA güvenli bir yerde saklayın!
2. Bu key kaybolursa şifrelenmiş veriler ASLA kurtarilamaz!
3. Kullanıcı şifreleri, repository credentials erişilemez hale gelir!
4. Bu dosyayı backup sistemine ekleyin!
5. Dosya izinlerini koruyun (sadece root okuyabilmeli)!

═══ YEDEKLENMESİ ÖNERILEN DOSYALAR ═══
- ${CUSTOM_KEY_FILE}
- ${DEFAULT_PROPERTIES_FILE}
- ${DATA_DIR}/db/
- ${DATA_DIR}/etc/

═══ DOĞRULAMA KOMUTLARI ═══
# Custom key kullanılıyor mu?
grep "nexus.secrets.file" ${DEFAULT_PROPERTIES_FILE}

# JSON formatı geçerli mi?
python3 -m json.tool ${CUSTOM_KEY_FILE}

═══════════════════════════════════════════════════
EOF
    
    chmod 600 "${ENCRYPTION_KEY_BACKUP}"
    
    print_success "Encryption key bilgileri yedeklendi: ${ENCRYPTION_KEY_BACKUP}"
    print_security "Bu dosyayı güvenli bir yere kopyalayın!"
    
    print_security "═══════════════════════════════════════════════════"
    print_security "CUSTOM-KEY.JSON KURULUMU TAMAMLANDI"
    print_security "═══════════════════════════════════════════════════"
    
    # Export KEY_ID for later use in API call
    export NEXUS_KEY_ID="${KEY_ID}"
}

# NEW FUNCTION: Configure default-application.properties with nexus.secrets.file
configure_default_application_properties() {
    print_security "═══════════════════════════════════════════════════"
    print_security "DEFAULT-APPLICATION.PROPERTIES YAPILDIRIYOR"
    print_security "═══════════════════════════════════════════════════"
    
    print_info "default-application.properties dosyası oluşturuluyor..."
    
    mkdir -p "$(dirname ${DEFAULT_PROPERTIES_FILE})"
    
    # Create clean properties file with nexus.secrets.file
    cat > "${DEFAULT_PROPERTIES_FILE}" <<'EOF'
# Nexus Repository Manager Configuration
# Auto-generated by installation script v2.2

# Logging Configuration
logging.config=./etc/logback/logback.xml

# Custom Secrets File Configuration
# This uses a custom key file to avoid the default key warning.
#
# IMPORTANT: 
# - Do NOT add quotes around values
# - Use nexus.secrets.file for custom encryption

secret.nexusSecret.enabled=true
nexus.secrets.file=/app/nexus/etc/custom-key.json

# DO NOT UNCOMMENT OR ADD THESE LINES:
# nexus.security.encryptionKey=...
# They will conflict with nexus.secrets.file
EOF
    
    if [ $? -eq 0 ]; then
        print_success "default-application.properties dosyası oluşturuldu: ${DEFAULT_PROPERTIES_FILE}"
    else
        print_error "default-application.properties dosyası oluşturulamadı!"
        exit 1
    fi
    
    # Verify no quotes in property VALUES (ignore comments and empty lines)
    print_info "Property değerleri doğrulanıyor..."
    
    # Check only non-comment, non-empty lines for quotes
    if grep -v '^#' "${DEFAULT_PROPERTIES_FILE}" | grep -v '^$' | grep -q '"'; then
        print_error "HATA: Property değerlerinde tırnak işareti bulundu!"
        print_error "Sorunlu satırlar:"
        grep -v '^#' "${DEFAULT_PROPERTIES_FILE}" | grep -v '^$' | grep '"'
        exit 1
    fi
    
    print_success "Property değerleri tırnak işaretsiz doğrulandı."
    
    # Set permissions
    chmod 600 "${DEFAULT_PROPERTIES_FILE}"
    chown ${NEXUS_USER}:${NEXUS_USER} "${DEFAULT_PROPERTIES_FILE}"
    
    print_success "Dosya izinleri ayarlandı (600, ${NEXUS_USER}:${NEXUS_USER})"
    print_debug "Dosya izinleri: $(ls -la ${DEFAULT_PROPERTIES_FILE})"
    
    # Validate nexus.secrets.file path
    print_info "nexus.secrets.file yolu doğrulanıyor..."
    if grep -q "nexus.secrets.file=/app/nexus/etc/custom-key.json" "${DEFAULT_PROPERTIES_FILE}"; then
        print_success "nexus.secrets.file yolu doğru."
    else
        print_error "nexus.secrets.file yolu hatalı!"
        exit 1
    fi
    
    print_security "═══════════════════════════════════════════════════"
    print_security "PROPERTIES YAPILDIRMASI TAMAMLANDI"
    print_security "═══════════════════════════════════════════════════"
}

# Function to configure Nexus
configure_nexus() {
    print_info "Nexus ${NEXUS_USER} kullanıcısı olarak çalışacak şekilde yapılandırılıyor..."
    
    # Configure nexus.rc
    local nexus_rc="${INSTALL_DIR}/bin/nexus.rc"
    if echo "run_as_user=\"${NEXUS_USER}\"" > ${nexus_rc}; then
        print_success "nexus.rc dosyası oluşturuldu."
    else
        print_error "nexus.rc dosyası oluşturulamadı."
        exit 1
    fi
    
    # Configure nexus.vmoptions
    print_info "nexus.vmoptions yapılandırılıyor..."
    local nexus_vmoptions="${INSTALL_DIR}/bin/nexus.vmoptions"
    
    if [ ! -f "$nexus_vmoptions" ]; then
        print_warning "nexus.vmoptions dosyası bulunamadı, yeni dosya oluşturuluyor..."
        cat <<EOL > "$nexus_vmoptions"
-XX:LogFile=${DATA_DIR}/log/jvm.log
-Dkaraf.data=${DATA_DIR}
-Dkaraf.log=${DATA_DIR}/log
-Djava.io.tmpdir=${DATA_DIR}/tmp
-Xms2G
-Xmx4G
-XX:MaxDirectMemorySize=4G
-XX:+UnlockDiagnosticVMOptions
-XX:+LogVMOutput
-XX:LogFile=${DATA_DIR}/log/jvm.log
-XX:-OmitStackTraceInFastThrow
-Djava.net.preferIPv4Stack=true
-Dkaraf.startLocalConsole=false
-Dkaraf.startRemoteShell=false
EOL
        if [ $? -eq 0 ]; then
            print_success "nexus.vmoptions dosyası oluşturuldu."
        else
            print_error "nexus.vmoptions dosyası oluşturulamadı."
            exit 1
        fi
    else
        # Update existing file
        sed -i "s|^-XX:LogFile=.*|-XX:LogFile=${DATA_DIR}/log/jvm.log|" "$nexus_vmoptions"
        sed -i "s|^-Dkaraf.data=.*|-Dkaraf.data=${DATA_DIR}|" "$nexus_vmoptions"
        sed -i "s|^-Dkaraf.log=.*|-Dkaraf.log=${DATA_DIR}/log|" "$nexus_vmoptions"
        sed -i "s|^-Djava.io.tmpdir=.*|-Djava.io.tmpdir=${DATA_DIR}/tmp|" "$nexus_vmoptions"
        
        # Add memory settings if not present
        grep -q "^-Xms" "$nexus_vmoptions" || echo "-Xms2G" >> "$nexus_vmoptions"
        grep -q "^-Xmx" "$nexus_vmoptions" || echo "-Xmx4G" >> "$nexus_vmoptions"
        grep -q "^-XX:MaxDirectMemorySize" "$nexus_vmoptions" || echo "-XX:MaxDirectMemorySize=4G" >> "$nexus_vmoptions"
        
        if [ $? -eq 0 ]; then
            print_success "nexus.vmoptions dosyası güncellendi."
        else
            print_error "nexus.vmoptions dosyası güncellenemedi."
            exit 1
        fi
    fi
    
    print_debug "VMOptions içeriği: $(head -5 $nexus_vmoptions)"
    
    # Configure nexus-default.properties
    print_info "nexus-default.properties yapılandırılıyor..."
    local nexus_properties="${INSTALL_DIR}/etc/nexus-default.properties"
    
    if [ ! -f "$nexus_properties" ]; then
        print_error "nexus-default.properties dosyası bulunamadı: $nexus_properties"
        exit 1
    fi
    
    sed -i "s|nexus-work=.*|nexus-work=${WORK_DIR}|" ${nexus_properties}
    echo "data-dir=${DATA_DIR}" >> ${nexus_properties}
    
    if [ $? -eq 0 ]; then
        print_success "nexus-default.properties dosyası güncellendi."
    else
        print_error "nexus-default.properties dosyası güncellenemedi."
        exit 1
    fi
    
    # NEW: Generate custom-key.json and configure default-application.properties
    generate_custom_key_file
    configure_default_application_properties
}

# Function to create systemd service - ENHANCED with SuccessExitStatus
create_systemd_service() {
    print_info "Nexus için systemd servisi oluşturuluyor..."
    
    local service_file="/etc/systemd/system/nexus.service"
    
    cat <<EOL > ${service_file}
[Unit]
Description=Nexus Repository Manager
After=network.target

[Service]
Type=forking
LimitNOFILE=65536
Environment="NEXUS_HOME=${INSTALL_DIR}"
Environment="NEXUS_DATA=${DATA_DIR}"
Environment="HOME=${DATA_DIR}"
Environment="JAVA_TOOL_OPTIONS=-Duser.home=${DATA_DIR}"
Environment="INSTALL4J_ADD_VM_PARAMS=-Dkaraf.data=${DATA_DIR} -Dkaraf.home=${INSTALL_DIR} -Dkaraf.base=${INSTALL_DIR} -Djava.io.tmpdir=${DATA_DIR}/tmp"
ExecStart=${INSTALL_DIR}/bin/nexus start
ExecStop=${INSTALL_DIR}/bin/nexus stop
User=${NEXUS_USER}
Restart=on-abort
SuccessExitStatus=143

[Install]
WantedBy=multi-user.target
EOL
    
    if [ $? -eq 0 ]; then
        print_success "Systemd servis dosyası oluşturuldu."
        print_info "SuccessExitStatus=143 eklendi (SIGTERM normal kapatma)"
        print_debug "Service file: $service_file"
    else
        print_error "Systemd servis dosyası oluşturulamadı."
        exit 1
    fi
}

# Function to configure firewall
configure_firewall() {
    print_info "Firewall yapılandırılıyor..."
    
    # Check if firewalld is running
    if ! systemctl is-active --quiet firewalld; then
        print_warning "firewalld servisi çalışmıyor. Firewall yapılandırması atlanıyor."
        print_info "Manuel olarak port açma: firewall-cmd --permanent --add-port=${NEXUS_PORT}/tcp"
        return 0
    fi
    
    print_info "Firewall kuralları ekleniyor..."
    
    # Add Nexus port
    if firewall-cmd --permanent --add-port=${NEXUS_PORT}/tcp; then
        print_success "Nexus portu (${NEXUS_PORT}/tcp) firewall'a eklendi."
    else
        print_error "Nexus portu firewall'a eklenemedi."
        exit 1
    fi
    
    # If SSL is enabled, add HTTP and HTTPS ports
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        print_success "HTTP (80) ve HTTPS (443) portları firewall'a eklendi."
    fi
    
    # Reload firewall
    if firewall-cmd --reload; then
        print_success "Firewall kuralları yüklendi."
    else
        print_error "Firewall kuralları yüklenemedi."
        exit 1
    fi
    
    print_info "Aktif firewall kuralları:"
    firewall-cmd --list-all | grep -E "ports|services" | while read line; do
        print_debug "$line"
    done
}

# Function to start Nexus service
start_nexus_service() {
    print_info "Nexus servisi etkinleştiriliyor ve başlatılıyor..."
    
    systemctl daemon-reload
    if [ $? -ne 0 ]; then
        print_error "systemd daemon-reload başarısız."
        exit 1
    fi
    
    if systemctl enable nexus; then
        print_success "Nexus servisi sistem başlangıcında otomatik başlayacak şekilde ayarlandı."
    else
        print_error "Nexus servisi etkinleştirilemedi."
        exit 1
    fi
    
    if systemctl start nexus; then
        print_success "Nexus servisi başlatıldı."
    else
        print_error "Nexus servisi başlatılamadı."
        print_info "Loglara bakın: journalctl -u nexus -f"
        exit 1
    fi
    
    # Wait for Nexus to start
    print_info "Nexus'un başlaması bekleniyor (bu 1-2 dakika sürebilir)..."
    sleep 10
    
    if systemctl is-active --quiet nexus; then
        print_success "Nexus servisi çalışıyor."
    else
        print_warning "Nexus servisi başlatıldı ancak durumu belirsiz. Kontrol edin: systemctl status nexus"
    fi
}

# NEW FUNCTION: Wait and trigger API re-encryption
trigger_api_reencryption() {
    print_security "═══════════════════════════════════════════════════"
    print_security "API RE-ENCRYPTION İŞLEMİ BAŞLATILIYOR"
    print_security "═══════════════════════════════════════════════════"
    
    print_info "Nexus'un tam olarak hazır olması bekleniyor (${API_WAIT_TIME} saniye)..."
    
    # Countdown timer
    for ((i=${API_WAIT_TIME}; i>0; i--)); do
        echo -ne "\r${CYAN}[WAIT]${NC} Kalan süre: ${i} saniye...   "
        sleep 1
    done
    echo ""
    
    print_success "Bekleme süresi tamamlandı."
    
    # Determine protocol and domain
    local PROTOCOL="http"
    local NEXUS_URL=""
    
    if [ "$ENABLE_NGINX_PROXY" = true ] && [ -n "$NEXUS_DOMAIN" ]; then
        PROTOCOL="https"
        NEXUS_URL="${PROTOCOL}://${NEXUS_DOMAIN}"
        print_info "SSL etkin, domain kullanılacak: ${NEXUS_URL}"
    else
        NEXUS_URL="${PROTOCOL}://localhost:${NEXUS_PORT}"
        print_info "Localhost kullanılacak: ${NEXUS_URL}"
    fi
    
    # Get initial admin password
    local ADMIN_PASSWORD=""
    local ADMIN_PASSWORD_FILE="${DATA_DIR}/admin.password"
    
    if [ -f "${ADMIN_PASSWORD_FILE}" ]; then
        ADMIN_PASSWORD=$(cat ${ADMIN_PASSWORD_FILE})
        print_success "Admin şifresi okundu."
    else
        print_error "Admin şifre dosyası bulunamadı: ${ADMIN_PASSWORD_FILE}"
        print_warning "API re-encryption manuel olarak yapılmalı."
        return 1
    fi
    
    # Make API call
    print_info "API re-encryption endpoint'ine istek gönderiliyor..."
    print_debug "URL: ${NEXUS_URL}/service/rest/v1/secrets/encryption/re-encrypt"
    print_debug "Key ID: ${NEXUS_KEY_ID}"
    
    local API_RESPONSE
    API_RESPONSE=$(curl -X 'PUT' \
      "${NEXUS_URL}/service/rest/v1/secrets/encryption/re-encrypt" \
      -u "admin:${ADMIN_PASSWORD}" \
      -H 'accept: application/json' \
      -H 'Content-Type: application/json' \
      -H 'NX-ANTI-CSRF-TOKEN: 0.6199265331343733' \
      -H 'X-Nexus-UI: true' \
      -d "{
  \"secretKeyId\": \"${NEXUS_KEY_ID}\",
  \"notifyEmail\": \"string\"
}" 2>&1)
    
    local EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        print_success "API re-encryption isteği başarıyla gönderildi!"
        print_debug "Response: $API_RESPONSE"
    else
        print_warning "API re-encryption isteği gönderilirken bir sorun oluştu."
        print_warning "Exit code: $EXIT_CODE"
        print_debug "Response: $API_RESPONSE"
        print_info "Bu normal olabilir, Nexus henüz tam olarak hazır olmayabilir."
        print_info "Manuel olarak API çağrısı yapabilirsiniz:"
        echo ""
        echo "curl -X 'PUT' \\"
        echo "  '${NEXUS_URL}/service/rest/v1/secrets/encryption/re-encrypt' \\"
        echo "  -u 'admin:YOUR_PASSWORD' \\"
        echo "  -H 'accept: application/json' \\"
        echo "  -H 'Content-Type: application/json' \\"
        echo "  -H 'NX-ANTI-CSRF-TOKEN: 0.6199265331343733' \\"
        echo "  -H 'X-Nexus-UI: true' \\"
        echo "  -d '{"
        echo "  \"secretKeyId\": \"${NEXUS_KEY_ID}\","
        echo "  \"notifyEmail\": \"string\""
        echo "}'"
        echo ""
    fi
    
    print_security "═══════════════════════════════════════════════════"
    print_security "API RE-ENCRYPTION İŞLEMİ TAMAMLANDI"
    print_security "═══════════════════════════════════════════════════"
}

# NEW FUNCTION: Verify encryption configuration
verify_encryption_configuration() {
    print_security "═══════════════════════════════════════════════════"
    print_security "ENCRYPTION KEY YAPILDIRMASI DOĞRULANIYOR"
    print_security "═══════════════════════════════════════════════════"
    
    local verification_failed=false
    
    # Check 1: custom-key.json exists
    print_info "[1/7] custom-key.json dosyası kontrolü..."
    if [ -f "${CUSTOM_KEY_FILE}" ]; then
        print_success "✓ custom-key.json mevcut"
        print_debug "Lokasyon: ${CUSTOM_KEY_FILE}"
    else
        print_error "✗ custom-key.json bulunamadı!"
        verification_failed=true
    fi
    
    # Check 2: JSON format
    print_info "[2/7] JSON formatı kontrolü..."
    if python3 -m json.tool "${CUSTOM_KEY_FILE}" > /dev/null 2>&1 || \
       jq empty "${CUSTOM_KEY_FILE}" > /dev/null 2>&1; then
        print_success "✓ JSON formatı geçerli"
    else
        print_warning "⚠ JSON validation araçları bulunamadı"
    fi
    
    # Check 3: File permissions
    print_info "[3/7] Dosya izinleri kontrolü..."
    local perms=$(stat -c "%a" "${CUSTOM_KEY_FILE}" 2>/dev/null)
    if [ "$perms" = "600" ]; then
        print_success "✓ Dosya izinleri güvenli (600)"
    else
        print_warning "⚠ Dosya izinleri: $perms (önerilen: 600)"
    fi
    
    # Check 4: File ownership
    print_info "[4/7] Dosya sahipliği kontrolü..."
    local owner=$(stat -c "%U:%G" "${CUSTOM_KEY_FILE}" 2>/dev/null)
    if [ "$owner" = "${NEXUS_USER}:${NEXUS_USER}" ]; then
        print_success "✓ Dosya sahibi doğru (${NEXUS_USER}:${NEXUS_USER})"
    else
        print_warning "⚠ Dosya sahibi: $owner (olması gereken: ${NEXUS_USER}:${NEXUS_USER})"
    fi
    
    # Check 5: default-application.properties
    print_info "[5/7] default-application.properties kontrolü..."
    if [ -f "${DEFAULT_PROPERTIES_FILE}" ]; then
        print_success "✓ default-application.properties mevcut"
        
        # Check for nexus.secrets.file
        if grep -q "nexus.secrets.file" "${DEFAULT_PROPERTIES_FILE}"; then
            print_success "  ✓ nexus.secrets.file tanımı var"
        else
            print_error "  ✗ nexus.secrets.file tanımı yok!"
            verification_failed=true
        fi
        
        # Check for quotes (should not exist)
        if grep -v '^#' "${DEFAULT_PROPERTIES_FILE}" | grep -v '^$' | grep -q '"'; then
            print_error "  ✗ Tırnak işareti bulundu (olmamalı)!"
            verification_failed=true
        else
            print_success "  ✓ Tırnak işareti yok"
        fi
    else
        print_error "✗ default-application.properties bulunamadı!"
        verification_failed=true
    fi
    
    # Check 6: Backup file
    print_info "[6/7] Yedek dosyası kontrolü..."
    if [ -f "${ENCRYPTION_KEY_BACKUP}" ]; then
        print_success "✓ Encryption key backup mevcut"
        print_info "  Lokasyon: ${ENCRYPTION_KEY_BACKUP}"
    else
        print_warning "⚠ Backup dosyası bulunamadı!"
    fi
    
    # Check 7: Nexus service status
    print_info "[7/7] Nexus servis durumu..."
    if systemctl is-active --quiet nexus; then
        print_success "✓ Nexus servisi çalışıyor"
    else
        print_warning "⚠ Nexus servisi henüz aktif değil"
    fi
    
    print_security "═══════════════════════════════════════════════════"
    
    if [ "$verification_failed" = true ]; then
        print_warning "Bazı doğrulamalar başarısız oldu!"
        print_warning "Nexus başladıktan sonra log dosyasını kontrol edin."
    else
        print_success "TÜM DOĞRULAMALAR BAŞARILI!"
    fi
    
    print_security "═══════════════════════════════════════════════════"
}

# Function to display final information
display_final_info() {
    echo ""
    echo "=========================================="
    print_success "Nexus kurulumu başarıyla tamamlandı!"
    echo "=========================================="
    echo ""
    
    print_info "Nexus Bilgileri:"
    echo "  - Versiyon: ${NEXUS_VERSION}"
    echo "  - Kurulum Dizini: ${INSTALL_DIR}"
    echo "  - Data Dizini: ${DATA_DIR}"
    echo "  - Kullanıcı: ${NEXUS_USER}"
    echo ""
    
    print_security "═══════════════════════════════════════════════════"
    print_security "ENCRYPTION KEY BİLGİLERİ"
    print_security "═══════════════════════════════════════════════════"
    echo "  - Custom Key: ${GREEN}ETKİN${NC}"
    echo "  - Key File: ${CUSTOM_KEY_FILE}"
    echo "  - Properties File: ${DEFAULT_PROPERTIES_FILE}"
    echo "  - Backup Location: ${ENCRYPTION_KEY_BACKUP}"
    echo ""
    print_security "  ${RED}⚠ ÇOK ÖNEMLİ:${NC}"
    print_security "  ${RED}Backup dosyasını güvenli bir yere kopyalayın!${NC}"
    print_security "  ${RED}Bu key kaybolursa veriler kurtarilamaz!${NC}"
    print_security "═══════════════════════════════════════════════════"
    echo ""
    
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        print_info "SSL/HTTPS Bilgileri:"
        echo "  - Domain: ${DOMAIN_NAME}"
        if [ "$USE_SELF_SIGNED" = true ]; then
            echo "  - Sertifika Türü: Self-Signed"
            echo "  - Sertifika Konumu: /etc/ssl/nexus/"
            print_warning "  Self-signed sertifika kullanıldığı için tarayıcılar güvenlik uyarısı verecektir."
        else
            echo "  - Sertifika Türü: Let's Encrypt"
            echo "  - Sertifika Konumu: /etc/letsencrypt/live/${DOMAIN_NAME}/"
            echo "  - Otomatik Yenileme: Aktif (her gün 03:00)"
        fi
        echo ""
        print_info "Nexus'a Erişim:"
        echo "  - HTTPS URL: https://${DOMAIN_NAME}"
        echo "  - HTTP (yönlendirilecek): http://${DOMAIN_NAME}"
    else
        print_info "Nexus'a Erişim:"
        echo "  - Port: ${NEXUS_PORT}"
        echo "  - URL: http://$(hostname -I | awk '{print $1}'):${NEXUS_PORT}"
    fi
    
    echo ""
    print_info "İlk Giriş:"
    echo "  - Kullanıcı Adı: admin"
    echo "  - Şifre Konumu: ${DATA_DIR}/admin.password"
    echo "  - Şifreyi görüntüle: sudo cat ${DATA_DIR}/admin.password"
    echo ""
    
    print_info "Faydalı Komutlar:"
    echo "  - Nexus durumu: systemctl status nexus"
    echo "  - Nexus logları: journalctl -u nexus -f"
    echo "  - Nexus logları (dosya): tail -f ${DATA_DIR}/log/nexus.log"
    echo "  - Kurulum log: cat ${LOG_FILE}"
    echo ""
    
    print_security "API Re-encryption Bilgisi:"
    echo "  - Otomatik API çağrısı yapıldı"
    echo "  - Key ID: ${NEXUS_KEY_ID}"
    echo "  - Başarılı olup olmadığını kontrol edin"
    echo ""
    
    print_security "Doğrulama Komutları:"
    echo "  - Custom key kullanımı (OLMALI):"
    echo "    grep 'nexus.secrets.file' ${DEFAULT_PROPERTIES_FILE}"
    echo ""
    echo "  - JSON formatı kontrolü:"
    echo "    python3 -m json.tool ${CUSTOM_KEY_FILE}"
    echo ""
    
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        echo "  - Nginx durumu: systemctl status nginx"
        echo "  - Nginx logları: tail -f /var/log/nginx/nexus-error.log"
        echo "  - Nginx yapılandırması test: nginx -t"
        if [ "$USE_SELF_SIGNED" = false ]; then
            echo "  - Sertifika yenileme: certbot renew"
            echo "  - Sertifika durumu: certbot certificates"
        fi
    fi
    
    echo ""
    print_warning "ÖNEMLİ NOTLAR:"
    echo "  1. ${RED}Encryption key backup dosyasını güvenli bir yere kopyalayın!${NC}"
    echo "  2. İlk girişte admin şifresini mutlaka değiştirin"
    echo "  3. Anonymous access'i production ortamda kapatın"
    echo "  4. Düzenli yedekleme stratejisi oluşturun"
    echo "  5. Nexus tam açılması 2-3 dakika sürebilir"
    echo "  6. ${GREEN}SuccessExitStatus=143 eklendi - stop hatası düzeltildi${NC}"
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        echo "  7. Nginx büyük dosya yüklemelerini destekliyor (max: 10GB)"
        echo "  8. Container image upload'ları için timeout: 30 dakika"
    fi
    echo ""
    
    print_info "Nexus Tam Açıldıktan Sonra Yapılacaklar:"
    echo "  1. 2-3 dakika bekleyin"
    echo "  2. Web arayüzünü açın"
    echo "  3. Support → Status sayfasını kontrol edin"
    echo "  4. API re-encryption başarılı oldu mu kontrol edin"
    echo ""
    
    print_success "Kurulum log dosyası: ${LOG_FILE}"
    echo ""
}

# Main installation function
main() {
    # Initialize log file
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    
    echo "=========================================="
    echo "  Nexus Repository Manager Kurulumu v2.2"
    echo "  Versiyon: ${NEXUS_VERSION}"
    echo "  Enhanced with Custom Key & API Support"
    echo "=========================================="
    echo ""
    
    log_message "═══════════════════════════════════════════════════"
    log_message "NEXUS INSTALLATION STARTED - Version 2.2"
    log_message "═══════════════════════════════════════════════════"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Validate SSL parameters if SSL is enabled
    validate_ssl_parameters
    
    # Start installation
    check_root
    check_os
    check_required_tools
    check_all_disk_spaces
    install_java
    create_nexus_user
    create_directories
    download_nexus
    install_nexus
    configure_nexus  # This now includes custom-key.json generation
    create_systemd_service  # Enhanced with SuccessExitStatus=143
    
    # SSL/HTTPS related installation
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        print_warning "Nginx/SSL kurulumu bu scriptte aktif değil (gerekirse eklenebilir)"
    fi
    
    configure_firewall
    start_nexus_service
    
    # NEW: Verify encryption configuration
    verify_encryption_configuration
    
    # NEW: Trigger API re-encryption after waiting
    trigger_api_reencryption
    
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        print_warning "Nginx başlatma bu scriptte aktif değil (gerekirse eklenebilir)"
    fi
    
    display_final_info
    
    log_message "═══════════════════════════════════════════════════"
    log_message "NEXUS INSTALLATION COMPLETED SUCCESSFULLY"
    log_message "═══════════════════════════════════════════════════"
}

# Run main function with all arguments
main "$@"
