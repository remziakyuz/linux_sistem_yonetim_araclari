#!/bin/bash

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
NC='\033[0m' # No Color

# Function to print colored messages
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Function to check if script is run as root
check_root() {
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
                shift
                ;;
            --domain)
                DOMAIN_NAME="$2"
                shift 2
                ;;
            --email)
                SSL_EMAIL="$2"
                shift 2
                ;;
            --self-signed)
                USE_SELF_SIGNED=true
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
Nexus Repository Manager Kurulum Scripti
Kullanım: $0 [OPTIONS]

SEÇENEKLER:
    --enable-ssl           Nginx reverse proxy ve SSL/HTTPS'i etkinleştir
    --domain DOMAIN        SSL için domain adı (örn: nexus.example.com)
    --email EMAIL          Let's Encrypt için email adresi
    --self-signed          Let's Encrypt yerine self-signed sertifika kullan
    --help                 Bu yardım mesajını göster

ÖRNEKLER:
    # Basit kurulum (sadece HTTP)
    $0

    # Let's Encrypt ile SSL kurulumu
    $0 --enable-ssl --domain nexus.example.com --email admin@example.com

    # Self-signed sertifika ile SSL kurulumu
    $0 --enable-ssl --domain nexus.example.com --self-signed

NOT: SSL kullanımı için domain DNS kayıtlarının sunucuya işaret etmesi gerekir.
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
    
    if [ ! -d "$check_dir" ]; then
        print_error "Disk alanı kontrolü için geçerli dizin bulunamadı: $target_dir"
        return 1
    fi
    
    # Get available space in MB
    local available_space=$(df -BM "$check_dir" | awk 'NR==2 {print $4}' | sed 's/M//')
    
    print_info "${dir_description} için disk alanı kontrolü: ${available_space}MB mevcut, ${min_space_mb}MB gerekli"
    
    if [ "$available_space" -lt "$min_space_mb" ]; then
        print_error "${dir_description} için yetersiz disk alanı!"
        print_error "Mevcut: ${available_space}MB, Gerekli: ${min_space_mb}MB"
        return 1
    fi
    
    print_success "${dir_description} için yeterli disk alanı mevcut."
    return 0
}

# Function to check all required disk spaces
check_all_disk_spaces() {
    print_info "Disk alanı kontrolleri başlatılıyor..."
    
    local all_checks_passed=true
    
    check_disk_space "$INSTALL_DIR" "$MIN_INSTALL_SPACE" "Kurulum dizini (INSTALL_DIR)" || all_checks_passed=false
    check_disk_space "$REPO_DIR" "$MIN_REPO_SPACE" "Repository dizini (REPO_DIR)" || all_checks_passed=false
    check_disk_space "$WORK_DIR" "$MIN_WORK_SPACE" "Çalışma dizini (WORK_DIR)" || all_checks_passed=false
    
    if [ "$all_checks_passed" = false ]; then
        print_error "Disk alanı kontrolleri başarısız oldu. Yeterli alan sağladıktan sonra tekrar deneyin."
        exit 1
    fi
    
    print_success "Tüm disk alanı kontrolleri başarılı."
}

# Function to install Java
install_java() {
    print_info "JDK ${JAVA_VERSION} kontrolü yapılıyor..."
    
    # Check if JDK 17 is installed
    if rpm -qa | grep -q 'java-17-openjdk'; then
        print_success "JDK ${JAVA_VERSION} zaten yüklü, kurulum atlanıyor."
    else
        print_info "JDK ${JAVA_VERSION} kuruluyor..."
        if yum install -y java-17-openjdk java-17-openjdk-devel; then
            print_success "JDK ${JAVA_VERSION} başarıyla kuruldu."
        else
            print_error "JDK ${JAVA_VERSION} kurulumu başarısız oldu."
            exit 1
        fi
    fi
    
    # Verify JDK installation
    print_info "JDK versiyonu doğrulanıyor..."
    if ! command -v java &> /dev/null; then
        print_error "Java komutu bulunamadı. JDK kurulumu başarısız."
        exit 1
    fi
    
    java_version=$(java -version 2>&1 | head -n 1 | grep -o "17" | head -n 1)
    if [ "$java_version" != "$JAVA_VERSION" ]; then
        print_error "JDK ${JAVA_VERSION} doğrulaması başarısız."
        print_error "Beklenen: ${JAVA_VERSION}, Bulunan: ${java_version}"
        exit 1
    fi
    
    print_success "JDK ${JAVA_VERSION} kullanıma hazır."
}

# Function to create Nexus user
create_nexus_user() {
    print_info "Nexus kullanıcısı ve grubu oluşturuluyor..."
    
    # Create group if not exists
    if ! getent group ${NEXUS_GID} >/dev/null; then
        if groupadd -g ${NEXUS_GID} ${NEXUS_USER}; then
            print_success "Nexus grubu (GID: ${NEXUS_GID}) oluşturuldu."
        else
            print_error "Nexus grubu oluşturulamadı."
            exit 1
        fi
    else
        print_info "Nexus grubu zaten mevcut."
    fi
    
    # Create user if not exists
    if ! getent passwd ${NEXUS_UID} >/dev/null; then
        if useradd -u ${NEXUS_UID} -g ${NEXUS_GID} -m -d ${INSTALL_DIR} -s /sbin/nologin ${NEXUS_USER}; then
            print_success "Nexus kullanıcısı (UID: ${NEXUS_UID}) oluşturuldu."
        else
            print_error "Nexus kullanıcısı oluşturulamadı."
            exit 1
        fi
    else
        print_info "Nexus kullanıcısı zaten mevcut."
    fi
}

# Function to create directories
create_directories() {
    print_info "Gerekli dizinler oluşturuluyor..."
    
    local dirs=("${INSTALL_DIR}" "${REPO_DIR}" "${WORK_DIR}" "${DATA_DIR}")
    
    for dir in "${dirs[@]}"; do
        if mkdir -p "$dir"; then
            print_success "Dizin oluşturuldu: $dir"
        else
            print_error "Dizin oluşturulamadı: $dir"
            exit 1
        fi
    done
    
    # Set ownership
    print_info "Dizin sahiplikleri ayarlanıyor..."
    if chown -R ${NEXUS_USER}:${NEXUS_USER} ${INSTALL_DIR} ${REPO_DIR} ${WORK_DIR} ${DATA_DIR}; then
        print_success "Dizin sahiplikleri başarıyla ayarlandı."
    else
        print_error "Dizin sahiplikleri ayarlanamadı."
        exit 1
    fi
}

# Function to download or use existing Nexus archive
download_nexus() {
    print_info "Nexus arşivi kontrol ediliyor..."
    
    # Check if tar file exists in current directory
    if [ -f "./${NEXUS_TAR}" ]; then
        print_success "Mevcut Nexus arşivi bulundu, kullanılıyor."
        if cp ./${NEXUS_TAR} /tmp/; then
            print_success "Nexus arşivi /tmp dizinine kopyalandı."
        else
            print_error "Nexus arşivi /tmp dizinine kopyalanamadı."
            exit 1
        fi
    else
        print_info "Nexus Repository indiriliyor..."
        print_info "İndirme URL'si: ${NEXUS_DOWNLOAD_URL}"
        
        if curl -L -f -o /tmp/${NEXUS_TAR} ${NEXUS_DOWNLOAD_URL}; then
            print_success "Nexus Repository başarıyla indirildi."
        else
            print_error "Nexus Repository indirilemedi."
            print_error "URL'yi kontrol edin: ${NEXUS_DOWNLOAD_URL}"
            exit 1
        fi
    fi
    
    # Verify downloaded file exists and is not empty
    if [ ! -f "/tmp/${NEXUS_TAR}" ]; then
        print_error "Nexus arşiv dosyası bulunamadı: /tmp/${NEXUS_TAR}"
        exit 1
    fi
    
    if [ ! -s "/tmp/${NEXUS_TAR}" ]; then
        print_error "Nexus arşiv dosyası boş: /tmp/${NEXUS_TAR}"
        rm -f /tmp/${NEXUS_TAR}
        exit 1
    fi
    
    print_success "Nexus arşiv dosyası doğrulandı."
}

# Function to extract and install Nexus
install_nexus() {
    print_info "Nexus Repository kurulumu yapılıyor..."
    
    if tar -xzf /tmp/${NEXUS_TAR} -C ${INSTALL_DIR} --strip-components=1; then
        print_success "Nexus başarıyla çıkartıldı."
    else
        print_error "Nexus arşivi çıkartılamadı."
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
    rm -f /tmp/${NEXUS_TAR}
    print_success "Geçici dosyalar temizlendi."
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
}

# Function to create systemd service
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

[Install]
WantedBy=multi-user.target
EOL
    
    if [ $? -eq 0 ]; then
        print_success "Systemd servis dosyası oluşturuldu."
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
        return 0
    fi
    
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        # For Nginx proxy, open HTTP and HTTPS ports
        print_info "Nginx için HTTP ve HTTPS portları açılıyor..."
        
        if firewall-cmd --permanent --add-service=http; then
            print_success "HTTP (80) portu açıldı."
        else
            print_warning "HTTP portu açılamadı."
        fi
        
        if firewall-cmd --permanent --add-service=https; then
            print_success "HTTPS (443) portu açıldı."
        else
            print_warning "HTTPS portu açılamadı."
        fi
        
        # Nexus port should only be accessible from localhost
        print_info "Nexus portu sadece localhost'tan erişilebilir olacak."
    else
        # Direct access to Nexus
        if firewall-cmd --permanent --add-port=${NEXUS_PORT}/tcp; then
            print_success "Firewall kuralı eklendi: ${NEXUS_PORT}/tcp"
        else
            print_error "Firewall kuralı eklenemedi."
            exit 1
        fi
    fi
    
    if firewall-cmd --reload; then
        print_success "Firewall yeniden yüklendi."
    else
        print_error "Firewall yeniden yüklenemedi."
        exit 1
    fi
}

# Function to install Nginx
install_nginx() {
    if [ "$ENABLE_NGINX_PROXY" = false ]; then
        return 0
    fi
    
    print_info "Nginx reverse proxy kuruluyor..."
    
    if rpm -qa | grep -q 'nginx'; then
        print_success "Nginx zaten yüklü."
    else
        if yum install -y nginx; then
            print_success "Nginx başarıyla kuruldu."
        else
            print_error "Nginx kurulumu başarısız oldu."
            exit 1
        fi
    fi
    
    # Enable nginx service
    if systemctl enable nginx; then
        print_success "Nginx servisi sistem başlangıcında otomatik başlayacak."
    else
        print_warning "Nginx servisi etkinleştirilemedi."
    fi
}

# Function to install Certbot for Let's Encrypt
install_certbot() {
    if [ "$ENABLE_NGINX_PROXY" = false ] || [ "$USE_SELF_SIGNED" = true ]; then
        return 0
    fi
    
    print_info "Certbot (Let's Encrypt) kuruluyor..."
    
    # Install EPEL repository
    if ! rpm -qa | grep -q 'epel-release'; then
        if yum install -y epel-release; then
            print_success "EPEL repository eklendi."
        else
            print_warning "EPEL repository eklenemedi."
        fi
    fi
    
    # Install certbot and nginx plugin
    if yum install -y certbot python3-certbot-nginx; then
        print_success "Certbot başarıyla kuruldu."
    else
        print_error "Certbot kurulumu başarısız oldu."
        exit 1
    fi
}

# Function to generate self-signed certificate
generate_self_signed_cert() {
    if [ "$USE_SELF_SIGNED" = false ]; then
        return 0
    fi
    
    print_info "Self-signed SSL sertifikası oluşturuluyor..."
    
    local ssl_dir="/etc/ssl/nexus"
    mkdir -p ${ssl_dir}
    
    # Generate self-signed certificate
    if openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout ${ssl_dir}/nexus.key \
        -out ${ssl_dir}/nexus.crt \
        -subj "/C=TR/ST=Istanbul/L=Istanbul/O=Organization/CN=${DOMAIN_NAME}"; then
        print_success "Self-signed sertifika oluşturuldu."
        print_warning "DİKKAT: Self-signed sertifika kullanılıyor. Tarayıcılar güvenlik uyarısı verecektir."
    else
        print_error "Self-signed sertifika oluşturulamadı."
        exit 1
    fi
    
    # Set permissions
    chmod 600 ${ssl_dir}/nexus.key
    chmod 644 ${ssl_dir}/nexus.crt
}

# Function to obtain Let's Encrypt certificate
obtain_letsencrypt_cert() {
    if [ "$USE_SELF_SIGNED" = true ]; then
        return 0
    fi
    
    print_info "Let's Encrypt sertifikası alınıyor..."
    print_warning "Bu işlem için domain DNS kaydının bu sunucuya işaret etmesi gerekir."
    
    # Stop nginx temporarily if running
    systemctl stop nginx 2>/dev/null
    
    # Obtain certificate
    if certbot certonly --standalone --non-interactive --agree-tos \
        --email ${SSL_EMAIL} \
        -d ${DOMAIN_NAME}; then
        print_success "Let's Encrypt sertifikası başarıyla alındı."
    else
        print_error "Let's Encrypt sertifikası alınamadı."
        print_error "DNS ayarlarını kontrol edin ve domain'in bu sunucuya işaret ettiğinden emin olun."
        exit 1
    fi
    
    # Setup auto-renewal
    if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
        (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'") | crontab -
        print_success "Otomatik sertifika yenileme görevi eklendi."
    fi
}

# Function to configure Nginx reverse proxy
configure_nginx_proxy() {
    if [ "$ENABLE_NGINX_PROXY" = false ]; then
        return 0
    fi
    
    print_info "Nginx reverse proxy yapılandırılıyor..."
    
    local nginx_conf="/etc/nginx/conf.d/nexus.conf"
    local ssl_cert_path
    local ssl_key_path
    
    if [ "$USE_SELF_SIGNED" = true ]; then
        ssl_cert_path="/etc/ssl/nexus/nexus.crt"
        ssl_key_path="/etc/ssl/nexus/nexus.key"
    else
        ssl_cert_path="/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem"
        ssl_key_path="/etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem"
    fi
    
    # Create Nginx configuration
    cat <<EOF > ${nginx_conf}
# Nexus Repository Manager Reverse Proxy Configuration

# HTTP to HTTPS redirect
server {
    listen ${NGINX_PORT};
    server_name ${DOMAIN_NAME};
    
    # Let's Encrypt verification
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # Redirect all other traffic to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server
server {
    listen ${NGINX_SSL_PORT} ssl http2;
    server_name ${DOMAIN_NAME};
    
    # SSL Configuration
    ssl_certificate ${ssl_cert_path};
    ssl_certificate_key ${ssl_key_path};
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    
    # SSL session cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS (optional, uncomment if needed)
    # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Logging
    access_log /var/log/nginx/nexus-access.log;
    error_log /var/log/nginx/nexus-error.log;
    
    # Client body size (for large artifact uploads - e.g., Docker images, large JARs)
    # Set to 0 for unlimited, or specify a large value
    client_max_body_size 10G;
    
    # Client body timeout - how long to wait for client to send body
    client_body_timeout 300s;
    
    # Client header timeout
    client_header_timeout 60s;
    
    # Keepalive settings
    keepalive_timeout 300s;
    
    # Buffer settings for large uploads
    client_body_buffer_size 512k;
    client_body_temp_path /var/lib/nginx/tmp/client_body;
    
    # Proxy settings
    location / {
        proxy_pass http://127.0.0.1:${NEXUS_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        
        # Extended timeouts for large uploads (e.g., 3GB+ Docker images)
        proxy_connect_timeout 900;      # 15 minutes - connection establishment
        proxy_send_timeout 1800;        # 30 minutes - sending request to upstream
        proxy_read_timeout 1800;        # 30 minutes - reading response from upstream
        send_timeout 1800;              # 30 minutes - sending response to client
        
        # Disable buffering for large uploads (streaming mode)
        # This prevents Nginx from buffering the entire file before sending to Nexus
        proxy_request_buffering off;
        
        # Disable proxy buffering for downloads
        proxy_buffering off;
        
        # Large buffer sizes for better performance
        proxy_buffer_size 128k;
        proxy_buffers 8 128k;
        proxy_busy_buffers_size 256k;
    }
    
    # Docker registry support (if needed, uncomment and configure)
    # location /v2/ {
    #     proxy_pass http://127.0.0.1:${NEXUS_PORT}/v2/;
    #     proxy_set_header Host \$host;
    #     proxy_set_header X-Real-IP \$remote_addr;
    #     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    #     proxy_set_header X-Forwarded-Proto \$scheme;
    #     
    #     # Docker requires this
    #     client_max_body_size 0;
    #     chunked_transfer_encoding on;
    # }
}
EOF
    
    if [ $? -eq 0 ]; then
        print_success "Nginx yapılandırması oluşturuldu: ${nginx_conf}"
    else
        print_error "Nginx yapılandırması oluşturulamadı."
        exit 1
    fi
    
    # Test Nginx configuration
    print_info "Nginx yapılandırması test ediliyor..."
    if nginx -t; then
        print_success "Nginx yapılandırması geçerli."
    else
        print_error "Nginx yapılandırması geçersiz. Lütfen kontrol edin."
        exit 1
    fi
    
    # Configure SELinux for Nginx (if enabled)
    if command -v getenforce &> /dev/null && [ "$(getenforce)" != "Disabled" ]; then
        print_info "SELinux için Nginx izinleri ayarlanıyor..."
        setsebool -P httpd_can_network_connect 1 2>/dev/null || print_warning "SELinux httpd_can_network_connect ayarlanamadı."
    fi
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

# Function to start Nginx service
start_nginx_service() {
    if [ "$ENABLE_NGINX_PROXY" = false ]; then
        return 0
    fi
    
    print_info "Nginx servisi başlatılıyor..."
    
    if systemctl start nginx; then
        print_success "Nginx servisi başlatıldı."
    else
        print_error "Nginx servisi başlatılamadı."
        print_info "Nginx loglarını kontrol edin: journalctl -u nginx -f"
        exit 1
    fi
    
    if systemctl is-active --quiet nginx; then
        print_success "Nginx servisi çalışıyor."
    else
        print_warning "Nginx durumu belirsiz."
    fi
}

# Function to display final information
display_final_info() {
    echo ""
    echo "=========================================="
    print_success "Nexus kurulumu başarıyla tamamlandı!"
    echo "=========================================="
    echo ""
    print_info "Nexus Bilgileri:"
    echo "  - Kurulum Dizini: ${INSTALL_DIR}"
    echo "  - Data Dizini: ${DATA_DIR}"
    echo "  - Kullanıcı: ${NEXUS_USER}"
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
    echo "  1. İlk girişte admin şifresini mutlaka değiştirin"
    echo "  2. Anonymous access'i production ortamda kapatın"
    echo "  3. Düzenli yedekleme stratejisi oluşturun"
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        echo "  4. Nginx büyük dosya yüklemelerini destekliyor (max: 10GB)"
        echo "  5. Container image upload'ları için timeout: 30 dakika"
    fi
    if [ "$ENABLE_NGINX_PROXY" = true ] && [ "$USE_SELF_SIGNED" = false ]; then
        echo "  6. Let's Encrypt sertifikası otomatik yenilenecektir"
    fi
    echo ""
    
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        print_info "Büyük Dosya Upload Yapılandırması:"
        echo "  - Maximum dosya boyutu: 10GB"
        echo "  - Upload timeout: 30 dakika"
        echo "  - Streaming mode: Aktif (buffering kapalı)"
        echo "  - Docker image push: Destekleniyor"
        echo ""
        print_info "Özel ihtiyaçlar için:"
        echo "  - 10GB+ dosyalar: /etc/nginx/conf.d/nexus.conf → client_max_body_size"
        echo "  - Daha uzun timeout: proxy_read_timeout ve proxy_send_timeout değerlerini artırın"
        echo ""
    fi
}

# Main installation function
main() {
    echo "=========================================="
    echo "  Nexus Repository Manager Kurulumu"
    echo "  Versiyon: ${NEXUS_VERSION}"
    echo "=========================================="
    echo ""
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Validate SSL parameters if SSL is enabled
    validate_ssl_parameters
    
    # Start installation
    check_root
    check_os
    check_all_disk_spaces
    install_java
    create_nexus_user
    create_directories
    download_nexus
    install_nexus
    configure_nexus
    create_systemd_service
    
    # SSL/HTTPS related installation
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        install_nginx
        if [ "$USE_SELF_SIGNED" = true ]; then
            generate_self_signed_cert
        else
            install_certbot
            obtain_letsencrypt_cert
        fi
        configure_nginx_proxy
    fi
    
    configure_firewall
    start_nexus_service
    
    if [ "$ENABLE_NGINX_PROXY" = true ]; then
        start_nginx_service
    fi
    
    display_final_info
}

# Run main function with all arguments
main "$@"
