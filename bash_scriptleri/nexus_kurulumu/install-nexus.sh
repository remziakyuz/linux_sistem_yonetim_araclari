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

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
    echo -e "[INFO] $1"
}

# Function to check if script is run as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "Bu script root kullanıcısı ile çalıştırılmalıdır."
        exit 1
    fi
    print_success "Root yetki kontrolü başarılı."
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
    
    if firewall-cmd --permanent --add-port=${NEXUS_PORT}/tcp; then
        print_success "Firewall kuralı eklendi: ${NEXUS_PORT}/tcp"
    else
        print_error "Firewall kuralı eklenemedi."
        exit 1
    fi
    
    if firewall-cmd --reload; then
        print_success "Firewall yeniden yüklendi."
    else
        print_error "Firewall yeniden yüklenemedi."
        exit 1
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
    
    # Wait a moment and check service status
    sleep 3
    if systemctl is-active --quiet nexus; then
        print_success "Nexus servisi çalışıyor."
    else
        print_warning "Nexus servisi başlatıldı ancak durumu belirsiz. Kontrol edin: systemctl status nexus"
    fi
}

# Main installation function
main() {
    echo "=========================================="
    echo "  Nexus Repository Manager Kurulumu"
    echo "  Versiyon: ${NEXUS_VERSION}"
    echo "=========================================="
    echo ""
    
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
    configure_firewall
    start_nexus_service
    
    echo ""
    echo "=========================================="
    print_success "Nexus kurulumu başarıyla tamamlandı!"
    echo "=========================================="
    echo ""
    print_info "Nexus Bilgileri:"
    echo "  - Port: ${NEXUS_PORT}"
    echo "  - Kurulum Dizini: ${INSTALL_DIR}"
    echo "  - Data Dizini: ${DATA_DIR}"
    echo "  - Kullanıcı: ${NEXUS_USER}"
    echo ""
    print_info "Nexus'a erişim için:"
    echo "  - URL: http://$(hostname -I | awk '{print $1}'):${NEXUS_PORT}"
    echo "  - İlk giriş şifresi: ${DATA_DIR}/admin.password"
    echo ""
    print_info "Faydalı komutlar:"
    echo "  - Servis durumu: systemctl status nexus"
    echo "  - Logları görüntüle: journalctl -u nexus -f"
    echo "  - Servisi durdur: systemctl stop nexus"
    echo "  - Servisi başlat: systemctl start nexus"
    echo ""
}

# Run main function
main
