#!/usr/bin/env bash
# ==============================================================================
# ssl-trust-unified.sh — Kurumsal TLS/SSL güven (trust) dağıtım aracı
# ==============================================================================
# Amaç:
#   Yerel/kurumsal sertifikalı uygulamalara (FreeIPA, Satellite/Foreman, Git,
#   container registry vb.) güvenli erişimi tek adımda sağlamak:
#     1) Hedef host'lardan TLS sertifika zincirini (PEM) çeker
#     2) Zincirdeki CA (CA:TRUE) sertifikalarından ca-bundle üretir
#     3) OS trust store'a kurar
#        (RHEL/Fedora/OEL/Rocky/Alma, Debian/Ubuntu, SUSE, Arch, Alpine, Gentoo)
#     4) Podman/Docker certs.d/<host[:port]>/ca.crt yazar
#     5) Tarayıcı NSS DB'lerini günceller — Firefox / Chrome / Chromium / Edge /
#        Brave (snap ve flatpak kurulumları dahil)
#          → root modunda: tüm kullanıcılar (işlemler DOSYA SAHİBİ kullanıcı
#            kimliğiyle yapılır; sahiplik bozulmaz)
#          → --user-mode : yalnızca çalışan kullanıcı (sudo GEREKMEZ)
#     6) Java truststore'larına CA import eder (keytool)
#          → sistem JVM'leri, JAVA_HOME, SDKMAN
#          → RHEL/Debian'da OS trust ile otomatik senkron cacerts atlanır
#     7) Terminal/CLI kullanıcıları için PEM/CRT/DER/P7B + birleşik bundle üretir
#
# Sürüm  : 2.0
# Tarih  : 2026-07-07
#
# v2.0 DEĞİŞİKLİKLERİ (v1.2 üzerine):
#   [GÜVENLİK] eval tamamen kaldırıldı; tüm komutlar argüman dizisiyle çalışır.
#   [BUGFIX]  --dry-run artık gerçekten çalışır: zincir çekilir/analiz edilir,
#             kalıcı hiçbir değişiklik yapılmaz (dosyalar geçici dizinde).
#   [BUGFIX]  s_client çıktısındaki PEM dışı satırlar chain.pem'e sızmıyor.
#   [BUGFIX]  Root modunda NSS işlemleri hedef kullanıcı kimliğiyle yapılır
#             (runuser/sudo -u) — root sahipli cert9.db oluşmaz.
#   [BUGFIX]  Çoklu sertifikalı bundle'larda certutil/keytool'a sertifikalar
#             TEK TEK import edilir (önceden yalnız ilki eklenirdi).
#   [BUGFIX]  ~/.pki/nssdb "her zaman true" koşul hatası düzeltildi.
#   [BUGFIX]  parse hatasının alt-kabukta kaybolması (die-in-subshell) giderildi.
#   [BUGFIX]  Var olan dosya: içerik aynıysa atlanır (idempotent); farklıysa
#             --force olmadan DOKUNULMAZ, --force ile yedek alınıp yazılır.
#   [BUGFIX]  Root olarak çalışırken sudo gerekmez; root değilken sudo yoksa
#             erken ve net hata verilir.
#   [BUGFIX]  --profile, --base-domain olmadan verilirse artık hata verir
#             (önceden sessizce yutuluyordu).
#   [BUGFIX]  bash 4.2 (RHEL7) boş dizi + set -u uyumluluğu.
#   [YENİ]    Java truststore desteği (--install-java, --java-storepass).
#   [YENİ]    SUSE, Arch, Alpine aileleri; SELinux restorecon.
#   [YENİ]    snap/flatpak Chromium/Chrome/Edge/Brave NSS yolları.
#   [YENİ]    NSS/Java importları idempotent (aynı takma ad yenilenir).
#   [YENİ]    chain.p7b, cas/ca-NN.pem, all-ca-bundle.pem, env-hints.sh çıktıları.
#   [YENİ]    Sertifika özeti loglanır; süresi dolmuş sertifika uyarısı.
#   [YENİ]    IPv6 ([addr]:port), https:// öneki, port/host doğrulaması.
#   [YENİ]    Başarı/başarısızlık özeti; hata varsa exit 2 (CI dostu).
#   [KALDIRILDI] csplit bağımlılığı (awk ile taşınabilir bölme).
# ==============================================================================

set -euo pipefail
shopt -s nullglob
export LC_ALL=C
umask 022

VERSION="2.0"
RELEASE_DATE="2026-07-07"

# ---------- loglama ----------
log(){  printf '[%s] %s\n'        "$(date +'%F %T')" "$*"; }
warn(){ printf '[%s] WARNING: %s\n' "$(date +'%F %T')" "$*" >&2; }
err(){  printf '[%s] ERROR: %s\n'  "$(date +'%F %T')" "$*" >&2; }
die(){  err "$*"; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# ---------- yapılandırma (varsayılanlar) ----------
OUT_DIR="./ssl-trust-out"
INSTALL_SYSTEM=1
INSTALL_CONTAINERS=1
INSTALL_NSS=0
INSTALL_JAVA=1
USER_MODE=0
DRY_RUN=0
FORCE=0
TIMEOUT_SECS=12
JAVA_STOREPASS="changeit"

TARGETS=()
LOCAL_CA_FILES=()
AUTO_LOCAL_CA=0
BASE_DOMAIN=""
PROFILES=()
SVC_KV=()

OK_TARGETS=()
FAILED=()

IS_ROOT=0
[[ ${EUID:-$(id -u)} -eq 0 ]] && IS_ROOT=1

CERTUTIL_CHECKED=0
CERTUTIL_OK=0
TIMEOUT_WARNED=0

# ---------- yardım ----------
usage(){
  cat <<'EOF'
Usage:
  ssl-trust-unified.sh [options] --target host[:port] [--target host2 ...]

MODES
  Default (root/sudo)     : OS trust + Podman/Docker certs.d + Java truststore
                            + (optional --install-nss) all users' browsers
  --user-mode             : Does NOT require sudo. Updates only the current user's
                            browsers (Firefox/Chrome/Chromium/Edge/Brave; incl. snap+flatpak)
                            and the user's own Java installations (JAVA_HOME, SDKMAN).
                            OS trust and container registries are not touched.

TARGET OPTIONS
  --target <host[:port]>     Target (443 if no port). May be given multiple times.
                             IPv6: --target "[2001:db8::1]:8443"  Scheme accepted: https://host
  --from-file <path>         One host[:port] per line (blank lines and # comments supported).
  --profile <list>           Profile targets: all or comma-separated: freeipa,satellite,foreman,git,registry
                             (--base-domain is required)
  --base-domain <domain>     Domain for profile hosts (e.g.: example.com)
  --svc <name>=<host[:port]> Service host; if no port, the service default is used (registry=5000, others 443).
  --out <dir>                Output directory (default: ./ssl-trust-out)

INSTALL OPTIONS
  --no-install               Do not install anything; only generate files.
  --install-system           Install into the OS trust store (default: on)
  --no-install-system        Do not install into the OS trust store
  --install-containers       Install Podman/Docker certs.d (default: on)
  --no-install-containers    Do not install Podman/Docker certs.d
  --install-nss              Add to browser NSS DBs (requires certutil)
  --install-java             Add to Java truststores (default: on; requires keytool)
  --no-install-java          Do not add to Java truststores
  --java-storepass <pass>    Java keystore password (default: changeit)
  --all                      Shortcut: system + containers + nss + java

  --add-local-ca <path>      Also process a local CA file (may be given multiple times)
  --auto-local-ca            Automatically add known local CA files
                             (/etc/ipa/ca.crt, katello/foreman-proxy ca.pem ...)

  --timeout <sec>            openssl s_client wait time (default: 12)
  --dry-run                  Analyze and print what would be done; make NO PERMANENT CHANGES.
  --force                    Back up an existing file with different content and overwrite it.
  --version                  Print the version.
  -h, --help                 This help.

GENERATED FILES (per target, in <out>/<host_port>/):
  chain.pem        The full chain sent by the server
  chain.p7b        PKCS#7 form of the chain (for Java/Windows import)
  ca-bundle.pem    CA:TRUE certificates (leaf if none) — a .crt copy is also written
  ca-bundle.der    DER form of the FIRST certificate in the bundle (single certificate!)
  cas/ca-NN.pem    Each CA certificate as a separate file (used by NSS/Java imports)
Additionally:
  <out>/all-ca-bundle.pem   Union of unique CAs from all targets
  <out>/env-hints.sh        (--user-mode) environment variable suggestions for CLI tools

EXAMPLES
  # Root/sudo: OS trust + containers + Java (+NSS if you want, via --install-nss):
  sudo ./ssl-trust-unified.sh --target git.company.local --install-nss

  # Regular user (no sudo): browsers + user Java:
  ./ssl-trust-unified.sh --user-mode --target git.company.local

  # With profiles:
  sudo ./ssl-trust-unified.sh --profile all --base-domain company.local \
       --svc registry=registry.company.local:5000

  # Local CA file:
  ./ssl-trust-unified.sh --user-mode --add-local-ca ~/Downloads/company-ca.pem
EOF
}

# ---------- geçici alan ve temizlik ----------
TMP_ROOT="$(mktemp -d)" || die "Failed to create temporary directory."
cleanup(){ rm -rf "${TMP_ROOT}" 2>/dev/null || true; }
trap cleanup EXIT

ALLCA_DIR="${TMP_ROOT}/allca"
mkdir -p "${ALLCA_DIR}"

# ---------- yetki yardımcıları (eval YOK) ----------
# as_root: değiştirici sistem işlemleri. root ise doğrudan, değilse sudo ile.
as_root(){
  if [[ "$DRY_RUN" -eq 1 ]]; then echo "DRY-RUN(root)> $*"; return 0; fi
  if [[ "$USER_MODE" -eq 1 ]]; then warn "operation requiring root skipped (--user-mode): $*"; return 0; fi
  if [[ "$IS_ROOT" -eq 1 ]]; then "$@"; else sudo "$@"; fi
}

# as_user <kullanıcı> <komut...>: komutu hedef kullanıcı kimliğiyle çalıştırır.
as_user(){
  local u="$1"; shift
  if [[ "$DRY_RUN" -eq 1 ]]; then echo "DRY-RUN(user:${u})> $*"; return 0; fi
  if [[ "$u" == "$(id -un)" ]]; then
    "$@"
  elif [[ "$IS_ROOT" -eq 1 ]] && have runuser; then
    runuser -u "$u" -- "$@"
  elif have sudo; then
    sudo -u "$u" -- "$@"
  else
    warn "runuser/sudo not available; skipped operation for user '${u}': $*"
    return 1
  fi
}

# ---------- OS ailesi tespiti ----------
detect_os_family(){
  local id="" like=""
  if [[ -r /etc/os-release ]]; then
    id="$(. /etc/os-release 2>/dev/null; echo "${ID:-}")"
    like="$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")"
  fi
  case "$id" in
    fedora|rhel|centos|rocky|almalinux|ol|oraclelinux|amzn) echo rhel;   return;;
    debian|ubuntu|linuxmint|pop|raspbian|kali|alpine)       echo debian; return;;
    opensuse*|sles|sled)                                    echo suse;   return;;
    arch|manjaro|endeavouros)                               echo arch;   return;;
    gentoo)                                                 echo gentoo; return;;
  esac
  case " ${like} " in
    *" rhel "*|*" fedora "*|*" centos "*) echo rhel;   return;;
    *" debian "*|*" ubuntu "*)            echo debian; return;;
    *" suse "*)                           echo suse;   return;;
    *" arch "*)                           echo arch;   return;;
  esac
  [[ -f /etc/redhat-release || -f /etc/oracle-release ]] && { echo rhel;   return; }
  [[ -f /etc/debian_version ]]                            && { echo debian; return; }
  [[ -f /etc/gentoo-release ]]                            && { echo gentoo; return; }
  echo unknown
}

# ---------- hedef ayrıştırma / doğrulama ----------
sanitize_key(){ printf '%s' "$1" | tr ':[]' '___'; }

# Sonuçları global HOST/PORT'a yazar (alt-kabukta die kaybolmasın diye).
HOST=""; PORT=""
parse_target(){
  local orig="$1" t="$1"
  t="${t#https://}"; t="${t#tls://}"; t="${t#tcp://}"; t="${t%%/*}"
  HOST=""; PORT=""
  if [[ "$t" == \[*\]* || "$t" == \[*\] ]]; then          # IPv6: [addr] veya [addr]:port
    HOST="${t%%]*}"; HOST="${HOST#[}"
    local rest="${t#*]}"
    if [[ "$rest" == :* ]]; then PORT="${rest#:}"; else PORT=443; fi
  elif [[ "$t" == *:* ]]; then
    HOST="${t%%:*}"; PORT="${t##*:}"
  else
    HOST="$t"; PORT=443
  fi
  if [[ -z "$HOST" ]]; then err "Invalid target: ${orig}"; return 1; fi
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    err "Invalid port: ${orig}"; return 1
  fi
  if ! [[ "$HOST" =~ ^[A-Za-z0-9._:-]+$ ]]; then
    err "Invalid host name (allowed: letters/digits/._:-): ${orig}"; return 1
  fi
  return 0
}

# ---------- zincir çekme / ayrıştırma ----------
fetch_chain(){
  # Salt-okuma ağ işlemi: dry-run'da da çalışır (analiz için); diske yalnız
  # EFFECTIVE_OUT altına yazar (dry-run'da geçici dizindir).
  local host="$1" port="$2" out_pem="$3"
  local raw="${TMP_ROOT}/raw-$$-${RANDOM}.txt"
  local -a cmd=(openssl s_client -showcerts -connect "${host}:${port}")
  # SNI: IP adreslerine servername gönderilmez
  if ! [[ "$host" =~ ^[0-9.]+$ || "$host" == *:* ]]; then
    cmd+=(-servername "$host")
  fi
  if have timeout; then
    cmd=(timeout "${TIMEOUT_SECS}s" "${cmd[@]}")
  elif [[ "$TIMEOUT_WARNED" -eq 0 ]]; then
    warn "timeout command not found; openssl s_client may hang for a long time."
    TIMEOUT_WARNED=1
  fi
  "${cmd[@]}" </dev/null >"$raw" 2>/dev/null || true
  # Yalnızca PEM bloklarını al (aradaki s:/i: özet satırları dahil edilmez)
  awk '/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{p=0}' \
    "$raw" > "$out_pem"
  rm -f "$raw" 2>/dev/null || true
  grep -q -- "-----BEGIN CERTIFICATE-----" "$out_pem"
}

split_chain(){
  # csplit bağımlılığı olmadan taşınabilir PEM bölme
  local chain="$1" outdir="$2"
  mkdir -p "$outdir"
  rm -f "$outdir"/cert-*.pem
  awk -v dir="$outdir" '
    /-----BEGIN CERTIFICATE-----/ { n++; fname=sprintf("%s/cert-%02d.pem", dir, n); p=1 }
    p { print > fname }
    /-----END CERTIFICATE-----/   { p=0; close(fname) }
  ' "$chain"
}

is_ca(){
  openssl x509 -in "$1" -noout -text 2>/dev/null | grep -q 'CA:TRUE'
}

log_cert_line(){
  local pem="$1" subj end
  subj="$(openssl x509 -in "$pem" -noout -subject 2>/dev/null | sed 's/^subject=//; s/^ *//')" || true
  end="$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null | cut -d= -f2-)" || true
  [[ -n "$subj" ]] || return 0
  log "    certificate: ${subj} (expires: ${end:-?})"
  if ! openssl x509 -in "$pem" -noout -checkend 0 >/dev/null 2>&1; then
    warn "    EXPIRED certificate: ${subj}"
  fi
}

collect_ca(){
  # Birleşik bundle için parmak izine göre benzersiz toplama
  local fp
  fp="$(openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':')" || return 0
  [[ -n "$fp" ]] || return 0
  [[ -f "${ALLCA_DIR}/${fp}.pem" ]] || cp "$1" "${ALLCA_DIR}/${fp}.pem"
}

build_ca_bundle(){
  # chain -> out_bundle (CA:TRUE olanlar) + cas_out/ca-NN.pem (tek tek)
  local chain="$1" out="$2" cas_out="$3"
  local tmp="${TMP_ROOT}/split-$$-${RANDOM}"
  mkdir -p "$tmp" "$cas_out"
  rm -f "$cas_out"/ca-*.pem
  split_chain "$chain" "$tmp"
  : > "$out"
  local f n=0 found=0 first="" last=""
  for f in "$tmp"/cert-*.pem; do
    [[ -z "$first" ]] && first="$f"
    last="$f"
    log_cert_line "$f"
    if is_ca "$f"; then
      n=$((n+1))
      cp "$f" "$(printf '%s/ca-%02d.pem' "$cas_out" "$n")"
      cat "$f" >> "$out"; printf '\n' >> "$out"
      found=1
    fi
  done
  if [[ -z "$first" ]]; then
    err "Failed to parse chain: ${chain}"
    return 1
  fi
  if [[ "$found" -eq 0 ]]; then
    warn "  No CA:TRUE certificate found in chain; the first certificate (leaf/self-signed) will be used."
    cp "$first" "${cas_out}/ca-01.pem"
    cat "$first" > "$out"
  fi
  # Bilgi: sunucu kök CA göndermiyorsa not düş
  if [[ -n "$last" ]]; then
    local sh ih
    sh="$(openssl x509 -in "$last" -noout -subject_hash 2>/dev/null)" || true
    ih="$(openssl x509 -in "$last" -noout -issuer_hash  2>/dev/null)" || true
    if [[ -n "$sh" && -n "$ih" && "$sh" != "$ih" ]]; then
      log "  Info: the server does not send the root CA; the bundle contains an intermediate CA" \
          "(sufficient for modern validators)."
    fi
  fi
  return 0
}

# ---------- güvenli dosya kurulumu (root alanı) ----------
install_file_root(){
  # kullanım: install_file_root <src> <dst> [mode]
  # - içerik aynıysa atla (idempotent)
  # - farklıysa: --force yoksa DOKUNMA; --force ile yedekle + yaz
  local src="$1" dst="$2" mode="${3:-0644}"
  if [[ -f "$dst" ]] && cmp -s "$src" "$dst" 2>/dev/null; then
    log "  same content, skipped: ${dst}"
    return 0
  fi
  if [[ -f "$dst" ]]; then
    if [[ "$FORCE" -eq 1 ]]; then
      local b="${dst}.bak.$(date +%s)"
      as_root cp -a "$dst" "$b" || { warn "  backup failed: ${dst}"; return 1; }
      log "  backup: ${b}"
    else
      warn "  existing file has different content; skipped because --force was not given: ${dst}"
      return 0
    fi
  fi
  as_root install -m "$mode" "$src" "$dst" || { warn "  copy failed: ${dst}"; return 1; }
  if have restorecon; then
    as_root restorecon -F "$dst" 2>/dev/null || true
  fi
  return 0
}

# ---------- OS trust kurulumu ----------
install_system_trust(){
  local bundle="$1" name="$2" family dst
  if [[ "$USER_MODE" -eq 1 ]]; then
    warn "OS trust store installation skipped in --user-mode."
    return 0
  fi
  family="$(detect_os_family)"
  case "$family" in
    rhel)
      dst="/etc/pki/ca-trust/source/anchors/${name}.crt"
      as_root mkdir -p /etc/pki/ca-trust/source/anchors || true
      install_file_root "$bundle" "$dst" || return 0
      as_root update-ca-trust extract || warn "update-ca-trust failed."
      ;;
    debian|gentoo)
      dst="/usr/local/share/ca-certificates/${name}.crt"
      as_root mkdir -p /usr/local/share/ca-certificates || true
      install_file_root "$bundle" "$dst" || return 0
      as_root update-ca-certificates || warn "update-ca-certificates failed."
      ;;
    suse)
      dst="/etc/pki/trust/anchors/${name}.crt"
      as_root mkdir -p /etc/pki/trust/anchors || true
      install_file_root "$bundle" "$dst" || return 0
      as_root update-ca-certificates || warn "update-ca-certificates failed."
      ;;
    arch)
      dst="/etc/ca-certificates/trust-source/anchors/${name}.crt"
      as_root mkdir -p /etc/ca-certificates/trust-source/anchors || true
      install_file_root "$bundle" "$dst" || return 0
      as_root update-ca-trust || warn "update-ca-trust failed."
      ;;
    *)
      warn "Unsupported distribution (system trust skipped). Files were still generated."
      ;;
  esac
  return 0
}

# ---------- Konteyner registry certs.d ----------
install_containers(){
  local bundle="$1" host="$2" port="$3" key wrote=0
  if [[ "$USER_MODE" -eq 1 ]]; then
    warn "Container certs.d installation skipped in --user-mode."
    return 0
  fi
  key="$host"
  [[ "$port" != "443" ]] && key="${host}:${port}"
  if have podman || [[ -d /etc/containers ]]; then
    as_root mkdir -p "/etc/containers/certs.d/${key}" || true
    install_file_root "$bundle" "/etc/containers/certs.d/${key}/ca.crt" || true
    wrote=1
  fi
  if have docker || [[ -d /etc/docker ]]; then
    as_root mkdir -p "/etc/docker/certs.d/${key}" || true
    install_file_root "$bundle" "/etc/docker/certs.d/${key}/ca.crt" || true
    wrote=1
  fi
  [[ "$wrote" -eq 0 ]] && log "  podman/docker not found; certs.d skipped."
  return 0
}

# ---------- NSS / certutil ----------
ensure_certutil(){
  if [[ "$CERTUTIL_CHECKED" -eq 1 ]]; then
    [[ "$CERTUTIL_OK" -eq 1 ]]; return
  fi
  CERTUTIL_CHECKED=1
  if have certutil; then CERTUTIL_OK=1; return 0; fi
  CERTUTIL_OK=0
  warn "certutil not found; browser NSS imports will be skipped."
  case "$(detect_os_family)" in
    rhel)   warn "Install with: sudo dnf -y install nss-tools";;
    debian) warn "Install with: sudo apt -y install libnss3-tools";;
    suse)   warn "Install with: sudo zypper install mozilla-nss-tools";;
    arch)   warn "Install with: sudo pacman -S nss";;
    gentoo) warn "Install with: sudo emerge -av dev-libs/nss (USE=utils)";;
    *)      warn "Install with: nss-tools / libnss3-tools depending on your distribution";;
  esac
  return 1
}

nss_db_init(){
  # kullanım: nss_db_init <owner> <sql|dbm> <dbdir>
  local owner="$1" dbtype="$2" dbdir="$3" dbfile="cert9.db"
  [[ "$dbtype" == "dbm" ]] && dbfile="cert8.db"
  [[ -f "${dbdir}/${dbfile}" ]] && return 0
  as_user "$owner" mkdir -p "$dbdir" || return 1
  as_user "$owner" certutil -d "${dbtype}:${dbdir}" -N --empty-password >/dev/null 2>&1 || true
  return 0
}

nss_add(){
  # kullanım: nss_add <owner> <sql|dbm> <dbdir> <nick> <pem>
  # idempotent: aynı takma ad varsa silinip yeniden eklenir (sertifika yenileme)
  local owner="$1" dbtype="$2" dbdir="$3" nick="$4" pem="$5"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if as_user "$owner" certutil -L -d "${dbtype}:${dbdir}" -n "$nick" >/dev/null 2>&1; then
      as_user "$owner" certutil -D -d "${dbtype}:${dbdir}" -n "$nick" >/dev/null 2>&1 || true
    fi
  fi
  as_user "$owner" certutil -A -d "${dbtype}:${dbdir}" -n "$nick" -t "CT,," -i "$pem" \
    >/dev/null 2>&1 || warn "    certutil add failed: ${dbdir} (${nick})"
  return 0
}

nss_add_dir(){
  # cas_dir içindeki her sertifikayı tek tek ekler (çoklu-PEM bug'ının çözümü)
  local owner="$1" dbtype="$2" dbdir="$3" nick="$4" cas_dir="$5"
  local -a certs=( "$cas_dir"/ca-*.pem )
  [[ ${#certs[@]} -gt 0 ]] || return 0
  local i=0 c a
  for c in "${certs[@]}"; do
    i=$((i+1))
    a="$nick"; [[ ${#certs[@]} -gt 1 ]] && a="${nick}-${i}"
    nss_add "$owner" "$dbtype" "$dbdir" "$a" "$c"
  done
  return 0
}

install_user_nss(){
  # kullanım: install_user_nss <cas_dir> <nick> <home> <owner>
  local cas_dir="$1" nick="$2" home="$3" owner="$4"
  [[ -d "$home" ]] || return 0
  local updated=0 db dir

  # 1) Chrome/Chromium/Edge/Brave ortak NSS DB'leri (sql)
  #    Ana ~/.pki/nssdb yoksa oluşturulur; snap/flatpak olanlara yalnızca
  #    zaten varsa dokunulur (boş uygulama dizini yaratmamak için).
  nss_db_init "$owner" sql "${home}/.pki/nssdb" || true
  local -a sqldbs=(
    "${home}/.pki/nssdb"
    "${home}/snap/chromium/current/.pki/nssdb"
    "${home}/.var/app/com.google.Chrome/.pki/nssdb"
    "${home}/.var/app/com.microsoft.Edge/.pki/nssdb"
    "${home}/.var/app/org.chromium.Chromium/.pki/nssdb"
    "${home}/.var/app/com.brave.Browser/.pki/nssdb"
  )
  for db in "${sqldbs[@]}"; do
    if [[ -f "${db}/cert9.db" ]] || { [[ "$DRY_RUN" -eq 1 ]] && [[ "$db" == "${home}/.pki/nssdb" ]]; }; then
      log "    Updating NSS (Chrome family): ${db}"
      nss_add_dir "$owner" sql "$db" "$nick" "$cas_dir"
      updated=1
    fi
  done

  # 2) Firefox profilleri (klasik + snap + flatpak)
  local -a ff_bases=(
    "${home}/.mozilla/firefox"
    "${home}/snap/firefox/common/.mozilla/firefox"
    "${home}/.var/app/org.mozilla.firefox/.mozilla/firefox"
  )
  local base
  for base in "${ff_bases[@]}"; do
    [[ -d "$base" ]] || continue
    while IFS= read -r -d '' db; do
      dir="$(dirname "$db")"
      if [[ "$db" == *cert9.db ]]; then
        log "    Updating NSS (Firefox sql): ${dir}"
        nss_add_dir "$owner" sql "$dir" "$nick" "$cas_dir"
      else
        log "    Updating NSS (Firefox dbm): ${dir}"
        nss_add_dir "$owner" dbm "$dir" "$nick" "$cas_dir"
      fi
      updated=1
    done < <(find "$base" -maxdepth 2 -type f \( -name cert9.db -o -name cert8.db \) -print0 2>/dev/null || true)
  done

  [[ "$updated" -eq 0 ]] && warn "  No NSS profile found to update for ${home}."
  return 0
}

install_all_users_nss(){
  # root modu: /root + /home/* (uid >= 1000 olan sahipler)
  local cas_dir="$1" nick="$2"
  ensure_certutil || return 0
  local d owner uid
  for d in /root /home/*; do
    [[ -d "$d" ]] || continue
    owner="$(stat -c %U "$d" 2>/dev/null || true)"
    [[ -n "$owner" ]] || continue
    uid="$(id -u "$owner" 2>/dev/null || echo -1)"
    if [[ "$d" == "/root" ]] || [[ "$uid" -ge 1000 ]]; then
      log "  NSS: ${d} (user: ${owner})"
      install_user_nss "$cas_dir" "$nick" "$d" "$owner" || true
    fi
  done
  return 0
}

install_current_user_nss(){
  local cas_dir="$1" nick="$2"
  ensure_certutil || return 0
  log "  Updating current user NSS: ${HOME}"
  install_user_nss "$cas_dir" "$nick" "${HOME}" "$(id -un)"
  return 0
}

# ---------- Java truststore ----------
java_is_system_managed(){
  # RHEL/Debian: sistem-java cacerts OS trust ile otomatik senkron olur
  local real
  real="$(readlink -f "$1" 2>/dev/null || echo "$1")"
  case "$real" in
    /etc/pki/ca-trust/extracted/java/*|/etc/pki/java/*|/etc/ssl/certs/java/*) return 0;;
  esac
  return 1
}

java_stores(){
  # Aday cacerts dosyalarını (realpath'e göre tekilleştirilmiş) listeler
  local -a raw=()
  local d r
  for d in /usr/lib/jvm/*/lib/security/cacerts  /usr/lib/jvm/*/jre/lib/security/cacerts \
           /usr/java/*/lib/security/cacerts     /usr/java/*/jre/lib/security/cacerts \
           /opt/*/lib/security/cacerts          /opt/*/jre/lib/security/cacerts; do
    [[ -e "$d" ]] && raw+=("$d")
  done
  if [[ -n "${JAVA_HOME:-}" ]]; then
    for d in "${JAVA_HOME}/lib/security/cacerts" "${JAVA_HOME}/jre/lib/security/cacerts"; do
      [[ -e "$d" ]] && raw+=("$d")
    done
  fi
  for d in "${HOME}"/.sdkman/candidates/java/*/lib/security/cacerts; do
    [[ -e "$d" ]] && raw+=("$d")
  done
  local -A seen=()
  for d in ${raw[@]+"${raw[@]}"}; do
    r="$(readlink -f "$d" 2>/dev/null || echo "$d")"
    [[ -n "${seen[$r]+x}" ]] && continue
    seen[$r]=1
    printf '%s\n' "$d"
  done
  return 0
}

java_run(){
  # kullanım: java_run <store> <komut...>  — yazma yetkisine göre çalıştırır
  local store="$1"; shift
  if [[ "$DRY_RUN" -eq 1 ]]; then echo "DRY-RUN(java)> $*"; return 0; fi
  if [[ -w "$store" ]]; then
    "$@"
  elif [[ "$USER_MODE" -eq 1 ]]; then
    warn "    no write permission (--user-mode), skipped: ${store}"
    return 1
  else
    as_root "$@"
  fi
}

java_import_dir(){
  # kullanım: java_import_dir <store> <cas_dir> <nick>
  local store="$1" cas_dir="$2" nick="$3"
  local jhome kt
  jhome="${store%/lib/security/cacerts}"; jhome="${jhome%/jre}"
  if [[ -x "${jhome}/bin/keytool" ]]; then
    kt="${jhome}/bin/keytool"
  elif have keytool; then
    kt="keytool"
  else
    warn "    keytool not found; skipped: ${store}"
    return 0
  fi
  local -a certs=( "$cas_dir"/ca-*.pem )
  [[ ${#certs[@]} -gt 0 ]] || return 0
  local i=0 c alias
  for c in "${certs[@]}"; do
    i=$((i+1))
    alias="$nick"; [[ ${#certs[@]} -gt 1 ]] && alias="${nick}-${i}"
    alias="$(printf '%s' "$alias" | tr '[:upper:]' '[:lower:]')"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      # idempotent: aynı takma ad varsa yenile (sil + ekle)
      if "$kt" -list -keystore "$store" -storepass "$JAVA_STOREPASS" -alias "$alias" >/dev/null 2>&1; then
        java_run "$store" "$kt" -delete -alias "$alias" \
          -keystore "$store" -storepass "$JAVA_STOREPASS" >/dev/null 2>&1 || true
      fi
    fi
    java_run "$store" "$kt" -importcert -noprompt -trustcacerts -alias "$alias" \
      -file "$c" -keystore "$store" -storepass "$JAVA_STOREPASS" >/dev/null 2>&1 || \
      warn "    keytool import failed: ${store} (${alias}) — is the storepass correct?"
  done
  return 0
}

install_java(){
  local cas_dir="$1" nick="$2"
  local -a stores=()
  local s
  while IFS= read -r s; do [[ -n "$s" ]] && stores+=("$s"); done < <(java_stores)
  if [[ ${#stores[@]} -eq 0 ]]; then
    log "  No Java installation found; Java import skipped."
    return 0
  fi
  for s in "${stores[@]}"; do
    if java_is_system_managed "$s"; then
      log "  Java (auto-synced with OS trust, skipping): ${s}"
      continue
    fi
    if [[ "$USER_MODE" -eq 1 && ! -w "$s" ]]; then
      warn "  Java (no write permission, skipped in --user-mode): ${s}"
      continue
    fi
    log "  Updating Java truststore: ${s}"
    java_import_dir "$s" "$cas_dir" "$nick"
  done
  return 0
}

# ---------- Yerel CA otomatik tespiti ----------
auto_local_ca(){
  local -a cands=(
    "/etc/ipa/ca.crt"
    "/etc/pki/katello/certs/katello-default-ca.crt"
    "/etc/foreman-proxy/ssl/ca.pem"
    "/etc/foreman-proxy/ssl/certs/ca.pem"
    "/etc/foreman-proxy/ssl/ca/ca.pem"
    "/etc/foreman-proxy/certs/ca.pem"
  )
  local f
  for f in "${cands[@]}"; do
    [[ -f "$f" ]] && LOCAL_CA_FILES+=("$f")
  done
  return 0
}

# ---------- Profil / servis yardımcıları ----------
default_port_for_service(){
  case "$1" in
    registry) echo "5000" ;;
    *)        echo "443"  ;;
  esac
}

normalize_service_name(){
  case "$1" in
    ipa)     echo "freeipa"   ;;
    katello) echo "satellite" ;;
    gitrepo) echo "git"       ;;
    *)       echo "$1"        ;;
  esac
}

add_target_with_default_port(){
  local svc="$1" hostport="$2"
  svc="$(normalize_service_name "$svc")"
  [[ -z "$hostport" ]] && return 0
  if [[ "$hostport" == *:* ]]; then
    TARGETS+=("$hostport")
  else
    TARGETS+=("${hostport}:$(default_port_for_service "$svc")")
  fi
  return 0
}

expand_profiles(){
  local kv svc hp p
  for kv in ${SVC_KV[@]+"${SVC_KV[@]}"}; do
    svc="${kv%%=*}"
    hp="${kv#*=}"
    add_target_with_default_port "$svc" "$hp"
  done

  if [[ ${#PROFILES[@]} -gt 0 && -z "$BASE_DOMAIN" ]]; then
    die "--base-domain is required for --profile."
  fi
  [[ -n "$BASE_DOMAIN" ]] || return 0

  # 'all' açılımı
  local -a plist=()
  local has_all=0
  for p in ${PROFILES[@]+"${PROFILES[@]}"}; do
    p="$(normalize_service_name "$p")"
    [[ "$p" == "all" ]] && has_all=1 || plist+=("$p")
  done
  [[ "$has_all" -eq 1 ]] && plist=(freeipa satellite foreman git registry)

  for p in ${plist[@]+"${plist[@]}"}; do
    case "$p" in
      freeipa|satellite|foreman|git|registry)
        add_target_with_default_port "$p" "${p}.${BASE_DOMAIN}" ;;
      *)
        warn "Unknown profile skipped: ${p} (valid: freeipa,satellite,foreman,git,registry,all)" ;;
    esac
  done
  return 0
}

# ---------- Argüman ayrıştırma ----------
[[ $# -gt 0 ]] || { usage; exit 1; }

req_val(){ [[ $# -ge 2 && -n "${2:-}" ]] || die "Value required for ${1}."; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)           req_val "$1" "${2:-}"; TARGETS+=("$2"); shift 2;;
    --target=*)         TARGETS+=("${1#*=}"); shift;;
    --from-file)
      req_val "$1" "${2:-}"
      [[ -f "$2" ]] || die "File not found: $2"
      while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"           # CRLF temizliği
        line="${line%%#*}"             # yorum
        read -r tok _rest <<< "$line" || true
        [[ -z "${tok:-}" ]] && continue
        [[ -n "${_rest:-}" ]] && warn "--from-file: extra field ignored: ${_rest}"
        TARGETS+=("$tok")
      done < "$2"
      shift 2;;
    --profile)          req_val "$1" "${2:-}"; IFS=',' read -ra _p <<< "$2"; PROFILES+=("${_p[@]}"); shift 2;;
    --profile=*)        IFS=',' read -ra _p <<< "${1#*=}"; PROFILES+=("${_p[@]}"); shift;;
    --base-domain)      req_val "$1" "${2:-}"; BASE_DOMAIN="$2"; shift 2;;
    --base-domain=*)    BASE_DOMAIN="${1#*=}"; shift;;
    --svc)
      req_val "$1" "${2:-}"
      [[ "$2" == *=* ]] || die "--svc format: name=host[:port] (given: $2)"
      SVC_KV+=("$2"); shift 2;;
    --svc=*)
      _v="${1#*=}"
      [[ "$_v" == *=* ]] || die "--svc format: name=host[:port] (given: $_v)"
      SVC_KV+=("$_v"); shift;;
    --out)              req_val "$1" "${2:-}"; OUT_DIR="$2"; shift 2;;
    --out=*)            OUT_DIR="${1#*=}"; shift;;
    --user-mode)        USER_MODE=1; INSTALL_NSS=1; shift;;
    --no-install)       INSTALL_SYSTEM=0; INSTALL_CONTAINERS=0; INSTALL_NSS=0; INSTALL_JAVA=0; shift;;
    --install-system)   INSTALL_SYSTEM=1; shift;;
    --no-install-system)     INSTALL_SYSTEM=0; shift;;
    --install-containers)    INSTALL_CONTAINERS=1; shift;;
    --no-install-containers) INSTALL_CONTAINERS=0; shift;;
    --install-nss)      INSTALL_NSS=1; shift;;
    --install-java)     INSTALL_JAVA=1; shift;;
    --no-install-java)  INSTALL_JAVA=0; shift;;
    --java-storepass)   req_val "$1" "${2:-}"; JAVA_STOREPASS="$2"; shift 2;;
    --java-storepass=*) JAVA_STOREPASS="${1#*=}"; shift;;
    --add-local-ca)     req_val "$1" "${2:-}"; [[ -f "$2" ]] || die "CA file not found: $2"; LOCAL_CA_FILES+=("$2"); shift 2;;
    --add-local-ca=*)   _f="${1#*=}"; [[ -f "$_f" ]] || die "CA file not found: $_f"; LOCAL_CA_FILES+=("$_f"); shift;;
    --auto-local-ca)    AUTO_LOCAL_CA=1; shift;;
    --timeout)
      req_val "$1" "${2:-}"
      [[ "$2" =~ ^[0-9]+$ ]] || die "--timeout must be numeric: $2"
      TIMEOUT_SECS="$2"; shift 2;;
    --timeout=*)
      _t="${1#*=}"
      [[ "$_t" =~ ^[0-9]+$ ]] || die "--timeout must be numeric: $_t"
      TIMEOUT_SECS="$_t"; shift;;
    --dry-run)          DRY_RUN=1; shift;;
    --force)            FORCE=1; shift;;
    --all)              INSTALL_SYSTEM=1; INSTALL_CONTAINERS=1; INSTALL_NSS=1; INSTALL_JAVA=1; shift;;
    --version)          echo "ssl-trust-unified ${VERSION} (${RELEASE_DATE})"; exit 0;;
    -h|--help)          usage; exit 0;;
    *)                  die "Unknown parameter: $1 (help: --help)";;
  esac
done

# ---------- Ön kontroller ve normalizasyon ----------
need openssl
need awk

# user-mode: root alanı kurulumları her koşulda kapalı
if [[ "$USER_MODE" -eq 1 ]]; then
  INSTALL_SYSTEM=0
  INSTALL_CONTAINERS=0
fi

[[ "$AUTO_LOCAL_CA" -eq 1 ]] && auto_local_ca
expand_profiles

if [[ ${#TARGETS[@]} -eq 0 && ${#LOCAL_CA_FILES[@]} -eq 0 ]]; then
  die "At least one --target or --add-local-ca/--auto-local-ca is required."
fi

# root değil + user-mode değil + kurulum isteniyor → sudo şart
if [[ "$IS_ROOT" -eq 0 && "$USER_MODE" -eq 0 && "$DRY_RUN" -eq 0 ]]; then
  if [[ "$INSTALL_SYSTEM" -eq 1 || "$INSTALL_CONTAINERS" -eq 1 || \
        "$INSTALL_NSS" -eq 1    || "$INSTALL_JAVA" -eq 1 ]]; then
    have sudo || die "You are not root and sudo is not available. Either run as root or use --user-mode."
  fi
fi

# Çıkış dizini: dry-run'da geçici alanda (kalıcı iz bırakma)
if [[ "$DRY_RUN" -eq 1 ]]; then
  EFFECTIVE_OUT="${TMP_ROOT}/out"
  log "DRY-RUN: no permanent changes will be made; files will be analyzed in a temporary directory."
else
  EFFECTIVE_OUT="$OUT_DIR"
fi
mkdir -p "$EFFECTIVE_OUT" || die "Failed to create output directory: ${EFFECTIVE_OUT}"

if [[ "$USER_MODE" -eq 1 ]]; then
  log "*** USER MODE — sudo NOT required ***"
  log "    Only browser NSS DBs under ${HOME} and user Java installations will be updated."
  ensure_certutil || true
fi

log "Version : ${VERSION} (${RELEASE_DATE})"
log "OUT_DIR : ${EFFECTIVE_OUT}"
log "SYSTEM: ${INSTALL_SYSTEM} | CONTAINERS: ${INSTALL_CONTAINERS} | NSS: ${INSTALL_NSS} | JAVA: ${INSTALL_JAVA} | USER_MODE: ${USER_MODE} | DRY: ${DRY_RUN} | FORCE: ${FORCE}"

# ---------- Hedef işleme ----------
process_target(){
  local target="$1"
  if ! parse_target "$target"; then
    FAILED+=("$target")
    return 0
  fi
  local host="$HOST" port="$PORT"
  local key tdir chain cabundle cas_dir nick
  key="$host"; [[ "$port" != "443" ]] && key="${host}:${port}"
  tdir="${EFFECTIVE_OUT}/$(sanitize_key "$key")"
  mkdir -p "$tdir"
  chain="${tdir}/chain.pem"
  cabundle="${tdir}/ca-bundle.pem"
  cas_dir="${tdir}/cas"
  nick="CA-${host}-${port}"

  log "Target: ${host}:${port}"
  log "  fetching certificate chain..."
  if ! fetch_chain "$host" "$port" "$chain"; then
    warn "  failed to fetch chain (${host}:${port}) — skipped"
    FAILED+=("$target")
    return 0
  fi

  log "  building ca-bundle"
  if ! build_ca_bundle "$chain" "$cabundle" "$cas_dir"; then
    warn "  failed to build ca-bundle (${host}:${port}) — skipped"
    FAILED+=("$target")
    return 0
  fi
  cp "$cabundle" "${tdir}/ca-bundle.crt"
  openssl x509 -in "$cabundle" -outform der -out "${tdir}/ca-bundle.der" 2>/dev/null || true
  openssl crl2pkcs7 -nocrl -certfile "$chain" -out "${tdir}/chain.p7b" 2>/dev/null || true
  local c
  for c in "$cas_dir"/ca-*.pem; do collect_ca "$c"; done

  if [[ "$INSTALL_SYSTEM" -eq 1 ]]; then
    log "  installing OS trust"
    install_system_trust "$cabundle" "$(sanitize_key "$key")"
  fi
  if [[ "$INSTALL_CONTAINERS" -eq 1 ]]; then
    log "  installing Podman/Docker certs.d"
    install_containers "$cabundle" "$host" "$port"
  fi
  if [[ "$INSTALL_NSS" -eq 1 ]]; then
    if [[ "$USER_MODE" -eq 1 ]]; then
      install_current_user_nss "$cas_dir" "$nick"
    else
      log "  NSS import (all users)"
      install_all_users_nss "$cas_dir" "$nick"
    fi
  fi
  if [[ "$INSTALL_JAVA" -eq 1 ]]; then
    install_java "$cas_dir" "$nick"
  fi
  OK_TARGETS+=("$target")
  log "  done: ${host}:${port}"
  return 0
}

# ---------- Yerel CA işleme ----------
process_local_ca(){
  local f="$1" base name tdir cas_dir tmp i c
  [[ -f "$f" ]] || { warn "Local CA not found: $f"; FAILED+=("$f"); return 0; }
  base="$(basename "$f")"; name="local_${base%.*}"
  tdir="${EFFECTIVE_OUT}/$(sanitize_key "$name")"
  cas_dir="${tdir}/cas"
  mkdir -p "$tdir" "$cas_dir"
  rm -f "$cas_dir"/ca-*.pem

  log "Local CA: ${f}"
  cp "$f" "${tdir}/ca-bundle.pem"
  tmp="${TMP_ROOT}/local-$$-${RANDOM}"
  mkdir -p "$tmp"
  split_chain "$f" "$tmp"
  i=0
  for c in "$tmp"/cert-*.pem; do
    i=$((i+1))
    cp "$c" "$(printf '%s/ca-%02d.pem' "$cas_dir" "$i")"
    log_cert_line "$c"
    collect_ca "$c"
  done
  if [[ "$i" -eq 0 ]]; then
    warn "  no PEM certificate found: ${f} — skipped"
    FAILED+=("$f")
    return 0
  fi
  cp "${tdir}/ca-bundle.pem" "${tdir}/ca-bundle.crt"
  openssl x509 -in "${tdir}/ca-bundle.pem" -outform der -out "${tdir}/ca-bundle.der" 2>/dev/null || true

  if [[ "$INSTALL_SYSTEM" -eq 1 ]]; then
    log "  installing OS trust (local CA)"
    install_system_trust "${tdir}/ca-bundle.pem" "$(sanitize_key "$name")"
  fi
  if [[ "$INSTALL_NSS" -eq 1 ]]; then
    if [[ "$USER_MODE" -eq 1 ]]; then
      install_current_user_nss "$cas_dir" "CA-${name}"
    else
      log "  NSS import (all users)"
      install_all_users_nss "$cas_dir" "CA-${name}"
    fi
  fi
  if [[ "$INSTALL_JAVA" -eq 1 ]]; then
    install_java "$cas_dir" "CA-${name}"
  fi
  OK_TARGETS+=("$f")
  return 0
}

# ---------- Tekilleştirme ----------
dedup_list(){
  # stdin: satırlar → stdout: sıra korunarak benzersiz satırlar
  awk '!seen[$0]++'
}

dedup_targets(){
  local -a out=()
  local t
  while IFS= read -r t; do
    [[ -n "$t" ]] && out+=("$t")
  done < <(printf '%s\n' ${TARGETS[@]+"${TARGETS[@]}"} | dedup_list)
  TARGETS=(${out[@]+"${out[@]}"})
}

dedup_local_cas(){
  local -a out=()
  local f
  while IFS= read -r f; do
    [[ -n "$f" ]] && out+=("$f")
  done < <(printf '%s\n' ${LOCAL_CA_FILES[@]+"${LOCAL_CA_FILES[@]}"} | dedup_list)
  LOCAL_CA_FILES=(${out[@]+"${out[@]}"})
}

# ---------- Son çıktılar ----------
write_env_hints(){
  local bundle="$1" out="${EFFECTIVE_OUT}/env-hints.sh"
  cat > "$out" <<EOF
# Generated by ssl-trust-unified ${VERSION} — $(date +'%F %T')
# Environment variable suggestions for terminal/CLI tools (source at your own discretion):
#
#   source "${out}"
#
# NODE_EXTRA_CA_CERTS  : EXTRA CA for Node.js (added on top of system CAs — safe)
export NODE_EXTRA_CA_CERTS="${bundle}"
#
# The following REPLACE the system CA stores; enable only if really needed:
# export GIT_SSL_CAINFO="${bundle}"        # git
# export CURL_CA_BUNDLE="${bundle}"        # curl
# export REQUESTS_CA_BUNDLE="${bundle}"    # python-requests
# export SSL_CERT_FILE="${bundle}"         # many openssl-based tools
EOF
  log "Environment hints: ${out}"
}

finalize_outputs(){
  local -a fps=( "${ALLCA_DIR}"/*.pem )
  [[ ${#fps[@]} -gt 0 ]] || return 0
  local out="${EFFECTIVE_OUT}/all-ca-bundle.pem"
  cat "${fps[@]}" > "$out"
  log "Combined CA bundle: ${out} (${#fps[@]} unique certificates)"
  [[ "$USER_MODE" -eq 1 ]] && write_env_hints "$out"
  return 0
}

# ---------- Ana akış ----------
dedup_targets
dedup_local_cas

for t in ${TARGETS[@]+"${TARGETS[@]}"};        do process_target  "$t"; done
for f in ${LOCAL_CA_FILES[@]+"${LOCAL_CA_FILES[@]}"}; do process_local_ca "$f"; done

finalize_outputs

# ---------- Özet ve çıkış kodu ----------
log "----------------------------------------------------------------------"
log "DONE. Succeeded: ${#OK_TARGETS[@]}  Failed: ${#FAILED[@]}  Output: ${EFFECTIVE_OUT}"
if [[ "$DRY_RUN" -eq 1 ]]; then
  log "DRY-RUN: no permanent changes were made."
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
  warn "Failed target(s): ${FAILED[*]}"
  exit 2
fi
exit 0
