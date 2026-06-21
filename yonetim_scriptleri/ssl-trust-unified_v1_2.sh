#!/usr/bin/env bash
set -euo pipefail

# ssl-trust-unified.sh
# - Hostlardan TLS sertifika zinciri (PEM) çeker
# - Zincirde CA:TRUE olan sertifikaları seçip ca-bundle üretir (bulamazsa uyarır)
# - OS trust store'a ekler (Fedora/RHEL/OEL/Rocky + Debian/Ubuntu + Gentoo)  [sudo gerekir]
# - Podman/Docker certs.d/<host[:port]>/ca.crt yazar                          [sudo gerekir]
# - Firefox/Chrome/Edge (Linux) NSS DB'lerine otomatik ekler (certutil)
#     → sudo varsa: tüm kullanıcılar için (/root + /home/*)
#     → sudo yoksa:  yalnızca çalışan kullanıcının home dizini (sudo GEREKMEZ)
# - Tarayıcı import için PEM/CRT/DER dosyaları üretir
#
# Sürüm  : 1.2
# Tarih  : 2025-06-07

VERSION="1.2"
RELEASE_DATE="2025-06-07"

log(){ printf '[%s] %s\n' "$(date +'%F %T')" "$*"; }
warn(){ printf '[%s] UYARI: %s\n' "$(date +'%F %T')" "$*" >&2; }
die(){ printf '[%s] HATA: %s\n' "$(date +'%F %T')" "$*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Gerekli komut yok: $1"; }

# ---------- yapılandırma ----------
OUT_DIR="./ssl-trust-out"
INSTALL_SYSTEM=1
INSTALL_CONTAINERS=1
INSTALL_NSS=0
USER_MODE=0          # Normal kullanıcı modu (yalnızca $HOME, sudo yok)
DRY_RUN=0
FORCE=0
TIMEOUT_SECS=12
TARGETS=()
LOCAL_CA_FILES=()
AUTO_LOCAL_CA=0

BASE_DOMAIN=""
PROFILES=()
SVC_KV=()

# ---------- yardım ----------
usage(){
  cat <<'EOF'
Kullanım:
  ssl-trust-unified.sh [seçenekler] --target host[:port] [--target host2 ...]

MODLAR
  Varsayılan (root/sudo)  : OS trust store + Podman/Docker certs.d + (isteğe bağlı) tüm kullanıcı NSS
  --user-mode             : sudo GEREKTIRMEZ. Yalnızca çalışan kullanıcının tarayıcıları (Firefox,
                            Chrome, Edge) için NSS DB güncellenir + ~/ssl-trust-out/ altına dosyalar yazılır.
                            OS trust ve container kayıtları yapılmaz (sudo olmadan mümkün değil).

HEDEF SEÇENEKLERİ
  --target <host[:port]>     Hedef (port yoksa 443). Birden çok kez verilebilir.
  --from-file <path>         İçinde host[:port] satırları olan dosya.
  --profile <liste>          Profil hedefleri: all veya virgüllü: freeipa,satellite,foreman,git,registry
  --base-domain <domain>     Profil için host üretirken kullanılacak domain (örn: example.com)
  --svc <ad>=<host[:port]>   Servis host'u ver; port yoksa servis varsayılanı kullanılır.
  --out <dir>                Çıkış dizini (varsayılan: ./ssl-trust-out)

KURULUM SEÇENEKLERİ (sudo gerekir; --user-mode'da etkisiz)
  --no-install               Hiç kurulum yapma, sadece dosya üret.
  --install-system           OS trust store'a kur (varsayılan: açık)
  --no-install-system        OS trust store'a kurma
  --install-containers       Podman/Docker certs.d kur (varsayılan: açık)
  --no-install-containers    Podman/Docker certs.d kurma
  --install-nss              Firefox/Chrome/Edge NSS DB'lerine de ekle (certutil gerekir)
  --all                      Kısa yol: --install-system --install-containers --install-nss

  --add-local-ca <path>      Yerel CA dosyasını da işle (birden çok kez)
  --auto-local-ca            Bu makinede bilinen CA dosyalarını otomatik ekle
                             (/etc/ipa/ca.crt, katello/foreman-proxy ca.pem ...)

  --timeout <sec>            openssl s_client bekleme süresi (varsayılan: 12)
  --dry-run                  Komutları yaz, çalıştırma.
  --force                    Var olan dosyaların üstüne yaz (yedek alır)
  -h, --help                 Bu yardım

Üretilen dosyalar (hedef başına):
  <out>/<host_port>/chain.pem       (tüm zincir)
  <out>/<host_port>/ca-bundle.pem   (CA:TRUE olanlar; yoksa leaf)
  <out>/<host_port>/ca-bundle.crt   (kopya)
  <out>/<host_port>/ca-bundle.der   (DER, tarayıcı import için)

NORMAL KULLANICI HIZLI KULLANIM
  # Firefox / Chrome / Edge için NSS güncelle (sudo yok):
  ./ssl-trust-unified.sh --user-mode --target git.sirket.local

  # Birden fazla hedef:
  ./ssl-trust-unified.sh --user-mode \
      --target freeipa.sirket.local \
      --target registry.sirket.local:5000

  # Yerel CA dosyası varsa:
  ./ssl-trust-unified.sh --user-mode --add-local-ca ~/Downloads/sirket-ca.pem \
      --target git.sirket.local
EOF
}

# ---------- çalıştırma yardımcıları ----------
run(){
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN> $*"
  else
    eval "$@"
  fi
}

# sudo_run: root modunda sudo kullanır; user-mode'da uyarı verir ve atlar
sudo_run(){
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN(sudo)> $*"
    return 0
  fi
  if [[ "$USER_MODE" -eq 1 ]]; then
    warn "sudo gerektiren işlem atlandı (--user-mode): $*"
    return 0
  fi
  sudo bash -c "$*"
}

# ---------- OS tespiti ----------
detect_os_family(){
  if [[ -f /etc/gentoo-release ]]; then echo gentoo; return; fi
  if [[ -f /etc/redhat-release ]] || [[ -f /etc/rocky-release ]] || [[ -f /etc/oracle-release ]]; then echo rhel; return; fi
  if [[ -f /etc/debian_version ]]; then echo debian; return; fi
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release || true
    case "${ID:-}" in
      fedora|rhel|centos|rocky|almalinux|ol|oraclelinux) echo rhel; return;;
      debian|ubuntu|linuxmint|pop) echo debian; return;;
      gentoo) echo gentoo; return;;
    esac
  fi
  echo unknown
}

# ---------- yardımcı fonksiyonlar ----------
sanitize_key(){ echo "$1" | sed 's/:/_/g'; }

parse_host_port(){
  local t="$1" host port
  if [[ "$t" == *:* ]]; then host="${t%%:*}"; port="${t##*:}"; else host="$t"; port=443; fi
  [[ -n "$host" ]] || die "Geçersiz target: $t"
  [[ -n "$port" ]] || port=443
  echo "$host" "$port"
}

fetch_chain(){
  local host="$1" port="$2" out_pem="$3"
  local raw
  raw="$(mktemp)"
  if command -v timeout >/dev/null 2>&1; then
    run "timeout ${TIMEOUT_SECS}s openssl s_client -showcerts -servername '${host}' -connect '${host}:${port}' </dev/null >'${raw}' 2>/dev/null || true"
  else
    warn "timeout komutu yok; openssl s_client uzun sürebilir."
    run "openssl s_client -showcerts -servername '${host}' -connect '${host}:${port}' </dev/null >'${raw}' 2>/dev/null || true"
  fi
  run "awk 'BEGIN{c=0} /BEGIN CERTIFICATE/{c++} {if(c>0) print} /END CERTIFICATE/{print \"\"}' '${raw}' > '${out_pem}'"
  rm -f "${raw}" || true
  grep -q "BEGIN CERTIFICATE" "${out_pem}"
}

split_chain(){
  local chain_pem="$1" out_dir="$2"
  run "mkdir -p '${out_dir}'"
  run "csplit -q -f '${out_dir}/cert-' -b '%02d.pem' '${chain_pem}' '/-----BEGIN CERTIFICATE-----/' '{*}' >/dev/null 2>&1 || true"
  run "find '${out_dir}' -type f -name 'cert-00.pem' -size 0 -delete 2>/dev/null || true"
}

is_ca(){
  local pem="$1"
  openssl x509 -in "${pem}" -noout -text 2>/dev/null | grep -qE 'Basic Constraints:.*CA:TRUE|CA:TRUE'
}

build_ca_bundle(){
  local chain_pem="$1" out_bundle="$2"
  local tmp
  tmp="$(mktemp -d)"
  split_chain "${chain_pem}" "${tmp}"
  : > "${out_bundle}"
  local found=0
  for f in "${tmp}"/cert-*.pem; do
    [[ -f "$f" ]] || continue
    if is_ca "$f"; then
      cat "$f" >> "${out_bundle}"
      printf "\n" >> "${out_bundle}"
      found=1
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    warn "Zincirde CA:TRUE bulunamadı; leaf sertifika trust'a uygun olmayabilir. İlk sertifika eklenecek."
    local first
    first="$(ls -1 "${tmp}"/cert-*.pem 2>/dev/null | head -n1 || true)"
    [[ -n "$first" ]] || die "Zincir parse edilemedi: ${chain_pem}"
    cat "$first" > "${out_bundle}"
  fi
  rm -rf "${tmp}" || true
}

backup_if_exists(){
  local path="$1" runner="${2:-sudo_run}"
  if [[ -f "$path" && "$FORCE" -eq 1 ]]; then
    local b="${path}.bak.$(date +%s)"
    if [[ "$runner" == "run" ]]; then
      run "cp -a '${path}' '${b}'"
    else
      sudo_run "cp -a '${path}' '${b}'"
    fi
    log "Yedek: ${b}"
  fi
}

# ---------- OS trust kurulumu (sudo) ----------
install_system_trust(){
  local bundle_pem="$1" name="$2" family dst
  if [[ "$USER_MODE" -eq 1 ]]; then
    warn "OS trust store kurulumu --user-mode'da atlandı. Tarayıcı NSS güncellemesi yapılacak."
    return 0
  fi
  family="$(detect_os_family)"
  case "$family" in
    rhel)
      dst="/etc/pki/ca-trust/source/anchors/${name}.crt"
      sudo_run "mkdir -p /etc/pki/ca-trust/source/anchors"
      backup_if_exists "$dst"
      sudo_run "cp '${bundle_pem}' '${dst}' && chmod 0644 '${dst}'"
      sudo_run "update-ca-trust extract"
      ;;
    debian|gentoo)
      dst="/usr/local/share/ca-certificates/${name}.crt"
      sudo_run "mkdir -p /usr/local/share/ca-certificates"
      backup_if_exists "$dst"
      sudo_run "cp '${bundle_pem}' '${dst}' && chmod 0644 '${dst}'"
      sudo_run "update-ca-certificates"
      ;;
    *)
      die "Desteklenmeyen dağıtım/OS (system trust)."
      ;;
  esac
}

# ---------- Konteyner registry (sudo) ----------
install_containers(){
  local bundle_pem="$1" host="$2" port="$3" key
  if [[ "$USER_MODE" -eq 1 ]]; then
    warn "Konteyner certs.d kurulumu --user-mode'da atlandı."
    return 0
  fi
  key="$host"
  [[ "$port" != 443 ]] && key="${host}:${port}"
  local pdir="/etc/containers/certs.d/${key}"
  local ddir="/etc/docker/certs.d/${key}"
  sudo_run "mkdir -p '${pdir}' '${ddir}'"
  backup_if_exists "${pdir}/ca.crt"
  backup_if_exists "${ddir}/ca.crt"
  sudo_run "cp '${bundle_pem}' '${pdir}/ca.crt' && cp '${bundle_pem}' '${ddir}/ca.crt'"
  sudo_run "chmod 0644 '${pdir}/ca.crt' '${ddir}/ca.crt'"
}

# ---------- NSS / certutil ----------
ensure_certutil(){
  if command -v certutil >/dev/null 2>&1; then return 0; fi
  warn "certutil bulunamadı; NSS otomatik import atlanacak."
  case "$(detect_os_family)" in
    rhel)   warn "Kurulum: sudo dnf -y install nss-tools";;
    debian) warn "Kurulum: sudo apt -y install libnss3-tools";;
    gentoo) warn "Kurulum: sudo emerge -av app-misc/nss";;
    *)      warn "Kurulum: dağıtımınıza göre nss-tools veya libnss3-tools";;
  esac
  return 1
}

# NSS veritabanına tek sertifika ekle
nss_add(){
  local dbtype="$1" dbdir="$2" nick="$3" certpem="$4"
  if [[ ! -d "$dbdir" ]]; then
    warn "NSS DB dizini bulunamadı: $dbdir"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN> certutil -A -d ${dbtype}:${dbdir} -n \"${nick}\" -t \"CT,,\" -i \"${certpem}\""
    return 0
  fi
  certutil -A -d "${dbtype}:${dbdir}" -n "${nick}" -t "CT,," -i "${certpem}" >/dev/null 2>&1 || \
    warn "  certutil ekleme başarısız: ${dbdir}"
}

# NSS DB oluştur (yoksa)
nss_init(){
  local dbtype="$1" dbdir="$2"
  if [[ "$dbtype" == "sql" ]]; then
    [[ -f "${dbdir}/cert9.db" ]] && return 0
  else
    [[ -f "${dbdir}/cert8.db" ]] && return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN> certutil -d ${dbtype}:${dbdir} -N --empty-password"
    return 0
  fi
  mkdir -p "$dbdir"
  certutil -d "${dbtype}:${dbdir}" -N --empty-password >/dev/null 2>&1 || true
}

# ---- Kullanıcı başına NSS ----
# home: hedef kullanıcının home dizini
install_user_nss(){
  local certpem="$1" nick="$2" home="$3"
  [[ -d "$home" ]] || return 0

  local updated=0

  # 1) Chrome/Chromium/Edge shared NSS DB: ~/.pki/nssdb (sql)
  local nssdb="${home}/.pki/nssdb"
  if [[ -d "$nssdb" ]] || [[ ! -f "${nssdb}/cert9.db" ]]; then
    nss_init "sql" "$nssdb"
    if [[ -d "$nssdb" ]]; then
      log "    NSS (Chrome/Edge) güncelleniyor: ${nssdb}"
      nss_add "sql" "$nssdb" "$nick" "$certpem"
      updated=1
    fi
  fi

  # 2) Firefox profilleri (~/.mozilla/firefox)
  local ff_base="${home}/.mozilla/firefox"
  if [[ -d "$ff_base" ]]; then
    while IFS= read -r -d '' db; do
      local dir
      dir="$(dirname "$db")"
      if [[ "$db" == *cert9.db ]]; then
        log "    NSS (Firefox sql) güncelleniyor: ${dir}"
        nss_add "sql" "$dir" "$nick" "$certpem"
      else
        log "    NSS (Firefox dbm) güncelleniyor: ${dir}"
        nss_add "dbm" "$dir" "$nick" "$certpem"
      fi
      updated=1
    done < <(find "$ff_base" -maxdepth 2 -type f \( -name cert9.db -o -name cert8.db \) -print0 2>/dev/null || true)
  fi

  # 3) Firefox Snap profili: ~/snap/firefox/common/.mozilla/firefox
  local ff_snap="${home}/snap/firefox/common/.mozilla/firefox"
  if [[ -d "$ff_snap" ]]; then
    while IFS= read -r -d '' db; do
      local dir
      dir="$(dirname "$db")"
      if [[ "$db" == *cert9.db ]]; then
        log "    NSS (Firefox Snap sql) güncelleniyor: ${dir}"
        nss_add "sql" "$dir" "$nick" "$certpem"
      else
        log "    NSS (Firefox Snap dbm) güncelleniyor: ${dir}"
        nss_add "dbm" "$dir" "$nick" "$certpem"
      fi
      updated=1
    done < <(find "$ff_snap" -maxdepth 2 -type f \( -name cert9.db -o -name cert8.db \) -print0 2>/dev/null || true)
  fi

  # 4) Flatpak Firefox: ~/.var/app/org.mozilla.firefox/.mozilla/firefox
  local ff_flatpak="${home}/.var/app/org.mozilla.firefox/.mozilla/firefox"
  if [[ -d "$ff_flatpak" ]]; then
    while IFS= read -r -d '' db; do
      local dir
      dir="$(dirname "$db")"
      if [[ "$db" == *cert9.db ]]; then
        log "    NSS (Firefox Flatpak sql) güncelleniyor: ${dir}"
        nss_add "sql" "$dir" "$nick" "$certpem"
      fi
      updated=1
    done < <(find "$ff_flatpak" -maxdepth 2 -type f -name cert9.db -print0 2>/dev/null || true)
  fi

  # 5) Chromium (~/.config/chromium → genelde ~/.pki/nssdb kullanır ama yine de kontrol)
  local chromium_nss="${home}/.config/chromium/Default/Network/Certificates"
  # Chromium NSS için ~/.pki/nssdb zaten yeterli; burada ek işlem gerekmez.

  # 6) Microsoft Edge (~/.config/microsoft-edge)
  # Edge de sistem NSS (sql:~/.pki/nssdb) kullanır; yukarıda kapsandı.

  if [[ "$updated" -eq 0 ]]; then
    warn "  ${home} için güncellenecek NSS profili bulunamadı."
  fi
}

# --install-nss (root mod): tüm kullanıcılar
install_all_users_nss(){
  local certpem="$1" nick="$2"
  ensure_certutil || return 0

  if [[ "$USER_MODE" -eq 1 ]]; then
    log "  Kullanıcı NSS güncelleniyor: ${HOME}"
    install_user_nss "$certpem" "$nick" "${HOME}"
    return 0
  fi

  install_user_nss "$certpem" "$nick" "/root" || true
  if [[ -d /home ]]; then
    for d in /home/*; do
      [[ -d "$d" ]] || continue
      local u uid
      u="$(basename "$d")"
      uid="$(id -u "$u" 2>/dev/null || echo 0)"
      if [[ "$uid" -ge 1000 ]]; then
        install_user_nss "$certpem" "$nick" "$d" || true
      fi
    done
  fi
}

# --user-mode: yalnızca çalışan kullanıcının NSS
install_current_user_nss(){
  local certpem="$1" nick="$2"
  ensure_certutil || return 0
  log "  Kullanıcı NSS güncelleniyor: ${HOME}"
  install_user_nss "$certpem" "$nick" "${HOME}"
}

# ---------- Yerel CA otomatik tespit ----------
auto_local_ca(){
  local cands=(
    "/etc/ipa/ca.crt"
    "/etc/pki/katello/certs/katello-default-ca.crt"
    "/etc/foreman-proxy/ssl/ca.pem"
    "/etc/foreman-proxy/ssl/certs/ca.pem"
    "/etc/foreman-proxy/ssl/ca/ca.pem"
    "/etc/foreman-proxy/certs/ca.pem"
  )
  for f in "${cands[@]}"; do
    [[ -f "$f" ]] && LOCAL_CA_FILES+=("$f")
  done
}

# ---------- Profil / servis yardımcıları ----------
default_port_for_service(){
  case "$1" in
    registry) echo "5000" ;;
    freeipa|ipa) echo "443" ;;
    satellite|katello|foreman) echo "443" ;;
    git|gitrepo|gitea|gitlab) echo "443" ;;
    *) echo "443" ;;
  esac
}

normalize_service_name(){
  case "$1" in
    ipa) echo "freeipa" ;;
    katello) echo "satellite" ;;
    gitrepo) echo "git" ;;
    *) echo "$1" ;;
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
}

expand_profiles(){
  local kv svc hp
  for kv in "${SVC_KV[@]:-}"; do
    svc="${kv%%=*}"
    hp="${kv#*=}"
    add_target_with_default_port "$svc" "$hp"
  done

  if [[ -n "${BASE_DOMAIN:-}" ]]; then
    local p
    for p in "${PROFILES[@]:-}"; do
      p="$(normalize_service_name "$p")"
      if [[ "$p" == "all" ]]; then
        PROFILES=("freeipa" "satellite" "foreman" "git" "registry")
        break
      fi
    done

    local expanded=()
    local p2
    for p2 in "${PROFILES[@]:-}"; do
      p2="$(normalize_service_name "$p2")"
      case "$p2" in
        freeipa|satellite|foreman|git|registry) expanded+=("$p2") ;;
        *) expanded+=("$p2") ;;
      esac
    done
    PROFILES=("${expanded[@]}")

    for p in "${PROFILES[@]:-}"; do
      case "$p" in
        freeipa)    add_target_with_default_port "freeipa"   "freeipa.${BASE_DOMAIN}" ;;
        satellite)  add_target_with_default_port "satellite" "satellite.${BASE_DOMAIN}" ;;
        foreman)    add_target_with_default_port "foreman"   "foreman.${BASE_DOMAIN}" ;;
        git)        add_target_with_default_port "git"       "git.${BASE_DOMAIN}" ;;
        registry)   add_target_with_default_port "registry"  "registry.${BASE_DOMAIN}" ;;
      esac
    done
  fi
}

# ---------- Argüman ayrıştırma ----------
[[ $# -gt 0 ]] || { usage; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)           TARGETS+=("$2"); shift 2;;
    --from-file)
      [[ -f "$2" ]] || die "Dosya yok: $2"
      while IFS= read -r line; do
        line="${line%%#*}"; line="$(echo "$line" | xargs || true)"; [[ -z "$line" ]] && continue
        TARGETS+=("$line")
      done < "$2"
      shift 2;;
    --profile)
      IFS=',' read -ra _p <<< "$2"
      PROFILES+=("${_p[@]}")
      shift 2;;
    --base-domain)      BASE_DOMAIN="$2"; shift 2;;
    --svc)              SVC_KV+=("$2"); shift 2;;
    --out)              OUT_DIR="$2"; shift 2;;
    --user-mode)        USER_MODE=1; INSTALL_SYSTEM=0; INSTALL_CONTAINERS=0; INSTALL_NSS=1; shift;;
    --no-install)       INSTALL_SYSTEM=0; INSTALL_CONTAINERS=0; INSTALL_NSS=0; shift;;
    --install-system)   INSTALL_SYSTEM=1; shift;;
    --no-install-system) INSTALL_SYSTEM=0; shift;;
    --install-containers) INSTALL_CONTAINERS=1; shift;;
    --no-install-containers) INSTALL_CONTAINERS=0; shift;;
    --install-nss)      INSTALL_NSS=1; shift;;
    --add-local-ca)     [[ -f "$2" ]] || die "CA dosyası yok: $2"; LOCAL_CA_FILES+=("$2"); shift 2;;
    --auto-local-ca)    AUTO_LOCAL_CA=1; shift;;
    --timeout)          TIMEOUT_SECS="$2"; shift 2;;
    --dry-run)          DRY_RUN=1; shift;;
    --force)            FORCE=1; shift;;
    --all)              INSTALL_SYSTEM=1; INSTALL_CONTAINERS=1; INSTALL_NSS=1; shift;;
    -h|--help)          usage; exit 0;;
    --profile=*)        IFS=',' read -ra _p <<< "${1#*=}"; PROFILES+=("${_p[@]}"); shift;;
    --base-domain=*)    BASE_DOMAIN="${1#*=}"; shift;;
    --svc=*)            SVC_KV+=("${1#*=}"); shift;;
    --out=*)            OUT_DIR="${1#*=}"; shift;;
    --target=*)         TARGETS+=("${1#*=}"); shift;;
    --timeout=*)        TIMEOUT_SECS="${1#*=}"; shift;;
    --add-local-ca=*)   f="${1#*=}"; [[ -f "$f" ]] || die "CA dosyası yok: $f"; LOCAL_CA_FILES+=("$f"); shift;;
    *)                  die "Bilinmeyen parametre: $1";;
  esac
done

# ---------- Ön kontroller ----------
need openssl
run "mkdir -p '${OUT_DIR}'"
[[ "$AUTO_LOCAL_CA" -eq 1 ]] && auto_local_ca
expand_profiles

if [[ "${#TARGETS[@]}" -eq 0 && "${#LOCAL_CA_FILES[@]}" -eq 0 ]]; then
  die "En az bir --target veya --add-local-ca/--auto-local-ca gerekli."
fi

# --user-mode: certutil zorunlu değil ama önerilir
if [[ "$USER_MODE" -eq 1 ]]; then
  log "*** KULLANICI MODU — sudo GEREKMİYOR ***"
  log "    Yalnızca $(eval echo ~${USER:-$(whoami)}) altındaki Firefox/Chrome/Edge NSS veritabanları güncellenir."
  if ! command -v certutil >/dev/null 2>&1; then
    warn "certutil bulunamadı! NSS import yapılamayacak."
    case "$(detect_os_family)" in
      rhel)   warn "Kurulum: sudo dnf -y install nss-tools";;
      debian) warn "Kurulum: sudo apt -y install libnss3-tools";;
      *)      warn "Kurulum: nss-tools veya libnss3-tools";;
    esac
  fi
fi

log "Sürüm   : ${VERSION} (${RELEASE_DATE})"
log "OUT_DIR : ${OUT_DIR}"
log "SYSTEM  : ${INSTALL_SYSTEM} | CONTAINERS: ${INSTALL_CONTAINERS} | NSS: ${INSTALL_NSS} | USER_MODE: ${USER_MODE} | DRY: ${DRY_RUN} | FORCE: ${FORCE}"

# ---------- Hedef işleme ----------
process_target(){
  local target="$1" host port key tdir chain cabundle nick
  read -r host port < <(parse_host_port "$target")
  key="$host"; [[ "$port" != 443 ]] && key="${host}:${port}"
  tdir="${OUT_DIR}/$(sanitize_key "$key")"
  run "mkdir -p '${tdir}'"
  chain="${tdir}/chain.pem"
  cabundle="${tdir}/ca-bundle.pem"
  nick="CA-${host}-${port}"

  log "Hedef: ${host}:${port}"
  log "  zincir alınıyor..."
  if ! fetch_chain "$host" "$port" "$chain"; then
    warn "  zincir alınamadı (${host}:${port}) — atlandı"
    return 0
  fi

  log "  ca-bundle oluşturuluyor"
  build_ca_bundle "$chain" "$cabundle"
  run "cp '${cabundle}' '${tdir}/ca-bundle.crt'"
  run "openssl x509 -in '${cabundle}' -outform der -out '${tdir}/ca-bundle.der' >/dev/null 2>&1 || true"

  if [[ "$INSTALL_SYSTEM" -eq 1 ]]; then
    log "  OS trust kuruluyor"
    install_system_trust "$cabundle" "$(sanitize_key "$key")"
  fi
  if [[ "$INSTALL_CONTAINERS" -eq 1 ]]; then
    log "  Podman/Docker certs.d kuruluyor"
    install_containers "$cabundle" "$host" "$port"
  fi
  if [[ "$INSTALL_NSS" -eq 1 ]]; then
    if [[ "$USER_MODE" -eq 1 ]]; then
      log "  Tarayıcı NSS güncelleniyor (kullanıcı modu)"
      install_current_user_nss "$cabundle" "$nick"
    else
      log "  NSS import deneniyor (tüm kullanıcılar)"
      install_all_users_nss "$cabundle" "$nick"
    fi
  fi
  log "  tamam: ${host}:${port}"
}

# ---------- Yerel CA işleme ----------
process_local_ca(){
  local f="$1" base name tdir
  [[ -f "$f" ]] || return 0
  base="$(basename "$f")"; name="local_${base%.*}"
  tdir="${OUT_DIR}/${name}"
  run "mkdir -p '${tdir}'"
  run "cp '${f}' '${tdir}/ca-bundle.pem'"
  run "cp '${tdir}/ca-bundle.pem' '${tdir}/ca-bundle.crt'"
  run "openssl x509 -in '${tdir}/ca-bundle.pem' -outform der -out '${tdir}/ca-bundle.der' >/dev/null 2>&1 || true"

  if [[ "$INSTALL_SYSTEM" -eq 1 ]]; then
    log "Yerel CA OS trust kuruluyor: ${f}"
    install_system_trust "${tdir}/ca-bundle.pem" "$name"
  fi
  if [[ "$INSTALL_NSS" -eq 1 ]]; then
    if [[ "$USER_MODE" -eq 1 ]]; then
      install_current_user_nss "${tdir}/ca-bundle.pem" "CA-${name}"
    else
      install_all_users_nss "${tdir}/ca-bundle.pem" "CA-${name}"
    fi
  fi
}

# ---------- Çift hedef temizliği ----------
dedup_targets(){
  local -A seen=()
  local t
  local -a out=()
  for t in "${TARGETS[@]:-}"; do
    [[ -z "$t" ]] && continue
    if [[ -z "${seen[$t]+x}" ]]; then
      seen[$t]=1
      out+=("$t")
    fi
  done
  TARGETS=("${out[@]}")
}

dedup_targets

for t in "${TARGETS[@]:-}"; do process_target "$t"; done
for f in "${LOCAL_CA_FILES[@]:-}"; do process_local_ca "$f"; done

log "BİTTİ. Dosyalar: ${OUT_DIR}"
