#!/usr/bin/env bash
#
# create-ovirt-user.sh  (v2 - temiz surum)
# -----------------------------------------------------------------------------
# oVirt / OLVM internal kullanicisi olusturur, parola atar ve opsiyonel olarak
# REST API uzerinden SISTEM seviyesinde bir rol (SuperUser) baglar.
#
# Engine (Manager) makinesinde 'root' olarak calistirilmalidir.
#
# oVirt kurali: bir izin = KULLANICI + ROL + NESNE. Sistem geneli (global) izin
# icin nesne "System"dir; bunun REST karsiligi ust seviye /permissions
# koleksiyonudur. ADMIN tipli bir rolu (SuperUser) yalnizca SuperUser atayabilir
# -> token'i aldigin hesap gercek SuperUser olmalidir (ornn admin@internal).
# -----------------------------------------------------------------------------
set -euo pipefail

# ============================== YAPILANDIRMA =================================
# --- Olusturulacak kullanici ---
NEW_USER="ansadmin"
NEW_USER_PW="ansadminpass"
NEW_USER_FIRST="Ansible"
NEW_USER_LAST="Admin"

# --- Rol atamasi icin baglanilacak YONETICI (GERCEK SuperUser olmali) ---
# ONEMLI: Buraya "Token alindi" ciktisini veren TAM giris adini yaz.
# Senin ortaminda calisan deger: admin@ovirt@internal
ADMIN_LOGIN="admin@internal"
ADMIN_PW="adminpass"

# --- Ortam ---
ENGINE_FQDN="$(hostname -f)"          # gerekirse elle: olvmm.lab.akyuz.tech
AUTHZ="internal-authz"                # engine'e kullanici eklerken authz adi
PW_VALID_TO="2030-12-31 23:59:59Z"    # parola gecerlilik sonu (UTC)

# --- Rol ---
ASSIGN_ROLE=true                      # false => sadece kullanici + parola
ROLE_NAME="SuperUser"                 # sistem seviyesi rol

# --- Davranis ---
DRY_RUN=false
LOG_FILE="/var/log/create-ovirt-user.log"
# ============================================================================

# --- Argumanlar ---
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --no-role) ASSIGN_ROLE=false ;;
    -h|--help)
      echo "Kullanim: $0 [--dry-run] [--no-role]"
      echo "  --dry-run   Komutlari calistirmadan gosterir"
      echo "  --no-role   Sadece kullanici+parola olusturur, rol atamaz"
      exit 0 ;;
    *) echo "Bilinmeyen arguman: $arg" >&2; exit 2 ;;
  esac
done

# --- Renkli loglama ---
C_R='\033[0;31m'; C_G='\033[0;32m'; C_Y='\033[0;33m'; C_B='\033[0;34m'; C_N='\033[0m'
_ts() { date '+%F %T'; }
log()  { echo -e "${C_B}[$(_ts)]${C_N} $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${C_G}[ OK ]${C_N} $*"  | tee -a "$LOG_FILE"; }
warn() { echo -e "${C_Y}[WARN]${C_N} $*"  | tee -a "$LOG_FILE"; }
err()  { echo -e "${C_R}[FAIL]${C_N} $*"  | tee -a "$LOG_FILE" >&2; }
die()  { err "$*"; exit 1; }

JDBC="ovirt-aaa-jdbc-tool"
API="https://${ENGINE_FQDN}/ovirt-engine/api"
SSO="https://${ENGINE_FQDN}/ovirt-engine/sso/oauth/token"
TOKEN=""
HTTP_STATUS=""
HTTP_BODY=""

# --- REST cagrisi: govde HTTP_BODY'ye, durum kodu HTTP_STATUS'a yazilir ---
api() {  # api METHOD PATH [JSON_BODY]
  local method="$1" path="$2" body="${3:-}"
  local tmp; tmp="$(mktemp)"
  local args=(-sk -o "$tmp" -w '%{http_code}' -X "$method"
    -H "Authorization: Bearer ${TOKEN}"
    -H "Accept: application/json"
    -H "Content-Type: application/json")
  [[ -n "$body" ]] && args+=(-d "$body")
  HTTP_STATUS="$(curl "${args[@]}" "${API}${path}")"
  HTTP_BODY="$(cat "$tmp")"; rm -f "$tmp"
}

# --- On kontroller ---
preflight() {
  [[ $EUID -eq 0 ]] || die "Bu script root olarak calistirilmalidir."
  command -v "$JDBC" >/dev/null 2>&1 || die "'$JDBC' bulunamadi. Engine makinesinde misiniz?"
  command -v curl    >/dev/null 2>&1 || die "'curl' gerekli."
  command -v jq      >/dev/null 2>&1 || die "'jq' gerekli (dnf install -y jq)."
  touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/create-ovirt-user.log"
  log "On kontroller tamam. Engine: ${ENGINE_FQDN}"
}

# --- 1) Kullaniciyi olustur (idempotent) ---
create_user() {
  if $JDBC user show "$NEW_USER" >/dev/null 2>&1; then
    warn "Kullanici '$NEW_USER' zaten mevcut, olusturma atlaniyor."
    return 0
  fi
  log "Kullanici olusturuluyor: $NEW_USER"
  if $DRY_RUN; then
    echo -e "${C_Y}[DRY-RUN]${C_N} $JDBC user add '$NEW_USER' --attribute=firstName='$NEW_USER_FIRST' --attribute=lastName='$NEW_USER_LAST'"
  else
    "$JDBC" user add "$NEW_USER" \
      --attribute=firstName="$NEW_USER_FIRST" \
      --attribute=lastName="$NEW_USER_LAST"
    ok "Kullanici olusturuldu: $NEW_USER"
  fi
}

# --- 2) Parola ata (env uzerinden -> loglara/ps'e dusmez) ---
set_password() {
  log "Parola ataniyor: $NEW_USER"
  if $DRY_RUN; then
    echo -e "${C_Y}[DRY-RUN]${C_N} $JDBC user password-reset '$NEW_USER' --password=env:OVIRT_NEW_PW --password-valid-to='$PW_VALID_TO'"
    return 0
  fi
  OVIRT_NEW_PW="$NEW_USER_PW" \
    "$JDBC" user password-reset "$NEW_USER" \
      --password=env:OVIRT_NEW_PW \
      --password-valid-to="$PW_VALID_TO"
  "$JDBC" user unlock "$NEW_USER" >/dev/null 2>&1 || true
  ok "Parola atandi (gecerlilik: $PW_VALID_TO)"
}

# --- 3) SSO token al ---
get_token() {
  log "REST API icin SSO token aliniyor (${ADMIN_LOGIN})"
  local resp
  resp="$(curl -sk \
    -H "Accept: application/json" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "scope=ovirt-app-api" \
    --data-urlencode "username=${ADMIN_LOGIN}" \
    --data-urlencode "password=${ADMIN_PW}" \
    "$SSO")"
  TOKEN="$(echo "$resp" | jq -r '.access_token // empty')"
  [[ -n "$TOKEN" ]] || die "Token alinamadi. Yanit: $resp"
  ok "Token alindi."
}

# --- 3b) Grantor gercekten SuperUser mi? (ADMIN rol atama on sarti) ---
verify_grantor_superuser() {
  # Sistem izinlerini listeleyebilmek ve SuperUser sahiplerini gormek icin
  api GET "/permissions?follow=role,user"
  if [[ "$HTTP_STATUS" != "200" ]]; then
    warn "Sistem izinleri okunamadi (HTTP $HTTP_STATUS). Grantor yetkisi kisitli olabilir."
    return 0
  fi
  local su_users
  su_users="$(echo "$HTTP_BODY" | jq -r \
    '[.permission[]? | select(.role.name=="SuperUser") | .user.id] | unique | .[]' 2>/dev/null || true)"
  if [[ -z "$su_users" ]]; then
    warn "Sistem seviyesinde SuperUser sahibi tespit edilemedi; devam ediliyor."
  else
    log "Mevcut sistem SuperUser sahibi kullanici sayisi: $(echo "$su_users" | grep -c . )"
  fi
}

# --- 4) Kullaniciyi engine'e ekle ve SISTEM seviyesi rolu bagla ---
assign_role() {
  get_token
  verify_grantor_superuser

  # Kullanici engine'de kayitli mi?
  api GET "/users"
  [[ "$HTTP_STATUS" == "200" ]] || die "Kullanici listesi alinamadi (HTTP $HTTP_STATUS): $HTTP_BODY"
  local uid
  uid="$(echo "$HTTP_BODY" | jq -r \
    --arg u "${NEW_USER}@${AUTHZ}" \
    '.user[]? | select(.user_name==$u) | .id' | head -n1)"

  if [[ -z "$uid" ]]; then
    log "Kullanici engine'e ekleniyor: ${NEW_USER}@${AUTHZ}"
    local ubody
    ubody="$(jq -n \
      --arg un "${NEW_USER}@${AUTHZ}" \
      --arg pr "$NEW_USER" \
      --arg dn "$AUTHZ" \
      '{user_name:$un, principal:$pr, namespace:"*", domain:{name:$dn}}')"
    if $DRY_RUN; then
      echo -e "${C_Y}[DRY-RUN]${C_N} POST /users -> $ubody"; return 0
    fi
    api POST "/users" "$ubody"
    [[ "$HTTP_STATUS" =~ ^20 ]] || die "Kullanici engine'e eklenemedi (HTTP $HTTP_STATUS): $HTTP_BODY"
    uid="$(echo "$HTTP_BODY" | jq -r '.id // empty')"
    [[ -n "$uid" ]] || die "Kullanici id alinamadi: $HTTP_BODY"
    ok "Kullanici engine'e eklendi (id=$uid)"
  else
    warn "Kullanici engine'de zaten kayitli (id=$uid)"
  fi

  # Rol zaten atanmis mi?
  api GET "/users/${uid}/permissions?follow=role"
  if [[ "$HTTP_STATUS" == "200" ]] && \
     echo "$HTTP_BODY" | jq -e --arg r "$ROLE_NAME" \
       '[.permission[]? | select(.role.name==$r)] | length > 0' >/dev/null 2>&1; then
    warn "Rol '$ROLE_NAME' zaten atanmis, atlaniyor."
    return 0
  fi

  # Rol ID'sini cek (isimle cozumleme bazi surumlerde hataliydi)
  api GET "/roles"
  [[ "$HTTP_STATUS" == "200" ]] || die "Roller alinamadi (HTTP $HTTP_STATUS): $HTTP_BODY"
  local rid
  rid="$(echo "$HTTP_BODY" | jq -r \
    --arg r "$ROLE_NAME" '.role[]? | select(.name==$r) | .id' | head -n1)"
  [[ -n "$rid" ]] || die "'$ROLE_NAME' rolu bulunamadi."
  log "Sistem seviyesi rol atanoyor: $ROLE_NAME (rid=$rid)"

  if $DRY_RUN; then
    echo -e "${C_Y}[DRY-RUN]${C_N} POST /permissions (role=$rid user=$uid)"; return 0
  fi

  # --- 1. deneme: JSON ---
  local pbody
  pbody="$(jq -n --arg rid "$rid" --arg uid "$uid" \
    '{role:{id:$rid}, user:{id:$uid}}')"
  api POST "/permissions" "$pbody"
  log "JSON denemesi -> HTTP $HTTP_STATUS"

  # --- basarisizsa 2. deneme: XML (SDK bu komutta XML kullanir) ---
  if ! [[ "$HTTP_STATUS" =~ ^20 || "$HTTP_STATUS" == "409" ]]; then
    local xbody tmp
    xbody="<permission><role id=\"${rid}\"/><user id=\"${uid}\"/></permission>"
    tmp="$(mktemp)"
    HTTP_STATUS="$(curl -sk -o "$tmp" -w '%{http_code}' -X POST \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Accept: application/xml" \
      -H "Content-Type: application/xml" \
      -d "$xbody" "${API}/permissions")"
    HTTP_BODY="$(cat "$tmp")"; rm -f "$tmp"
    log "XML denemesi  -> HTTP $HTTP_STATUS"
  fi

  case "$HTTP_STATUS" in
    20*) ok "Rol '$ROLE_NAME' atandi (sistem geneli)." ;;
    409) warn "Izin zaten mevcut (HTTP 409) - kabul edildi." ;;
    *)
      err "Rol atanamadi (HTTP $HTTP_STATUS)."
      echo "$HTTP_BODY" | (jq . 2>/dev/null || cat)
      echo
      err "TESHIS (HTTP koduna gore):"
      err "  400/415 => govde/format sorunu (JSON+XML ikisi de denendi)."
      err "  403/500 + 'Operation Failed' => grantor yetkisi yetersiz."
      err "           '${ADMIN_LOGIN}' hesabi System uzerinde MANIPULATE_PERMISSIONS"
      err "           (yani tam SuperUser) degilse ADMIN rolu atayamaz."
      err "           Gercek SuperUser hesabiyla ADMIN_LOGIN'i degistirip tekrar dene."
      err "  404     => user/role id cozumlenemedi."
      exit 1 ;;
  esac
}

# --- Ozet dogrulama ---
verify() {
  $DRY_RUN && return 0
  log "Dogrulama (jdbc):"
  $JDBC user show "$NEW_USER" 2>/dev/null | grep -E 'Name|Disabled|Account|Valid' | sed 's/^/    /' || true
  if $ASSIGN_ROLE && [[ -n "$TOKEN" ]]; then
    api GET "/users?search=name%3D${NEW_USER}"
    local uid
    uid="$(echo "$HTTP_BODY" | jq -r --arg u "${NEW_USER}@${AUTHZ}" \
      '.user[]? | select(.user_name==$u) | .id' | head -n1)"
    if [[ -n "$uid" ]]; then
      api GET "/users/${uid}/permissions?follow=role"
      log "Atanmis roller:"
      echo "$HTTP_BODY" | jq -r '.permission[]?.role.name' 2>/dev/null | sort -u | sed 's/^/    /' || true
    fi
  fi
}

# =============================== AKIS =======================================
main() {
  preflight
  log "=== oVirt kullanici olusturma basladi (dry-run=${DRY_RUN}) ==="
  create_user
  set_password
  if $ASSIGN_ROLE; then
    assign_role
  else
    warn "Rol atamasi devre disi (--no-role)."
  fi
  verify
  ok "Tamamlandi. Giris kullanici adi: ${NEW_USER}  (profil: internal)"
}

main "$@"
