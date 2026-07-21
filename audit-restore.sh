#!/bin/bash
# audit-restore.sh — Audit cPanel sites against restore_site.sh fix phases
# Validates ACL-based permissions (suPHP), cache, .htaccess, dev controllers, logs
# Run on VPS as root:  bash audit-restore.sh

set -euo pipefail

ALLOWED_IP="82.84.108.8"
SKIP_DIRS="^(cPanelInstall|virtfs|cpeasyapache|\.cp|trash|tmp)$"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="/tmp/audit-restore-${TIMESTAMP}"
CSV_TESTS="${OUTDIR}/test_results.csv"
CSV_SUMMARY="${OUTDIR}/site_summary.csv"
TARBALL="/tmp/audit-restore-${TIMESTAMP}.tar.gz"

mkdir -p "$OUTDIR"

# ── Build domain lookup from /etc/trueuserdomains ───────────────
declare -A USER_DOMAIN
if [ -f /etc/trueuserdomains ]; then
  while IFS=': ' read -r domain user _; do
    [ -z "$user" ] && continue
    USER_DOMAIN["$user"]="$domain"
  done < /etc/trueuserdomains
fi

# ── Collect cPanel users ────────────────────────────────────────
USERS=()
for d in /home/*/public_html; do
  [ ! -d "$d" ] && continue
  name="$(basename "$(dirname "$d")")"
  echo "$name" | grep -qE "$SKIP_DIRS" && continue
  USERS+=("$name")
done

if [ ${#USERS[@]} -eq 0 ]; then
  echo "No cPanel user directories found in /home/"
  exit 1
fi

echo "Auditing ${#USERS[@]} cPanel accounts..."

# ── CSV header ──────────────────────────────────────────────────
echo '"test_id","fix_phase","site","result","reason"' > "$CSV_TESTS"

TEST_ID=0

emit() {
  TEST_ID=$((TEST_ID + 1))
  printf '"%s","%s","%s","%s","%s"\n' "$TEST_ID" "$1" "$2" "$3" "$4" >> "$CSV_TESTS"
}

# ── Helper: check ACL for user+nobody rwX ───────────────────────
check_acl() {
  local path="$1"
  local user="$2"
  local acl_output

  acl_output=$(getfacl -p "$path" 2>/dev/null)

  local has_user_acl=false
  local has_nobody_acl=false
  local has_default_user=false
  local has_default_nobody=false

  echo "$acl_output" | grep -q "^user:${user}:rw" && has_user_acl=true || true
  echo "$acl_output" | grep -q "^user:nobody:rw" && has_nobody_acl=true || true
  echo "$acl_output" | grep -q "^default:user:${user}:rw" && has_default_user=true || true
  echo "$acl_output" | grep -q "^default:user:nobody:rw" && has_default_nobody=true || true

  local missing=""
  [ "$has_user_acl" = false ] && missing="acl:${user}:rwX"
  [ "$has_nobody_acl" = false ] && missing="${missing:+${missing} }acl:nobody:rwX"
  [ "$has_default_user" = false ] && missing="${missing:+${missing} }default:${user}:rwX"
  [ "$has_default_nobody" = false ] && missing="${missing:+${missing} }default:nobody:rwX"

  echo "$missing"
}

# ── Detect site type ────────────────────────────���───────────────
detect_type() {
  local home="$1"
  local user="$2"
  if [ -d "$home/app" ] && ([ -f "$home/app/AppKernel.php" ] || [ -f "$home/app/autoload.php" ]); then
    echo "ar"
  elif [ -f "$home/vendor/autoload.php" ] && [[ "$user" == ar* ]]; then
    echo "ar"
  else
    echo "site"
  fi
}

# ── Check MySQL strict mode (global) ───────────────────────────
MYSQL_PHASE="9-mysql_strict_mode"
if command -v mysql &>/dev/null; then
  MODE=$(mysql -N -e "SELECT @@GLOBAL.sql_mode;" 2>/dev/null || echo "error")
  if [ "$MODE" = "error" ]; then
    emit "$MYSQL_PHASE" "(global)" "FAIL" "Cannot connect to MySQL"
  elif echo "$MODE" | grep -qi "STRICT_TRANS_TABLES"; then
    emit "$MYSQL_PHASE" "(global)" "FAIL" "STRICT_TRANS_TABLES is ON: $MODE"
  else
    emit "$MYSQL_PHASE" "(global)" "OK" ""
  fi
else
  emit "$MYSQL_PHASE" "(global)" "SKIP" "mysql client not found"
fi

# ── Per-user checks ────────────────────────────��───────────────
for USER in "${USERS[@]}"; do
  HOME="/home/$USER"
  PH="$HOME/public_html"
  HT="$PH/.htaccess"
  TYPE=$(detect_type "$HOME" "$USER")

  # --- Phase 2: ACL-based permissions on shared dirs ───────────
  PHASE="2-permissions_acl"

  if [ "$TYPE" = "ar" ]; then
    # Symfony 2.x: app/cache, app/logs, spool
    SHARED_DIRS="app/cache app/logs spool var/cache var/logs"
  else
    # Symfony 1.x: cache, log
    SHARED_DIRS="cache log"
  fi

  ACL_ISSUES=""
  for dir in $SHARED_DIRS; do
    path="$HOME/$dir"
    [ ! -d "$path" ] && continue
    missing=$(check_acl "$path" "$USER")
    if [ -n "$missing" ]; then
      ACL_ISSUES="${ACL_ISSUES:+${ACL_ISSUES}; }${dir}: ${missing}"
    fi
  done

  # Also check upload dirs in public_html
  for dir in uploads form_upload export download repository; do
    path="$PH/$dir"
    [ ! -d "$path" ] && continue
    missing=$(check_acl "$path" "$USER")
    if [ -n "$missing" ]; then
      ACL_ISSUES="${ACL_ISSUES:+${ACL_ISSUES}; }public_html/${dir}: ${missing}"
    fi
  done

  if [ -z "$ACL_ISSUES" ]; then
    # Check shared dirs exist at all
    MISSING_DIRS=""
    if [ "$TYPE" = "ar" ]; then
      [ ! -d "$HOME/app/cache" ] && [ ! -d "$HOME/var/cache" ] && MISSING_DIRS="cache"
      [ ! -d "$HOME/app/logs" ] && [ ! -d "$HOME/var/logs" ] && [ ! -d "$HOME/var/log" ] && MISSING_DIRS="${MISSING_DIRS:+${MISSING_DIRS} }logs"
    else
      [ ! -d "$HOME/cache" ] && MISSING_DIRS="cache"
      [ ! -d "$HOME/log" ] && MISSING_DIRS="${MISSING_DIRS:+${MISSING_DIRS} }log"
    fi
    if [ -n "$MISSING_DIRS" ]; then
      emit "$PHASE" "$USER" "FAIL" "Missing dirs: $MISSING_DIRS"
    else
      emit "$PHASE" "$USER" "OK" ""
    fi
  else
    emit "$PHASE" "$USER" "FAIL" "$ACL_ISSUES"
  fi

  # --- Phase 2b: PHP files owned by cPanel user (suPHP requirement) ─
  PHASE="2b-php_ownership"
  if ! id "$USER" &>/dev/null; then
    emit "$PHASE" "$USER" "SKIP" "System user $USER does not exist"
  else
  BAD_PHP=$(find "$PH" -maxdepth 1 -name '*.php' -type f ! -user "$USER" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$BAD_PHP" -eq 0 ]; then
    emit "$PHASE" "$USER" "OK" ""
  else
    emit "$PHASE" "$USER" "FAIL" "${BAD_PHP} .php files in public_html not owned by $USER (suPHP will 500)"
  fi
  fi

  # --- Phase 3: Symfony cache cleared ──────────────────────────
  PHASE="3-cache_cleared"
  if [ "$TYPE" = "ar" ]; then
    CACHE_DIR="$HOME/app/cache"
    [ ! -d "$CACHE_DIR" ] && CACHE_DIR="$HOME/var/cache"
  else
    CACHE_DIR="$HOME/cache"
  fi

  if [ -d "$CACHE_DIR" ]; then
    CACHE_COUNT=$(find "$CACHE_DIR" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')
    if [ "$CACHE_COUNT" -eq 0 ]; then
      emit "$PHASE" "$USER" "OK" ""
    else
      emit "$PHASE" "$USER" "WARN" "${CACHE_COUNT} entries in cache (may be stale)"
    fi
  else
    emit "$PHASE" "$USER" "SKIP" "No cache directory found"
  fi

  # --- Phase 4: .htaccess ExpiresActive/ExpiresDefault ─────────
  PHASE="4-htaccess_expires"
  if [ -f "$HT" ]; then
    MATCH=$(grep -nE '^[[:space:]]*Expires(Active|Default)' "$HT" 2>/dev/null || true)
    if [ -n "$MATCH" ]; then
      LINENUM=$(echo "$MATCH" | head -1 | cut -d: -f1)
      emit "$PHASE" "$USER" "FAIL" "Uncommented Expires directive at .htaccess:${LINENUM}"
    else
      emit "$PHASE" "$USER" "OK" ""
    fi
  else
    emit "$PHASE" "$USER" "SKIP" "No .htaccess found"
  fi

  # --- Phase 5: Dev controllers with allowed IP ────────────────
  PHASE="5-dev_controllers"
  DEV_ISSUES=""
  for devfile in frontend_dev.php backend_dev.php content_dev.php cli_dev.php admin_dev.php; do
    filepath="$PH/$devfile"
    if [ -f "$filepath" ]; then
      if ! grep -q "$ALLOWED_IP" "$filepath"; then
        DEV_ISSUES="${DEV_ISSUES:+${DEV_ISSUES}; }${devfile} missing IP"
      fi
    fi
  done

  # Count how many dev files exist at all
  DEV_COUNT=$(find "$PH" -maxdepth 1 -name '*_dev.php' -type f 2>/dev/null | wc -l | tr -d ' ')
  if [ "$DEV_COUNT" -eq 0 ]; then
    emit "$PHASE" "$USER" "SKIP" "No *_dev.php files found"
  elif [ -z "$DEV_ISSUES" ]; then
    emit "$PHASE" "$USER" "OK" ""
  else
    emit "$PHASE" "$USER" "FAIL" "$DEV_ISSUES"
  fi

  # --- Phase 6: error_log in docroot ───────────────────────────
  PHASE="6-error_log_docroot"
  if [ -f "$PH/error_log" ]; then
    SIZE=$(du -h "$PH/error_log" 2>/dev/null | cut -f1)
    emit "$PHASE" "$USER" "FAIL" "error_log exists in public_html ($SIZE)"
  else
    emit "$PHASE" "$USER" "OK" ""
  fi

  # --- Phase 7: Oversized logs (>100MB) ────────────────────────
  PHASE="7-oversized_logs"
  BIG_LOGS=""
  for logdir in "$HOME/log" "$HOME/app/logs" "$HOME/var/logs" "$HOME/var/log"; do
    [ ! -d "$logdir" ] && continue
    while IFS= read -r logfile; do
      SIZE=$(du -h "$logfile" 2>/dev/null | cut -f1)
      BIG_LOGS="${BIG_LOGS:+${BIG_LOGS}; }$(basename "$logfile") ($SIZE)"
    done < <(find "$logdir" -type f -name "*.log" -size +100M 2>/dev/null)
  done

  if [ -z "$BIG_LOGS" ]; then
    emit "$PHASE" "$USER" "OK" ""
  else
    emit "$PHASE" "$USER" "FAIL" "$BIG_LOGS"
  fi

  # --- Phase 8: moxiemanager data dirs ACLs ────────────────────
  PHASE="8-moxiemanager_data"
  MOX_ISSUES=""
  while IFS= read -r moxdir; do
    missing=$(check_acl "$moxdir" "$USER")
    if [ -n "$missing" ]; then
      MOX_ISSUES="${MOX_ISSUES:+${MOX_ISSUES}; }$(echo "$moxdir" | sed "s|$HOME/||"): ${missing}"
    fi
  done < <(find "$PH" -type d -path '*/moxiemanager/data' 2>/dev/null)

  MOX_COUNT=$(find "$PH" -type d -path '*/moxiemanager/data' 2>/dev/null | wc -l | tr -d ' ')
  if [ "$MOX_COUNT" -eq 0 ]; then
    emit "$PHASE" "$USER" "SKIP" "No moxiemanager/data found"
  elif [ -z "$MOX_ISSUES" ]; then
    emit "$PHASE" "$USER" "OK" ""
  else
    emit "$PHASE" "$USER" "FAIL" "$MOX_ISSUES"
  fi

  # --- Phase 10: PHP version (ea-php55 should be ea-php53) ─────
  PHASE="10-php_version"
  DOMAIN="${USER_DOMAIN[$USER]:-}"
  if [ -n "$DOMAIN" ]; then
    USERDATA="/var/cpanel/userdata/${USER}/${DOMAIN}"
    if [ -f "$USERDATA" ]; then
      SITE_PHP=$(grep '^phpversion:' "$USERDATA" 2>/dev/null | awk '{print $2}')
      if [ "$SITE_PHP" = "ea-php55" ]; then
        emit "$PHASE" "$USER" "FAIL" "Running ea-php55, should be ea-php53"
      elif [ -z "$SITE_PHP" ]; then
        emit "$PHASE" "$USER" "WARN" "No phpversion in userdata"
      else
        emit "$PHASE" "$USER" "OK" "$SITE_PHP"
      fi
    else
      emit "$PHASE" "$USER" "SKIP" "No userdata file found"
    fi
  else
    emit "$PHASE" "$USER" "SKIP" "Domain unknown"
  fi

done

echo "  -> ${TEST_ID} tests written to test_results.csv"

# ── Generate site_summary.csv from test_results.csv ─────────────
echo '"domain","cpanel_user","folder","type","fixes_ok","fixes_needed"' > "$CSV_SUMMARY"

declare -A SITE_OK
declare -A SITE_FAIL
declare -A SITE_TYPE

while IFS=',' read -r _id phase site result reason; do
  phase=$(echo "$phase" | tr -d '"')
  site=$(echo "$site" | tr -d '"')
  result=$(echo "$result" | tr -d '"')

  [ "$site" = "site" ] || [ "$site" = "(global)" ] && continue

  if [ "$result" = "FAIL" ]; then
    SITE_FAIL["$site"]="${SITE_FAIL[$site]:+${SITE_FAIL[$site]};}${phase}"
  elif [ "$result" = "OK" ]; then
    SITE_OK["$site"]="${SITE_OK[$site]:+${SITE_OK[$site]};}${phase}"
  fi
done < "$CSV_TESTS"

# Detect types for summary
for USER in "${USERS[@]}"; do
  HOME="/home/$USER"
  SITE_TYPE["$USER"]=$(detect_type "$HOME" "$USER")
done

SEEN_SITES=()
declare -A SEEN_MAP
for USER in "${USERS[@]}"; do
  if [ -z "${SEEN_MAP[$USER]+x}" ]; then
    SEEN_MAP["$USER"]=1
    SEEN_SITES+=("$USER")
  fi
done

for USER in "${SEEN_SITES[@]}"; do
  DOMAIN="${USER_DOMAIN[$USER]:-unknown}"
  FOLDER="/home/${USER}"
  TYPE="${SITE_TYPE[$USER]:-site}"
  OK_LIST="${SITE_OK[$USER]:-}"
  FAIL_LIST="${SITE_FAIL[$USER]:-}"

  OK_COUNT=0
  FAIL_COUNT=0
  [ -n "$OK_LIST" ] && OK_COUNT=$(echo "$OK_LIST" | tr ';' '\n' | wc -l | tr -d ' ')
  [ -n "$FAIL_LIST" ] && FAIL_COUNT=$(echo "$FAIL_LIST" | tr ';' '\n' | wc -l | tr -d ' ')

  if [ "$FAIL_COUNT" -eq 0 ]; then
    TOTAL=$OK_COUNT
    FIXES_OK="ALL (${OK_COUNT}/${TOTAL})"
    FIXES_NEEDED=""
  else
    TOTAL=$((OK_COUNT + FAIL_COUNT))
    FIXES_OK="${OK_COUNT}/${TOTAL}"
    FIXES_NEEDED="$FAIL_LIST"
  fi

  printf '"%s","%s","%s","%s","%s","%s"\n' "$DOMAIN" "$USER" "$FOLDER" "$TYPE" "$FIXES_OK" "$FIXES_NEEDED" >> "$CSV_SUMMARY"
done

echo "  -> site_summary.csv generated"

# ── Compress ────────────────────────────────────────────────────
tar -czf "$TARBALL" -C /tmp "audit-restore-${TIMESTAMP}"

echo ""
echo "=== Audit complete ==="
echo "Archive: $TARBALL"
echo "TARBALL_PATH=${TARBALL}"
