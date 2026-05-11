#!/bin/bash
# fix-restore.sh — Fix common issues after cPanel backup restore
# Usage: ./fix-restore.sh /home/sitecode [--fix-mysql]

set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Usage: $0 /home/sitecode [--fix-mysql]"
  exit 1
fi

HOMEDIR="$1"
FIX_MYSQL=false
shift
while [ $# -gt 0 ]; do
  case "$1" in
    --fix-mysql) FIX_MYSQL=true ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

PUBLIC_HTML="$HOMEDIR/public_html"
HTACCESS="$PUBLIC_HTML/.htaccess"
ALLOWED_IP="82.84.108.8"

if [ ! -d "$HOMEDIR" ]; then
  echo "Error: $HOMEDIR does not exist"
  exit 1
fi

echo "=== Fixing $HOMEDIR ==="

# 1. Comment out ExpiresActive and ExpiresDefault in .htaccess
if [ -f "$HTACCESS" ]; then
  cp "$HTACCESS" "$HTACCESS.bak"
  sed -i 's/^\([[:space:]]*Expires\(Active\|Default\)\)/#\1/' "$HTACCESS"
  echo "[OK] Commented out ExpiresActive/ExpiresDefault in .htaccess"
else
  echo "[SKIP] No .htaccess found"
fi

# 2. Create log directory and fix permissions
mkdir -p "$HOMEDIR/log"
chown -R nobody:nobody "$HOMEDIR/log"
chmod 775 "$HOMEDIR/log"
echo "[OK] Fixed log directory permissions"

# 3. Clear Symfony cache
if [ -d "$HOMEDIR/cache" ]; then
  rm -rf "$HOMEDIR/cache"/*
  chown -R nobody:nobody "$HOMEDIR/cache"
  chmod -R 775 "$HOMEDIR/cache"
  echo "[OK] Cleared Symfony cache"
fi

# 4. Fix public_html directory permissions for uploads
find "$PUBLIC_HTML" -type d -print0 | xargs -0 chown nobody:nobody
find "$PUBLIC_HTML" -type d -print0 | xargs -0 chmod 775
echo "[OK] Fixed public_html directory permissions"

# 5. Ensure dev controllers have allowed IP
for devfile in frontend_dev.php backend_dev.php; do
  filepath="$PUBLIC_HTML/$devfile"
  if [ -f "$filepath" ]; then
    if grep -q "$ALLOWED_IP" "$filepath"; then
      echo "[OK] $devfile already has $ALLOWED_IP"
    else
      sed -i "s/array('/array('$ALLOWED_IP', '/" "$filepath"
      echo "[OK] Added $ALLOWED_IP to $devfile"
    fi
  else
    if [ "$devfile" = "frontend_dev.php" ]; then
      APP="frontend"
    else
      APP="backend"
    fi
    cat > "$filepath" <<'DEVEOF'
<?php

if (!in_array(@$_SERVER['REMOTE_ADDR'], array('IPPLACEHOLDER', '127.0.0.1', '::1')))
{
  die('You are not allowed to access this file. Check '.basename(__FILE__).' for more information.');
}

require_once(dirname(__FILE__).'/../config/ProjectConfiguration.class.php');

$configuration = ProjectConfiguration::getApplicationConfiguration('APPPLACEHOLDER', 'dev', true);
sfContext::createInstance($configuration)->dispatch();
DEVEOF
    sed -i "s/IPPLACEHOLDER/$ALLOWED_IP/" "$filepath"
    sed -i "s/APPPLACEHOLDER/$APP/" "$filepath"
    chown nobody:nobody "$filepath"
    echo "[OK] Created $devfile with $ALLOWED_IP"
  fi
done

# 6. Disable MySQL strict mode (opt-in)
if [ "$FIX_MYSQL" = true ]; then
  mysql -e "SET GLOBAL sql_mode = 'ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION';"
  grep -q 'sql_mode' /etc/my.cnf && \
    sed -i 's/^sql_mode.*/sql_mode = ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION/' /etc/my.cnf || \
    sed -i '/\[mysqld\]/a sql_mode = ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION' /etc/my.cnf
  echo "[OK] Disabled MySQL STRICT_TRANS_TABLES (runtime + my.cnf)"
else
  echo "[SKIP] MySQL fix (use --fix-mysql to enable)"
fi

# 7. Restart services
systemctl restart httpd
echo "[OK] Restarted httpd"
systemctl restart mysqld
echo "[OK] Restarted mysqld"

echo "=== Done ==="
