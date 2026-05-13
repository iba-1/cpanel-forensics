#!/bin/bash
# Switch a cPanel account's PHP version while preserving extensions
# Usage: bash switch_php_version.sh <domain> <target_php>
# Example: bash switch_php_version.sh tecnoidealsrl.com ea-php53
#          bash switch_php_version.sh tecnoidealsrl.com ea-php70
#
# What it does:
#   1. Detects current PHP version for the domain
#   2. Lists extensions installed on current version
#   3. Installs missing extensions on target version
#   4. Switches the domain to target version
#   5. Verifies the switch

set -uo pipefail

DOMAIN="${1:?Usage: $0 <domain> <target_php_version>}"
TARGET="${2:?Usage: $0 <domain> <target_php_version (e.g. ea-php53, ea-php70, ea-php80)>}"

# Normalize target — accept "5.3", "53", "php53", "ea-php53"
TARGET=$(echo "$TARGET" | sed -E 's/^(php|ea-php)?//; s/\.//g')
TARGET="ea-php${TARGET}"

echo "========================================="
echo "  PHP Version Switch"
echo "  Domain:  $DOMAIN"
echo "  Target:  $TARGET"
echo "========================================="

# ─────────────────────────────────────────────
# 1. Detect current PHP version
# ─────────────────────────────────────────────
echo ""
echo "[1] Detecting current PHP version for $DOMAIN..."

# Get current handler/version from cPanel
CURRENT=$(/usr/local/cpanel/bin/whmapi1 php_get_domain_handler domain="$DOMAIN" 2>/dev/null \
    | grep 'current:' | awk '{print $2}' | sed 's|cgi||; s|/.*||')

if [ -z "$CURRENT" ]; then
    # Fallback: check MultiPHP config
    CURRENT=$(grep "$DOMAIN" /var/cpanel/userdata/*/php_fpm.yaml 2>/dev/null \
        | grep -oP 'ea-php\d+' | head -1)
fi

if [ -z "$CURRENT" ]; then
    # Fallback: try whmapi1 differently
    CURRENT=$(/usr/local/cpanel/bin/whmapi1 php_get_vhost_versions domain="$DOMAIN" 2>/dev/null \
        | grep -oP 'ea-php\d+' | head -1)
fi

if [ -z "$CURRENT" ]; then
    echo "  WARNING: Could not auto-detect current PHP version."
    echo "  Listing installed PHP versions:"
    rpm -qa | grep 'ea-php.*-php-cli' | sort
    echo ""
    read -p "  Enter current PHP version (e.g. ea-php55): " CURRENT
fi

echo "  Current: $CURRENT"
echo "  Target:  $TARGET"

if [ "$CURRENT" = "$TARGET" ]; then
    echo "  Already on $TARGET — nothing to do."
    exit 0
fi

# ─────────────────────────────────────────────
# 2. Get extensions on current version
# ─────────────────────────────────────────────
echo ""
echo "[2] Listing extensions installed on $CURRENT..."

CURRENT_EXTS=$(rpm -qa | grep "^${CURRENT}-php-" | sed "s/^${CURRENT}-php-//" | sed 's/-[0-9].*//' | sort -u)
EXT_COUNT=$(echo "$CURRENT_EXTS" | wc -l)

echo "  Found $EXT_COUNT extensions on $CURRENT:"
echo "$CURRENT_EXTS" | while read -r ext; do
    echo "    - $ext"
done

# ─────────────────────────────────────────────
# 3. Check what's already installed on target
# ─────────────────────────────────────────────
echo ""
echo "[3] Checking what's already installed on $TARGET..."

TARGET_EXTS=$(rpm -qa | grep "^${TARGET}-php-" | sed "s/^${TARGET}-php-//" | sed 's/-[0-9].*//' | sort -u)

# Find what's missing
MISSING=""
while read -r ext; do
    [ -z "$ext" ] && continue
    if ! echo "$TARGET_EXTS" | grep -qx "$ext"; then
        MISSING="$MISSING $ext"
    fi
done <<< "$CURRENT_EXTS"

# Check if target base is installed
if ! rpm -qa | grep -q "^${TARGET}-runtime"; then
    echo "  Target PHP runtime not installed. Installing $TARGET base..."
    yum install -y "${TARGET}-runtime" "${TARGET}-php-cli" "${TARGET}-php-common" "${TARGET}-php-litespeed" 2>/dev/null
fi

# ─────────────────────────────────────────────
# 4. Install missing extensions on target
# ─────────────────────────────────────────────
echo ""
if [ -n "$MISSING" ]; then
    echo "[4] Installing missing extensions on $TARGET..."
    INSTALL_LIST=""
    SKIPPED=""
    for ext in $MISSING; do
        PKG="${TARGET}-php-${ext}"
        # Check if package exists in repos
        if yum list available "$PKG" &>/dev/null || yum list installed "$PKG" &>/dev/null; then
            INSTALL_LIST="$INSTALL_LIST $PKG"
            echo "  Will install: $PKG"
        else
            SKIPPED="$SKIPPED $ext"
            echo "  SKIP: $PKG (not available for $TARGET)"
        fi
    done

    if [ -n "$INSTALL_LIST" ]; then
        echo ""
        echo "  Installing: $INSTALL_LIST"
        yum install -y $INSTALL_LIST
    fi

    if [ -n "$SKIPPED" ]; then
        echo ""
        echo "  WARNING — Extensions not available on $TARGET:"
        for ext in $SKIPPED; do
            echo "    - $ext (was on $CURRENT, no equivalent for $TARGET)"
        done
    fi
else
    echo "[4] All extensions already present on $TARGET — nothing to install."
fi

# ─────────────────────────────────────────────
# 5. Switch the domain to target PHP version
# ─────────────────────────────────────────────
echo ""
echo "[5] Switching $DOMAIN from $CURRENT → $TARGET..."

# Use whmapi1 to set PHP version
RESULT=$(/usr/local/cpanel/bin/whmapi1 php_set_vhost_versions version="$TARGET" vhost-0="$DOMAIN" 2>&1)

if echo "$RESULT" | grep -q 'result: 1'; then
    echo "  Switch successful."
else
    echo "  whmapi1 result:"
    echo "$RESULT" | head -20
    echo ""
    echo "  If whmapi1 failed, try manually in WHM → MultiPHP Manager"
fi

# ─────────────────────────────────────────────
# 6. Verify
# ─────────────────────────────────────────────
echo ""
echo "[6] Verifying..."

# Check new version
NEW_VER=$(/usr/local/cpanel/bin/whmapi1 php_get_domain_handler domain="$DOMAIN" 2>/dev/null \
    | grep 'current:' | awk '{print $2}')
echo "  Domain handler: $NEW_VER"

# Compare extensions
echo ""
echo "  Extension comparison ($CURRENT → $TARGET):"
echo "  ─────────────────────────────────────"
TARGET_EXTS_NOW=$(rpm -qa | grep "^${TARGET}-php-" | sed "s/^${TARGET}-php-//" | sed 's/-[0-9].*//' | sort -u)

while read -r ext; do
    [ -z "$ext" ] && continue
    if echo "$TARGET_EXTS_NOW" | grep -qx "$ext"; then
        echo "    [OK] $ext"
    else
        echo "    [!!] $ext — MISSING on $TARGET"
    fi
done <<< "$CURRENT_EXTS"

echo ""
echo "========================================="
echo "  Done: $DOMAIN"
echo "  Was:  $CURRENT"
echo "  Now:  $TARGET"
echo "========================================="
