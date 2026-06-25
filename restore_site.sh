#!/bin/bash
# restore_site.sh — Full cPanel site restore from .tar.gz backup
# Runs /scripts/restorepkg, then applies all Symfony 1.x fixes
#
# Usage:
#   bash restore_site.sh /path/to/backup.tar.gz                  # restore one site
#   bash restore_site.sh /home/backups/*.tar.gz                   # restore all
#   bash restore_site.sh --dry-run /path/to/backup.tar.gz        # show what would happen
#   bash restore_site.sh --fix-mysql /path/to/backup.tar.gz      # also fix MySQL strict mode
#   bash restore_site.sh --php 5.3 /path/to/backup.tar.gz        # also switch PHP version
#   bash restore_site.sh --fix-only tecnoid3vbay                  # fix permissions only, no tar needed
#   bash restore_site.sh --fix-only user1 user2 user3             # fix multiple accounts
#   bash restore_site.sh --fix-only ar13opv36icebay --type ar     # fix as area-riservata (Symfony 2.x)
#   bash restore_site.sh --skip-restore /home/backups/user.tar.gz # skip restorepkg, only fix
#
# What it does per site:
#   1. Runs /scripts/restorepkg to restore cPanel account
#   2. Fixes Symfony 1.x permissions (log/, cache/, uploads, plugins)
#   3. Clears Symfony cache
#   4. Comments out ExpiresActive/ExpiresDefault in .htaccess
#   5. Adds allowed IP to dev controllers
#   6. Removes error_log from public docroot
#   7. Truncates oversized log files
#   8. Optionally switches PHP version (--php)
#   9. Optionally fixes MySQL strict mode (--fix-mysql)
#  10. Restarts Apache

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ALLOWED_IP="82.84.108.8"
FIX_MYSQL=false
DRY_RUN=false
SKIP_RESTORE=false
TARGET_PHP=""
SITE_TYPE=""  # "ar" for area-riservata (Symfony 2.x), "site" for normal (Symfony 1.x), "" for auto-detect
BACKUPS=()
FIX_ONLY_USERS=()

# ─────────────────────────────────────────────
# Parse arguments
# ─────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --fix-mysql)   FIX_MYSQL=true ;;
        --dry-run)     DRY_RUN=true ;;
        --skip-restore) SKIP_RESTORE=true ;;
        --fix-only)
            SKIP_RESTORE=true
            shift
            while [ $# -gt 0 ] && [[ "$1" != --* ]]; do
                FIX_ONLY_USERS+=("$1")
                shift
            done
            continue
            ;;
        --type)
            shift
            SITE_TYPE="${1:?--type requires 'ar' or 'site'}"
            if [ "$SITE_TYPE" != "ar" ] && [ "$SITE_TYPE" != "site" ]; then
                echo "ERROR: --type must be 'ar' (area-riservata/Symfony 2.x) or 'site' (normal/Symfony 1.x)"
                exit 1
            fi
            ;;
        --php)
            shift
            TARGET_PHP="${1:?--php requires a version (e.g. 5.3, 7.0)}"
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Usage: $0 [OPTIONS] <backup.tar.gz> [...]"
            echo "       $0 --fix-only <username> [username2 ...] [OPTIONS]"
            exit 1
            ;;
        *)
            BACKUPS+=("$1")
            ;;
    esac
    shift
done

# Convert --fix-only usernames to fake backup paths so the main loop works
for u in "${FIX_ONLY_USERS[@]}"; do
    BACKUPS+=("/home/${u}.tar.gz")
done

if [ ${#BACKUPS[@]} -eq 0 ]; then
    echo "Usage: $0 [OPTIONS] <backup.tar.gz> [...]"
    echo "       $0 --fix-only <username> [username2 ...] [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --fix-only USER  Fix permissions only (no restore needed, takes usernames)"
    echo "  --type TYPE      Site type: 'ar' (area-riservata/Symfony 2.x) or 'site' (Symfony 1.x)"
    echo "                   If omitted, auto-detects by checking for app/ directory"
    echo "  --dry-run        Show what would happen without making changes"
    echo "  --fix-mysql      Disable MySQL STRICT_TRANS_TABLES"
    echo "  --php VERSION    Switch account to PHP version (e.g. 5.3, 7.0, 8.0)"
    echo "  --skip-restore   Skip /scripts/restorepkg, only apply fixes (needs .tar.gz path)"
    exit 1
fi

# ─────────────────────────────────────────────
# Setup logging — all output goes to screen + log file
# Wrap everything in a subshell piped to tee
# (exec > >(tee) is unreliable — only captures last command)
# ─────────────────────────────────────────────
LOGDIR="/root/restore_logs"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/restore_$(date +%Y%m%d_%H%M%S).log"

log() { echo "[$(date '+%H:%M:%S')] $1"; }

# Export variables and functions so the subshell can see them
export LOGDIR LOGFILE ALLOWED_IP FIX_MYSQL DRY_RUN SKIP_RESTORE TARGET_PHP
export -f log

(
log "Log file: $LOGFILE"

# ─────────────────────────────────────────────
# Process each backup
# ─────────────────────────────────────────────
TOTAL=${#BACKUPS[@]}
CURRENT=0
FAILED=()
SUCCEEDED=()

for BACKUP in "${BACKUPS[@]}"; do
    CURRENT=$((CURRENT+1))

    echo ""
    log "========================================="
    log "  [$CURRENT/$TOTAL] Processing: $(basename "$BACKUP")"
    log "========================================="

    # Extract username from backup filename
    # cPanel backups are named: username.tar.gz or cpmove-username.tar.gz
    FILENAME=$(basename "$BACKUP" .tar.gz)
    USER=$(echo "$FILENAME" | sed 's/^cpmove-//')
    HOME_DIR="/home/$USER"
    PUBLIC_HTML="$HOME_DIR/public_html"

    # Validate backup file (skip check for --fix-only)
    if [ "$SKIP_RESTORE" = false ] && [ ! -f "$BACKUP" ]; then
        log "  ERROR: File not found: $BACKUP"
        FAILED+=("$BACKUP (not found)")
        continue
    fi

    log "  User:    $USER"
    [ "$SKIP_RESTORE" = false ] && log "  Backup:  $BACKUP"
    log "  Home:    $HOME_DIR"

    if [ "$DRY_RUN" = true ]; then
        log "  [DRY RUN] Would restore and fix $USER"
        log "  [DRY RUN] Would run: /scripts/restorepkg $BACKUP"
        [ -n "$TARGET_PHP" ] && log "  [DRY RUN] Would switch PHP to $TARGET_PHP"
        SUCCEEDED+=("$USER (dry run)")
        continue
    fi

    # ─────────────────────────────────────────
    # Step 1: Restore cPanel account
    # ─────────────────────────────────────────
    if [ "$SKIP_RESTORE" = false ]; then
        log "  [1/10] Running /scripts/restorepkg..."
        RESTOREPKG_LOG="$LOGDIR/restorepkg_${USER}_$(date +%Y%m%d_%H%M%S).log"
        if /scripts/restorepkg "$BACKUP" 2>&1 | tee "$RESTOREPKG_LOG" | tail -20; then
            log "  [1/10] restorepkg completed. Full output: $RESTOREPKG_LOG"
        else
            log "  [1/10] ERROR: restorepkg failed for $BACKUP. Full output: $RESTOREPKG_LOG"
            FAILED+=("$USER (restorepkg failed — see $RESTOREPKG_LOG)")
            continue
        fi
    else
        log "  [1/10] SKIPPED restorepkg (--skip-restore)"
    fi

    # Verify home directory exists after restore
    if [ ! -d "$HOME_DIR" ]; then
        log "  ERROR: $HOME_DIR does not exist after restore"
        FAILED+=("$USER (no home dir after restore)")
        continue
    fi

    # Get user UID/GID
    USER_UID=$(id -u "$USER" 2>/dev/null)
    USER_GID=$(id -g "$USER" 2>/dev/null)

    if [ -z "$USER_UID" ] || [ -z "$USER_GID" ]; then
        log "  ERROR: Could not resolve UID/GID for $USER"
        FAILED+=("$USER (no uid/gid)")
        continue
    fi

    # ─────────────────────────────────────────
    # Step 2: Detect site type + Fix permissions
    # ─────────────────────────────────────────

    # Auto-detect type if not specified
    DETECTED_TYPE="$SITE_TYPE"
    if [ -z "$DETECTED_TYPE" ]; then
        HAS_SF2_STRUCTURE=false
        HAS_AR_PREFIX=false

        # Check Symfony 2.x file structure
        if [ -d "$HOME_DIR/app" ] && \
           ([ -f "$HOME_DIR/app/AppKernel.php" ] || [ -f "$HOME_DIR/app/autoload.php" ]); then
            HAS_SF2_STRUCTURE=true
        fi
        [ -f "$HOME_DIR/vendor/autoload.php" ] && HAS_SF2_STRUCTURE=true

        # Check username prefix
        [[ "$USER" == ar* ]] && HAS_AR_PREFIX=true

        if [ "$HAS_SF2_STRUCTURE" = true ] && [ "$HAS_AR_PREFIX" = true ]; then
            DETECTED_TYPE="ar"
        elif [ "$HAS_SF2_STRUCTURE" = true ] || [ "$HAS_AR_PREFIX" = true ]; then
            # One signal but not both — ask
            log "    UNCERTAIN: prefix_ar=$HAS_AR_PREFIX, sf2_structure=$HAS_SF2_STRUCTURE"
            log "    Is $USER an area-riservata (Symfony 2.x) or a normal site (Symfony 1.x)?"
            read -p "    Enter type [ar/site]: " DETECTED_TYPE
            if [ "$DETECTED_TYPE" != "ar" ] && [ "$DETECTED_TYPE" != "site" ]; then
                log "    Invalid input — defaulting to 'site'"
                DETECTED_TYPE="site"
            fi
        else
            DETECTED_TYPE="site"
        fi
    fi

    log "  [2/10] Fixing permissions (type: $DETECTED_TYPE)..."

    # 2a. Restore public_html ownership
    CURRENT_OWNER=$(stat -c '%u' "$PUBLIC_HTML" 2>/dev/null)
    if [ "${CURRENT_OWNER:-}" = "65534" ]; then
        log "    public_html: nobody → $USER"
        chown "$USER_UID:$USER_GID" "$PUBLIC_HTML"
    fi

    # 2b. Restore PHP files in public_html root
    find "$PUBLIC_HTML" -maxdepth 1 -type f -user nobody -exec chown "$USER_UID:$USER_GID" {} + 2>/dev/null

    # Helper: make a dir shared-writable by both CLI user and Apache (nobody)
    # Uses setfacl (Symfony recommended) so both users get rwX on existing + future files
    # Ref: https://symfony.com/doc/current/setup/file_permissions.html
    fix_shared_dir() {
        local path="$1"
        local label="$2"
        if [ -d "$path" ]; then
            log "    $label → ACL: $USER+nobody rwX (setfacl)"
            # Set permissions on existing files and folders
            setfacl -R -m u:"$USER":rwX -m u:nobody:rwX "$path" 2>/dev/null
            # Set default permissions for future files and folders
            setfacl -dR -m u:"$USER":rwX -m u:nobody:rwX "$path" 2>/dev/null
        fi
    }

    if [ "$DETECTED_TYPE" = "ar" ]; then
        # ─────────────────────────────────────
        # AREA RISERVATA — Symfony 2.x
        # Structure: app/cache/, app/logs/, spool/, vendor/, web/ (=public_html)
        # Cache/logs/spool must be writable by BOTH CLI user and Apache (nobody)
        # ─────────────────────────────────────
        log "    [AR/Symfony 2.x] Fixing app/cache, app/logs, spool, var/cache, var/logs..."

        # Shared writable dirs (CLI + Apache): cache, logs, spool, sessions
        for dir in app/cache app/logs spool var/cache var/logs var/log var/sessions var/spool; do
            fix_shared_dir "$HOME_DIR/$dir" "$dir/"
        done

        # Create missing dirs
        for dir in app/cache app/logs spool; do
            path="$HOME_DIR/$dir"
            if [ ! -d "$path" ]; then
                mkdir -p "$path"
                setfacl -R -m u:"$USER":rwX -m u:nobody:rwX "$path" 2>/dev/null
                setfacl -dR -m u:"$USER":rwX -m u:nobody:rwX "$path" 2>/dev/null
                log "    Created missing $dir/ (ACL: $USER+nobody rwX)"
            fi
        done

        # vendor/ — user-owned, readable
        if [ -d "$HOME_DIR/vendor" ]; then
            log "    vendor/ → $USER_UID:$USER_GID 755 (composer deps)"
            chown -R "$USER_UID:$USER_GID" "$HOME_DIR/vendor"
            chmod -R 755 "$HOME_DIR/vendor"
        fi

        # app/config — user-owned (contains parameters.yml with DB creds)
        if [ -d "$HOME_DIR/app/config" ]; then
            chown -R "$USER_UID:$USER_GID" "$HOME_DIR/app/config"
            chmod -R 755 "$HOME_DIR/app/config"
        fi

        # web/uploads or public_html/uploads and Flysystem file storage
        for dir in uploads bundles media files images; do
            fix_shared_dir "$PUBLIC_HTML/$dir" "public_html/$dir/"
        done

        # Also handle log/ at home root if it exists (some AR sites have both)
        fix_shared_dir "$HOME_DIR/log" "log/"

    else
        # ─────────────────────────────────────
        # NORMAL SITE — Symfony 1.x
        # Structure: cache/, log/, public_html/ (=web), plugins/
        # Cache/log must be writable by BOTH CLI user and Apache (nobody)
        # ─────────────────────────────────────
        log "    [Site/Symfony 1.x] Fixing cache, log, uploads, plugins..."

        # Shared writable dirs (CLI + Apache)
        for dir in log cache; do
            fix_shared_dir "$HOME_DIR/$dir" "$dir/"
        done

        # Create log dir if missing
        if [ ! -d "$HOME_DIR/log" ]; then
            mkdir -p "$HOME_DIR/log"
            setfacl -R -m u:"$USER":rwX -m u:nobody:rwX "$HOME_DIR/log" 2>/dev/null
            setfacl -dR -m u:"$USER":rwX -m u:nobody:rwX "$HOME_DIR/log" 2>/dev/null
            log "    Created missing log/ (ACL: $USER+nobody rwX)"
        fi

        # Upload directories in public_html
        for dir in uploads form_upload export download repository files images; do
            fix_shared_dir "$PUBLIC_HTML/$dir" "public_html/$dir/"
        done

        # Plugin dirs with numbered subdirs (runtime uploads like dgNewsPlugin/102/)
        find "$PUBLIC_HTML" -maxdepth 2 -type d -regex '.*/[0-9]+$' 2>/dev/null | while read -r numdir; do
            plugin_dir=$(dirname "$numdir")
            if [ "$plugin_dir" != "$PUBLIC_HTML" ]; then
                fix_shared_dir "$plugin_dir" "$(basename "$plugin_dir")/ (plugin uploads)"
            fi
        done

        # Static asset dirs — restore to user ownership, 755
        find "$PUBLIC_HTML" -maxdepth 1 -type d -user nobody | while read -r subdir; do
            dirname=$(basename "$subdir")
            case "$dirname" in
                uploads|form_upload|export|download|repository)
                    continue
                    ;;
            esac
            if find "$subdir" -maxdepth 1 -type d -regex '.*/[0-9]+$' 2>/dev/null | grep -q .; then
                fix_shared_dir "$subdir" "$(basename "$subdir")/ (plugin with uploads)"
            else
                chown -R "$USER_UID:$USER_GID" "$subdir"
                chmod -R 755 "$subdir"
            fi
        done
    fi

    # TinyMCE moxiemanager data dirs (cache, storage, logs, temp, files)
    # These need shared ACLs because moxiemanager writes session/cache data at runtime
    find "$PUBLIC_HTML" -type d -path '*/moxiemanager/data' 2>/dev/null | while read -r moxdir; do
        fix_shared_dir "$moxdir" "$(echo "$moxdir" | sed "s|$HOME_DIR/||")/"
    done

    # cms_*/images/ dirs (sfCmsPlugin gallery uploads with numbered subdirs)
    find "$PUBLIC_HTML" -maxdepth 2 -type d -name 'images' -path '*/cms_*/*' 2>/dev/null | while read -r cmsimg; do
        fix_shared_dir "$cmsimg" "$(echo "$cmsimg" | sed "s|$HOME_DIR/||")/"
    done

    log "  [2/10] Permissions fixed."

    # ─────────────────────────────────────────
    # Step 3: Clear Symfony cache
    # ─────────────────────────────────────────
    log "  [3/10] Clearing Symfony cache..."

    # Clear cache and reapply ACLs so next writes (CLI or Apache) both work
    if [ "$DETECTED_TYPE" = "ar" ]; then
        # Symfony 2.x — must wipe app/cache completely (ClassCollectionLoader crashes on stale compiled classes)
        for cdir in "$HOME_DIR/app/cache" "$HOME_DIR/var/cache"; do
            if [ -d "$cdir" ]; then
                rm -rf "$cdir"/*
                setfacl -R -m u:"$USER":rwX -m u:nobody:rwX "$cdir" 2>/dev/null
                setfacl -dR -m u:"$USER":rwX -m u:nobody:rwX "$cdir" 2>/dev/null
                log "    Cleared $cdir (ACL: $USER+nobody rwX on new files)"
            fi
        done
    else
        # Symfony 1.x
        if [ -d "$HOME_DIR/cache" ]; then
            rm -rf "$HOME_DIR/cache"/*
            setfacl -R -m u:"$USER":rwX -m u:nobody:rwX "$HOME_DIR/cache" 2>/dev/null
            setfacl -dR -m u:"$USER":rwX -m u:nobody:rwX "$HOME_DIR/cache" 2>/dev/null
            log "    Cleared cache/ (ACL: $USER+nobody rwX on new files)"
        fi
    fi

    # ─────────────────────────────────────────
    # Step 4: Fix .htaccess
    # ─────────────────────────────────────────
    log "  [4/10] Fixing .htaccess..."
    HTACCESS="$PUBLIC_HTML/.htaccess"
    if [ -f "$HTACCESS" ]; then
        cp "$HTACCESS" "$HTACCESS.bak"
        sed -i 's/^\([[:space:]]*Expires\(Active\|Default\)\)/#\1/' "$HTACCESS"
        log "    Commented out ExpiresActive/ExpiresDefault."
    else
        log "    No .htaccess found — skipping."
    fi

    # ─────────────────────────────────────────
    # Step 5: Dev controllers — add allowed IP
    # ─────────────────────────────────────────
    log "  [5/10] Fixing dev controllers (allowed IP: $ALLOWED_IP)..."
    for devfile in frontend_dev.php backend_dev.php content_dev.php cli_dev.php admin_dev.php; do
        filepath="$PUBLIC_HTML/$devfile"
        if [ -f "$filepath" ]; then
            if grep -q "$ALLOWED_IP" "$filepath"; then
                log "    $devfile — already has $ALLOWED_IP"
            else
                sed -i "s/array('/array('$ALLOWED_IP', '/" "$filepath"
                log "    $devfile — added $ALLOWED_IP"
            fi
        fi
    done

    # ─────────────────────────────────────────
    # Step 6: Remove error_log from docroot
    # ─────────────────────────────────────────
    log "  [6/10] Removing error_log from docroot..."
    if [ -f "$PUBLIC_HTML/error_log" ]; then
        SIZE=$(du -h "$PUBLIC_HTML/error_log" | cut -f1)
        rm -f "$PUBLIC_HTML/error_log"
        log "    Removed $PUBLIC_HTML/error_log ($SIZE)"
    else
        log "    None found."
    fi

    # ─────────────────────────────────────────
    # Step 7: Truncate oversized log files
    # ─────────────────────────────────────────
    log "  [7/10] Truncating oversized logs (>100MB)..."
    for logdir in "$HOME_DIR/log" "$HOME_DIR/app/logs" "$HOME_DIR/var/logs" "$HOME_DIR/var/log"; do
        [ ! -d "$logdir" ] && continue
        find "$logdir" -type f -name "*.log" -size +100M 2>/dev/null | while read -r logfile; do
            SIZE=$(du -h "$logfile" | cut -f1)
            : > "$logfile"
            log "    Truncated $logfile ($SIZE → 0)"
        done
    done

    # ─────────────────────────────────────────
    # Step 8: Switch PHP version (if requested)
    # ─────────────────────────────────────────
    if [ -n "$TARGET_PHP" ]; then
        log "  [8/10] Switching PHP version to $TARGET_PHP..."

        # Normalize version
        PHP_VER=$(echo "$TARGET_PHP" | sed -E 's/^(php|ea-php)?//; s/\.//g')
        PHP_PKG="ea-php${PHP_VER}"

        # Find domains for this user
        DOMAINS=$(grep "$USER" /etc/trueuserdomains 2>/dev/null | awk -F: '{print $1}' | tr -d ' ')

        if [ -n "$DOMAINS" ]; then
            # Get current extensions
            CURRENT_PHP=$(/usr/local/cpanel/bin/whmapi1 php_get_domain_handler domain="$(echo "$DOMAINS" | head -1)" 2>/dev/null \
                | grep 'current:' | awk '{print $2}' | sed 's|cgi||; s|/.*||')

            # If CURRENT_PHP is empty (system_default/inherit) or different, proceed with switch
            if [ -z "$CURRENT_PHP" ] || [ "$CURRENT_PHP" != "$PHP_PKG" ]; then
                # When inheriting system default, detect it for extension copying
                if [ -z "$CURRENT_PHP" ]; then
                    CURRENT_PHP=$(/usr/local/cpanel/bin/whmapi1 php_get_system_default_version 2>/dev/null \
                        | grep 'version:' | awk '{print $2}')
                    [ -n "$CURRENT_PHP" ] && log "    Current PHP (system default): $CURRENT_PHP"
                fi
                # Install matching extensions
                EXTS=$(rpm -qa | grep "^${CURRENT_PHP}-php-" | sed "s/^${CURRENT_PHP}-php-//" | sed 's/-[0-9].*//' | sort -u)
                INSTALL_LIST=""
                for ext in $EXTS; do
                    PKG="${PHP_PKG}-php-${ext}"
                    if yum list available "$PKG" &>/dev/null; then
                        INSTALL_LIST="$INSTALL_LIST $PKG"
                    fi
                done

                if [ -n "$INSTALL_LIST" ]; then
                    log "    Installing extensions for $PHP_PKG..."
                    yum install -y $INSTALL_LIST &>/dev/null
                fi

                # Ensure handler is registered in php.conf (newly installed versions may lack it)
                if ! grep -q "^${PHP_PKG}:" /etc/cpanel/ea4/php.conf 2>/dev/null; then
                    echo "${PHP_PKG}: cgi" >> /etc/cpanel/ea4/php.conf
                    log "    Registered ${PHP_PKG} handler in /etc/cpanel/ea4/php.conf"
                fi

                # Switch each domain
                for domain in $DOMAINS; do
                    /usr/local/cpanel/bin/whmapi1 php_set_vhost_versions version="$PHP_PKG" vhost-0="$domain" &>/dev/null
                    log "    Switched $domain → $PHP_PKG"
                done
            else
                log "    Already on $PHP_PKG (confirmed) — skipping."
            fi
        else
            log "    No domains found for $USER — skipping PHP switch."
        fi
    else
        log "  [8/10] PHP version — no change requested."
    fi

    # ─────────────────────────────────────────
    # Step 9: MySQL strict mode (if requested)
    # ─────────────────────────────────────────
    if [ "$FIX_MYSQL" = true ]; then
        log "  [9/10] Fixing MySQL strict mode..."
        mysql -e "SET GLOBAL sql_mode = 'ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION';" 2>/dev/null
        if grep -q 'sql_mode' /etc/my.cnf 2>/dev/null; then
            sed -i 's/^sql_mode.*/sql_mode = ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION/' /etc/my.cnf
        else
            sed -i '/\[mysqld\]/a sql_mode = ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION' /etc/my.cnf
        fi
        log "    MySQL strict mode disabled."
    else
        log "  [9/10] MySQL — no change requested."
    fi

    # ─────────────────────────────────────────
    # Step 10: Verify
    # ─────────────────────────────────────────
    log "  [10/10] Verifying..."
    log "    public_html: $(stat -c '%U:%G %a' "$PUBLIC_HTML" 2>/dev/null)"
    [ -d "$HOME_DIR/log" ] && log "    log/:         $(stat -c '%U:%G %a' "$HOME_DIR/log" 2>/dev/null)"
    [ -d "$HOME_DIR/cache" ] && log "    cache/:       $(stat -c '%U:%G %a' "$HOME_DIR/cache" 2>/dev/null)"

    SUCCEEDED+=("$USER")
    log "  Done: $USER"
done

# ─────────────────────────────────────────────
# Restart Apache (once, after all restores)
# ─────────────────────────────────────────────
if [ "$DRY_RUN" = false ]; then
    echo ""
    log "Restarting Apache..."
    systemctl restart httpd 2>/dev/null && log "  Apache restarted." || log "  WARNING: Apache restart failed"
fi

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
log "========================================="
log "  RESTORE COMPLETE"
log "  Total:     $TOTAL"
log "  Succeeded: ${#SUCCEEDED[@]}"
log "  Failed:    ${#FAILED[@]}"
log "========================================="

if [ ${#SUCCEEDED[@]} -gt 0 ]; then
    log "  Succeeded:"
    for s in "${SUCCEEDED[@]}"; do
        log "    - $s"
    done
fi

if [ ${#FAILED[@]} -gt 0 ]; then
    log "  Failed:"
    for f in "${FAILED[@]}"; do
        log "    - $f"
    done
fi

log ""
log "  Full log:        $LOGFILE"
log "  Per-site logs:   $LOGDIR/restorepkg_*.log"
echo ""
) 2>&1 | tee "$LOGFILE"
