#!/bin/bash
# Fix Symfony 1.x permissions per site on cPanel/CloudLinux
# Adapted for project layout where project root = /home/<user>/
# and public_html = Symfony's web/ directory
#
# Usage:
#   bash fix_symfony_perms.sh <username>              # fix permissions
#   bash fix_symfony_perms.sh --backup <username>     # backup first, then fix
#   bash fix_symfony_perms.sh --backup-only <username> # backup only, no changes
#
# What it does:
#   1. Restores public_html ownership to cPanel user (was nobody:nobody)
#   2. Sets log/ and cache/ to user-owned, group nobody, 775 (Apache can write)
#   3. Sets upload dirs inside public_html to group nobody, 775
#   4. Truncates oversized log files (>100MB)
#   5. Removes error_log from public docroot (security risk)

set -uo pipefail

# ─────────────────────────────────────────────
# Parse arguments
# ─────────────────────────────────────────────
BACKUP=0
BACKUP_ONLY=0

case "${1:-}" in
    --backup)
        BACKUP=1
        shift
        ;;
    --backup-only)
        BACKUP=1
        BACKUP_ONLY=1
        shift
        ;;
esac

USER="${1:?Usage: $0 [--backup|--backup-only] <cpanel_username>}"
HOME_DIR="/home/$USER"

if [ ! -d "$HOME_DIR" ]; then
    echo "ERROR: $HOME_DIR does not exist"
    exit 1
fi

if [ ! -d "$HOME_DIR/public_html" ]; then
    echo "ERROR: $HOME_DIR/public_html does not exist"
    exit 1
fi

USER_UID=$(id -u "$USER" 2>/dev/null)
USER_GID=$(id -g "$USER" 2>/dev/null)

if [ -z "$USER_UID" ] || [ -z "$USER_GID" ]; then
    echo "ERROR: Could not resolve UID/GID for user $USER"
    exit 1
fi

echo "========================================="
echo "  Symfony 1.x Permission Fix"
echo "  User:  $USER ($USER_UID:$USER_GID)"
echo "  Home:  $HOME_DIR"
echo "  Mode:  $([ $BACKUP_ONLY -eq 1 ] && echo "backup only" || ([ $BACKUP -eq 1 ] && echo "backup + fix" || echo "fix only"))"
echo "========================================="

# ─────────────────────────────────────────────
# Backup (if requested)
# ─────────────────────────────────────────────
if [ "$BACKUP" -eq 1 ]; then
    BACKUP_DIR="/home/${USER}_perms_backup_$(date +%Y%m%d_%H%M%S)"
    echo ""
    echo "[BACKUP] Creating permission snapshot before changes..."
    echo "  Destination: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"

    # Save full ownership/permission map
    echo "  Saving ownership map (find -ls) → $BACKUP_DIR/permissions.txt"
    find "$HOME_DIR" -maxdepth 1 -ls > "$BACKUP_DIR/permissions.txt" 2>/dev/null

    echo "  Saving public_html ownership map → $BACKUP_DIR/public_html_perms.txt"
    find "$HOME_DIR/public_html" -maxdepth 2 -ls > "$BACKUP_DIR/public_html_perms.txt" 2>/dev/null

    echo "  Saving log/ ownership → $BACKUP_DIR/log_perms.txt"
    ls -laR "$HOME_DIR/log/" > "$BACKUP_DIR/log_perms.txt" 2>/dev/null

    echo "  Saving cache/ ownership → $BACKUP_DIR/cache_perms.txt"
    ls -la "$HOME_DIR/cache/" > "$BACKUP_DIR/cache_perms.txt" 2>/dev/null

    # Backup log files (copy, not move — they may be actively written to)
    if [ -d "$HOME_DIR/log" ]; then
        echo "  Backing up log files → $BACKUP_DIR/log/"
        cp -a "$HOME_DIR/log/" "$BACKUP_DIR/log/" 2>/dev/null
    fi

    # Backup .htaccess
    [ -f "$HOME_DIR/public_html/.htaccess" ] && cp -a "$HOME_DIR/public_html/.htaccess" "$BACKUP_DIR/.htaccess" 2>/dev/null

    # Backup error_log if present
    [ -f "$HOME_DIR/public_html/error_log" ] && cp -a "$HOME_DIR/public_html/error_log" "$BACKUP_DIR/error_log" 2>/dev/null

    # Save restore script
    cat > "$BACKUP_DIR/restore.sh" <<'RESTORE'
#!/bin/bash
# Restore original permissions from backup
# Usage: bash restore.sh
BACKUP_DIR="$(dirname "$0")"
HOME_DIR="$(head -1 "$BACKUP_DIR/home_path.txt")"
echo "Restoring permissions from $BACKUP_DIR to $HOME_DIR..."
# Restore log files
[ -d "$BACKUP_DIR/log" ] && cp -a "$BACKUP_DIR/log/"* "$HOME_DIR/log/" 2>/dev/null
# Restore .htaccess
[ -f "$BACKUP_DIR/.htaccess" ] && cp -a "$BACKUP_DIR/.htaccess" "$HOME_DIR/public_html/.htaccess" 2>/dev/null
echo "File restore done. To restore ownership, review $BACKUP_DIR/permissions.txt"
echo "and run chown/chmod manually based on the saved state."
RESTORE
    echo "$HOME_DIR" > "$BACKUP_DIR/home_path.txt"
    chmod +x "$BACKUP_DIR/restore.sh"

    echo "  Backup complete: $BACKUP_DIR"

    if [ "$BACKUP_ONLY" -eq 1 ]; then
        echo ""
        echo "  --backup-only mode: no changes made."
        exit 0
    fi
fi

# ─────────────────────────────────────────────
# 1. Restore public_html ownership to cPanel user
#    (only the directory itself, not recursively —
#     subdirs with uploads need nobody group access)
# ─────────────────────────────────────────────
echo ""
CURRENT_OWNER=$(stat -c '%u' "$HOME_DIR/public_html")
if [ "$CURRENT_OWNER" = "65534" ]; then
    echo "[1] Restoring public_html directory ownership: nobody → $USER ($USER_UID:$USER_GID)"
    echo "  chown $USER_UID:$USER_GID $HOME_DIR/public_html"
    chown "$USER_UID:$USER_GID" "$HOME_DIR/public_html"
else
    echo "[1] public_html already owned by UID $CURRENT_OWNER — skipping"
fi

# Restore ownership of PHP files in public_html (front controllers, config)
echo "  Restoring ownership of PHP files in public_html root..."
find "$HOME_DIR/public_html" -maxdepth 1 -type f -user nobody -exec chown "$USER_UID:$USER_GID" {} + 2>/dev/null
echo "  Done."

# ─────────────────────────────────────────────
# 2. Fix Symfony log/ and cache/ dirs
#    Project root = /home/<user>/
#    log/ and cache/ need: owned by user, group nobody, 775
# ─────────────────────────────────────────────
echo ""
echo "[2] Fixing Symfony log/ and cache/ directories (need Apache write access)..."

for dir in log cache; do
    path="$HOME_DIR/$dir"
    if [ -d "$path" ]; then
        echo "  Found: $path"
        echo "    → chown -R $USER_UID:nobody $path"
        chown -R "$USER_UID" "$path"
        chgrp -R nobody "$path"
        echo "    → chmod -R 775 $path"
        chmod -R 775 "$path"
    fi
done

# Also handle app/logs, app/cache, var/log, var/cache if they exist
for dir in app/logs app/cache var/log var/cache; do
    path="$HOME_DIR/$dir"
    if [ -d "$path" ]; then
        echo "  Found: $path"
        chown -R "$USER_UID" "$path"
        chgrp -R nobody "$path"
        chmod -R 775 "$path"
        echo "    → set to $USER_UID:nobody 775"
    fi
done

echo "  Done."

# ─────────────────────────────────────────────
# 3. Fix upload/form directories inside public_html
#    These need Apache write access for file uploads
# ─────────────────────────────────────────────
echo ""
echo "[3] Fixing upload directories in public_html (Apache needs write for uploads)..."

# Known upload directories
for dir in uploads form_upload export download repository; do
    path="$HOME_DIR/public_html/$dir"
    if [ -d "$path" ]; then
        echo "  Found upload dir: $path"
        echo "    → chown -R $USER_UID:nobody $path, chmod 775"
        chown -R "$USER_UID" "$path"
        chgrp -R nobody "$path"
        chmod -R 775 "$path"
    fi
done

# Symfony plugins that create upload subdirs at runtime (dgNewsPlugin/102/, etc.)
# Detect by looking for numbered subdirs (article ID folders) or upload patterns
echo "  Scanning for plugin dirs with dynamic upload folders..."
find "$HOME_DIR/public_html" -maxdepth 2 -type d -regex '.*/[0-9]+$' 2>/dev/null | while read -r numdir; do
    plugin_dir=$(dirname "$numdir")
    plugin_name=$(basename "$plugin_dir")
    if [ "$plugin_dir" != "$HOME_DIR/public_html" ]; then
        echo "  Found plugin with upload dirs: $plugin_dir (contains $(basename "$numdir")/)"
        echo "    → chown -R $USER_UID:nobody $plugin_dir, chmod 775"
        chown -R "$USER_UID" "$plugin_dir"
        chgrp -R nobody "$plugin_dir"
        chmod -R 775 "$plugin_dir"
    fi
done

echo "  Done."

# ─────────────────────────────────────────────
# 4. Fix subdirectories in public_html that are
#    currently nobody:nobody (plugin assets, css, js, images)
#    These are static — should be owned by user, readable by all
# ─────────────────────────────────────────────
echo ""
echo "[4] Restoring ownership of static asset dirs in public_html..."

find "$HOME_DIR/public_html" -maxdepth 1 -type d -user nobody | while read -r subdir; do
    dirname=$(basename "$subdir")
    # Skip known writable dirs (handled in step 3)
    case "$dirname" in
        uploads|form_upload|export|download|repository)
            continue
            ;;
    esac
    # Skip plugin dirs that have numbered subdirs (dynamic uploads)
    if find "$subdir" -maxdepth 1 -type d -regex '.*/[0-9]+$' 2>/dev/null | grep -q .; then
        echo "  $subdir → $USER_UID:nobody 775 (plugin with upload dirs)"
        chown -R "$USER_UID" "$subdir"
        chgrp -R nobody "$subdir"
        chmod -R 775 "$subdir"
    else
        echo "  $subdir → $USER_UID:$USER_GID 755 (static assets)"
        chown -R "$USER_UID:$USER_GID" "$subdir"
        chmod -R 755 "$subdir"
    fi
done

echo "  Done."

# ─────────────────────────────────────────────
# 5. Truncate oversized log files
# ─────────────────────────────────────────────
echo ""
echo "[5] Checking for oversized log files (>100MB)..."

find "$HOME_DIR/log" -type f -name "*.log" -size +100M 2>/dev/null | while read -r logfile; do
    SIZE=$(du -h "$logfile" | cut -f1)
    echo "  OVERSIZED: $logfile ($SIZE)"
    echo "    → truncating (content preserved in backup if --backup was used)"
    : > "$logfile"
    echo "    → truncated to 0 bytes"
done

echo "  Done."

# ─────────────────────────────────────────────
# 6. Remove error_log from public docroot
# ─────────────────────────────────────────────
echo ""
echo "[6] Checking for error_log in public docroot (security risk — exposes server info)..."

if [ -f "$HOME_DIR/public_html/error_log" ]; then
    SIZE=$(du -h "$HOME_DIR/public_html/error_log" | cut -f1)
    echo "  FOUND: $HOME_DIR/public_html/error_log ($SIZE)"
    echo "    → removing (backed up if --backup was used)"
    rm -f "$HOME_DIR/public_html/error_log"
    echo "    → removed"
else
    echo "  None found."
fi

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "========================================="
echo "  Done: $USER"
echo "  public_html owner: $(stat -c '%U:%G (%a)' "$HOME_DIR/public_html")"
[ -d "$HOME_DIR/log" ] && echo "  log/ owner:         $(stat -c '%U:%G (%a)' "$HOME_DIR/log")"
[ -d "$HOME_DIR/cache" ] && echo "  cache/ owner:       $(stat -c '%U:%G (%a)' "$HOME_DIR/cache")"
[ -n "${BACKUP_DIR:-}" ] && echo "  backup:             $BACKUP_DIR"
echo "========================================="
