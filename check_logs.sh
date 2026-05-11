#!/bin/bash
# Log reader + watcher for a specific domain on cPanel server
# Usage: bash check_logs.sh <domain>
# Example: bash check_logs.sh example.com

DOMAIN="${1:?Usage: $0 <domain>}"
SAVE_FILE="/tmp/logs_${DOMAIN//[^a-zA-Z0-9._-]/_}.txt"

echo "========================================="
echo "  Log search for: ${DOMAIN}"
echo "========================================="

# Directories where domain-specific logs live
SEARCH_DIRS=(
    "/var/log/httpd"
    "/var/log/apache2"
    "/usr/local/apache/logs"
    "/usr/local/apache/domlogs"
    "/etc/httpd/logs"
    "/home/*/logs"
)

FOUND_LOGS=()

echo ""
echo "[1] Searching for logs specific to ${DOMAIN}..."
echo "-----------------------------------------"

# Find logs whose filename contains the domain
for dir in "${SEARCH_DIRS[@]}"; do
    while IFS= read -r f; do
        if [ -n "$f" ]; then
            FOUND_LOGS+=("$f")
            echo "  found: $f"
        fi
    done < <(find $dir -type f \( -iname "*${DOMAIN}*" -o -iname "*${DOMAIN//./_}*" \) ! -name "*.gz" 2>/dev/null)
done

# Check cPanel domlogs (often named exactly as the domain)
for f in /usr/local/apache/domlogs/*/"${DOMAIN}" \
         /usr/local/apache/domlogs/"${DOMAIN}" \
         /usr/local/apache/domlogs/"${DOMAIN}-ssl_log" \
         /usr/local/apache/domlogs/"${DOMAIN}"-bytes_log; do
    if [ -f "$f" ] && [[ ! " ${FOUND_LOGS[*]} " =~ " $f " ]] && [[ "$f" != *.gz ]]; then
        FOUND_LOGS+=("$f")
        echo "  found: $f"
    fi
done

# Check for domain-specific error logs inside home dirs
for f in /home/*/logs/"${DOMAIN}"* \
         /home/*/logs/"${DOMAIN}".error.log \
         /home/*/logs/"${DOMAIN}"-error_log; do
    if [ -f "$f" ] && [[ ! " ${FOUND_LOGS[*]} " =~ " $f " ]] && [[ "$f" != *.gz ]]; then
        FOUND_LOGS+=("$f")
        echo "  found: $f"
    fi
done

if [ ${#FOUND_LOGS[@]} -eq 0 ]; then
    echo ""
    echo "  No domain-specific logs found."
    echo "  Searching general error logs for mentions of ${DOMAIN}..."
    echo ""
    for f in /var/log/httpd/error_log /usr/local/apache/logs/error_log /var/log/apache2/error.log; do
        if [ -f "$f" ]; then
            COUNT=$(grep -c "$DOMAIN" "$f" 2>/dev/null)
            if [ "$COUNT" -gt 0 ]; then
                echo "  found ${COUNT} mentions in: $f"
                FOUND_LOGS+=("$f")
            fi
        fi
    done
fi

if [ ${#FOUND_LOGS[@]} -eq 0 ]; then
    echo "  No logs found for ${DOMAIN}"
    exit 1
fi

# Save log locations to file
echo ""
echo "[2] Saving log locations to ${SAVE_FILE}"
echo "-----------------------------------------"
printf '%s\n' "${FOUND_LOGS[@]}" > "$SAVE_FILE"
echo "  Saved ${#FOUND_LOGS[@]} path(s)"
cat "$SAVE_FILE"

# Show last lines from each
echo ""
echo "[3] Last 50 lines from each log"
echo "-----------------------------------------"
for f in "${FOUND_LOGS[@]}"; do
    echo ""
    echo "--- $f ---"
    tail -50 "$f" 2>/dev/null
done

# Ask before watching
echo ""
echo "========================================="
echo "  Found ${#FOUND_LOGS[@]} log(s) for ${DOMAIN}"
echo "  Log paths saved to: ${SAVE_FILE}"
echo "========================================="
echo ""
read -p "Watch these logs live with tail -f? [y/N] " ANSWER
case "$ANSWER" in
    [yY]|[yY][eE][sS])
        echo ""
        echo "Watching... Press Ctrl+C to stop"
        echo ""
        tail -f "${FOUND_LOGS[@]}"
        ;;
    *)
        echo "Done."
        ;;
esac
