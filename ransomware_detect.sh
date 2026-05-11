#!/bin/bash
# Ransomware Detection Script for cPanel/CloudLinux servers
# Run as root. Can run standalone or after forensic_collect.sh
# Usage: bash ransomware_detect.sh [output_dir] [forensic_collect_dir]
#   output_dir: where to write results (default: /root/ransomware_scan_<date>)
#   forensic_collect_dir: path to forensic_collect.sh output (optional, for history reuse)

set -uo pipefail

OUTDIR="${1:-/root/ransomware_scan_$(hostname)_$(date +%Y%m%d_%H%M%S)}"
FORENSIC_DIR="${2:-}"
mkdir -p "$OUTDIR"/{ransom_notes,encrypted_samples,backup_evidence}

log() { echo "[$(date '+%H:%M:%S')] $1"; }

REPORT="$OUTDIR/ransomware_indicators.txt"
echo "=== RANSOMWARE INDICATOR SCAN ===" > "$REPORT"
echo "Host: $(hostname)" >> "$REPORT"
echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"

log "========================================="
log "  RANSOMWARE DETECTION - $(hostname)"
log "  Started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
log "  Output:  $OUTDIR"
log "========================================="

ALERTS=0

# ─────────────────────────────────────────────
# 1. RANSOM NOTES
# ─────────────────────────────────────────────
log "[1/8] Searching for ransom note files (reason: ransomware drops README/DECRYPT instructions in every directory)"
log "  Scanning /home /var /root /tmp → $REPORT + $OUTDIR/ransom_notes/"
echo "" >> "$REPORT"
echo "--- Ransom note files ---" >> "$REPORT"

find /home /var /root /tmp -maxdepth 4 -type f \( \
    -iname "README_TO_DECRYPT*" -o -iname "DECRYPT_*" -o -iname "HOW_TO_RECOVER*" \
    -o -iname "HOW_TO_DECRYPT*" -o -iname "RESTORE_FILES*" -o -iname "YOUR_FILES*" \
    -o -iname "RECOVER_*" -o -iname "*RANSOM*" -o -iname "HELP_DECRYPT*" \
    -o -iname "_readme.txt" -o -iname "ATTENTION*.txt" -o -iname "LOCKED*.txt" \
    -o -iname "!README!*" -o -iname "#DECRYPT#*" -o -iname "PAYMENT*" \
    -o -iname "*RESTORE*YOUR*" -o -iname "*READ_ME*" -o -iname "*IMPORTANT*READ*" \
    \) -ls 2>/dev/null | while read -r line; do
        echo "$line" >> "$REPORT"
        fpath=$(echo "$line" | awk '{print $NF}')
        if [ -f "$fpath" ]; then
            log "    FOUND ransom note: $fpath → $OUTDIR/ransom_notes/"
            cp -a "$fpath" "$OUTDIR/ransom_notes/" 2>/dev/null
        fi
    done || true

# Count: standard ransom notes + Sorry-specific README.md notes
RANSOM_COUNT=$(find /home /var /root /tmp -maxdepth 4 -type f \( \
    -iname "README_TO_DECRYPT*" -o -iname "DECRYPT_*" -o -iname "HOW_TO_RECOVER*" \
    -o -iname "HOW_TO_DECRYPT*" -o -iname "RESTORE_FILES*" -o -iname "YOUR_FILES*" \
    -o -iname "RECOVER_*" -o -iname "*RANSOM*" -o -iname "HELP_DECRYPT*" \
    -o -iname "_readme.txt" -o -iname "LOCKED*.txt" \
    \) 2>/dev/null | wc -l)
SORRY_COUNT=$(find /home /var /root /tmp -maxdepth 4 -name "README.md" -type f -exec \
    grep -lEi '(sorry|qtox|tox.id|decrypt|ransom|taobao)' {} + 2>/dev/null | wc -l)
RANSOM_COUNT=$((RANSOM_COUNT + SORRY_COUNT))

if [ "$RANSOM_COUNT" -gt 0 ]; then
    log "  [!] ALERT: Found $RANSOM_COUNT ransom note files"
    ALERTS=$((ALERTS+1))
else
    log "  No ransom notes found."
fi

# Sorry/SorryGo specific: ransom note is README.md (blends in with repos)
log "  Searching for Sorry/SorryGo ransom notes (reason: this ransomware uses README.md as ransom note) — find README.md with ransom keywords → $REPORT"
echo "" >> "$REPORT"
echo "--- Sorry/SorryGo specific: README.md ransom notes ---" >> "$REPORT"
find /home /var /root /tmp -maxdepth 4 -name "README.md" -type f -exec \
    grep -lEi '(sorry|qtox|tox.id|decrypt|encrypt.*files|bitcoin|btc|monero|xmr|ransom|taobao|AES.*RSA)' {} + \
    2>/dev/null | while read -r readme; do
        log "    FOUND Sorry ransom note: $readme → $OUTDIR/ransom_notes/"
        echo "SORRY RANSOM NOTE: $readme" >> "$REPORT"
        cp -a "$readme" "$OUTDIR/ransom_notes/README.md_from_$(dirname "$readme" | tr '/' '_')" 2>/dev/null
    done || true

# ─────────────────────────────────────────────
# 2. TOR / PAYMENT URLS
# ─────────────────────────────────────────────
log "[2/8] Searching for .onion URLs and crypto wallet addresses (reason: ransom payment links in dropped files)"
log "  Scanning text/html files in /home /root /tmp → $REPORT + $OUTDIR/ransom_notes/"
echo "" >> "$REPORT"
echo "--- Files containing .onion URLs or crypto wallet references ---" >> "$REPORT"

find /home /root /var/www /tmp -maxdepth 4 -type f \( -name "*.txt" -o -name "*.html" -o -name "*.htm" -o -name "*.hta" \) -exec \
    grep -lEi '\.onion|bitcoin|btc wallet|monero|xmr wallet|ransom|decrypt.*key|pay.*restore|tox chat|qtox|tox.id|3D7889AEC00F|taobao|sorry.*encrypt' {} + \
    2>/dev/null | while read -r onionfile; do
        log "    FOUND .onion/crypto reference: $onionfile → $OUTDIR/ransom_notes/"
        echo "$onionfile" >> "$REPORT"
        cp -a "$onionfile" "$OUTDIR/ransom_notes/" 2>/dev/null
    done || true

# ─────────────────────────────────────────────
# 3. ENCRYPTED FILE EXTENSIONS
# ─────────────────────────────────────────────
log "[3/8] Searching for ransomware-associated file extensions (reason: ransomware renames files with .encrypted/.locked/.crypt)"
log "  Scanning /home for known ransomware extensions → $REPORT + $OUTDIR/encrypted_samples/"
echo "" >> "$REPORT"
echo "--- Files with ransomware-associated extensions ---" >> "$REPORT"

ENCRYPTED_FOUND=0
for ext in sorry \
           encrypted locked crypt crypted enc cipher locky cerber zepto wallet \
           zzzzz micro aaa abc xyz lck rhino dharma bip arena gamma combo hacked \
           lockbit revil conti phobos makop devos roger eking eight thanos mallox \
           elbie cuba gotham monti play 8base trigona noescape cactus akira; do
    count=$(find /home -maxdepth 5 -name "*.${ext}" -type f 2>/dev/null | head -100 | wc -l)
    if [ "$count" -gt 0 ]; then
        log "    FOUND $count files with .${ext} extension"
        echo "FOUND $count files with .${ext} extension:" >> "$REPORT"
        find /home -maxdepth 5 -name "*.${ext}" -type f -ls 2>/dev/null | head -20 >> "$REPORT"
        # Collect first 3 samples
        find /home -maxdepth 5 -name "*.${ext}" -type f 2>/dev/null | head -3 | while read -r ef; do
            log "      Sample: $ef → $OUTDIR/encrypted_samples/"
            cp -a "$ef" "$OUTDIR/encrypted_samples/" 2>/dev/null
        done
        ENCRYPTED_FOUND=$((ENCRYPTED_FOUND+count))
    fi
done

if [ "$ENCRYPTED_FOUND" -gt 0 ]; then
    log "  [!] ALERT: Found $ENCRYPTED_FOUND files with ransomware extensions"
    ALERTS=$((ALERTS+1))
else
    log "  No ransomware file extensions found."
fi

# ─────────────────────────────────────────────
# 4. MASS FILE MODIFICATION
# ─────────────────────────────────────────────
log "[4/8] Analyzing file modification timestamps (reason: encryption changes mtime on thousands of files in same hour)"
log "  Counting files modified per hour in last 7 days under /home → $REPORT"
echo "" >> "$REPORT"
echo "--- Mass file modification analysis (files modified per hour, last 7 days) ---" >> "$REPORT"
echo "  (>1000 files in one hour is suspicious, >5000 is strong ransomware indicator)" >> "$REPORT"

find /home -maxdepth 4 -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:00\n' 2>/dev/null \
    | sort | uniq -c | sort -rn | head -20 >> "$REPORT" 2>/dev/null || \
find /home -maxdepth 4 -type f -mtime -7 -exec stat -c '%y' {} + 2>/dev/null \
    | cut -d: -f1 | sort | uniq -c | sort -rn | head -20 >> "$REPORT" 2>/dev/null || true

# Check if any hour had >1000 modifications
MASS_MOD=$(find /home -maxdepth 4 -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:00\n' 2>/dev/null \
    | sort | uniq -c | sort -rn | head -1 | awk '{print $1}' 2>/dev/null)
if [ "${MASS_MOD:-0}" -gt 1000 ]; then
    log "  [!] ALERT: $MASS_MOD files modified in a single hour — possible mass encryption"
    ALERTS=$((ALERTS+1))
else
    log "  No mass modification anomaly detected."
fi

# ─────────────────────────────────────────────
# 5. ENCRYPTION COMMANDS IN HISTORIES
# ─────────────────────────────────────────────
log "[5/8] Scanning shell histories for encryption commands (reason: attacker may have used openssl/gpg to encrypt files)"

HIST_DIR="$FORENSIC_DIR/histories"
if [ -z "$FORENSIC_DIR" ] || [ ! -d "$HIST_DIR" ]; then
    # Collect histories ourselves
    HIST_DIR="$OUTDIR/histories"
    mkdir -p "$HIST_DIR"
    while IFS=: read -r user _ _ _ _ home _; do
        [ ! -d "$home" ] && continue
        for hfile in .bash_history .zsh_history .sh_history; do
            if [ -f "$home/$hfile" ]; then
                mkdir -p "$HIST_DIR/$user"
                log "    Dumping $home/$hfile (reason: check for encryption commands) → $HIST_DIR/$user/$hfile"
                cp -a "$home/$hfile" "$HIST_DIR/$user/" 2>/dev/null
            fi
        done
    done < /etc/passwd
fi

log "  Scanning collected histories → $REPORT"
echo "" >> "$REPORT"
echo "--- Encryption-related commands in shell histories ---" >> "$REPORT"
find "$HIST_DIR" -type f -exec \
    grep -HnEi '(openssl.*(enc|aes|des|bf)|gpg.*(-c|--symmetric|--encrypt)|ccrypt|7z.*-p|zip.*-P|mcrypt|shred|wipe|srm|chmod.*000|find.*-exec.*rm|find.*-delete)' {} + \
    >> "$REPORT" 2>/dev/null || true

ENCR_CMDS=$(find "$HIST_DIR" -type f -exec \
    grep -cEi '(openssl.*(enc|aes|des|bf)|gpg.*(-c|--symmetric|--encrypt)|ccrypt|shred|wipe)' {} + \
    2>/dev/null | awk -F: '{sum+=$2} END {print sum}')
if [ "${ENCR_CMDS:-0}" -gt 0 ]; then
    log "  [!] ALERT: Found $ENCR_CMDS encryption-related commands in histories"
    ALERTS=$((ALERTS+1))
else
    log "  No encryption commands found in histories."
fi

# ─────────────────────────────────────────────
# 6. BACKUP DESTRUCTION
# ─────────────────────────────────────────────
log "[6/8] Checking backup integrity (reason: ransomware deletes/encrypts backups to prevent recovery)"
echo "" >> "$REPORT"
echo "--- Backup status ---" >> "$REPORT"

log "  Dumping cPanel backup configs → $REPORT + $OUTDIR/backup_evidence/"
echo "cPanel backup configuration:" >> "$REPORT"
for f in /var/cpanel/backups/*.conf; do
    if [ -f "$f" ]; then
        echo "  --- $f ---" >> "$REPORT"
        cat "$f" >> "$REPORT" 2>/dev/null
        cp -a "$f" "$OUTDIR/backup_evidence/" 2>/dev/null
    fi
done 2>/dev/null || echo "  No backup configs found" >> "$REPORT"

echo "" >> "$REPORT"
echo "Backup directories:" >> "$REPORT"
for bdir in /backup /home/backup /var/backup /usr/local/cpanel/backups /home/cpmove-*; do
    if [ -d "$bdir" ]; then
        entry_count=$(ls -1 "$bdir" 2>/dev/null | wc -l)
        newest=$(ls -lt "$bdir" 2>/dev/null | head -2 | tail -1)
        log "    $bdir — $entry_count entries"
        echo "  $bdir — $entry_count entries, newest: $newest" >> "$REPORT"
        ls -la "$bdir" >> "$REPORT" 2>/dev/null
    else
        echo "  $bdir — MISSING" >> "$REPORT"
    fi
done

log "  Checking histories for backup deletion commands → $REPORT"
echo "" >> "$REPORT"
echo "Backup deletion commands in histories:" >> "$REPORT"
find "$HIST_DIR" -type f -exec \
    grep -HnEi '(rm.*backup|rm.*\.tar|rm.*\.gz|rm.*\.sql|rm.*\.bak|rm -rf /backup|rm -rf /home/backup|shred.*backup|find.*backup.*-delete)' {} + \
    >> "$REPORT" 2>/dev/null || echo "  None found" >> "$REPORT"

# ─────────────────────────────────────────────
# 7. KNOWN RANSOMWARE PROCESSES
# ─────────────────────────────────────────────
log "[7/8] Checking for known ransomware process names (reason: encryption process may still be running)"
echo "" >> "$REPORT"
echo "--- Running processes matching ransomware families ---" >> "$REPORT"

PS_SRC="$OUTDIR/ps_snapshot.txt"
ps auxwwf > "$PS_SRC" 2>/dev/null
log "  Dumping process tree (reason: check against known ransomware names) — ps auxwwf → $PS_SRC"

grep -Ei '(sorry.?go|encryptor|cryptor|locker|ransom|lockbit|revil|sodinokibi|ryuk|conti|blackcat|alphv|phobos|dharma|stop.djvu|makop|hive|royal|akira|black.basta|clop|lockfile|babuk|ragnar|netwalker|maze|avaddon|egregor|darkside|blackmatter|vice.society|trigona|rhysida|cactus|play.crypt|8base|noescape|hunters)' \
    "$PS_SRC" 2>/dev/null | grep -v grep >> "$REPORT" || echo "  None found in running processes" >> "$REPORT"

# Also check for suspicious generic patterns
echo "" >> "$REPORT"
echo "--- Suspicious generic encryption patterns in processes ---" >> "$REPORT"
grep -Ei '(\.enc |\.crypt |encrypt|cipher|aes-256|chacha20|salsa20)' \
    "$PS_SRC" 2>/dev/null | grep -v grep >> "$REPORT" || echo "  None found" >> "$REPORT"

# ─────────────────────────────────────────────
# 8. FILE ENTROPY CHECK (detect encrypted files by magic bytes)
# ─────────────────────────────────────────────
log "[8/8] Checking file headers for encryption (reason: encrypted files lose their magic bytes — a .jpg that doesn't start with FFD8 is likely encrypted)"
echo "" >> "$REPORT"
echo "--- File header analysis (files with wrong magic bytes = likely encrypted) ---" >> "$REPORT"

CHECKED=0
CORRUPTED=0
for home_dir in /home/*/public_html; do
    [ ! -d "$home_dir" ] && continue
    # Check a sample of common file types
    for f in $(find "$home_dir" -maxdepth 3 \( -name "*.jpg" -o -name "*.png" -o -name "*.pdf" -o -name "*.doc" -o -name "*.docx" -o -name "*.zip" \) -type f 2>/dev/null | head -10); do
        CHECKED=$((CHECKED+1))
        ext="${f##*.}"
        header=$(od -A n -t x1 -N 4 "$f" 2>/dev/null | tr -d ' ')
        case "$ext" in
            jpg|jpeg) expected="ffd8ff" ;;
            png)      expected="89504e47" ;;
            pdf)      expected="25504446" ;;
            zip|docx) expected="504b0304" ;;
            doc)      expected="d0cf11e0" ;;
            *)        continue ;;
        esac
        if [ -n "$header" ] && [[ ! "$header" == ${expected}* ]]; then
            echo "CORRUPTED: $f (expected: $expected, got: $header)" >> "$REPORT"
            log "    CORRUPTED file header: $f (expected $expected, got $header)"
            CORRUPTED=$((CORRUPTED+1))
        fi
    done
done

if [ "$CORRUPTED" -gt 0 ]; then
    log "  [!] ALERT: $CORRUPTED of $CHECKED sampled files have wrong magic bytes — likely encrypted"
    ALERTS=$((ALERTS+1))
else
    log "  Checked $CHECKED file headers — all match expected magic bytes."
fi

# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────
echo "" >> "$REPORT"
echo "=========================================" >> "$REPORT"
echo "  SUMMARY: $ALERTS alert(s) triggered" >> "$REPORT"
echo "=========================================" >> "$REPORT"

log ""
log "========================================="
log "  RANSOMWARE SCAN COMPLETE"
log "  Output: $OUTDIR"
log "  Report: $REPORT"

if [ "$ALERTS" -gt 0 ]; then
    log "  [!!!] $ALERTS ALERT(S) TRIGGERED — REVIEW IMMEDIATELY"
else
    log "  [OK] No ransomware indicators found"
fi
log "========================================="

# Compress
TARFILE="/root/ransomware_scan_$(hostname)_$(date +%Y%m%d_%H%M%S).tar.gz"
log ""
log "  Compressing to $TARFILE ..."
tar czf "$TARFILE" -C "$(dirname "$OUTDIR")" "$(basename "$OUTDIR")" 2>/dev/null

log ""
log "  Archive: $TARFILE ($(du -h "$TARFILE" | cut -f1))"
log "  Transfer off-server with:"
log "    scp root@$(hostname):$TARFILE ."
log ""
