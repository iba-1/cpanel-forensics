#!/bin/bash
# WHM/cPanel Forensic Collection & Exfiltration Detection
# Target: CloudLinux / cPanel servers
# Run as root. Ideally mount disk read-only first.
# Usage: bash forensic_collect.sh [output_dir]

set -uo pipefail

OUTDIR="${1:-/root/forensic_$(hostname)_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"/{logs,histories,network,crontabs,processes,users,cpanel,suspicious,hashes,audit,configs}

log() { echo "[$(date '+%H:%M:%S')] $1"; }

log "========================================="
log "  FORENSIC COLLECTION - $(hostname)"
log "  Started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
log "  Output:  $OUTDIR"
log "========================================="

# ─────────────────────────────────────────────
# 1. PRESERVE VOLATILE STATE FIRST
#    (network, processes, memory — changes every second)
# ─────────────────────────────────────────────
log "[1/12] Capturing volatile state — network and processes change every second, must capture first"

log "  Dumping all socket connections (reason: detect active C2/exfil channels) — ss -anp → $OUTDIR/network/all_connections.txt"
ss -anp > "$OUTDIR/network/all_connections.txt" 2>/dev/null

log "  Dumping all socket connections via netstat (reason: fallback/cross-reference) — netstat -anp → $OUTDIR/network/netstat_all.txt"
netstat -anp > "$OUTDIR/network/netstat_all.txt" 2>/dev/null

log "  Dumping listening ports (reason: detect backdoor listeners) — ss -tulnp → $OUTDIR/network/listening_ports.txt"
ss -tulnp > "$OUTDIR/network/listening_ports.txt" 2>/dev/null

log "  Dumping process tree with full args (reason: detect malicious processes) — ps auxwwf → $OUTDIR/processes/ps_tree.txt"
ps auxwwf > "$OUTDIR/processes/ps_tree.txt" 2>/dev/null

log "  Dumping processes sorted by age (reason: find recently spawned suspicious procs) — ps -eo ... → $OUTDIR/processes/ps_by_age.txt"
ps -eo pid,ppid,uid,user,args,etime,lstart --sort=-etime > "$OUTDIR/processes/ps_by_age.txt" 2>/dev/null

log "  Dumping network file handles (reason: map processes to remote IPs) — lsof -nPi → $OUTDIR/network/lsof_network.txt"
lsof -nPi > "$OUTDIR/network/lsof_network.txt" 2>/dev/null

log "  Dumping open files in /tmp (reason: detect staging/webshell activity) — lsof +D /tmp → $OUTDIR/suspicious/lsof_tmp.txt"
lsof +D /tmp > "$OUTDIR/suspicious/lsof_tmp.txt" 2>/dev/null

log "  Dumping open files in /dev/shm (reason: ramdisk used for fileless malware) — lsof +D /dev/shm → $OUTDIR/suspicious/lsof_devshm.txt"
lsof +D /dev/shm > "$OUTDIR/suspicious/lsof_devshm.txt" 2>/dev/null

log "  Dumping /proc for all processes with network sockets (reason: preserve cmdline/exe/environ before process dies)"
for pid in $(lsof -nPi 2>/dev/null | awk 'NR>1{print $2}' | sort -u); do
    if [ -d "/proc/$pid" ]; then
        pdir="$OUTDIR/processes/proc_$pid"
        mkdir -p "$pdir"
        cat "/proc/$pid/cmdline" > "$pdir/cmdline" 2>/dev/null
        ls -la "/proc/$pid/exe" > "$pdir/exe_link" 2>/dev/null
        cat "/proc/$pid/environ" | tr '\0' '\n' > "$pdir/environ" 2>/dev/null
        ls -la "/proc/$pid/fd/" > "$pdir/fd_list" 2>/dev/null
        cat "/proc/$pid/maps" > "$pdir/maps" 2>/dev/null
    fi
done

log "  Dumping IP addresses (reason: verify interfaces, detect rogue IPs) — ip addr → $OUTDIR/network/ip_addresses.txt"
ip addr > "$OUTDIR/network/ip_addresses.txt" 2>/dev/null || ifconfig -a > "$OUTDIR/network/ifconfig.txt" 2>/dev/null

log "  Dumping routing table (reason: detect traffic redirection) — ip route → $OUTDIR/network/routes.txt"
ip route > "$OUTDIR/network/routes.txt" 2>/dev/null || route -n > "$OUTDIR/network/routes.txt" 2>/dev/null

log "  Dumping iptables rules (reason: detect firewall tampering/port forwards) — iptables -L → $OUTDIR/network/iptables.txt"
iptables -L -n -v --line-numbers > "$OUTDIR/network/iptables.txt" 2>/dev/null

log "  Dumping iptables NAT table (reason: detect hidden port forwards) — iptables -t nat → $OUTDIR/network/iptables_nat.txt"
iptables -t nat -L -n -v > "$OUTDIR/network/iptables_nat.txt" 2>/dev/null

log "  Dumping /etc/resolv.conf (reason: detect DNS hijacking) — /etc/resolv.conf → $OUTDIR/network/resolv.conf"
cp -a /etc/resolv.conf "$OUTDIR/network/resolv.conf" 2>/dev/null

log "  Phase 1 complete."

# ─────────────────────────────────────────────
# 2. SYSTEM LOGS (copy raw, don't parse yet)
# ─────────────────────────────────────────────
log "[2/12] Collecting system logs — full dumps for offline analysis"

log "  Dumping entire /var/log/ (reason: contains auth, mail, kernel, cron, apache logs) — /var/log/ → $OUTDIR/logs/var_log/"
cp -a /var/log/ "$OUTDIR/logs/var_log" 2>/dev/null

log "  Dumping Apache domlogs (reason: per-domain access logs, detect webshell access) — /usr/local/apache/domlogs/ → $OUTDIR/logs/domlogs/"
cp -a /usr/local/apache/domlogs/ "$OUTDIR/logs/domlogs" 2>/dev/null

log "  Dumping Apache error/access logs (reason: detect exploit attempts, errors) — /usr/local/apache/logs/ → $OUTDIR/logs/apache_logs/"
cp -a /usr/local/apache/logs/ "$OUTDIR/logs/apache_logs" 2>/dev/null

log "  Phase 2 complete."

# ─────────────────────────────────────────────
# 3. CPANEL LOGS
# ─────────────────────────────────────────────
log "[3/12] Collecting cPanel/WHM logs — detect unauthorized access and file manager abuse"

CPDIR="$OUTDIR/cpanel"

log "  Dumping cPanel logs (reason: WHM/cPanel access, session, error logs) — /usr/local/cpanel/logs/ → $CPDIR/cpanel_logs/"
cp -a /usr/local/cpanel/logs/ "$CPDIR/cpanel_logs" 2>/dev/null

log "  Dumping cPanel user configs (reason: detect rogue accounts, permission changes) — /var/cpanel/users/ → $CPDIR/cpanel_users/"
cp -a /var/cpanel/users/ "$CPDIR/cpanel_users" 2>/dev/null || true

log "  Dumping domain-to-user mappings (reason: identify all hosted domains) — /etc/trueuserdomains → $CPDIR/trueuserdomains.txt"
cp -a /etc/trueuserdomains "$CPDIR/trueuserdomains.txt" 2>/dev/null

log "  Dumping domain ownership (reason: identify account hierarchy) — /etc/trueuserowners → $CPDIR/trueuserowners.txt"
cp -a /etc/trueuserowners "$CPDIR/trueuserowners.txt" 2>/dev/null

log "  Dumping WHM transfer sessions (reason: detect unauthorized account migrations) — /var/cpanel/transfer_sessions/ → $CPDIR/transfer_sessions/"
cp -a /var/cpanel/transfer_sessions/ "$CPDIR/transfer_sessions" 2>/dev/null || true

log "  Extracting file manager activity (reason: detect file downloads/uploads via cPanel GUI) — grep from /usr/local/cpanel/logs/access_log → $CPDIR/filemanager_activity.txt"
grep -Ei '(download|upload|fileop|file_and_dir)' /usr/local/cpanel/logs/access_log 2>/dev/null \
    | tail -500 > "$CPDIR/filemanager_activity.txt" 2>/dev/null || true

log "  Phase 3 complete."

# ─────────────────────────────────────────────
# 4. LOGIN HISTORY
# ─────────────────────────────────────────────
log "[4/12] Collecting login history — detect unauthorized access and brute force"

log "  Dumping successful login history (reason: identify all sessions, IPs, timestamps) — last -Faixw → $OUTDIR/users/last_full.txt"
last -Faixw > "$OUTDIR/users/last_full.txt" 2>/dev/null || last > "$OUTDIR/users/last_full.txt" 2>/dev/null

log "  Dumping failed login attempts (reason: detect brute force, credential stuffing) — lastb -Faixw → $OUTDIR/users/lastb_failed.txt"
lastb -Faixw > "$OUTDIR/users/lastb_failed.txt" 2>/dev/null || lastb > "$OUTDIR/users/lastb_failed.txt" 2>/dev/null

log "  Dumping last login per user (reason: find accounts that logged in unexpectedly) — lastlog → $OUTDIR/users/lastlog.txt"
lastlog > "$OUTDIR/users/lastlog.txt" 2>/dev/null

log "  Dumping /var/log/wtmp (reason: raw binary login records for forensic tools) — /var/log/wtmp → $OUTDIR/users/wtmp"
cp -a /var/log/wtmp "$OUTDIR/users/wtmp" 2>/dev/null

log "  Dumping /var/log/btmp (reason: raw binary failed login records) — /var/log/btmp → $OUTDIR/users/btmp"
cp -a /var/log/btmp "$OUTDIR/users/btmp" 2>/dev/null

log "  Extracting SSH auth events (reason: accepted/failed/invalid SSH logins) — grep from /var/log/secure* → $OUTDIR/users/ssh_auth_events.txt"
grep -E '(Accepted|Failed|Invalid|session opened|session closed|Did not receive)' \
    /var/log/secure > "$OUTDIR/users/ssh_auth_events.txt" 2>/dev/null
for f in /var/log/secure-*; do
    [ -f "$f" ] && [[ "$f" != *.gz ]] && \
    grep -E '(Accepted|Failed|Invalid|session opened)' "$f" >> "$OUTDIR/users/ssh_auth_events.txt" 2>/dev/null
done

log "  Phase 4 complete."

# ─────────────────────────────────────────────
# 5. SHELL HISTORIES (all users)
# ─────────────────────────────────────────────
log "[5/12] Collecting shell histories — detect attacker commands, data staging, exfil"

while IFS=: read -r user _ uid _ _ home shell; do
    [ ! -d "$home" ] && continue
    userdir="$OUTDIR/histories/$user"
    found=0
    for hfile in .bash_history .zsh_history .sh_history .mysql_history .psql_history \
                 .python_history .lesshst .viminfo .wget-hsts .nano_history; do
        if [ -f "$home/$hfile" ]; then
            [ $found -eq 0 ] && mkdir -p "$userdir"
            log "  Dumping $home/$hfile (reason: shell/tool history for user $user) → $userdir/$hfile"
            cp -a "$home/$hfile" "$userdir/" 2>/dev/null
            found=1
        fi
    done
done < /etc/passwd

log "  Phase 5 complete."

# ─────────────────────────────────────────────
# 6. CRONTABS
# ─────────────────────────────────────────────
log "[6/12] Collecting crontabs — detect persistence, scheduled exfil (T1029), crypto miners"

log "  Dumping per-user crontabs (reason: attacker persistence via scheduled tasks) — /var/spool/cron/ → $OUTDIR/crontabs/user_crons/"
cp -a /var/spool/cron/ "$OUTDIR/crontabs/user_crons" 2>/dev/null || true

log "  Dumping system cron.d (reason: system-level scheduled tasks) — /etc/cron.d/ → $OUTDIR/crontabs/cron.d/"
cp -a /etc/cron.d/ "$OUTDIR/crontabs/cron.d" 2>/dev/null || true

log "  Dumping daily cron jobs — /etc/cron.daily/ → $OUTDIR/crontabs/cron.daily/"
cp -a /etc/cron.daily/ "$OUTDIR/crontabs/cron.daily" 2>/dev/null || true

log "  Dumping hourly cron jobs — /etc/cron.hourly/ → $OUTDIR/crontabs/cron.hourly/"
cp -a /etc/cron.hourly/ "$OUTDIR/crontabs/cron.hourly" 2>/dev/null || true

log "  Dumping /etc/crontab (reason: system crontab) — /etc/crontab → $OUTDIR/crontabs/etc_crontab"
cp -a /etc/crontab "$OUTDIR/crontabs/etc_crontab" 2>/dev/null || true

log "  Phase 6 complete."

# ─────────────────────────────────────────────
# 7. USER ACCOUNTS & SSH KEYS
# ─────────────────────────────────────────────
log "[7/12] Collecting user accounts & SSH keys — detect rogue accounts, unauthorized keys"

log "  Dumping /etc/passwd (reason: detect rogue accounts, UID 0 backdoors) — /etc/passwd → $OUTDIR/users/passwd"
cp -a /etc/passwd "$OUTDIR/users/passwd" 2>/dev/null

log "  Dumping /etc/shadow (reason: detect tampered password hashes) — /etc/shadow → $OUTDIR/users/shadow"
cp -a /etc/shadow "$OUTDIR/users/shadow" 2>/dev/null

log "  Dumping /etc/group (reason: detect unauthorized group memberships) — /etc/group → $OUTDIR/users/group"
cp -a /etc/group "$OUTDIR/users/group" 2>/dev/null

log "  Dumping /etc/sudoers (reason: detect privilege escalation grants) — /etc/sudoers → $OUTDIR/users/sudoers"
cp -a /etc/sudoers "$OUTDIR/users/sudoers" 2>/dev/null

log "  Dumping /etc/sudoers.d/ (reason: drop-in sudo rules) — /etc/sudoers.d/ → $OUTDIR/users/sudoers.d/"
cp -a /etc/sudoers.d/ "$OUTDIR/users/sudoers.d" 2>/dev/null || true

log "  Dumping /etc/ssh/ (reason: sshd_config, host keys, detect tampering) — /etc/ssh/ → $OUTDIR/users/etc_ssh/"
cp -a /etc/ssh/ "$OUTDIR/users/etc_ssh" 2>/dev/null || true

log "  Dumping per-user .ssh/ directories (reason: authorized_keys, known_hosts, SSH config)"
while IFS=: read -r user _ _ _ _ home _; do
    if [ -d "$home/.ssh" ]; then
        mkdir -p "$OUTDIR/users/ssh_per_user/$user"
        log "    $home/.ssh/ → $OUTDIR/users/ssh_per_user/$user/"
        cp -a "$home/.ssh/" "$OUTDIR/users/ssh_per_user/$user/" 2>/dev/null
    fi
    for k in "$home/"*.pub "$home/"*.pem; do
        if [ -f "$k" ]; then
            mkdir -p "$OUTDIR/suspicious/unusual_keys/$user"
            log "    UNUSUAL KEY outside .ssh: $k (reason: keys in home root are suspicious) → $OUTDIR/suspicious/unusual_keys/$user/"
            cp -a "$k" "$OUTDIR/suspicious/unusual_keys/$user/" 2>/dev/null
        fi
    done
done < /etc/passwd

log "  Phase 7 complete."

# ─────────────────────────────────────────────
# 8. AUDITD LOGS (tools exist on this server)
# ─────────────────────────────────────────────
log "[8/12] Collecting audit data — syscall-level evidence of command execution"

if [ -f /var/log/audit/audit.log ]; then
    log "  Dumping /var/log/audit/ (reason: auditd syscall logs, command execution evidence) — /var/log/audit/ → $OUTDIR/audit/"
    cp -a /var/log/audit/ "$OUTDIR/audit/" 2>/dev/null

    log "  Generating aureport --summary → $OUTDIR/audit/aureport_summary.txt"
    aureport --summary > "$OUTDIR/audit/aureport_summary.txt" 2>/dev/null

    log "  Generating aureport --auth (reason: authentication events) → $OUTDIR/audit/aureport_auth.txt"
    aureport --auth > "$OUTDIR/audit/aureport_auth.txt" 2>/dev/null

    log "  Generating aureport --login (reason: login events) → $OUTDIR/audit/aureport_login.txt"
    aureport --login > "$OUTDIR/audit/aureport_login.txt" 2>/dev/null

    log "  Generating aureport --anomaly (reason: anomalous events) → $OUTDIR/audit/aureport_anomaly.txt"
    aureport --anomaly > "$OUTDIR/audit/aureport_anomaly.txt" 2>/dev/null

    log "  Generating aureport --failed (reason: failed operations) → $OUTDIR/audit/aureport_failed.txt"
    aureport --failed > "$OUTDIR/audit/aureport_failed.txt" 2>/dev/null

    log "  Extracting EXECVE events (reason: every command executed under audit) → $OUTDIR/audit/ausearch_execve.txt"
    ausearch -m EXECVE --raw > "$OUTDIR/audit/ausearch_execve.txt" 2>/dev/null || true
else
    log "  WARNING: /var/log/audit/audit.log not found — auditd not running or logs wiped"
    echo "auditd not running or no logs found" > "$OUTDIR/audit/NOT_AVAILABLE.txt"
    auditctl -s > "$OUTDIR/audit/auditctl_status.txt" 2>/dev/null
fi

log "  Phase 8 complete."

# ─────────────────────────────────────────────
# 9. FILE INTEGRITY & TIMESTAMPS
#    (no sha256sum/md5sum on this server — use openssl)
# ─────────────────────────────────────────────
log "[9/12] Collecting file integrity data — detect trojanized binaries and rootkits"

HASHFILE="$OUTDIR/hashes/critical_binaries.txt"
log "  Hashing critical binaries with openssl (reason: detect replaced/trojanized tools) → $HASHFILE"
echo "# Hashes of critical binaries — compare against known-good" > "$HASHFILE"
for bin in /bin/ls /bin/ps /bin/netstat /usr/bin/find /usr/bin/lsof /usr/sbin/ss \
           /usr/sbin/sshd /bin/login /usr/bin/passwd /bin/su /usr/bin/crontab \
           /usr/sbin/httpd /usr/bin/curl /usr/bin/wget; do
    if [ -f "$bin" ]; then
        hash=$(openssl dgst -sha256 "$bin" 2>/dev/null)
        echo "$hash" >> "$HASHFILE"
    fi
done

log "  Running rpm -Va in background (reason: detect all tampered RPM-installed files) → $OUTDIR/hashes/rpm_verify.txt"
rpm -Va > "$OUTDIR/hashes/rpm_verify.txt" 2>/dev/null &
RPM_PID=$!

log "  Finding system binaries modified in last 7 days (reason: recent tampering) → $OUTDIR/suspicious/recently_modified_binaries.txt"
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -type f -mtime -7 -ls \
    > "$OUTDIR/suspicious/recently_modified_binaries.txt" 2>/dev/null

log "  Finding SUID/SGID binaries (reason: privilege escalation backdoors) → $OUTDIR/suspicious/suid_sgid_files.txt"
find / -xdev \( -path "*/virtfs/*" -o -path "*/cagefs/*" -o -path "/proc/*" -o -path "/sys/*" \) -prune \
    -o \( -perm -4000 -o -perm -2000 \) -type f -ls -print \
    > "$OUTDIR/suspicious/suid_sgid_files.txt" 2>/dev/null

log "  Finding root-owned files in /home (reason: attacker drops files as root in user dirs) → $OUTDIR/suspicious/root_owned_in_homes.txt"
find /home -user root -type f ! -path "*/virtfs/*" -ls \
    > "$OUTDIR/suspicious/root_owned_in_homes.txt" 2>/dev/null

log "  Phase 9 complete."

# ─────────────────────────────────────────────
# 10. EXFILTRATION INDICATORS
# ─────────────────────────────────────────────
log "[10/12] Scanning for exfiltration indicators — MITRE ATT&CK T1041/T1048/T1567"

EXFIL="$OUTDIR/suspicious/exfiltration_indicators.txt"
echo "=== EXFILTRATION INDICATOR SCAN ===" > "$EXFIL"
echo "Timestamp: $(date -u)" >> "$EXFIL"

# 10a. Suspicious commands in all bash histories (T1041, T1048)
log "  Scanning collected histories for exfil commands (reason: scp/curl/nc/mysqldump in history = data theft) → $EXFIL"
echo "" >> "$EXFIL"
echo "--- Data exfiltration commands in histories ---" >> "$EXFIL"
find "$OUTDIR/histories" -type f -exec \
    grep -HnEi '(scp |sftp |rsync |curl.*(-d|--data|-F|--upload)|wget.*--post|tar.*\|.*(curl|nc|ncat)|mysqldump|pg_dump|zip.*-r.*\||\|.*base64|/dev/tcp|nc -w|ncat.*-e|socat|python.*http\.server|python.*SimpleHTTP|exfil|lftp|rclone|mega-)' {} + \
    >> "$EXFIL" 2>/dev/null || true

# 10b. Large outbound transfers in Apache domlogs (T1030)
log "  Scanning Apache domlogs for responses >10MB (reason: large data served = possible dump download) — /usr/local/apache/domlogs/ → $EXFIL"
echo "" >> "$EXFIL"
echo "--- Responses >10MB in Apache logs (potential data dumps) ---" >> "$EXFIL"
find /usr/local/apache/domlogs -type f ! -name "*.gz" ! -name "*.offset" -exec \
    awk '$10 ~ /^[0-9]+$/ && $10 > 10485760 {print FILENAME": "$0}' {} + \
    2>/dev/null | tail -200 >> "$EXFIL" || true

# 10c. Staging areas (/tmp, /dev/shm) — list AND collect (T1074)
log "  Scanning /tmp and /dev/shm for staging files (reason: attackers stage archives before exfil) — listing → $EXFIL, files → $OUTDIR/suspicious/tmp_files/ and devshm_files/"
echo "" >> "$EXFIL"
echo "--- Suspicious files in /tmp and /dev/shm ---" >> "$EXFIL"
find /tmp /dev/shm -type f \( \
    -name "*.tar*" -o -name "*.zip" -o -name "*.sql" -o -name "*.gz" \
    -o -name "*.dump" -o -name "*.csv" -o -name "*.bak" -o -name ".*" \
    -o -name "*.php" -o -name "*.pl" -o -name "*.py" -o -name "*.sh" \
    \) -ls 2>/dev/null >> "$EXFIL" || true

mkdir -p "$OUTDIR/suspicious/tmp_files" "$OUTDIR/suspicious/devshm_files"
find /tmp -maxdepth 2 -type f ! -name "*.sock" -exec cp -a {} "$OUTDIR/suspicious/tmp_files/" \; 2>/dev/null || true
find /dev/shm -type f -exec cp -a {} "$OUTDIR/suspicious/devshm_files/" \; 2>/dev/null || true

# 10d. Exim mail logs — bulk sending (T1048 via SMTP)
log "  Analyzing Exim mail log for bulk senders (reason: mass email = data exfil via SMTP) — /var/log/exim_mainlog → $EXFIL"
echo "" >> "$EXFIL"
echo "--- Unusual mail volume per sender (top 20) ---" >> "$EXFIL"
if [ -f /var/log/exim_mainlog ]; then
    grep '<=' /var/log/exim_mainlog 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i ~ /^<.*>$/) print $i}' \
        | sort | uniq -c | sort -rn | head -20 >> "$EXFIL" 2>/dev/null
fi

# 10e. Webshells — PHP files with dangerous functions — list AND collect
log "  Scanning PHP files for webshell signatures (reason: eval/exec/passthru = remote code execution) — /home/*/public_html/*.php → $EXFIL + $OUTDIR/suspicious/webshells/"
echo "" >> "$EXFIL"
echo "--- PHP files with shell/eval functions (potential webshells) ---" >> "$EXFIL"
mkdir -p "$OUTDIR/suspicious/webshells"
find /home/*/public_html -name "*.php" -newer /var/log/wtmp -exec \
    grep -lEi '(eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_)|system\s*\(\s*\$|passthru\s*\(|shell_exec\s*\(|exec\s*\(\s*\$|proc_open|popen\s*\(\s*\$|assert\s*\(\s*\$|preg_replace\s*\(.*\/e)' {} + \
    2>/dev/null | head -200 | tee -a "$EXFIL" | while read -r webshell; do
        destdir="$OUTDIR/suspicious/webshells/$(dirname "$webshell" | sed 's|^/||' | tr '/' '_')"
        mkdir -p "$destdir"
        cp -a "$webshell" "$destdir/" 2>/dev/null
    done || true

# 10f. Recently modified PHP (last 30 days)
log "  Listing PHP files modified in last 30 days (reason: recently planted webshells) — /home/*/public_html/*.php → $EXFIL"
echo "" >> "$EXFIL"
echo "--- PHP files modified in last 30 days ---" >> "$EXFIL"
find /home/*/public_html -name "*.php" -mtime -30 -ls 2>/dev/null \
    | head -300 >> "$EXFIL" || true

# 10g. Outbound connections to unusual ports (T1041)
log "  Checking established connections to non-standard ports (reason: C2 channels use unusual ports) — from $OUTDIR/network/all_connections.txt → $EXFIL"
echo "" >> "$EXFIL"
echo "--- Established connections to non-standard ports ---" >> "$EXFIL"
grep ESTAB "$OUTDIR/network/all_connections.txt" 2>/dev/null \
    | grep -vE ':(22|25|53|80|110|143|443|465|587|993|995|2082|2083|2086|2087|2095|2096|3306|6379|11211) ' \
    >> "$EXFIL" || true

# 10h. Suspicious cron entries (T1029 — Scheduled Transfer)
log "  Scanning crontabs for exfil/backdoor commands (reason: curl/wget/nc in cron = persistence + scheduled exfil) — /var/spool/cron/ + /etc/cron.* → $EXFIL"
echo "" >> "$EXFIL"
echo "--- Suspicious cron entries ---" >> "$EXFIL"
find /var/spool/cron /etc/cron.d /etc/cron.daily /etc/cron.hourly -type f -exec \
    grep -HEi '(curl|wget|nc |ncat|bash -i|python|perl -e|ruby|base64|/dev/tcp|mkfifo|\|.*sh|\|.*bash|pastebin|transfer\.sh|ngrok)' {} + \
    >> "$EXFIL" 2>/dev/null || true

# 10i. SSH tunnels / port forwards
log "  Checking sshd_config for tunneling (reason: SSH tunnels bypass firewall for exfil) — /etc/ssh/sshd_config → $EXFIL (full file already in $OUTDIR/users/etc_ssh/)"
echo "" >> "$EXFIL"
echo "--- SSH config (tunneling/forwarding) ---" >> "$EXFIL"
grep -Ei '(AllowTcpForwarding|GatewayPorts|PermitTunnel|PermitOpen)' /etc/ssh/sshd_config \
    >> "$EXFIL" 2>/dev/null || true

# 10j. DNS tunneling indicators (T1048.003)
log "  Scanning syslog for DNS tunneling (reason: long subdomain queries + TXT records = data encoded in DNS) — /var/log/messages → $EXFIL"
echo "" >> "$EXFIL"
echo "--- DNS tunneling indicators (long subdomains, high query volume) ---" >> "$EXFIL"
grep -rEi '(query\[|named|dnsmasq)' /var/log/messages 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if(length($i)>50 && $i ~ /\./) print}' \
    | sort | uniq -c | sort -rn | head -30 >> "$EXFIL" 2>/dev/null || true
grep -rEi '(type=TXT|type=NULL|type65|qtype=TXT)' /var/log/messages /var/log/secure 2>/dev/null \
    | tail -50 >> "$EXFIL" 2>/dev/null || true

# 10k. Cloud exfiltration indicators (T1567.002, T1537)
log "  Scanning for cloud transfer tools and credentials (reason: rclone/aws/gcloud = cloud exfil channel) → $EXFIL + $OUTDIR/suspicious/cloud_creds/"
echo "" >> "$EXFIL"
echo "--- Cloud storage/transfer tool usage ---" >> "$EXFIL"
for tool in aws gcloud az rclone mega-cmd mega-get mega-put s3cmd gsutil azcopy; do
    toolpath=$(which "$tool" 2>/dev/null)
    if [ -n "$toolpath" ]; then
        echo "FOUND: $toolpath" >> "$EXFIL"
        log "    FOUND cloud tool: $toolpath"
    fi
done

mkdir -p "$OUTDIR/suspicious/cloud_creds"
for home in /root /home/*; do
    [ ! -d "$home" ] && continue
    for cred in .aws/credentials .aws/config .boto .s3cfg \
                .config/gcloud/credentials.db .config/rclone/rclone.conf \
                .azure/accessTokens.json .megaCmd; do
        if [ -f "$home/$cred" ] || [ -d "$home/$cred" ]; then
            user=$(basename "$home")
            mkdir -p "$OUTDIR/suspicious/cloud_creds/$user"
            log "    CLOUD CRED: $home/$cred (user: $user) → $OUTDIR/suspicious/cloud_creds/$user/"
            cp -a "$home/$cred" "$OUTDIR/suspicious/cloud_creds/$user/" 2>/dev/null
            echo "CLOUD CRED: $home/$cred (user: $user)" >> "$EXFIL"
        fi
    done
done

log "  Checking lsof for connections to cloud storage domains (reason: active uploads to S3/GCS/Azure/Dropbox) → $EXFIL"
echo "" >> "$EXFIL"
echo "--- Connections to cloud storage IPs (from lsof) ---" >> "$EXFIL"
grep -Ei '(amazonaws|storage\.googleapis|blob\.core\.windows|dropbox|drive\.google|mega\.nz|transfer\.sh|pastebin|ngrok)' \
    "$OUTDIR/network/lsof_network.txt" >> "$EXFIL" 2>/dev/null || true

# 10l. Data volume anomaly — top outbound byte counts per destination (T1041)
log "  Aggregating outbound byte counts per client IP (reason: high volume = bulk data download/exfil) — /usr/local/apache/logs/access_log → $EXFIL"
echo "" >> "$EXFIL"
echo "--- Top 20 outbound byte destinations in Apache access logs ---" >> "$EXFIL"
if [ -f /usr/local/apache/logs/access_log ]; then
    awk '{sum[$1]+=$10} END {for(ip in sum) if(sum[ip]>0) printf "%15s  %12d bytes  (%d MB)\n", ip, sum[ip], sum[ip]/1048576}' \
        /usr/local/apache/logs/access_log 2>/dev/null \
        | sort -t'(' -k2 -rn | head -20 >> "$EXFIL" 2>/dev/null || true
fi

# 10m. Email exfiltration — large attachments (T1048 via SMTP)
log "  Scanning Exim for large email deliveries >5MB (reason: documents exfiltrated via email attachments) — /var/log/exim_mainlog → $EXFIL"
echo "" >> "$EXFIL"
echo "--- Exim large message deliveries (>5MB) ---" >> "$EXFIL"
if [ -f /var/log/exim_mainlog ]; then
    grep -E 'S=[0-9]' /var/log/exim_mainlog 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i ~ /^S=/) {gsub("S=","",$i); if($i+0>5242880) print}}' \
        | head -50 >> "$EXFIL" 2>/dev/null || true
fi

# Collect server configs
log "  Dumping Apache configs (reason: detect vhost tampering, rogue redirects) — /usr/local/apache/conf/ → $OUTDIR/configs/apache_conf/"
cp -a /usr/local/apache/conf/ "$OUTDIR/configs/apache_conf" 2>/dev/null || true

log "  Dumping Apache conf.d (reason: drop-in config overrides) — /usr/local/apache/conf.d/ → $OUTDIR/configs/apache_conf.d/"
cp -a /usr/local/apache/conf.d/ "$OUTDIR/configs/apache_conf.d" 2>/dev/null || true

log "  Dumping httpd conf (reason: alternate Apache config location) — /etc/httpd/conf/ → $OUTDIR/configs/httpd_conf/"
cp -a /etc/httpd/conf/ "$OUTDIR/configs/httpd_conf" 2>/dev/null || true

log "  Dumping httpd conf.d — /etc/httpd/conf.d/ → $OUTDIR/configs/httpd_conf.d/"
cp -a /etc/httpd/conf.d/ "$OUTDIR/configs/httpd_conf.d" 2>/dev/null || true

log "  Dumping /etc/hosts (reason: detect DNS hijacking via hosts file) — /etc/hosts → $OUTDIR/configs/hosts"
cp -a /etc/hosts "$OUTDIR/configs/hosts" 2>/dev/null || true

log "  Dumping /etc/resolv.conf (reason: detect rogue DNS servers) — /etc/resolv.conf → $OUTDIR/configs/resolv.conf"
cp -a /etc/resolv.conf "$OUTDIR/configs/resolv.conf" 2>/dev/null || true

log "  Dumping cPanel userdata (reason: per-domain DocumentRoot, SSL, vhost configs) — /var/cpanel/userdata/ → $OUTDIR/configs/cpanel_userdata/"
cp -a /var/cpanel/userdata/ "$OUTDIR/configs/cpanel_userdata" 2>/dev/null || true

log "  Collecting all .htaccess files (reason: attackers add redirects, backdoor rules) — /home/*/public_html/.htaccess → $OUTDIR/configs/"
find /home/*/public_html -name ".htaccess" -exec cp --parents {} "$OUTDIR/configs/" \; 2>/dev/null || true

log "  Phase 10 complete."

# ─────────────────────────────────────────────
# 11. CLOUDLINUX / LVEMANAGER SPECIFIC
# ─────────────────────────────────────────────
log "[11/12] CloudLinux-specific checks — CageFS breakout, resource abuse"

log "  Checking CageFS skeleton (reason: detect CageFS escape if skeleton passwd differs) — /usr/share/cagefs-skeleton/etc/passwd → $OUTDIR/suspicious/cagefs_skel.txt"
ls -la /usr/share/cagefs-skeleton/etc/passwd > "$OUTDIR/suspicious/cagefs_skel.txt" 2>/dev/null || true
cp -a /usr/share/cagefs-skeleton/etc/passwd "$OUTDIR/suspicious/cagefs_skel_passwd" 2>/dev/null || true

log "  Listing CageFS-enabled users (reason: verify isolation status) — cagefsctl --list-enabled → $OUTDIR/cpanel/cagefs_enabled_users.txt"
cagefsctl --list-enabled > "$OUTDIR/cpanel/cagefs_enabled_users.txt" 2>/dev/null || true

log "  Dumping LVE fault stats for 7 days (reason: CPU/mem spikes = crypto mining) — lveinfo → $OUTDIR/cpanel/lve_faults_7d.txt"
lveinfo --period=7d --by-fault=any --display-username > "$OUTDIR/cpanel/lve_faults_7d.txt" 2>/dev/null || true

log "  Phase 11 complete."

# ─────────────────────────────────────────────
# 12. WAIT FOR BACKGROUND JOBS & GENERATE REPORT
# ─────────────────────────────────────────────
log "[12/12] Generating report..."

if [ -n "${RPM_PID:-}" ]; then
    log "  Waiting for rpm -Va to finish (background job PID $RPM_PID)..."
    wait "$RPM_PID" 2>/dev/null
    log "  rpm -Va complete → $OUTDIR/hashes/rpm_verify.txt"
fi

REPORT="$OUTDIR/REPORT.txt"
cat > "$REPORT" <<ENDREPORT
=========================================
  FORENSIC COLLECTION REPORT
  Host:      $(hostname)
  OS:        $(cat /etc/redhat-release 2>/dev/null)
  Kernel:    $(uname -r)
  cPanel:    $(cat /usr/local/cpanel/version 2>/dev/null)
  Date:      $(date -u '+%Y-%m-%d %H:%M:%S UTC')
  Uptime:    $(uptime)
  SELinux:   Disabled
=========================================

QUICK TRIAGE
-----------------------------------------

1. UID 0 ACCOUNTS (should only be root):
$(awk -F: '$3 == 0 {print "   "$1" ("$7")"}' /etc/passwd 2>/dev/null)

2. FAILED SSH LOGINS (last 20):
$(tail -20 "$OUTDIR/users/lastb_failed.txt" 2>/dev/null)

3. SUCCESSFUL ROOT LOGINS:
$(grep 'root' "$OUTDIR/users/last_full.txt" 2>/dev/null | head -20)

4. MODIFIED SYSTEM BINARIES (last 7 days):
$(cat "$OUTDIR/suspicious/recently_modified_binaries.txt" 2>/dev/null | head -20)

5. RPM VERIFICATION FAILURES (tampered packages):
$(grep -E '^.{2}5' "$OUTDIR/hashes/rpm_verify.txt" 2>/dev/null | head -20)

6. SUSPICIOUS PROCESSES:
$(grep -Ei '(cryptonight|xmrig|minerd|/tmp/|/dev/shm/|base64|curl.*\|.*sh|wget.*\|.*sh|nc -l|perl -e|python -c)' "$OUTDIR/processes/ps_tree.txt" 2>/dev/null | grep -v grep | head -20)

7. UNUSUAL OUTBOUND CONNECTIONS:
$(cat "$OUTDIR/suspicious/exfiltration_indicators.txt" 2>/dev/null | sed -n '/non-standard ports/,/---/p' | grep -v '^---' | head -20)

8. WEBSHELLS DETECTED:
$(grep -c '.' "$OUTDIR/suspicious/exfiltration_indicators.txt" 2>/dev/null | head -1) indicators logged

9. STAGING FILES IN /tmp or /dev/shm:
$(find /tmp /dev/shm -type f \( -name "*.tar*" -o -name "*.zip" -o -name "*.sql" -o -name "*.gz" -o -name "*.dump" \) -ls 2>/dev/null | head -10)

10. SUSPICIOUS CRON ENTRIES:
$(grep -v '^---' "$OUTDIR/suspicious/exfiltration_indicators.txt" 2>/dev/null | grep -Ei '(curl|wget|nc |base64|/dev/tcp)' | head -10)

11. CLOUD TOOLS/CREDENTIALS FOUND:
$(grep 'FOUND:\|CLOUD CRED:' "$OUTDIR/suspicious/exfiltration_indicators.txt" 2>/dev/null | head -10)

12. DNS TUNNELING INDICATORS:
$(sed -n '/DNS tunneling/,/---/p' "$OUTDIR/suspicious/exfiltration_indicators.txt" 2>/dev/null | grep -v '^---' | head -10)

-----------------------------------------
NEXT STEPS:
  1. Review REPORT.txt (this file)
  2. Review suspicious/exfiltration_indicators.txt
  3. Review hashes/rpm_verify.txt for tampered binaries
  4. Review users/ssh_per_user/ for rogue authorized_keys
  5. Review histories/ for attacker commands
  6. Compare hashes/critical_binaries.txt against known-good
  7. Review suspicious/cloud_creds/ for cloud access keys
  8. Review suspicious/webshells/ for collected webshell files

COMPRESS & TRANSFER OFF-SERVER:
  tar czf forensic_\$(hostname).tar.gz $OUTDIR
=========================================
ENDREPORT

log ""
log "========================================="
log "  COLLECTION COMPLETE"
log "  Output: $OUTDIR"
log "  Report: $OUTDIR/REPORT.txt"
log "========================================="

# Quick alerts
ALERTS=0
if awk -F: '$3 == 0' /etc/passwd 2>/dev/null | grep -qv '^root:'; then
    log "  [!] ALERT: Non-root accounts with UID 0 found in /etc/passwd"
    ALERTS=$((ALERTS+1))
fi
if [ -s "$OUTDIR/suspicious/recently_modified_binaries.txt" ]; then
    log "  [!] ALERT: System binaries in /bin /sbin /usr/bin modified in last 7 days"
    ALERTS=$((ALERTS+1))
fi
if grep -qE '^.{2}5' "$OUTDIR/hashes/rpm_verify.txt" 2>/dev/null; then
    log "  [!] ALERT: rpm -Va found tampered packages (checksum mismatch)"
    ALERTS=$((ALERTS+1))
fi
if grep -qEi '(cryptonight|xmrig|minerd)' "$OUTDIR/processes/ps_tree.txt" 2>/dev/null; then
    log "  [!] ALERT: Possible crypto miner process detected in ps output"
    ALERTS=$((ALERTS+1))
fi
if [ -s "$OUTDIR/suspicious/lsof_devshm.txt" ]; then
    log "  [!] ALERT: Active files in /dev/shm (ramdisk — used for fileless malware)"
    ALERTS=$((ALERTS+1))
fi
if grep -q 'FOUND:' "$EXFIL" 2>/dev/null; then
    log "  [!] ALERT: Cloud transfer tools (rclone/aws/gcloud) installed on server"
    ALERTS=$((ALERTS+1))
fi
if grep -q 'CLOUD CRED:' "$EXFIL" 2>/dev/null; then
    log "  [!] ALERT: Cloud credentials found in user home directories"
    ALERTS=$((ALERTS+1))
fi
if ls "$OUTDIR/suspicious/cloud_creds"/*/* >/dev/null 2>&1; then
    log "  [!] ALERT: Cloud credential files collected — review for unauthorized access"
    ALERTS=$((ALERTS+1))
fi

if [ "$ALERTS" -eq 0 ]; then
    log "  [OK] No immediate red flags in quick scan"
    log "  Still review REPORT.txt and exfiltration_indicators.txt manually"
fi

# Compress into tar.gz
TARFILE="/root/forensic_$(hostname)_$(date +%Y%m%d_%H%M%S).tar.gz"
log ""
log "  Compressing all collected evidence to $TARFILE ..."
tar czf "$TARFILE" -C "$(dirname "$OUTDIR")" "$(basename "$OUTDIR")" 2>/dev/null

log ""
log "  Archive ready: $TARFILE ($(du -h "$TARFILE" | cut -f1))"
log "  Transfer off-server with:"
log "    scp root@$(hostname):$TARFILE ."
log ""
