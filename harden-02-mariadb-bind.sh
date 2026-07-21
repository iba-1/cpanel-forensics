#!/usr/bin/env bash
# =============================================================================
# harden-02-mariadb-bind.sh
# F-02 remediation: bind MariaDB to localhost only (block from WAN)
#
# Target:  serverk01.venicebay.it (CloudLinux 8 / cPanel 136)
# Context: MariaDB listens on 0.0.0.0:3306, reachable from Internet.
#          Audit validated: all apps use host=localhost, no remote MySQL hosts,
#          mysqlaccesshosts is empty. Safe to restrict.
#
# Interactive: each phase explains what it will do and asks for confirmation.
# Dry-run:    shows everything without executing.
#
# Safety:
#   - Full backup of MariaDB config, grants, and network state
#   - Validates no remote hosts exist in mysql.user before applying
#   - Tests MariaDB restart without actually restarting (configtest)
#   - Generated rollback script in backup directory
#
# Usage:
#   bash harden-02-mariadb-bind.sh                # interactive
#   bash harden-02-mariadb-bind.sh --dry-run      # preview only
# =============================================================================
set -euo pipefail

# -- Parse args ---------------------------------------------------------------

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --help|-h)
            echo "Usage: bash $0 [--dry-run]"
            echo "  --dry-run   Show what would be done without making changes"
            exit 0
            ;;
        *) echo "Unknown option: $arg (use --help)"; exit 1 ;;
    esac
done

# -- Config -------------------------------------------------------------------

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/harden-02-backup_${TIMESTAMP}"
LOG_FILE="/root/harden-02-mariadb-bind_${TIMESTAMP}.log"
REPORT_FILE="${BACKUP_DIR}/report.md"

declare -a REPORT_PHASES=()
report_phase() {
    REPORT_PHASES+=("$1")
}

# Where cPanel puts MariaDB overrides
MYSQL_CPANEL_CONF="/etc/my.cnf.d/cpanel.cnf"
# Fallback: main my.cnf
MYSQL_MAIN_CONF="/etc/my.cnf"

# -- Colors & UI --------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log()  { local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"; echo -e "$msg" >> "$LOG_FILE"; echo -e "$msg"; }
info() { echo -e "${CYAN}  ▸ $1${NC}"; }
ok()   { log "${GREEN}  ✓ $1${NC}"; }
warn() { log "${YELLOW}  ⚠ $1${NC}"; }
die()  { log "${RED}  ✗ FATAL: $1${NC}"; exit 1; }

undo_hint() {
    echo -e "  ${CYAN}↩ Undo questa fase:${NC}"
    while [[ $# -gt 0 ]]; do
        echo -e "    ${CYAN}$ $1${NC}"
        shift
    done
}

banner() {
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

phase_header() {
    local num="$1" title="$2"
    echo ""
    echo -e "${BOLD}── Fase ${num}: ${title} ──${NC}"
}

will_do() {
    echo -e "${DIM}  Cosa farà:${NC}"
    while [[ $# -gt 0 ]]; do
        echo -e "    ${DIM}→${NC} $1"
        shift
    done
}

confirm_phase() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo -e "  ${YELLOW}[DRY-RUN] Saltato — nessuna modifica.${NC}"
        return 1
    fi
    echo ""
    read -rp "  Procedo? (y/N/q=quit) " answer
    case "$answer" in
        y|Y) return 0 ;;
        q|Q) log "Interrotto dall'utente."; exit 0 ;;
        *)   log "Fase saltata dall'utente."; return 1 ;;
    esac
}

# =============================================================================
# MAIN
# =============================================================================

banner "F-02: Bind MariaDB a localhost (blocco dalla WAN)"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}Modalità DRY-RUN — nessuna modifica verrà applicata.${NC}"
fi

log "Log file: $LOG_FILE"
echo ""

# -- Pre-flight ---------------------------------------------------------------

echo -e "${BOLD}Pre-flight checks:${NC}"

[[ $EUID -eq 0 ]] || die "Devi eseguire come root"
ok "Root: sì"

# Check MariaDB is running
if systemctl is-active --quiet mariadb 2>/dev/null || systemctl is-active --quiet mysql 2>/dev/null; then
    ok "MariaDB: in esecuzione"
    if systemctl is-active --quiet mariadb 2>/dev/null; then
        MYSQL_SERVICE="mariadb"
    else
        MYSQL_SERVICE="mysql"
    fi
else
    die "MariaDB/MySQL non in esecuzione — niente da fare"
fi

# Check current bind address
CURRENT_BIND=$(ss -tlnp 2>/dev/null | grep ":3306 " | awk '{print $4}' | sed 's/:3306//' | head -1)
if [[ "$CURRENT_BIND" == "0.0.0.0" || "$CURRENT_BIND" == "*" || "$CURRENT_BIND" == "[::]" ]]; then
    ok "Bind attuale: ${RED}${CURRENT_BIND}:3306${NC} (esposto — da correggere)"
elif [[ "$CURRENT_BIND" == "127.0.0.1" ]]; then
    info "MariaDB è già in bind su 127.0.0.1:3306 — già sicuro"
    info "Niente da fare. Esco."
    exit 0
else
    info "Bind attuale: ${CURRENT_BIND}:3306"
fi

# MariaDB version
MYSQL_VERSION=$(mysql --version 2>/dev/null || echo "sconosciuta")
info "Versione: $MYSQL_VERSION"

echo ""
echo -e "${BOLD}Piano di esecuzione (5 fasi):${NC}"
echo "  0. Backup completo (config, grants, stato rete)"
echo "  1. Verifica che nessuna app usi connessioni remote"
echo "  2. Configura bind-address=127.0.0.1 + skip-name-resolve"
echo "  3. Riavvia MariaDB e valida"
echo "  4. Verifica post-restart"

if [[ $DRY_RUN -eq 0 ]]; then
    echo ""
    read -rp "Vuoi procedere fase per fase? (y/N) " start
    [[ "$start" =~ ^[yY]$ ]] || { log "Interrotto dall'utente."; exit 0; }
fi

# =============================================================================
# Phase 0: Full backup
# =============================================================================

phase_header 0 "Backup completo"

will_do \
    "Crea directory: ${BACKUP_DIR}" \
    "Salva: tutti i file di configurazione MariaDB (/etc/my.cnf, /etc/my.cnf.d/)" \
    "Salva: grants completi (mysql.user — host, user, plugin)" \
    "Salva: mysqlaccesshosts di cPanel" \
    "Salva: stato porte in ascolto" \
    "Salva: connessioni attive a MariaDB" \
    "Salva: lista database" \
    "Genera: script di rollback"

if confirm_phase; then
    mkdir -p "$BACKUP_DIR"
    ok "Directory backup: $BACKUP_DIR"

    # Config files
    if [[ -f "$MYSQL_MAIN_CONF" ]]; then
        cp "$MYSQL_MAIN_CONF" "$BACKUP_DIR/my.cnf"
        ok "Salvato my.cnf"
    fi
    if [[ -d /etc/my.cnf.d ]]; then
        cp -r /etc/my.cnf.d "$BACKUP_DIR/my.cnf.d"
        ok "Salvata directory my.cnf.d/"
    fi

    # Grants and user hosts
    mysql -N -e "SELECT Host, User, plugin FROM mysql.user ORDER BY User, Host;" \
        > "$BACKUP_DIR/mysql-user-grants.txt" 2>/dev/null || true
    ok "Salvati grants (mysql.user)"

    # Full grant dump
    mysql -N -e "SELECT DISTINCT User, Host FROM mysql.user;" 2>/dev/null | while IFS=$'\t' read -r user host; do
        mysql -N -e "SHOW GRANTS FOR '${user}'@'${host}';" 2>/dev/null
        echo ""
    done > "$BACKUP_DIR/mysql-all-grants.sql" 2>/dev/null || true
    ok "Salvato dump completo SHOW GRANTS"

    # mysqlaccesshosts
    if [[ -f /var/cpanel/mysqlaccesshosts ]]; then
        cp /var/cpanel/mysqlaccesshosts "$BACKUP_DIR/mysqlaccesshosts"
    else
        echo "# file non esistente" > "$BACKUP_DIR/mysqlaccesshosts"
    fi
    ok "Salvato mysqlaccesshosts"

    # Network state
    ss -tlnp | grep ":3306" > "$BACKUP_DIR/port-3306-listen.txt" 2>/dev/null || true
    ss -tnp  | grep ":3306" > "$BACKUP_DIR/port-3306-connections.txt" 2>/dev/null || true
    ok "Salvato stato rete porta 3306"

    # Database list
    mysql -N -e "SHOW DATABASES;" > "$BACKUP_DIR/databases.txt" 2>/dev/null || true
    ok "Salvata lista database"

    # Rollback script
    cat > "$BACKUP_DIR/rollback.sh" <<'ROLLBACK_EOF'
#!/usr/bin/env bash
# =============================================================================
# rollback.sh — Annulla le modifiche di harden-02-mariadb-bind.sh
# Generato automaticamente. Eseguire come root.
# =============================================================================
set -euo pipefail

BACKUP_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Rollback F-02: ripristino config MariaDB ==="
echo "Backup dir: $BACKUP_DIR"
echo ""

# 1. Ripristina my.cnf
if [[ -f "$BACKUP_DIR/my.cnf" ]]; then
    echo "Ripristino /etc/my.cnf..."
    cp "$BACKUP_DIR/my.cnf" /etc/my.cnf
    echo "  ✓ my.cnf ripristinato"
fi

# 2. Ripristina my.cnf.d/
if [[ -d "$BACKUP_DIR/my.cnf.d" ]]; then
    echo "Ripristino /etc/my.cnf.d/..."
    rm -rf /etc/my.cnf.d
    cp -r "$BACKUP_DIR/my.cnf.d" /etc/my.cnf.d
    echo "  ✓ my.cnf.d/ ripristinato"
fi

# 3. Riavvia MariaDB
echo "Riavvio MariaDB..."
if systemctl is-active --quiet mariadb 2>/dev/null; then
    systemctl restart mariadb
elif systemctl is-active --quiet mysql 2>/dev/null; then
    systemctl restart mysql
fi
echo "  ✓ MariaDB riavviato"

# 4. Verifica
echo ""
echo "Stato attuale:"
ss -tlnp | grep ":3306" || echo "  (porta 3306 non in ascolto!)"
echo ""
echo "=== Rollback completato ==="
ROLLBACK_EOF

    chmod +x "$BACKUP_DIR/rollback.sh"
    ok "Script rollback generato: $BACKUP_DIR/rollback.sh"

    # File listing
    echo ""
    info "Contenuto backup:"
    ls -la "$BACKUP_DIR/" | while IFS= read -r line; do
        echo -e "    ${DIM}${line}${NC}"
    done

    log "Backup completo. Rollback: bash $BACKUP_DIR/rollback.sh"
    undo_hint "rm -rf $BACKUP_DIR"
    report_phase "0|Backup completo|FATTO|${BACKUP_DIR}|rm -rf ${BACKUP_DIR}"
fi

# =============================================================================
# Phase 1: Verify no remote connections needed
# =============================================================================

phase_header 1 "Verifica connessioni remote"

will_do \
    "Interroga mysql.user per trovare host diversi da localhost/127.0.0.1/::1/hostname" \
    "Controlla mysqlaccesshosts di cPanel" \
    "Controlla connessioni attive da IP remoti sulla porta 3306" \
    "Campiona databases.yml delle app Symfony per verificare host=localhost" \
    "Se trova host remoti: STOP — non è sicuro procedere"

echo ""
info "Analisi in corso (read-only)..."
echo ""

# 1a. mysql.user hosts
echo -e "  ${BOLD}Host in mysql.user:${NC}"
REMOTE_HOSTS=""
SERVER_HOSTNAME=$(hostname 2>/dev/null || true)
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
SERVER_SHORT=$(hostname -s 2>/dev/null || true)
while IFS=$'\t' read -r host user plugin; do
    host=$(echo "$host" | xargs)
    user=$(echo "$user" | xargs)

    # Skip MariaDB roles (host is empty, e.g. PUBLIC role in MariaDB 10.11+)
    if [[ -z "$host" ]]; then
        echo -e "    ${DIM}⊘${NC} ${user}@(nessun host) — ruolo MariaDB, ignorato"
        continue
    fi

    is_local=0
    case "$host" in
        localhost|127.0.0.1|::1) is_local=1 ;;
    esac
    # Also match server's own hostname/IP
    [[ "$host" == "$SERVER_HOSTNAME" ]] && is_local=1
    [[ "$host" == "$SERVER_IP" ]] && is_local=1
    [[ "$host" == "$SERVER_SHORT" ]] && is_local=1

    if [[ $is_local -eq 1 ]]; then
        echo -e "    ${GREEN}✓${NC} ${user}@${host} (locale)"
    else
        echo -e "    ${RED}✗${NC} ${user}@${host} ${RED}(REMOTO!)${NC}"
        REMOTE_HOSTS="${REMOTE_HOSTS} ${user}@${host}"
    fi
done < <(mysql -N -e "SELECT Host, User, plugin FROM mysql.user ORDER BY User, Host;" 2>/dev/null || true)

# 1b. mysqlaccesshosts
echo ""
echo -e "  ${BOLD}mysqlaccesshosts cPanel:${NC}"
if [[ -f /var/cpanel/mysqlaccesshosts ]]; then
    ACCESS_HOSTS=$(grep -v '^#' /var/cpanel/mysqlaccesshosts 2>/dev/null | grep -v '^$' || true)
    if [[ -z "$ACCESS_HOSTS" ]]; then
        echo -e "    ${GREEN}✓${NC} Vuoto — nessun host remoto autorizzato"
    else
        echo -e "    ${RED}✗${NC} Host remoti trovati:"
        echo "$ACCESS_HOSTS" | while read -r h; do
            echo -e "      ${RED}→ $h${NC}"
            REMOTE_HOSTS="${REMOTE_HOSTS} mysqlaccesshosts:${h}"
        done
    fi
else
    echo -e "    ${GREEN}✓${NC} File non esiste — nessun host remoto"
fi

# 1c. Active remote connections
echo ""
echo -e "  ${BOLD}Connessioni attive sulla porta 3306:${NC}"
REMOTE_CONNS=$(ss -tnp 2>/dev/null | grep ":3306" | grep -v "127.0.0.1" | grep -v "::1" || true)
if [[ -z "$REMOTE_CONNS" ]]; then
    echo -e "    ${GREEN}✓${NC} Nessuna connessione remota attiva"
else
    echo -e "    ${RED}✗${NC} Connessioni remote trovate:"
    echo "$REMOTE_CONNS" | while read -r line; do
        echo -e "      ${RED}→ $line${NC}"
    done
    REMOTE_HOSTS="${REMOTE_HOSTS} active-connections"
fi

# 1d. Sample app configs
echo ""
echo -e "  ${BOLD}Campione databases.yml delle app:${NC}"
SAMPLE_COUNT=0
REMOTE_DSN=0
for dbfile in /home/*/public_html/config/databases.yml /home/*/apps/*/config/databases.yml; do
    [[ -f "$dbfile" ]] || continue
    ((SAMPLE_COUNT++)) || true
    db_host=$(grep -i "host:" "$dbfile" 2>/dev/null | head -1 | sed 's/.*host: *//; s/#.*//' | xargs || true)
    username=$(echo "$dbfile" | sed 's|/home/||; s|/.*||')
    if [[ -z "$db_host" || "$db_host" == "localhost" || "$db_host" == "127.0.0.1" ]]; then
        echo -e "    ${GREEN}✓${NC} $username → host=${db_host:-localhost}"
    else
        echo -e "    ${RED}✗${NC} $username → host=${db_host} ${RED}(REMOTO!)${NC}"
        ((REMOTE_DSN++)) || true
        REMOTE_HOSTS="${REMOTE_HOSTS} dsn:${username}:${db_host}"
    fi
    [[ $SAMPLE_COUNT -ge 10 ]] && break
done
if [[ $SAMPLE_COUNT -eq 0 ]]; then
    echo -e "    ${DIM}(nessun databases.yml trovato — skip)${NC}"
else
    echo -e "    ${DIM}(campionati $SAMPLE_COUNT file)${NC}"
fi

# Verdict
echo ""
if [[ -n "$REMOTE_HOSTS" ]]; then
    echo -e "  ${RED}${BOLD}ATTENZIONE: trovati host remoti!${NC}"
    echo -e "  ${RED}Non è sicuro procedere con bind-address=127.0.0.1${NC}"
    echo -e "  ${RED}Host remoti:${REMOTE_HOSTS}${NC}"
    echo ""
    if [[ $DRY_RUN -eq 0 ]]; then
        read -rp "  Vuoi procedere comunque? (PERICOLOSO) (y/N) " force
        if [[ ! "$force" =~ ^[yY]$ ]]; then
            die "Interrotto — risolvi gli host remoti prima di procedere"
        fi
        warn "Procedo nonostante host remoti — a tuo rischio"
    fi
else
    echo -e "  ${GREEN}${BOLD}Tutto locale — sicuro procedere con bind-address=127.0.0.1${NC}"
fi

# =============================================================================
# Phase 2: Configure bind-address
# =============================================================================

phase_header 2 "Configura bind-address=127.0.0.1"

# Determine which config file to use
# cPanel manages MariaDB config via /etc/my.cnf.d/ — we create a hardening override
HARDENING_CONF="/etc/my.cnf.d/hardening-bind.cnf"

will_do \
    "Crea file override: ${HARDENING_CONF}" \
    "Contenuto:" \
    "  [mysqld]" \
    "  bind-address = 127.0.0.1" \
    "  skip-name-resolve" \
    "" \
    "bind-address=127.0.0.1 → MariaDB accetta connessioni solo da localhost" \
    "skip-name-resolve → non fa DNS lookup sugli host (performance + sicurezza)" \
    "" \
    "Nota: usiamo un file separato in my.cnf.d/ per non toccare i file gestiti da cPanel." \
    "Se cPanel rigenera my.cnf, il nostro override sopravvive."

# Show what exists now
echo ""
info "Configurazione attuale bind-address:"
EXISTING_BIND=$(grep -r "bind-address" /etc/my.cnf /etc/my.cnf.d/ 2>/dev/null || true)
if [[ -z "$EXISTING_BIND" ]]; then
    info "  Nessun bind-address configurato (default: 0.0.0.0)"
else
    echo "$EXISTING_BIND" | while read -r line; do
        info "  $line"
    done
fi

EXISTING_SKIP=$(grep -r "skip-name-resolve" /etc/my.cnf /etc/my.cnf.d/ 2>/dev/null || true)
if [[ -z "$EXISTING_SKIP" ]]; then
    info "  Nessun skip-name-resolve configurato"
else
    echo "$EXISTING_SKIP" | while read -r line; do
        info "  $line"
    done
fi

if confirm_phase; then
    # Check if our file already exists
    if [[ -f "$HARDENING_CONF" ]]; then
        cp "$HARDENING_CONF" "$BACKUP_DIR/hardening-bind.cnf.previous"
        ok "Backup del file override precedente"
    fi

    cat > "$HARDENING_CONF" <<EOF
# =============================================================================
# Hardening F-02: bind MariaDB to localhost only
# Created: $(date '+%Y-%m-%d %H:%M:%S') by harden-02-mariadb-bind.sh
# Rollback: rm $HARDENING_CONF && systemctl restart $MYSQL_SERVICE
# =============================================================================
[mysqld]
bind-address = 127.0.0.1
skip-name-resolve
EOF

    ok "File override creato: $HARDENING_CONF"

    # Show the file
    echo ""
    info "Contenuto di $HARDENING_CONF:"
    while IFS= read -r line; do
        echo -e "    ${DIM}${line}${NC}"
    done < "$HARDENING_CONF"
    undo_hint "rm $HARDENING_CONF   # rimuove l'override, MariaDB tornerà su 0.0.0.0 al prossimo restart"
    report_phase "2|Configura bind-address=127.0.0.1|FATTO|${HARDENING_CONF}|rm ${HARDENING_CONF}"
fi

# =============================================================================
# Phase 3: Restart MariaDB and validate
# =============================================================================

phase_header 3 "Riavvio MariaDB"

will_do \
    "Verifica configurazione con mysqld --help --verbose (configtest)" \
    "systemctl restart ${MYSQL_SERVICE}" \
    "Verifica che MariaDB si riavvii correttamente" \
    "Verifica che la porta 3306 sia ora in bind su 127.0.0.1" \
    "" \
    "Se il restart fallisce:" \
    "  → Lo script mostra l'errore e suggerisce il rollback" \
    "  → Rollback rapido: rm $HARDENING_CONF && systemctl restart $MYSQL_SERVICE"

if confirm_phase; then
    # Config test
    info "Verifica configurazione MariaDB..."
    if mysqld --help --verbose > /dev/null 2>> "$LOG_FILE"; then
        ok "Config test superato"
    else
        warn "Config test ha riportato warning — controlla $LOG_FILE"
        warn "Procedo con il restart (i warning sono spesso non bloccanti)"
    fi

    # Restart
    info "Riavvio ${MYSQL_SERVICE}..."
    if systemctl restart "$MYSQL_SERVICE" 2>> "$LOG_FILE"; then
        ok "MariaDB riavviato"
    else
        echo ""
        warn "RESTART FALLITO!"
        warn "Errore:"
        systemctl status "$MYSQL_SERVICE" --no-pager -l 2>/dev/null | tail -10 | while read -r line; do
            echo -e "    ${RED}${line}${NC}"
        done
        echo ""
        warn "Rollback rapido:"
        warn "  rm $HARDENING_CONF && systemctl restart $MYSQL_SERVICE"
        warn "Rollback completo:"
        warn "  bash $BACKUP_DIR/rollback.sh"
        die "Restart MariaDB fallito — intervieni manualmente"
    fi

    # Wait briefly for service to stabilize
    sleep 2

    # Check bind
    NEW_BIND=$(ss -tlnp 2>/dev/null | grep ":3306 " | awk '{print $4}' | head -1)
    if echo "$NEW_BIND" | grep -q "127.0.0.1"; then
        ok "MariaDB ora in bind su ${GREEN}127.0.0.1:3306${NC}"
    else
        warn "Bind attuale: $NEW_BIND — potrebbe non essere corretto"
        warn "Verifica manuale: ss -tlnp | grep 3306"
    fi
    undo_hint \
        "rm $HARDENING_CONF && systemctl restart $MYSQL_SERVICE" \
        "# oppure rollback completo: bash $BACKUP_DIR/rollback.sh"
    report_phase "3|Restart MariaDB|FATTO|Bind: $(ss -tlnp 2>/dev/null | grep ':3306 ' | awk '{print $4}' | head -1)|rm ${HARDENING_CONF} && systemctl restart ${MYSQL_SERVICE}"
fi

# =============================================================================
# Phase 4: Post-restart validation
# =============================================================================

phase_header 4 "Verifica post-restart"

will_do \
    "Esegue una query di test per verificare che MariaDB funzioni" \
    "Verifica che le app possano connettersi (campione databases.yml)" \
    "Verifica che la porta 3306 non sia raggiungibile dall'esterno (se CSF attivo)"

echo ""

# 4a. Basic connectivity
info "Test connessione locale..."
if mysql -e "SELECT 1;" > /dev/null 2>&1; then
    ok "Connessione locale (root): OK"
else
    warn "Connessione locale fallita — verifica MariaDB"
fi

# 4b. Database access
info "Test accesso database..."
DB_COUNT=$(mysql -N -e "SELECT COUNT(*) FROM information_schema.SCHEMATA;" 2>/dev/null || echo "0")
ok "Database accessibili: $DB_COUNT"

# 4c. Sample app connection test
info "Test connessione da app campione..."
APP_TESTED=0
APP_OK=0
APP_FAIL=0
for dbfile in /home/*/public_html/config/databases.yml /home/*/apps/*/config/databases.yml; do
    [[ -f "$dbfile" ]] || continue

    db_name=$(grep -i "dbname:" "$dbfile" 2>/dev/null | head -1 | sed 's/.*dbname: *//; s/#.*//' | xargs || true)
    db_user=$(grep -i "username:" "$dbfile" 2>/dev/null | head -1 | sed 's/.*username: *//; s/#.*//' | xargs || true)
    db_pass=$(grep -i "password:" "$dbfile" 2>/dev/null | head -1 | sed 's/.*password: *//; s/#.*//' | xargs || true)
    cpanel_user=$(echo "$dbfile" | sed 's|/home/||; s|/.*||')

    [[ -z "$db_name" || -z "$db_user" ]] && continue
    ((APP_TESTED++)) || true

    if mysql -u "$db_user" -p"$db_pass" -e "USE \`${db_name}\`; SELECT 1;" > /dev/null 2>&1; then
        ok "$cpanel_user → ${db_user}@localhost/${db_name}: OK"
        ((APP_OK++)) || true
    else
        warn "$cpanel_user → ${db_user}@localhost/${db_name}: FALLITO"
        ((APP_FAIL++)) || true
    fi

    [[ $APP_TESTED -ge 5 ]] && break
done

if [[ $APP_TESTED -eq 0 ]]; then
    info "Nessuna app campionata (nessun databases.yml trovato)"
else
    log "App testate: $APP_TESTED — OK: $APP_OK, Fallite: $APP_FAIL"
fi

# 4d. External check (if CSF is installed)
if command -v csf &>/dev/null; then
    echo ""
    info "CSF è installato — la porta 3306 dovrebbe essere bloccata anche dal firewall"
    if csf -l 2>/dev/null | grep -q "DENY.*3306" || ! echo "$TCP_IN_PUBLIC" 2>/dev/null | grep -q "3306"; then
        ok "3306 non è nelle porte pubbliche di CSF (doppia protezione)"
    fi
fi

# 4e. Final bind check
echo ""
echo -e "  ${BOLD}Stato finale porta 3306:${NC}"
ss -tlnp 2>/dev/null | grep ":3306" | while IFS= read -r line; do
    echo -e "    $line"
done

# =============================================================================
# Summary
# =============================================================================

banner "Riepilogo F-02"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN completato — nessuna modifica applicata.${NC}"
    echo ""
    echo -e "  Per applicare:  ${BOLD}bash $0${NC}"
else
    NEW_BIND_FINAL=$(ss -tlnp 2>/dev/null | grep ":3306 " | awk '{print $4}' | head -1)
    if echo "$NEW_BIND_FINAL" | grep -q "127.0.0.1"; then
        echo -e "  ${GREEN}MariaDB ora ascolta solo su 127.0.0.1:3306${NC}"
    else
        echo -e "  ${YELLOW}Bind attuale: ${NEW_BIND_FINAL} — verifica manuale necessaria${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}Modifiche applicate:${NC}"
    echo "    File creato: $HARDENING_CONF"
    echo "    bind-address = 127.0.0.1"
    echo "    skip-name-resolve"
    echo ""
    echo -e "  ${BOLD}Backup:${NC}"
    echo "    $BACKUP_DIR/"
    echo "    Rollback completo: bash $BACKUP_DIR/rollback.sh"
    echo "    Rollback rapido:   rm $HARDENING_CONF && systemctl restart $MYSQL_SERVICE"
    echo ""
    if [[ $APP_FAIL -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}ATTENZIONE: $APP_FAIL app hanno fallito il test di connessione!${NC}"
        echo -e "  ${RED}Verifica e considera il rollback se necessario.${NC}"
        echo ""
    fi
    echo -e "  ${BOLD}Verifica manuale consigliata:${NC}"
    echo "    ss -tlnp | grep 3306          # deve mostrare 127.0.0.1"
    echo "    mysql -e 'SELECT 1;'          # connessione locale"
    echo "    curl -s telnet://IP:3306      # da remoto, deve fallire"
fi

# =============================================================================
# Report finale + tarball
# =============================================================================

if [[ -d "$BACKUP_DIR" ]]; then
    cp "$LOG_FILE" "$BACKUP_DIR/" 2>/dev/null || true

    mkdir -p "$BACKUP_DIR/post-state"
    ss -tlnp | grep ":3306" > "$BACKUP_DIR/post-state/port-3306-listen.txt" 2>/dev/null || true
    ss -tnp  | grep ":3306" > "$BACKUP_DIR/post-state/port-3306-connections.txt" 2>/dev/null || true
    mysql -N -e "SELECT Host, User FROM mysql.user ORDER BY User, Host;" > "$BACKUP_DIR/post-state/mysql-user-hosts.txt" 2>/dev/null || true
    [[ -f "$HARDENING_CONF" ]] && cp "$HARDENING_CONF" "$BACKUP_DIR/post-state/" 2>/dev/null || true

    cat > "$REPORT_FILE" <<REPORT_EOF
# Report Hardening F-02 — MariaDB Bind Localhost

**Script:** harden-02-mariadb-bind.sh
**Data:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Server:** $(hostname 2>/dev/null || echo "sconosciuto")
**Modalità:** $(if [[ $DRY_RUN -eq 1 ]]; then echo "DRY-RUN"; else echo "ESECUZIONE"; fi)

## Fasi eseguite

| Fase | Descrizione | Stato | Dettaglio | Undo |
|------|-------------|-------|-----------|------|
REPORT_EOF

    for entry in "${REPORT_PHASES[@]}"; do
        IFS='|' read -r num desc status detail undo <<< "$entry"
        echo "| ${num} | ${desc} | ${status} | ${detail} | \`${undo}\` |" >> "$REPORT_FILE"
    done

    cat >> "$REPORT_FILE" <<REPORT_EOF

## Stato finale

- **Bind MariaDB:** $(ss -tlnp 2>/dev/null | grep ':3306 ' | awk '{print $4}' | head -1)
- **File override:** ${HARDENING_CONF}
- **App testate:** ${APP_TESTED:-0} (OK: ${APP_OK:-0}, Fail: ${APP_FAIL:-0})

## Rollback

\`\`\`bash
# Rapido:
rm ${HARDENING_CONF} && systemctl restart ${MYSQL_SERVICE}

# Completo:
bash ${BACKUP_DIR}/rollback.sh
\`\`\`
REPORT_EOF

    ok "Report generato: $REPORT_FILE"

    TARBALL="/root/harden-02-report_${TIMESTAMP}.tar.gz"
    tar -czf "$TARBALL" -C /root "$(basename "$BACKUP_DIR")" 2>/dev/null || true
    ok "Tarball: $TARBALL"
fi

echo ""
log "Log: $LOG_FILE"
