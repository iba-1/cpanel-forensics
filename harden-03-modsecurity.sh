#!/usr/bin/env bash
# =============================================================================
# harden-03-modsecurity.sh
# F-03 remediation: install ModSecurity + OWASP CRS on cPanel/EasyApache4
#
# Target:  serverk01.venicebay.it (CloudLinux 8 / cPanel 136)
# Context: No WAF in front of 29 PHP-EOL apps (Symfony 1.x/2.x on PHP 5.3/7.0).
#          ModSecurity provides virtual-patching while apps can't be upgraded.
#
# Interactive: each phase explains what it will do and asks for confirmation.
# Dry-run:    shows everything without executing.
#
# Safety:
#   - Full backup of Apache config and ModSecurity state
#   - Starts in DetectionOnly (log-only, no blocking)
#   - Apache config test before every restart
#   - Generated rollback script in backup directory
#
# Usage:
#   bash harden-03-modsecurity.sh                # interactive
#   bash harden-03-modsecurity.sh --dry-run      # preview only
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
BACKUP_DIR="/root/harden-03-backup_${TIMESTAMP}"
LOG_FILE="/root/harden-03-modsecurity_${TIMESTAMP}.log"
REPORT_FILE="${BACKUP_DIR}/report.md"

declare -a REPORT_PHASES=()
report_phase() {
    REPORT_PHASES+=("$1")
}

MODSEC_PKG="ea-apache24-mod_security2"
MODSEC_CONF_DIR="/etc/apache2/conf.d/modsec"
MODSEC_VENDOR_DIR="/etc/apache2/conf.d/modsec_vendor_configs"
MODSEC_CPANEL_CONF="/etc/apache2/conf.d/modsec2.cpanel.conf"
MODSEC_USER_CONF="/etc/apache2/conf.d/modsec2.user.conf"

# OWASP CRS via cPanel vendor system (configserver.com offline since ~2025)
OWASP_VENDOR_URL="https://updates.configserver.com/modsec/owasp"
OWASP_VENDOR_NAME="OWASP"
# GitHub is the reliable source
OWASP_CRS_VERSION="4.7.0"
OWASP_CRS_GITHUB_URL="https://github.com/coreruleset/coreruleset/archive/refs/tags/v${OWASP_CRS_VERSION}.tar.gz"

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

# Helper: safe Apache restart with config test
safe_apache_restart() {
    info "Config test Apache..."
    if httpd -t 2>> "$LOG_FILE"; then
        ok "Config test superato"
    else
        warn "Config test FALLITO — non riavvio Apache"
        warn "Errore:"
        httpd -t 2>&1 | tail -5 | while IFS= read -r line; do
            echo -e "    ${RED}${line}${NC}"
        done
        warn "Rollback: bash $BACKUP_DIR/rollback.sh"
        return 1
    fi

    info "Riavvio Apache..."
    if systemctl restart httpd 2>> "$LOG_FILE"; then
        ok "Apache riavviato"
        return 0
    else
        warn "Restart Apache FALLITO"
        systemctl status httpd --no-pager -l 2>/dev/null | tail -10 | while IFS= read -r line; do
            echo -e "    ${RED}${line}${NC}"
        done
        return 1
    fi
}

# =============================================================================
# MAIN
# =============================================================================

banner "F-03: Installazione ModSecurity + OWASP CRS"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}Modalità DRY-RUN — nessuna modifica verrà applicata.${NC}"
fi

log "Log file: $LOG_FILE"
echo ""

# -- Pre-flight ---------------------------------------------------------------

echo -e "${BOLD}Pre-flight checks:${NC}"

[[ $EUID -eq 0 ]] || die "Devi eseguire come root"
ok "Root: sì"

[[ -d /usr/local/cpanel ]] || die "cPanel non trovato"
ok "cPanel: trovato"

# Check Apache
if httpd -v &>/dev/null; then
    APACHE_VERSION=$(httpd -v 2>/dev/null | head -1)
    ok "Apache: $APACHE_VERSION"
else
    die "Apache (httpd) non trovato"
fi

# Check EasyApache4
if command -v ea4_metainfo &>/dev/null || [[ -d /etc/cpanel/ea4 ]]; then
    ok "EasyApache4: disponibile"
else
    warn "EasyApache4 non rilevato — l'installazione potrebbe differire"
fi

# Check if ModSecurity is already installed
MODSEC_INSTALLED=0
if rpm -q "$MODSEC_PKG" &>/dev/null; then
    MODSEC_INSTALLED=1
    info "ModSecurity: ${GREEN}già installato${NC} ($(rpm -q $MODSEC_PKG))"
elif httpd -M 2>/dev/null | grep -q "security2_module"; then
    MODSEC_INSTALLED=1
    info "ModSecurity: ${GREEN}modulo caricato${NC} (security2_module)"
else
    info "ModSecurity: ${RED}NON installato${NC}"
fi

# Check current modsec audit log location
MODSEC_AUDIT_LOG="/var/log/apache2/modsec_audit.log"
info "Audit log: $MODSEC_AUDIT_LOG"

echo ""
echo -e "${BOLD}Piano di esecuzione (6 fasi):${NC}"
echo "  0. Backup completo (config Apache, ModSecurity, vhost)"
echo "  1. Installa ModSecurity via EasyApache4"
echo "  2. Configura ModSecurity in DetectionOnly (log-only)"
echo "  3. Installa ruleset OWASP CRS"
echo "  4. Configura esclusioni per app Symfony legacy"
echo "  5. Restart Apache + validazione"

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
    "Salva: configurazione Apache principale (httpd.conf)" \
    "Salva: tutti i file in conf.d/ (include modsec se esistente)" \
    "Salva: moduli Apache caricati (httpd -M)" \
    "Salva: lista vhost (httpd -S)" \
    "Salva: configurazione ModSecurity esistente (se presente)" \
    "Salva: pacchetti EA4 installati" \
    "Genera: script di rollback"

if confirm_phase; then
    mkdir -p "$BACKUP_DIR"
    ok "Directory backup: $BACKUP_DIR"

    # Apache config
    if [[ -f /etc/apache2/conf/httpd.conf ]]; then
        cp /etc/apache2/conf/httpd.conf "$BACKUP_DIR/httpd.conf"
        ok "Salvato httpd.conf"
    fi

    # conf.d/
    if [[ -d /etc/apache2/conf.d ]]; then
        mkdir -p "$BACKUP_DIR/conf.d"
        cp -r /etc/apache2/conf.d/*.conf "$BACKUP_DIR/conf.d/" 2>/dev/null || true
        ok "Salvati file conf.d/"
    fi

    # ModSecurity configs (if any)
    if [[ -d "$MODSEC_CONF_DIR" ]]; then
        cp -r "$MODSEC_CONF_DIR" "$BACKUP_DIR/modsec"
        ok "Salvata configurazione ModSecurity"
    fi
    if [[ -d "$MODSEC_VENDOR_DIR" ]]; then
        cp -r "$MODSEC_VENDOR_DIR" "$BACKUP_DIR/modsec_vendor_configs"
        ok "Salvate configurazioni vendor ModSecurity"
    fi

    # Apache state
    httpd -M 2>/dev/null > "$BACKUP_DIR/apache-modules.txt" || true
    httpd -S 2>/dev/null > "$BACKUP_DIR/apache-vhosts.txt" || true
    ok "Salvato stato Apache (moduli + vhost)"

    # EA4 packages
    rpm -qa | grep ^ea- | sort > "$BACKUP_DIR/ea4-packages.txt" 2>/dev/null || true
    ok "Salvata lista pacchetti EA4"

    # Rollback script
    cat > "$BACKUP_DIR/rollback.sh" <<'ROLLBACK_EOF'
#!/usr/bin/env bash
# =============================================================================
# rollback.sh — Annulla le modifiche di harden-03-modsecurity.sh
# Generato automaticamente. Eseguire come root.
# =============================================================================
set -euo pipefail

BACKUP_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Rollback F-03: ripristino config Apache/ModSecurity ==="
echo "Backup dir: $BACKUP_DIR"
echo ""

# Option A: disable ModSecurity (keep installed)
echo "Scegli un'opzione:"
echo "  1) Disabilita ModSecurity (mantieni installato, rimuovi regole)"
echo "  2) Rimuovi completamente ModSecurity (yum remove)"
echo "  3) Ripristina config da backup (sovrascrive conf.d/)"
read -rp "Scelta (1/2/3): " choice

case "$choice" in
    1)
        echo "Disabilito ModSecurity..."
        if [[ -f /etc/apache2/conf.d/modsec2.cpanel.conf ]]; then
            sed -i 's/^SecRuleEngine .*/SecRuleEngine Off/' /etc/apache2/conf.d/modsec2.cpanel.conf
        fi
        echo "  ✓ SecRuleEngine impostato a Off"
        ;;
    2)
        echo "Rimuovo ModSecurity..."
        yum remove -y ea-apache24-mod_security2 2>/dev/null || true
        echo "  ✓ Pacchetto rimosso"
        ;;
    3)
        echo "Ripristino config da backup..."
        if [[ -d "$BACKUP_DIR/conf.d" ]]; then
            cp "$BACKUP_DIR/conf.d/"*.conf /etc/apache2/conf.d/ 2>/dev/null || true
            echo "  ✓ conf.d/ ripristinato"
        fi
        if [[ -f "$BACKUP_DIR/httpd.conf" ]]; then
            cp "$BACKUP_DIR/httpd.conf" /etc/apache2/conf/httpd.conf
            echo "  ✓ httpd.conf ripristinato"
        fi
        ;;
    *)
        echo "Opzione non valida, esco."
        exit 1
        ;;
esac

echo ""
echo "Config test Apache..."
if httpd -t 2>/dev/null; then
    echo "  ✓ Config OK"
    echo "Riavvio Apache..."
    systemctl restart httpd
    echo "  ✓ Apache riavviato"
else
    echo "  ✗ Config test fallito — verifica manualmente"
fi

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
# Phase 1: Install ModSecurity
# =============================================================================

phase_header 1 "Installa ModSecurity"

if [[ $MODSEC_INSTALLED -eq 1 ]]; then
    info "ModSecurity è già installato — salto l'installazione."
else
    will_do \
        "yum install -y ${MODSEC_PKG}" \
        "Installa il modulo Apache mod_security2 via EasyApache4" \
        "Il modulo viene caricato automaticamente da Apache" \
        "Non richiede rebuild EasyApache (è un pacchetto RPM diretto)"

    if confirm_phase; then
        info "Installazione in corso..."
        if yum install -y "$MODSEC_PKG" >> "$LOG_FILE" 2>&1; then
            ok "ModSecurity installato: $(rpm -q $MODSEC_PKG)"
            MODSEC_INSTALLED=1
        else
            warn "Installazione fallita via yum — provo con WHM API..."
            if /usr/local/cpanel/scripts/manage_ea4_pkgs install "$MODSEC_PKG" >> "$LOG_FILE" 2>&1; then
                ok "ModSecurity installato via WHM"
                MODSEC_INSTALLED=1
            else
                die "Installazione ModSecurity fallita. Controlla $LOG_FILE"
            fi
        fi

        # Verify module is loaded
        if httpd -M 2>/dev/null | grep -q "security2_module"; then
            ok "Modulo security2_module caricato in Apache"
        else
            warn "Modulo non ancora caricato — verrà attivato al restart"
        fi
        undo_hint \
            "yum remove -y $MODSEC_PKG && systemctl restart httpd" \
            "# oppure disabilita senza rimuovere: impostare SecRuleEngine Off"
        report_phase "1|Installa ModSecurity|FATTO|$(rpm -q $MODSEC_PKG 2>/dev/null)|yum remove -y ${MODSEC_PKG} && systemctl restart httpd"
    fi
fi

# =============================================================================
# Phase 2: Configure ModSecurity in DetectionOnly
# =============================================================================

phase_header 2 "Configura ModSecurity in DetectionOnly"

will_do \
    "Imposta SecRuleEngine DetectionOnly (log-only, NON blocca nulla)" \
    "Configura audit log in ${MODSEC_AUDIT_LOG}" \
    "Imposta limiti ragionevoli per request body (13MB) e response (512KB)" \
    "" \
    "DetectionOnly significa:" \
    "  → Le regole vengono valutate e le violazioni loggate" \
    "  → Ma nessuna richiesta viene bloccata" \
    "  → Puoi analizzare i log per escludere i falsi positivi" \
    "  → Poi passare a SecRuleEngine On quando sei sicuro"

# Show current state if modsec config exists
if [[ -f "$MODSEC_CPANEL_CONF" ]]; then
    CURRENT_ENGINE=$(grep "^SecRuleEngine" "$MODSEC_CPANEL_CONF" 2>/dev/null | head -1 || echo "non configurato")
    info "SecRuleEngine attuale: $CURRENT_ENGINE"
fi

if confirm_phase; then
    # cPanel creates modsec2.cpanel.conf — we use modsec2.user.conf for our overrides
    # This survives cPanel updates
    cat > "$MODSEC_USER_CONF" <<EOF
# =============================================================================
# ModSecurity user configuration — F-03 hardening
# Created: $(date '+%Y-%m-%d %H:%M:%S') by harden-03-modsecurity.sh
#
# This file is loaded AFTER modsec2.cpanel.conf, so our directives take
# precedence. cPanel does not overwrite this file.
#
# To switch to blocking mode:
#   sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' $MODSEC_USER_CONF
#   systemctl restart httpd
#
# To disable completely:
#   sed -i 's/^SecRuleEngine .*/SecRuleEngine Off/' $MODSEC_USER_CONF
#   systemctl restart httpd
# =============================================================================

# --- Engine mode ---
# DetectionOnly = log violations, don't block anything
SecRuleEngine DetectionOnly

# --- Audit logging ---
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABCDEFHZ
SecAuditLogType Serial
SecAuditLog ${MODSEC_AUDIT_LOG}

# --- Request body handling ---
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject

# --- Response body handling ---
SecResponseBodyAccess Off

# --- Temp / data dirs ---
SecTmpDir /tmp
SecDataDir /tmp

# --- Debug log (off by default, enable for troubleshooting) ---
# SecDebugLog /var/log/apache2/modsec_debug.log
# SecDebugLogLevel 3
EOF

    ok "Configurazione ModSecurity scritta: $MODSEC_USER_CONF"

    # Also ensure the cpanel conf has DetectionOnly if it exists
    if [[ -f "$MODSEC_CPANEL_CONF" ]]; then
        if grep -q "^SecRuleEngine" "$MODSEC_CPANEL_CONF"; then
            sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' "$MODSEC_CPANEL_CONF"
            ok "Aggiornato anche $MODSEC_CPANEL_CONF → DetectionOnly"
        fi
    fi

    info "Contenuto di $MODSEC_USER_CONF:"
    grep -v '^#' "$MODSEC_USER_CONF" | grep -v '^$' | while IFS= read -r line; do
        echo -e "    ${DIM}${line}${NC}"
    done
    undo_hint \
        "rm $MODSEC_USER_CONF && systemctl restart httpd" \
        "# oppure disabilita senza rimuovere:" \
        "sed -i 's/^SecRuleEngine .*/SecRuleEngine Off/' $MODSEC_USER_CONF && systemctl restart httpd"
    report_phase "2|Configura DetectionOnly|FATTO|${MODSEC_USER_CONF}|rm ${MODSEC_USER_CONF} && systemctl restart httpd"
fi

# =============================================================================
# Phase 3: Install OWASP CRS ruleset
# =============================================================================

phase_header 3 "Installa ruleset OWASP CRS"

will_do \
    "Usa il sistema vendor di cPanel per installare OWASP CRS" \
    "Il vendor system gestisce aggiornamenti automatici delle regole" \
    "Se non disponibile via vendor, installa manualmente da GitHub" \
    "" \
    "OWASP CRS (Core Rule Set) protegge contro:" \
    "  → SQL injection" \
    "  → Cross-Site Scripting (XSS)" \
    "  → Remote Code Execution (RCE)" \
    "  → Local/Remote File Inclusion (LFI/RFI)" \
    "  → PHP code injection" \
    "  → Webshell upload/access"

# Check if vendor system is available
VENDOR_INSTALLED=0
if [[ -d "$MODSEC_VENDOR_DIR" ]]; then
    EXISTING_VENDORS=$(ls "$MODSEC_VENDOR_DIR/" 2>/dev/null || true)
    if [[ -n "$EXISTING_VENDORS" ]]; then
        info "Vendor già presenti: $EXISTING_VENDORS"
    fi
fi

if confirm_phase; then
    # Try cPanel's built-in modsec vendor management
    INSTALLED_VIA=""

    # Method 1: cPanel WHM API
    if [[ -x /usr/local/cpanel/scripts/modsec_vendor ]]; then
        info "Provo installazione via cPanel modsec_vendor..."

        # List available vendors
        /usr/local/cpanel/scripts/modsec_vendor list 2>> "$LOG_FILE" | while IFS= read -r line; do
            echo -e "    ${DIM}${line}${NC}"
        done

        # Try to add OWASP vendor
        if /usr/local/cpanel/scripts/modsec_vendor add "$OWASP_VENDOR_URL" >> "$LOG_FILE" 2>&1; then
            ok "OWASP CRS installato via cPanel vendor system"
            INSTALLED_VIA="cpanel-vendor"
        else
            warn "cPanel vendor add fallito — provo metodo alternativo"
        fi
    fi

    # Method 2: WHM API2
    if [[ -z "$INSTALLED_VIA" ]] && command -v whmapi1 &>/dev/null; then
        info "Provo installazione via WHM API..."
        if whmapi1 modsec_add_vendor url="$OWASP_VENDOR_URL" >> "$LOG_FILE" 2>&1; then
            ok "OWASP CRS installato via WHM API"
            INSTALLED_VIA="whmapi"
        else
            warn "WHM API fallito — provo metodo manuale"
        fi
    fi

    # Method 3: Manual OWASP CRS install from GitHub
    if [[ -z "$INSTALLED_VIA" ]]; then
        info "Installazione manuale OWASP CRS da GitHub..."

        CRS_VERSION="4.7.0"
        CRS_DIR="/etc/apache2/conf.d/modsec_vendor_configs/OWASP"
        CRS_URL="https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"

        mkdir -p "$CRS_DIR"

        if curl -sSfL -o /tmp/owasp-crs.tar.gz "$CRS_URL" 2>> "$LOG_FILE"; then
            ok "OWASP CRS v${CRS_VERSION} scaricato"

            tar -xzf /tmp/owasp-crs.tar.gz -C /tmp/
            CRS_EXTRACTED="/tmp/coreruleset-${CRS_VERSION}"

            # Copy CRS setup config
            if [[ -f "${CRS_EXTRACTED}/crs-setup.conf.example" ]]; then
                cp "${CRS_EXTRACTED}/crs-setup.conf.example" "${CRS_DIR}/crs-setup.conf"
            fi

            # Copy rules
            if [[ -d "${CRS_EXTRACTED}/rules" ]]; then
                cp -r "${CRS_EXTRACTED}/rules" "${CRS_DIR}/"
            fi

            # Create include file for Apache
            cat > "/etc/apache2/conf.d/modsec_vendor_configs/owasp-crs-include.conf" <<CRSINC
# OWASP CRS v${CRS_VERSION} — installed by harden-03-modsecurity.sh
# Date: $(date '+%Y-%m-%d %H:%M:%S')
Include ${CRS_DIR}/crs-setup.conf
Include ${CRS_DIR}/rules/*.conf
CRSINC

            ok "OWASP CRS v${CRS_VERSION} installato manualmente in $CRS_DIR"
            INSTALLED_VIA="manual"

            # Cleanup
            rm -rf /tmp/owasp-crs.tar.gz "$CRS_EXTRACTED"
        else
            warn "Download OWASP CRS fallito"
            warn "URL: $CRS_URL"
            warn "Puoi installare manualmente dopo"
        fi
    fi

    if [[ -n "$INSTALLED_VIA" ]]; then
        ok "Ruleset OWASP CRS installato (metodo: $INSTALLED_VIA)"

        # Count rules
        RULE_FILES=$(find /etc/apache2/conf.d/modsec_vendor_configs/ -name "*.conf" -path "*/rules/*" 2>/dev/null | wc -l || echo "0")
        RULE_COUNT=$(grep -r "^SecRule" /etc/apache2/conf.d/modsec_vendor_configs/ 2>/dev/null | wc -l || echo "0")
        info "File di regole: $RULE_FILES"
        info "Regole totali: ~$RULE_COUNT"
        undo_hint \
            "rm -rf /etc/apache2/conf.d/modsec_vendor_configs/OWASP" \
            "rm -f /etc/apache2/conf.d/modsec_vendor_configs/owasp-crs-include.conf" \
            "# se installato via vendor: whmapi1 modsec_remove_vendor vendor_id=OWASP" \
            "systemctl restart httpd"
        report_phase "3|Installa OWASP CRS|FATTO|Metodo: ${INSTALLED_VIA}, ~${RULE_COUNT} regole|rm -rf OWASP/ owasp-crs-include.conf && systemctl restart httpd"
    fi
fi

# =============================================================================
# Phase 4: Symfony legacy exclusions
# =============================================================================

phase_header 4 "Esclusioni per app Symfony legacy"

will_do \
    "Crea esclusioni ModSecurity per i pattern comuni delle app Symfony 1.x/2.x" \
    "Previene falsi positivi su:" \
    "  → Frontend controller: /index.php, /frontend_dev.php, /backend.php" \
    "  → URL routing Symfony: parametri in query string complesse" \
    "  → Form CSRF token: _token parameter" \
    "  → Upload file: /uploads, /form_upload, /media" \
    "  → TinyMCE/MoxieManager: /moxiemanager/" \
    "" \
    "Le esclusioni vengono scritte in un file separato per facile manutenzione" \
    "Ricorda: siamo in DetectionOnly — le esclusioni sono per quando passerai a On"

EXCLUSION_CONF="/etc/apache2/conf.d/modsec_vendor_configs/symfony-legacy-exclusions.conf"

if confirm_phase; then
    cat > "$EXCLUSION_CONF" <<'EXCEOF'
# =============================================================================
# ModSecurity exclusions for Symfony 1.x/2.x legacy apps
# Created by harden-03-modsecurity.sh
#
# These rules disable specific CRS checks that cause false positives
# on the legacy Symfony stack. Review and tighten as you migrate apps.
# =============================================================================

# --- Symfony CSRF tokens ---
# Symfony forms submit _token (CSRF). CRS may flag it as injection attempt.
SecRuleUpdateTargetById 942100 "!ARGS:_token"
SecRuleUpdateTargetById 942200 "!ARGS:_token"
SecRuleUpdateTargetById 942260 "!ARGS:_token"

# --- Symfony routing / controller parameters ---
# Symfony 1.x uses module/action in query string, can look like path traversal.
SecRuleUpdateTargetById 930110 "!ARGS:module"
SecRuleUpdateTargetById 930110 "!ARGS:action"
SecRuleUpdateTargetById 930120 "!ARGS:module"
SecRuleUpdateTargetById 930120 "!ARGS:action"

# --- TinyMCE / MoxieManager ---
# MoxieManager sends JSON blobs and file paths that trigger injection rules.
SecRule REQUEST_URI "@beginsWith /moxiemanager/" \
    "id:9500001,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=941100-941999,\
    ctl:ruleRemoveById=942100-942999"

# --- File upload directories ---
# Upload handlers receive binary data that can trigger CRS body inspection.
SecRule REQUEST_URI "@rx ^/(uploads|form_upload|media|files|export|download|repository)/" \
    "id:9500002,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=920170,\
    ctl:ruleRemoveById=921110,\
    ctl:requestBodyAccess=Off"

# --- Symfony debug toolbar (dev controllers) ---
# These should be IP-restricted anyway, but exclude from WAF to avoid noise.
SecRule REQUEST_URI "@rx ^/(frontend_dev|backend_dev|app_dev)\.php" \
    "id:9500003,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleEngine=Off"

# --- Common false positives on legacy PHP ---
# PHP session cookies and Symfony-specific parameters
SecRuleUpdateTargetById 942100 "!REQUEST_COOKIES:PHPSESSID"
SecRuleUpdateTargetById 942100 "!REQUEST_COOKIES:symfony"

# --- Content-Type for Symfony form submissions ---
# Multipart forms with file uploads
SecRuleUpdateTargetById 920420 "!REQUEST_HEADERS:Content-Type"
EXCEOF

    ok "Esclusioni Symfony scritte: $EXCLUSION_CONF"

    info "Regole di esclusione create:"
    grep "^SecRule\|^SecRuleUpdate" "$EXCLUSION_CONF" | while IFS= read -r line; do
        echo -e "    ${DIM}${line}${NC}"
    done
    undo_hint "rm $EXCLUSION_CONF && systemctl restart httpd"
    report_phase "4|Esclusioni Symfony legacy|FATTO|${EXCLUSION_CONF}|rm ${EXCLUSION_CONF} && systemctl restart httpd"
fi

# =============================================================================
# Phase 5: Restart Apache + validation
# =============================================================================

phase_header 5 "Restart Apache + validazione"

will_do \
    "httpd -t — verifica configurazione (se fallisce, NON riavvia)" \
    "systemctl restart httpd — riavvia Apache con ModSecurity" \
    "Verifica che il modulo security2 sia caricato" \
    "Verifica che i siti rispondano (test HTTP su alcuni domini)" \
    "Controlla audit log per primi eventi"

if confirm_phase; then
    if safe_apache_restart; then
        # Verify module loaded
        if httpd -M 2>/dev/null | grep -q "security2_module"; then
            ok "Modulo security2_module caricato"
        else
            warn "Modulo security2_module non risulta caricato"
        fi

        # Check SecRuleEngine
        ACTIVE_ENGINE=$(grep "^SecRuleEngine" "$MODSEC_USER_CONF" 2>/dev/null | head -1 || echo "sconosciuto")
        ok "Engine mode: $ACTIVE_ENGINE"

        # Test some sites
        echo ""
        info "Test HTTP sui siti (campione)..."
        TEST_PASS=0
        TEST_FAIL=0
        for domain in grafco.it aiopveneto.it confartigianatotreviso.it cartoplastica.com tecnoidealsrl.com; do
            HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -H "Host: $domain" http://127.0.0.1/ 2>/dev/null || echo "000")
            if [[ "$HTTP_CODE" =~ ^(200|301|302|303|307|308)$ ]]; then
                ok "$domain → HTTP $HTTP_CODE"
                ((TEST_PASS++)) || true
            elif [[ "$HTTP_CODE" == "000" ]]; then
                warn "$domain → timeout/errore"
                ((TEST_FAIL++)) || true
            else
                warn "$domain → HTTP $HTTP_CODE"
                ((TEST_FAIL++)) || true
            fi
        done

        log "Test siti: $TEST_PASS OK, $TEST_FAIL warning"

        # Check audit log
        echo ""
        if [[ -f "$MODSEC_AUDIT_LOG" ]]; then
            AUDIT_LINES=$(wc -l < "$MODSEC_AUDIT_LOG" 2>/dev/null || echo "0")
            info "Audit log esiste: $MODSEC_AUDIT_LOG ($AUDIT_LINES righe)"
            if [[ $AUDIT_LINES -gt 0 ]]; then
                info "Ultime 5 righe:"
                tail -5 "$MODSEC_AUDIT_LOG" | while IFS= read -r line; do
                    echo -e "    ${DIM}${line}${NC}"
                done
            fi
        else
            info "Audit log non ancora creato (nessun evento finora)"
        fi
        undo_hint \
            "sed -i 's/^SecRuleEngine .*/SecRuleEngine Off/' $MODSEC_USER_CONF && systemctl restart httpd" \
            "# oppure rollback completo: bash $BACKUP_DIR/rollback.sh"
        report_phase "5|Restart Apache + validazione|FATTO|Siti OK: ${TEST_PASS}, Warning: ${TEST_FAIL}|SecRuleEngine Off && systemctl restart httpd"
    else
        warn "Apache non riavviato — ModSecurity potrebbe non essere attivo"
        warn "Risolvi il problema e riavvia: systemctl restart httpd"
    fi
fi

# =============================================================================
# Summary
# =============================================================================

banner "Riepilogo F-03"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN completato — nessuna modifica applicata.${NC}"
    echo ""
    echo -e "  Per applicare:  ${BOLD}bash $0${NC}"
else
    echo -e "  ${GREEN}ModSecurity installato in DetectionOnly mode.${NC}"
    echo ""
    echo -e "  ${BOLD}Stato:${NC}"
    echo "    Engine: DetectionOnly (log-only, non blocca nulla)"
    echo "    Ruleset: OWASP CRS"
    echo "    Esclusioni: Symfony 1.x/2.x legacy"
    echo "    Audit log: $MODSEC_AUDIT_LOG"
    echo ""
    echo -e "  ${BOLD}File creati:${NC}"
    echo "    $MODSEC_USER_CONF (config principale)"
    [[ -f "$EXCLUSION_CONF" ]] && echo "    $EXCLUSION_CONF (esclusioni Symfony)"
    echo ""
    echo -e "  ${BOLD}Backup:${NC}"
    echo "    $BACKUP_DIR/"
    echo "    Rollback: bash $BACKUP_DIR/rollback.sh"
    echo ""
    echo -e "  ${BOLD}Prossimi passi:${NC}"
    echo "    1. Monitora l'audit log per 24-48h:"
    echo "         tail -f $MODSEC_AUDIT_LOG"
    echo "    2. Analizza i falsi positivi e aggiungi esclusioni a:"
    echo "         $EXCLUSION_CONF"
    echo "    3. Quando sei sicuro, passa a blocking mode:"
    echo "         sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' $MODSEC_USER_CONF"
    echo "         systemctl restart httpd"
    echo "    4. Per disabilitare al volo (senza rimuovere):"
    echo "         sed -i 's/^SecRuleEngine .*/SecRuleEngine Off/' $MODSEC_USER_CONF"
    echo "         systemctl restart httpd"
fi

# =============================================================================
# Report finale + tarball
# =============================================================================

if [[ -d "$BACKUP_DIR" ]]; then
    cp "$LOG_FILE" "$BACKUP_DIR/" 2>/dev/null || true

    mkdir -p "$BACKUP_DIR/post-state"
    httpd -M > "$BACKUP_DIR/post-state/apache-modules.txt" 2>/dev/null || true
    httpd -S > "$BACKUP_DIR/post-state/apache-vhosts.txt" 2>/dev/null || true
    [[ -f "$MODSEC_USER_CONF" ]] && cp "$MODSEC_USER_CONF" "$BACKUP_DIR/post-state/" 2>/dev/null || true
    [[ -f "$EXCLUSION_CONF" ]] && cp "$EXCLUSION_CONF" "$BACKUP_DIR/post-state/" 2>/dev/null || true
    [[ -f "$MODSEC_AUDIT_LOG" ]] && tail -100 "$MODSEC_AUDIT_LOG" > "$BACKUP_DIR/post-state/modsec-audit-tail.txt" 2>/dev/null || true
    ls -la /etc/apache2/conf.d/modsec_vendor_configs/ > "$BACKUP_DIR/post-state/vendor-configs-listing.txt" 2>/dev/null || true

    cat > "$REPORT_FILE" <<REPORT_EOF
# Report Hardening F-03 — ModSecurity + OWASP CRS

**Script:** harden-03-modsecurity.sh
**Data:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Server:** $(hostname 2>/dev/null || echo "sconosciuto")
**Apache:** $(httpd -v 2>/dev/null | head -1 || echo "sconosciuto")
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

- **SecRuleEngine:** DetectionOnly (log-only)
- **Ruleset:** OWASP CRS
- **Audit log:** ${MODSEC_AUDIT_LOG}
- **Config:** ${MODSEC_USER_CONF}
- **Esclusioni:** ${EXCLUSION_CONF}

## File creati/modificati

- ${MODSEC_USER_CONF} (config ModSecurity user)
- ${EXCLUSION_CONF} (esclusioni Symfony legacy)
- /etc/apache2/conf.d/modsec_vendor_configs/ (ruleset OWASP CRS)

## Rollback

\`\`\`bash
# Disabilita ModSecurity (mantieni installato):
sed -i 's/^SecRuleEngine .*/SecRuleEngine Off/' ${MODSEC_USER_CONF}
systemctl restart httpd

# Rimuovi completamente:
bash ${BACKUP_DIR}/rollback.sh
\`\`\`

## Prossimi passi

1. Monitorare audit log 24-48h: \`tail -f ${MODSEC_AUDIT_LOG}\`
2. Aggiungere esclusioni per falsi positivi
3. Passare a blocking: \`SecRuleEngine On\`
REPORT_EOF

    ok "Report generato: $REPORT_FILE"

    TARBALL="/root/harden-03-report_${TIMESTAMP}.tar.gz"
    tar -czf "$TARBALL" -C /root "$(basename "$BACKUP_DIR")" 2>/dev/null || true
    ok "Tarball: $TARBALL"
fi

echo ""
log "Log: $LOG_FILE"
