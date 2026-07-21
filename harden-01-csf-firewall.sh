#!/usr/bin/env bash
# =============================================================================
# harden-01-csf-firewall.sh
# F-01 remediation: install CSF+LFD firewall with default-deny policy
#
# Target:  serverk01.venicebay.it (CloudLinux 8 / cPanel 136)
# Context: post-ransomware SorryGo (May 2026) — 25/26 ports reachable from WAN
#
# Interactive: each phase explains what it will do and asks for confirmation.
# Dry-run:    shows everything without executing.
#
# Safety:
#   - Full backup of firewall/network state BEFORE any change
#   - Auto-detects your SSH IP and adds it to whitelist
#   - CSF TESTING mode (auto-disables after 5 min on lockout)
#   - Rescue cron job: disables CSF after 15 min (removed on success)
#   - Generated rollback script in the backup directory
#
# Usage:
#   bash harden-01-csf-firewall.sh                           # interactive
#   bash harden-01-csf-firewall.sh --dry-run                 # preview only
#   ADMIN_IPS="82.84.108.8,X.X.X.X" bash harden-01-csf-firewall.sh
#
# Safe to re-run: skips install if CSF is already present.
# =============================================================================
set -euo pipefail

# -- Parse args ---------------------------------------------------------------

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --help|-h)
            echo "Usage: [ADMIN_IPS=\"ip1,ip2\"] bash $0 [--dry-run]"
            echo "  --dry-run   Show what would be done without making changes"
            exit 0
            ;;
        *) echo "Unknown option: $arg (use --help)"; exit 1 ;;
    esac
done

# -- Config -------------------------------------------------------------------

ADMIN_IPS="${ADMIN_IPS:-82.84.108.8}"

# Public TCP inbound — SSH and WHM restano pubblici (protezione via chiave SSH + 2FA)
# La restrizione per IP non è praticabile con IP dinamico dell'admin.
TCP_IN_PUBLIC="22,25,53,80,110,143,443,465,587,993,995,2077,2078,2082,2083,2086,2087,2095,2096"

TCP_OUT="20,21,22,25,37,43,53,80,110,113,443,465,587,873,993,995,2077,2078,2082,2083,2086,2087,2089,2095,2096,8080"
UDP_IN="53"
UDP_OUT="53,113,123,6277"
SSH_PORT="22"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/harden-01-backup_${TIMESTAMP}"
LOG_FILE="/root/harden-01-csf-firewall_${TIMESTAMP}.log"
REPORT_FILE="${BACKUP_DIR}/report.md"
RESCUE_CRON_TAG="HARDEN01_RESCUE_$$"
RESCUE_MINUTES=15

# Report accumulator
declare -a REPORT_PHASES=()
report_phase() {
    REPORT_PHASES+=("$1")
}

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
        q|Q) log "Interrotto dall'utente."; remove_rescue_cron; exit 0 ;;
        *)   log "Fase saltata dall'utente."; return 1 ;;
    esac
}

# -- CSF config helper -------------------------------------------------------

CSF_CONF="/etc/csf/csf.conf"

csf_set() {
    local key="$1" val="$2"
    if grep -q "^${key} " "$CSF_CONF"; then
        sed -i "s|^${key} .*|${key} = \"${val}\"|" "$CSF_CONF"
    elif grep -q "^#${key} " "$CSF_CONF"; then
        sed -i "s|^#${key} .*|${key} = \"${val}\"|" "$CSF_CONF"
    else
        echo "${key} = \"${val}\"" >> "$CSF_CONF"
    fi
}

# -- Rescue cron helpers ------------------------------------------------------

install_rescue_cron() {
    local rescue_time
    rescue_time=$(date -d "+${RESCUE_MINUTES} minutes" '+%M %H %d %m *' 2>/dev/null) \
        || rescue_time=$(date -v+${RESCUE_MINUTES}M '+%M %H %d %m *' 2>/dev/null) \
        || return 1

    (crontab -l 2>/dev/null || true; echo "${rescue_time} /usr/sbin/csf -x && /usr/bin/logger 'HARDEN01: rescue cron fired — CSF disabled' # ${RESCUE_CRON_TAG}") | crontab -
}

remove_rescue_cron() {
    (crontab -l 2>/dev/null || true) | grep -v "${RESCUE_CRON_TAG}" | crontab - 2>/dev/null || true
}

# -- Cleanup on exit ----------------------------------------------------------

cleanup() {
    remove_rescue_cron
}
trap cleanup EXIT

# =============================================================================
# MAIN
# =============================================================================

banner "F-01: Installazione firewall CSF+LFD (default-deny)"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}Modalità DRY-RUN — nessuna modifica verrà applicata.${NC}"
fi

log "Log file: $LOG_FILE"
echo ""

# -- Pre-flight ---------------------------------------------------------------

echo -e "${BOLD}Pre-flight checks:${NC}"

[[ $EUID -eq 0 ]] || die "Devi eseguire come root"
ok "Root: sì"

if [[ -d /usr/local/cpanel ]]; then
    ok "cPanel: trovato"
else
    die "cPanel non trovato — script pensato per server cPanel"
fi

# Auto-detect SSH IP and add to whitelist
if [[ -n "${SSH_CONNECTION:-}" ]]; then
    MY_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    if ! echo ",$ADMIN_IPS," | grep -q ",$MY_IP,"; then
        warn "Il tuo IP SSH attuale ($MY_IP) non è in ADMIN_IPS"
        info "Lo aggiungo automaticamente alla whitelist per evitare lockout"
        ADMIN_IPS="${ADMIN_IPS},${MY_IP}"
    fi
    ok "SSH da $MY_IP — presente nella whitelist"
else
    warn "Non rilevo SSH_CONNECTION — non sono in una sessione SSH?"
fi

# Check for multiple SSH sessions (safety: if this one dies, the other survives)
SSH_SESSIONS=$(who 2>/dev/null | grep -c "pts/" || true)
if [[ $SSH_SESSIONS -ge 2 ]]; then
    ok "Sessioni SSH attive: $SSH_SESSIONS (buono — hai una sessione di riserva)"
else
    warn "Solo 1 sessione SSH attiva. Consiglio: apri un secondo terminale SSH"
    warn "come rete di sicurezza prima di procedere."
    if [[ $DRY_RUN -eq 0 ]]; then
        read -rp "  Continuo con una sola sessione? (y/N) " confirm
        [[ "$confirm" =~ ^[yY]$ ]] || die "Interrotto — apri un secondo terminale SSH e riprova"
    fi
fi

# Current state summary
echo ""
echo -e "${BOLD}Stato attuale del server:${NC}"

if systemctl is-active --quiet firewalld 2>/dev/null; then
    info "firewalld: ${RED}attivo${NC} (verrà disabilitato)"
elif systemctl is-enabled --quiet firewalld 2>/dev/null; then
    info "firewalld: inattivo ma abilitato (verrà disabilitato)"
else
    info "firewalld: già inattivo/disabilitato"
fi

if [[ -x /usr/sbin/csf ]]; then
    info "CSF: già installato ($(csf -v 2>&1 | head -1))"
else
    info "CSF: non installato"
fi

OPEN_PORTS=$(ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | sed 's/.*://' | sort -un | tr '\n' ',' | sed 's/,$//')
info "Porte TCP in ascolto: $OPEN_PORTS"
info "Admin IPs da whitelistare: $ADMIN_IPS"

echo ""
echo -e "${BOLD}Piano di esecuzione (9 fasi):${NC}"
echo "  0. Backup completo stato pre-hardening + rescue cron"
echo "  1. Disabilita firewalld"
echo "  2. Scarica e installa CSF+LFD"
echo "  3. Configura CSF (default-deny, porte, LFD, SYN flood)"
echo "  4. Whitelist IP admin corrente in csf.allow"
echo "  5. (info) SSH e WHM restano pubblici — protezione via chiave + 2FA"
echo "  6. Documenta porte bloccate (111,3306,4190) in csf.deny"
echo "  7. Avvia CSF in TESTING mode (auto-disable dopo 5 min)"
echo "  8. Validazione connettività + report finale"

if [[ $DRY_RUN -eq 0 ]]; then
    echo ""
    read -rp "Vuoi procedere fase per fase? (y/N) " start
    [[ "$start" =~ ^[yY]$ ]] || { log "Interrotto dall'utente."; exit 0; }
fi

# =============================================================================
# Phase 0: Full backup + rescue cron
# =============================================================================

phase_header 0 "Backup completo + rescue cron"

will_do \
    "Crea directory di backup: ${BACKUP_DIR}" \
    "Salva: regole iptables correnti (iptables-save)" \
    "Salva: regole nftables correnti (nft list ruleset)" \
    "Salva: stato firewalld (zone, servizi, porte)" \
    "Salva: configurazione CSF se già presente (csf.conf, csf.allow, csf.deny)" \
    "Salva: sshd_config" \
    "Salva: porte in ascolto (ss -tlnp, ss -ulnp)" \
    "Salva: connessioni stabilite (ss -tnp)" \
    "Salva: crontab root corrente" \
    "Genera: script di rollback (rollback.sh) nella directory di backup" \
    "Installa: rescue cron — disabilita CSF automaticamente tra ${RESCUE_MINUTES} minuti" \
    "  (verrà rimosso alla fine dello script se tutto va bene)"

if confirm_phase; then
    mkdir -p "$BACKUP_DIR"
    ok "Directory backup: $BACKUP_DIR"

    # iptables
    if command -v iptables-save &>/dev/null; then
        iptables-save > "$BACKUP_DIR/iptables-rules.v4" 2>/dev/null || true
        ok "Salvate regole iptables (IPv4)"
    fi
    if command -v ip6tables-save &>/dev/null; then
        ip6tables-save > "$BACKUP_DIR/iptables-rules.v6" 2>/dev/null || true
        ok "Salvate regole iptables (IPv6)"
    fi

    # nftables
    if command -v nft &>/dev/null; then
        nft list ruleset > "$BACKUP_DIR/nftables-ruleset.conf" 2>/dev/null || true
        ok "Salvato ruleset nftables"
    fi

    # firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --list-all-zones > "$BACKUP_DIR/firewalld-zones.txt" 2>/dev/null || true
        firewall-cmd --list-ports > "$BACKUP_DIR/firewalld-ports.txt" 2>/dev/null || true
        firewall-cmd --list-services > "$BACKUP_DIR/firewalld-services.txt" 2>/dev/null || true
        ok "Salvato stato firewalld"
    else
        echo "# firewalld non attivo — niente da salvare" > "$BACKUP_DIR/firewalld-zones.txt"
        ok "firewalld non attivo — annotato"
    fi

    # CSF (if already installed)
    if [[ -d /etc/csf ]]; then
        mkdir -p "$BACKUP_DIR/csf"
        for f in csf.conf csf.allow csf.deny csf.ignore csf.pignore csf.rignore csf.fignore; do
            [[ -f "/etc/csf/$f" ]] && cp "/etc/csf/$f" "$BACKUP_DIR/csf/"
        done
        ok "Salvata configurazione CSF esistente"
    else
        ok "CSF non presente — niente da salvare"
    fi

    # sshd
    if [[ -f /etc/ssh/sshd_config ]]; then
        cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config"
        ok "Salvato sshd_config"
    fi

    # Network state
    ss -tlnp > "$BACKUP_DIR/listening-tcp.txt" 2>/dev/null || true
    ss -ulnp > "$BACKUP_DIR/listening-udp.txt" 2>/dev/null || true
    ss -tnp  > "$BACKUP_DIR/established-connections.txt" 2>/dev/null || true
    ok "Salvato stato rete (porte in ascolto + connessioni)"

    # Crontab
    crontab -l > "$BACKUP_DIR/crontab-root.txt" 2>/dev/null || echo "# nessun crontab" > "$BACKUP_DIR/crontab-root.txt"
    ok "Salvato crontab root"

    # Generate rollback script
    cat > "$BACKUP_DIR/rollback.sh" <<'ROLLBACK_EOF'
#!/usr/bin/env bash
# =============================================================================
# rollback.sh — Annulla le modifiche di harden-01-csf-firewall.sh
# Generato automaticamente. Eseguire come root.
# =============================================================================
set -euo pipefail

BACKUP_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Rollback F-01: ripristino stato pre-hardening ==="
echo "Backup dir: $BACKUP_DIR"
echo ""

# 1. Disabilita CSF
if command -v csf &>/dev/null; then
    echo "Disabilito CSF..."
    csf -x
    echo "  ✓ CSF disabilitato"
fi

# 2. Ripristina CSF config se c'era
if [[ -d "$BACKUP_DIR/csf" && -f "$BACKUP_DIR/csf/csf.conf" ]]; then
    echo "Ripristino configurazione CSF precedente..."
    for f in "$BACKUP_DIR/csf/"*; do
        cp "$f" "/etc/csf/$(basename "$f")"
    done
    echo "  ✓ Config CSF ripristinata"
    echo "Riavvio CSF con la config precedente..."
    csf -r
    echo "  ✓ CSF riavviato"
fi

# 3. Ripristina iptables
if [[ -f "$BACKUP_DIR/iptables-rules.v4" ]]; then
    echo "Ripristino regole iptables IPv4..."
    iptables-restore < "$BACKUP_DIR/iptables-rules.v4"
    echo "  ✓ Regole iptables ripristinate"
fi

# 4. Riabilita firewalld se era attivo
if [[ -f "$BACKUP_DIR/firewalld-zones.txt" ]] && ! grep -q "non attivo" "$BACKUP_DIR/firewalld-zones.txt"; then
    echo "Riabilito firewalld..."
    systemctl enable --now firewalld
    echo "  ✓ firewalld riabilitato"
fi

# 5. Ripristina crontab
if [[ -f "$BACKUP_DIR/crontab-root.txt" ]]; then
    echo "Ripristino crontab root..."
    crontab "$BACKUP_DIR/crontab-root.txt"
    echo "  ✓ Crontab ripristinato"
fi

echo ""
echo "=== Rollback completato ==="
echo "Verifica: ss -tlnp | head -20"
echo "Verifica: iptables -L -n | head -20"
ROLLBACK_EOF

    chmod +x "$BACKUP_DIR/rollback.sh"
    ok "Script rollback generato: $BACKUP_DIR/rollback.sh"

    # File listing
    echo ""
    info "Contenuto backup:"
    ls -la "$BACKUP_DIR/" | while IFS= read -r line; do
        echo -e "    ${DIM}${line}${NC}"
    done

    # Rescue cron
    echo ""
    info "Installo rescue cron: tra ${RESCUE_MINUTES} minuti CSF verrà disabilitato automaticamente"
    info "Se tutto va bene, verrà rimosso alla fine dello script"
    if install_rescue_cron; then
        ok "Rescue cron installato (csf -x tra ${RESCUE_MINUTES} min)"
        info "Per controllare: crontab -l | grep ${RESCUE_CRON_TAG}"
    else
        warn "Non riesco a calcolare la data per il rescue cron — procedo senza"
        warn "In caso di lockout affidati a TESTING mode (auto-disable 5 min)"
    fi

    log "Backup completo. Rollback: bash $BACKUP_DIR/rollback.sh"
    undo_hint \
        "rm -rf $BACKUP_DIR" \
        "crontab -l | grep -v '${RESCUE_CRON_TAG}' | crontab -"
    report_phase "0|Backup + rescue cron|FATTO|${BACKUP_DIR}|rm -rf ${BACKUP_DIR}"
fi

# =============================================================================
# Phase 1: Disable firewalld
# =============================================================================

phase_header 1 "Disabilita firewalld"

FIREWALLD_ACTIVE=$(systemctl is-active firewalld 2>/dev/null || true)
FIREWALLD_ENABLED=$(systemctl is-enabled firewalld 2>/dev/null || true)

if [[ "$FIREWALLD_ACTIVE" == "active" || "$FIREWALLD_ENABLED" == "enabled" ]]; then
    will_do \
        "systemctl stop firewalld    — ferma il servizio" \
        "systemctl disable firewalld — impedisce il riavvio automatico" \
        "Motivo: firewalld e CSF non possono coesistere (entrambi gestiscono iptables/nftables)" \
        "Rollback: bash $BACKUP_DIR/rollback.sh riabilita firewalld se era attivo"

    if confirm_phase; then
        systemctl stop firewalld 2>/dev/null || true
        systemctl disable firewalld 2>/dev/null || true
        ok "firewalld fermato e disabilitato"
        undo_hint "systemctl enable --now firewalld"
        report_phase "1|Disabilita firewalld|FATTO|systemctl stop+disable|systemctl enable --now firewalld"
    fi
else
    info "firewalld già inattivo/disabilitato — niente da fare"
fi

# =============================================================================
# Phase 2: Install CSF
# =============================================================================

phase_header 2 "Installa CSF+LFD"

if [[ -x /usr/sbin/csf ]]; then
    info "CSF è già installato: $(csf -v 2>&1 | head -1)"
    info "Salto l'installazione."
else
    will_do \
        "Scarica CSF da GitHub (aetherinox/csf-firewall) → /usr/src/csf.tgz" \
        "tar -xzf + bash install.sh — installa CSF e LFD" \
        "perl /etc/csf/csftest.pl — verifica i moduli iptables necessari" \
        "Cleanup: rimuove csf.tgz dopo l'installazione" \
        "Rollback: CSF include /etc/csf/uninstall.sh per rimozione pulita"

    if confirm_phase; then
        cd /usr/src

        # Primary: GitHub fork (configserver.com is offline since ~2025)
        CSF_URL="https://github.com/aetherinox/csf-firewall/archive/refs/heads/main.tar.gz"
        # Fallback: original configserver.com (if it comes back online)
        CSF_URL_FALLBACK="https://download.configserver.com/csf.tgz"

        if curl -sSfL -o csf.tgz "$CSF_URL" 2>/dev/null; then
            ok "CSF scaricato da GitHub"
        elif curl -sSfL -o csf.tgz "$CSF_URL_FALLBACK" 2>/dev/null; then
            ok "CSF scaricato da configserver.com (fallback)"
        else
            die "Download CSF fallito da entrambe le sorgenti"
        fi

        tar -xzf csf.tgz
        # GitHub archive extracts to csf-firewall-main/, rename to csf/
        if [[ -d csf-firewall-main ]]; then
            mv csf-firewall-main csf
        fi
        cd csf
        bash install.sh >> "$LOG_FILE" 2>&1
        ok "CSF installato: $(csf -v 2>&1 | head -1)"

        rm -f /usr/src/csf.tgz

        if perl /etc/csf/csftest.pl >> "$LOG_FILE" 2>&1; then
            ok "Test moduli CSF superato"
        else
            warn "Problemi nei moduli CSF — controlla $LOG_FILE"
        fi
        undo_hint \
            "csf -x   # disabilita CSF" \
            "bash /etc/csf/uninstall.sh   # rimuove CSF completamente"
        report_phase "2|Installa CSF+LFD|FATTO|$(csf -v 2>&1 | head -1)|bash /etc/csf/uninstall.sh"
    fi
fi

# =============================================================================
# Phase 3: Configure CSF
# =============================================================================

phase_header 3 "Configura CSF (default-deny)"

will_do \
    "Backup di csf.conf con timestamp prima delle modifiche" \
    "TESTING=1, TESTING_INTERVAL=5 — auto-disable dopo 5 min se lockout" \
    "TCP_IN (pubbliche): ${TCP_IN_PUBLIC}" \
    "TCP_OUT: ${TCP_OUT}" \
    "UDP_IN: ${UDP_IN}  |  UDP_OUT: ${UDP_OUT}" \
    "SYN flood protection: 75/s rate, burst 25" \
    "Connection limits: SSH;3, WHM;5, cPanel;20, HTTP/S;100" \
    "Port flood: SSH 3/300s, HTTP/S 50/5s" \
    "LFD brute-force: SSH=5, cPanel=5, SMTP=5, POP3/IMAP=10" \
    "Process tracking: 512MB mem limit, 7200s CPU limit" \
    "IPv6: disabilitato (nessun IPv6 pubblico sull'host)" \
    "ICMP: abilitato con rate-limit 5/s"

if confirm_phase; then
    [[ -f "$CSF_CONF" ]] || die "CSF config non trovato: $CSF_CONF"

    cp "$CSF_CONF" "${CSF_CONF}.pre-hardening.${TIMESTAMP}"
    ok "Backup csf.conf → csf.conf.pre-hardening.${TIMESTAMP}"

    # TESTING mode
    csf_set "TESTING" "1"
    csf_set "TESTING_INTERVAL" "5"

    # Syslog
    csf_set "RESTRICT_SYSLOG" "3"

    # Ports
    csf_set "TCP_IN" "$TCP_IN_PUBLIC"
    csf_set "TCP_OUT" "$TCP_OUT"
    csf_set "UDP_IN" "$UDP_IN"
    csf_set "UDP_OUT" "$UDP_OUT"

    # SSH
    csf_set "SSH_PORT" "$SSH_PORT"

    # Connection limits
    csf_set "CONNLIMIT" "22;3,2087;5,2083;20,80;100,443;100"
    csf_set "PORTFLOOD" "22;tcp;3;300,80;tcp;50;5,443;tcp;50;5"

    # SYN flood
    csf_set "SYNFLOOD" "1"
    csf_set "SYNFLOOD_RATE" "75/s"
    csf_set "SYNFLOOD_BURST" "25"

    # ICMP
    csf_set "ICMP_IN" "1"
    csf_set "ICMP_IN_RATE" "5/s"

    # Syslog monitoring
    csf_set "SYSLOG_CHECK" "300"

    # LFD brute-force thresholds
    csf_set "LF_TRIGGER" "0"
    csf_set "LF_SSHD" "5"
    csf_set "LF_FTPD" "10"
    csf_set "LF_SMTPAUTH" "5"
    csf_set "LF_POP3D" "10"
    csf_set "LF_IMAPD" "10"
    csf_set "LF_HTACCESS" "5"
    csf_set "LF_CPANEL" "5"
    csf_set "LF_MODSEC" "5"
    csf_set "LF_CXS" "0"

    # Belt-and-suspenders: drop 111 without logging
    csf_set "DROP_NOLOG" "111"

    # Process tracking
    csf_set "PT_LIMIT" "300"
    csf_set "PT_USERMEM" "512"
    csf_set "PT_USERTIME" "7200"

    # IPv6
    csf_set "IPV6" "0"

    ok "Configurazione CSF scritta"
    undo_hint "cp ${CSF_CONF}.pre-hardening.${TIMESTAMP} ${CSF_CONF} && csf -r"
    report_phase "3|Configura CSF default-deny|FATTO|TCP_IN=${TCP_IN_PUBLIC}|cp csf.conf.pre-hardening.${TIMESTAMP} csf.conf && csf -r"
fi

# =============================================================================
# Phase 4: Whitelist admin IPs
# =============================================================================

phase_header 4 "Whitelist IP admin"

CSF_ALLOW="/etc/csf/csf.allow"

IFS=',' read -ra IPS <<< "$ADMIN_IPS"
echo -e "${DIM}  Cosa farà:${NC}"
for ip in "${IPS[@]}"; do
    ip=$(echo "$ip" | xargs)
    [[ -z "$ip" ]] && continue
    if [[ -f "$CSF_ALLOW" ]] && grep -q "^${ip}\b" "$CSF_ALLOW" 2>/dev/null; then
        echo -e "    → $ip — già presente in csf.allow"
    else
        echo -e "    → ${BOLD}$ip${NC} — verrà aggiunto a csf.allow"
    fi
done
info "Gli IP in csf.allow bypassano TUTTE le regole del firewall (anche TCP_IN)"
info "Questo garantisce accesso a SSH (22), WHM (2086/2087) e tutte le altre porte"

if confirm_phase; then
    for ip in "${IPS[@]}"; do
        ip=$(echo "$ip" | xargs)
        [[ -z "$ip" ]] && continue
        if grep -q "^${ip}\b" "$CSF_ALLOW" 2>/dev/null; then
            ok "$ip già in csf.allow"
        else
            echo "$ip # Admin IP — hardening $(date +%Y-%m-%d)" >> "$CSF_ALLOW"
            ok "$ip aggiunto a csf.allow"
        fi
    done
    undo_hint \
        "sed -i '/Admin IP.*hardening/d' /etc/csf/csf.allow && csf -r" \
        "# oppure per singolo IP: csf -dr <IP>"
    report_phase "4|Whitelist IP admin|FATTO|IPs: ${ADMIN_IPS}|sed -i '/Admin IP.*hardening/d' csf.allow && csf -r"
fi

# =============================================================================
# Phase 5: Info — SSH/WHM restano pubblici
# =============================================================================

phase_header 5 "SSH e WHM restano pubblici (nessuna restrizione IP)"

info "L'admin non ha un IP fisso — non è possibile restringere per IP."
info "SSH (22), WHM (2086/2087) restano aperti al pubblico nel TCP_IN."
echo ""
info "La protezione è affidata a:"
info "  → SSH: autenticazione solo a chiave (F-05 — script separato)"
info "  → WHM: 2FA obbligatoria (F-08 — script separato)"
info "  → LFD/cPHulk: brute-force protection (configurata nella fase 3)"
info "  → csf.allow: il tuo IP corrente bypassa i rate-limit"
echo ""
info "Nessuna modifica in questa fase."
report_phase "5|SSH/WHM pubblici (info)|NESSUNA MODIFICA|Protezione via chiave+2FA|n/a"

# =============================================================================
# Phase 6: Document blocked ports in csf.deny
# =============================================================================

phase_header 6 "Documentazione porte bloccate in csf.deny"

CSF_DENY="/etc/csf/csf.deny"

will_do \
    "Aggiunge commenti a csf.deny per documentare le porte pericolose bloccate:" \
    "  111  rpcbind — vettore amplificazione DDoS (F-07)" \
    "  3306 MariaDB — database esposto a Internet (F-02)" \
    "  4190 ManageSieve — nessuna necessità pubblica" \
    "Nota: con default-deny queste porte sono già bloccate (non in TCP_IN)." \
    "Questo è defense-in-depth + documentazione per chi legge csf.deny."

if confirm_phase; then
    if [[ -f "$CSF_DENY" ]] && grep -q "rpcbind (F-07" "$CSF_DENY" 2>/dev/null; then
        ok "Documentazione già presente in csf.deny"
    else
        cat >> "$CSF_DENY" <<EOF

# --- Hardening $(date +%Y-%m-%d): porte pericolose bloccate ---
# Già bloccate da default-deny (non in TCP_IN); documentate qui per chiarezza.
# tcp:in:d=111  - rpcbind (F-07: vettore amplificazione DDoS)
# tcp:in:d=3306 - MariaDB (F-02: database esposto a Internet)
# tcp:in:d=4190 - ManageSieve (nessuna necessità pubblica)
EOF
        ok "Documentazione aggiunta a csf.deny"
        undo_hint "sed -i '/Hardening.*porte pericolose/,\$d' /etc/csf/csf.deny"
        report_phase "6|Documenta porte bloccate|FATTO|111,3306,4190 in csf.deny|sed -i '/Hardening.*porte pericolose/,\$d' csf.deny"
    fi
fi

# =============================================================================
# Phase 7: Start CSF in TESTING mode
# =============================================================================

phase_header 7 "Avvio CSF in TESTING mode"

will_do \
    "csf -r — riavvia/avvia CSF con la nuova configurazione" \
    "" \
    "Protezione anti-lockout a 3 livelli:" \
    "  1) TESTING mode: CSF si auto-disabilita dopo 5 min se lockout" \
    "  2) Rescue cron: csf -x automatico tra ${RESCUE_MINUTES} min (già installato)" \
    "  3) Rollback: bash $BACKUP_DIR/rollback.sh ripristina tutto" \
    "" \
    "Dopo la validazione, la fase 8 rimuoverà il rescue cron."

if confirm_phase; then
    csf -r >> "$LOG_FILE" 2>&1
    ok "CSF avviato in TESTING mode"

    if csf -l >> "$LOG_FILE" 2>&1; then
        RULE_COUNT=$(csf -l 2>/dev/null | grep -c "^Chain" || true)
        ok "Regole CSF attive (chains: $RULE_COUNT)"
    else
        warn "CSF potrebbe non funzionare — controlla: csf -l"
    fi
    undo_hint \
        "csf -x   # disabilita CSF immediatamente" \
        "# oppure aspetta 5 min (TESTING auto-disable)" \
        "# oppure: bash $BACKUP_DIR/rollback.sh   # rollback completo"
    report_phase "7|Avvio CSF TESTING mode|FATTO|Auto-disable 5 min|csf -x"
fi

# =============================================================================
# Phase 8: Validate connectivity + remove rescue cron
# =============================================================================

phase_header 8 "Validazione connettività"

will_do \
    "Verifica che i servizi critici siano ancora in ascolto sulle porte attese" \
    "Se tutto OK: rimuove il rescue cron (non serve più)" \
    "Se problemi: il rescue cron resta attivo e disabiliterà CSF tra pochi minuti"

declare -A SERVICES=(
    [80]="HTTP"
    [443]="HTTPS"
    [25]="SMTP"
    [993]="IMAPS"
    [2083]="cPanel SSL"
    [2087]="WHM SSL"
    [2096]="Webmail SSL"
)

# Always show the check (even in dry-run, since it's read-only)
PASS=0
FAIL=0
for port in "${!SERVICES[@]}"; do
    svc="${SERVICES[$port]}"
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        ok "$svc (porta $port) in ascolto"
        ((PASS++)) || true
    else
        warn "$svc (porta $port) NON in ascolto"
        ((FAIL++)) || true
    fi
done

log "Servizi verificati: $PASS OK, $FAIL warning"

if [[ $DRY_RUN -eq 0 && $FAIL -eq 0 ]]; then
    echo ""
    info "Tutti i servizi sono in ascolto. Il rescue cron verrà rimosso."
    info "Puoi comunque annullare tutto con: bash $BACKUP_DIR/rollback.sh"
    # rescue cron removed by EXIT trap
elif [[ $DRY_RUN -eq 0 && $FAIL -gt 0 ]]; then
    warn "Ci sono servizi non in ascolto. Il rescue cron resta attivo."
    warn "CSF verrà disabilitato automaticamente tra pochi minuti se non intervieni."
    warn "Per disabilitare subito: csf -x"
    warn "Per rollback completo:  bash $BACKUP_DIR/rollback.sh"
    # Don't remove rescue cron on exit if there are failures
    trap - EXIT
fi

# =============================================================================
# Summary
# =============================================================================

banner "Riepilogo F-01"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN completato — nessuna modifica applicata.${NC}"
    echo ""
    echo -e "  Per applicare:  ${BOLD}bash $0${NC}"
else
    echo -e "  ${GREEN}CSF installato e avviato in TESTING mode.${NC}"
    echo ""
    echo -e "  ${BOLD}Stato:${NC}"
    echo "    TESTING mode attivo (auto-disable dopo 5 min se lockout)"
    echo "    Admin IPs in csf.allow: $ADMIN_IPS"
    echo "    Porte pubbliche: $TCP_IN_PUBLIC"
    echo "    SSH/WHM: pubblici (protezione via chiave + 2FA, non IP)"
    echo "    Bloccate da WAN: 111, 3306, 4190"
    echo ""
    echo -e "  ${BOLD}Backup:${NC}"
    echo "    $BACKUP_DIR/"
    echo "    Rollback completo: bash $BACKUP_DIR/rollback.sh"
    echo ""
    echo -e "  ${BOLD}Anti-lockout:${NC}"
    echo "    Livello 1: TESTING mode (auto-disable 5 min)"
    echo "    Livello 2: Rescue cron (csf -x tra ${RESCUE_MINUTES} min) — rimosso se tutto OK"
    echo "    Livello 3: Rollback script nel backup"
    echo "    Emergenza: csf -x (da console/IPMI)"
    echo ""
    echo -e "  ${BOLD}Prossimi passi:${NC}"
    echo "    1. Da un altro terminale, verifica di poter ancora fare SSH"
    echo "    2. Verifica cPanel (2083) e Webmail (2096) per i clienti"
    echo "    3. Verifica WHM (2087)"
    echo "    4. Se tutto OK, disabilita TESTING:"
    echo "         sed -i 's/^TESTING .*/TESTING = \"0\"/' /etc/csf/csf.conf && csf -r"
    echo "    5. Eseguire F-05 (SSH solo chiave) e F-08 (2FA WHM) per blindare gli accessi"
fi

# =============================================================================
# Report finale + tarball
# =============================================================================

if [[ -d "$BACKUP_DIR" ]]; then
    phase_header 9 "Report finale + raccolta log"

    # Copy main log into backup dir
    cp "$LOG_FILE" "$BACKUP_DIR/" 2>/dev/null || true

    # Capture post-hardening state
    mkdir -p "$BACKUP_DIR/post-state"
    ss -tlnp > "$BACKUP_DIR/post-state/listening-tcp.txt" 2>/dev/null || true
    ss -ulnp > "$BACKUP_DIR/post-state/listening-udp.txt" 2>/dev/null || true
    [[ -x /usr/sbin/csf ]] && csf -l > "$BACKUP_DIR/post-state/csf-rules.txt" 2>/dev/null || true
    [[ -f "$CSF_CONF" ]] && cp "$CSF_CONF" "$BACKUP_DIR/post-state/csf.conf" 2>/dev/null || true
    [[ -f /etc/csf/csf.allow ]] && cp /etc/csf/csf.allow "$BACKUP_DIR/post-state/" 2>/dev/null || true
    [[ -f /etc/csf/csf.deny ]] && cp /etc/csf/csf.deny "$BACKUP_DIR/post-state/" 2>/dev/null || true
    systemctl is-active firewalld > "$BACKUP_DIR/post-state/firewalld-status.txt" 2>/dev/null || true

    # Generate report
    cat > "$REPORT_FILE" <<REPORT_EOF
# Report Hardening F-01 — CSF Firewall

**Script:** harden-01-csf-firewall.sh
**Data:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Server:** $(hostname 2>/dev/null || echo "sconosciuto")
**IP:** $(hostname -I 2>/dev/null | awk '{print $1}' || echo "sconosciuto")
**Operatore SSH da:** ${MY_IP:-sconosciuto}
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

## Configurazione applicata

- **TCP_IN:** ${TCP_IN_PUBLIC}
- **TCP_OUT:** ${TCP_OUT}
- **UDP_IN:** ${UDP_IN}
- **UDP_OUT:** ${UDP_OUT}
- **SSH/WHM:** Pubblici (no restrizione IP — protezione via chiave + 2FA)
- **LFD:** SSH=5, cPanel=5, SMTP=5, POP3/IMAP=10
- **SYN flood:** 75/s rate, burst 25
- **TESTING mode:** Attivo (auto-disable 5 min)

## File modificati

- /etc/csf/csf.conf (backup: csf.conf.pre-hardening.${TIMESTAMP})
- /etc/csf/csf.allow (aggiunti IP admin)
- /etc/csf/csf.deny (documentazione porte bloccate)

## Rollback

\`\`\`bash
# Rollback completo:
bash ${BACKUP_DIR}/rollback.sh

# Disabilita CSF al volo:
csf -x

# Ripristina solo la config:
cp ${CSF_CONF}.pre-hardening.${TIMESTAMP} ${CSF_CONF} && csf -r
\`\`\`

## Contenuto backup

$(ls -la "$BACKUP_DIR/" 2>/dev/null)

## Prossimi passi

1. Verificare SSH, cPanel, WHM, Webmail
2. Disabilitare TESTING mode se tutto OK
3. Eseguire F-05 (SSH solo chiave) e F-08 (2FA WHM)
REPORT_EOF

    ok "Report generato: $REPORT_FILE"

    # Create tarball
    TARBALL="/root/harden-01-report_${TIMESTAMP}.tar.gz"
    tar -czf "$TARBALL" -C /root "$(basename "$BACKUP_DIR")" 2>/dev/null || true
    ok "Tarball: $TARBALL"
    info "Contiene: backup pre-hardening, stato post-hardening, report, log, rollback.sh"
fi

echo ""
log "Log: $LOG_FILE"
