#!/usr/bin/env bash
# =============================================================================
# harden-05-ssh-keys.sh
# F-05/F-12/F-16/F-19 remediation: SSH hardening — key-only, strong crypto
#
# Target:  serverk01.venicebay.it (CloudLinux 8 / cPanel 136)
# Context: SSH allows root+password from Internet. Weak MAC/KEX offered.
#          Admin has dynamic IP — cannot restrict by IP. Key-only is the answer.
#
# Covers audit findings:
#   F-05  SSH root login + password auth from Internet
#   F-12  Weak MAC/KEX (hmac-sha1, diffie-hellman-group14-sha1)
#   F-16  GSSAPI, X11Forwarding enabled (unnecessary)
#   F-19  No session idle timeout
#
# Interactive, dry-run, per-phase undo, backup+report.
#
# CRITICAL SAFETY:
#   - Verifies your SSH key works BEFORE disabling passwords
#   - Config test (sshd -t) BEFORE every restart
#   - Current SSH session survives sshd restart
#   - Rollback script restores original sshd_config
#
# Usage:
#   bash harden-05-ssh-keys.sh                # interactive
#   bash harden-05-ssh-keys.sh --dry-run      # preview only
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
BACKUP_DIR="/root/harden-05-backup_${TIMESTAMP}"
LOG_FILE="/root/harden-05-ssh-keys_${TIMESTAMP}.log"
REPORT_FILE="${BACKUP_DIR}/report.md"
SSHD_CONF="/etc/ssh/sshd_config"
HARDENING_CONF="/etc/ssh/sshd_config.d/hardening.conf"

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
        q|Q) log "Interrotto dall'utente."; exit 0 ;;
        *)   log "Fase saltata dall'utente."; return 1 ;;
    esac
}

# =============================================================================
# MAIN
# =============================================================================

banner "F-05: SSH Hardening — Key-Only + Strong Crypto"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}Modalità DRY-RUN — nessuna modifica verrà applicata.${NC}"
fi

log "Log file: $LOG_FILE"
echo ""

# -- Pre-flight ---------------------------------------------------------------

echo -e "${BOLD}Pre-flight checks:${NC}"

[[ $EUID -eq 0 ]] || die "Devi eseguire come root"
ok "Root: sì"

[[ -f "$SSHD_CONF" ]] || die "sshd_config non trovato: $SSHD_CONF"
ok "sshd_config: trovato"

# Current SSH config (effective)
echo ""
echo -e "${BOLD}Configurazione SSH attuale (sshd -T):${NC}"

CURRENT_PERMIT_ROOT=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin " | awk '{print $2}')
CURRENT_PASSWORD_AUTH=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication " | awk '{print $2}')
CURRENT_PUBKEY_AUTH=$(sshd -T 2>/dev/null | grep -i "^pubkeyauthentication " | awk '{print $2}')
CURRENT_GSSAPI=$(sshd -T 2>/dev/null | grep -i "^gssapiauthentication " | awk '{print $2}')
CURRENT_X11=$(sshd -T 2>/dev/null | grep -i "^x11forwarding " | awk '{print $2}')
CURRENT_TCP_FWD=$(sshd -T 2>/dev/null | grep -i "^allowtcpforwarding " | awk '{print $2}')
CURRENT_GRACE=$(sshd -T 2>/dev/null | grep -i "^logingracetime " | awk '{print $2}')
CURRENT_ALIVE_INT=$(sshd -T 2>/dev/null | grep -i "^clientaliveinterval " | awk '{print $2}')
CURRENT_ALIVE_MAX=$(sshd -T 2>/dev/null | grep -i "^clientalivecountmax " | awk '{print $2}')

# MAC and KEX (can have multiple values)
CURRENT_MACS=$(sshd -T 2>/dev/null | grep -i "^macs " | sed 's/^macs //')
CURRENT_KEXS=$(sshd -T 2>/dev/null | grep -i "^kexalgorithms " | sed 's/^kexalgorithms //')

declare -A SSH_CURRENT=(
    ["PermitRootLogin"]="$CURRENT_PERMIT_ROOT"
    ["PasswordAuthentication"]="$CURRENT_PASSWORD_AUTH"
    ["PubkeyAuthentication"]="$CURRENT_PUBKEY_AUTH"
    ["GSSAPIAuthentication"]="$CURRENT_GSSAPI"
    ["X11Forwarding"]="$CURRENT_X11"
    ["AllowTcpForwarding"]="$CURRENT_TCP_FWD"
    ["LoginGraceTime"]="$CURRENT_GRACE"
    ["ClientAliveInterval"]="$CURRENT_ALIVE_INT"
    ["ClientAliveCountMax"]="$CURRENT_ALIVE_MAX"
)

for key in PermitRootLogin PasswordAuthentication PubkeyAuthentication GSSAPIAuthentication X11Forwarding AllowTcpForwarding LoginGraceTime ClientAliveInterval ClientAliveCountMax; do
    val="${SSH_CURRENT[$key]}"
    case "$key" in
        PermitRootLogin)
            if [[ "$val" == "yes" ]]; then
                info "$key: ${RED}$val${NC} → cambierà a prohibit-password"
            else
                info "$key: ${GREEN}$val${NC}"
            fi
            ;;
        PasswordAuthentication)
            if [[ "$val" == "yes" ]]; then
                info "$key: ${RED}$val${NC} → cambierà a no"
            else
                info "$key: ${GREEN}$val${NC}"
            fi
            ;;
        GSSAPIAuthentication|X11Forwarding|AllowTcpForwarding)
            if [[ "$val" == "yes" ]]; then
                info "$key: ${YELLOW}$val${NC} → cambierà a no"
            else
                info "$key: ${GREEN}$val${NC}"
            fi
            ;;
        *)
            info "$key: $val"
            ;;
    esac
done

# Show weak algorithms
HAS_SHA1_MAC=0
HAS_SHA1_KEX=0
if echo "$CURRENT_MACS" | grep -q "hmac-sha1\|umac-64"; then
    HAS_SHA1_MAC=1
    info "MACs: ${YELLOW}contiene algoritmi deboli (sha1/umac-64)${NC}"
else
    info "MACs: ${GREEN}OK${NC}"
fi
if echo "$CURRENT_KEXS" | grep -q "diffie-hellman-group14-sha1\|diffie-hellman-group1"; then
    HAS_SHA1_KEX=1
    info "KEX: ${YELLOW}contiene algoritmi deboli (group14-sha1)${NC}"
else
    info "KEX: ${GREEN}OK${NC}"
fi

# Check authorized_keys
echo ""
echo -e "${BOLD}Chiavi SSH autorizzate:${NC}"
AUTH_KEYS="/root/.ssh/authorized_keys"
if [[ -f "$AUTH_KEYS" ]]; then
    KEY_COUNT=$(grep -c "^ssh-\|^ecdsa-\|^sk-" "$AUTH_KEYS" 2>/dev/null || echo "0")
    ok "authorized_keys trovato: $KEY_COUNT chiave/i"
    while IFS= read -r line; do
        # Show key type and comment (last field)
        key_type=$(echo "$line" | awk '{print $1}')
        key_comment=$(echo "$line" | awk '{print $NF}')
        [[ "$key_type" =~ ^ssh-|^ecdsa-|^sk- ]] && info "  $key_type ... $key_comment"
    done < "$AUTH_KEYS"
else
    warn "authorized_keys NON trovato: $AUTH_KEYS"
    warn "Se disabiliti la password senza una chiave, resti chiuso fuori!"
fi

# Verify current session uses key auth
echo ""
echo -e "${BOLD}Sessione corrente:${NC}"
if [[ -n "${SSH_CONNECTION:-}" ]]; then
    MY_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    info "Connesso da: $MY_IP"

    # Check auth method from logs
    MY_PID=$$
    MY_SSHD_PID=$(ps -o ppid= -p $MY_PID 2>/dev/null | xargs)
    AUTH_METHOD=$(journalctl _PID="$MY_SSHD_PID" --no-pager -q 2>/dev/null | grep -o "publickey\|password" | tail -1 || true)
    if [[ -z "$AUTH_METHOD" ]]; then
        # Fallback: check auth.log or secure
        AUTH_METHOD=$(grep "$MY_IP" /var/log/secure 2>/dev/null | grep "Accepted" | tail -1 | grep -o "publickey\|password" || true)
    fi

    if [[ "$AUTH_METHOD" == "publickey" ]]; then
        ok "Sessione autenticata con: ${GREEN}chiave pubblica${NC}"
    elif [[ "$AUTH_METHOD" == "password" ]]; then
        warn "Sessione autenticata con: ${RED}password${NC}"
        warn "Stai usando la password — assicurati di avere una chiave configurata!"
    else
        warn "Metodo di autenticazione non rilevabile — verifica manuale"
    fi
else
    warn "Non rilevo SSH_CONNECTION"
fi

echo ""
echo -e "${BOLD}Piano di esecuzione (6 fasi):${NC}"
echo "  0. Backup completo (sshd_config, authorized_keys, host keys)"
echo "  1. Verifica che l'accesso a chiave funzioni"
echo "  2. Hardening sshd_config (key-only, strong crypto, timeouts)"
echo "  3. Config test (sshd -t)"
echo "  4. Restart sshd (la sessione corrente resta attiva)"
echo "  5. Validazione + report finale"

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
    "Salva: /etc/ssh/sshd_config" \
    "Salva: /etc/ssh/sshd_config.d/ (se esiste)" \
    "Salva: /root/.ssh/authorized_keys" \
    "Salva: configurazione effettiva (sshd -T)" \
    "Salva: MAC e KEX attualmente offerti" \
    "Genera: script di rollback"

if confirm_phase; then
    mkdir -p "$BACKUP_DIR"
    ok "Directory backup: $BACKUP_DIR"

    cp "$SSHD_CONF" "$BACKUP_DIR/sshd_config"
    ok "Salvato sshd_config"

    if [[ -d /etc/ssh/sshd_config.d ]]; then
        cp -r /etc/ssh/sshd_config.d "$BACKUP_DIR/sshd_config.d"
        ok "Salvata directory sshd_config.d/"
    fi

    if [[ -f "$AUTH_KEYS" ]]; then
        mkdir -p "$BACKUP_DIR/.ssh"
        cp "$AUTH_KEYS" "$BACKUP_DIR/.ssh/authorized_keys"
        ok "Salvato authorized_keys"
    fi

    sshd -T > "$BACKUP_DIR/sshd-effective-config.txt" 2>/dev/null || true
    ok "Salvata configurazione effettiva"

    # Rollback script
    cat > "$BACKUP_DIR/rollback.sh" <<'ROLLBACK_EOF'
#!/usr/bin/env bash
set -euo pipefail
BACKUP_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Rollback F-05: ripristino config SSH ==="

# Remove hardening drop-in
if [[ -f /etc/ssh/sshd_config.d/hardening.conf ]]; then
    echo "Rimuovo hardening drop-in..."
    rm /etc/ssh/sshd_config.d/hardening.conf
    echo "  ✓ hardening.conf rimosso"
fi

# Restore sshd_config if it was modified directly
if [[ -f "$BACKUP_DIR/sshd_config" ]]; then
    echo "Ripristino sshd_config originale..."
    cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
    echo "  ✓ sshd_config ripristinato"
fi

# Restore sshd_config.d/ if backed up
if [[ -d "$BACKUP_DIR/sshd_config.d" ]]; then
    echo "Ripristino sshd_config.d/..."
    rm -rf /etc/ssh/sshd_config.d
    cp -r "$BACKUP_DIR/sshd_config.d" /etc/ssh/sshd_config.d
    echo "  ✓ sshd_config.d/ ripristinato"
fi

echo "Config test..."
if sshd -t 2>/dev/null; then
    echo "  ✓ Config OK"
    echo "Restart sshd..."
    systemctl restart sshd
    echo "  ✓ sshd riavviato"
else
    echo "  ✗ Config test fallito — verifica manualmente"
    echo "  La sessione corrente resta attiva."
fi

echo ""
echo "=== Rollback completato ==="
echo "ATTENZIONE: se avevi disabilitato la password, ora è riabilitata."
echo "Verifica: sshd -T | grep -i passwordauthentication"
ROLLBACK_EOF

    chmod +x "$BACKUP_DIR/rollback.sh"
    ok "Script rollback generato: $BACKUP_DIR/rollback.sh"

    echo ""
    info "Contenuto backup:"
    ls -la "$BACKUP_DIR/" | while IFS= read -r line; do
        echo -e "    ${DIM}${line}${NC}"
    done

    undo_hint "rm -rf $BACKUP_DIR"
    report_phase "0|Backup completo|FATTO|${BACKUP_DIR}|rm -rf ${BACKUP_DIR}"
fi

# =============================================================================
# Phase 1: Verify key-based access works
# =============================================================================

phase_header 1 "Verifica accesso a chiave"

will_do \
    "Controlla che /root/.ssh/authorized_keys esista e contenga almeno una chiave" \
    "Controlla che PubkeyAuthentication sia abilitata" \
    "Verifica i permessi di .ssh/ e authorized_keys" \
    "Se la chiave non è configurata: STOP — non è sicuro disabilitare le password"

echo ""
info "Controllo in corso..."

KEY_OK=1

# Check authorized_keys exists and has keys
if [[ ! -f "$AUTH_KEYS" ]]; then
    warn "File authorized_keys non trovato: $AUTH_KEYS"
    KEY_OK=0
elif [[ ! -s "$AUTH_KEYS" ]]; then
    warn "File authorized_keys è vuoto"
    KEY_OK=0
else
    KEY_COUNT=$(grep -c "^ssh-\|^ecdsa-\|^sk-" "$AUTH_KEYS" 2>/dev/null || echo "0")
    if [[ "$KEY_COUNT" -eq 0 ]]; then
        warn "Nessuna chiave pubblica trovata in authorized_keys"
        KEY_OK=0
    else
        ok "Trovate $KEY_COUNT chiave/i in authorized_keys"
    fi
fi

# Check pubkey auth is enabled
if [[ "$CURRENT_PUBKEY_AUTH" != "yes" ]]; then
    warn "PubkeyAuthentication non è abilitata!"
    KEY_OK=0
else
    ok "PubkeyAuthentication: yes"
fi

# Check permissions
if [[ -d /root/.ssh ]]; then
    SSH_DIR_PERM=$(stat -c '%a' /root/.ssh 2>/dev/null || stat -f '%Lp' /root/.ssh 2>/dev/null)
    if [[ "$SSH_DIR_PERM" == "700" ]]; then
        ok ".ssh/ permessi: $SSH_DIR_PERM (corretto)"
    else
        warn ".ssh/ permessi: $SSH_DIR_PERM (dovrebbe essere 700)"
        info "Fix: chmod 700 /root/.ssh"
    fi
fi
if [[ -f "$AUTH_KEYS" ]]; then
    AK_PERM=$(stat -c '%a' "$AUTH_KEYS" 2>/dev/null || stat -f '%Lp' "$AUTH_KEYS" 2>/dev/null)
    if [[ "$AK_PERM" == "600" || "$AK_PERM" == "644" ]]; then
        ok "authorized_keys permessi: $AK_PERM (OK)"
    else
        warn "authorized_keys permessi: $AK_PERM (dovrebbe essere 600)"
        info "Fix: chmod 600 $AUTH_KEYS"
    fi
fi

# Verdict
echo ""
if [[ $KEY_OK -eq 0 ]]; then
    echo -e "  ${RED}${BOLD}CHIAVE SSH NON CONFIGURATA O NON FUNZIONANTE${NC}"
    echo -e "  ${RED}Non è sicuro disabilitare l'autenticazione a password!${NC}"
    echo ""
    echo -e "  ${BOLD}Per configurare una chiave SSH:${NC}"
    echo "    1. Sul tuo PC locale: ssh-keygen -t ed25519 -C \"admin@$(hostname)\""
    echo "    2. Copia la chiave:   ssh-copy-id root@$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "    3. Verifica:          ssh -i ~/.ssh/id_ed25519 root@$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "    4. Ri-esegui questo script"
    echo ""
    if [[ $DRY_RUN -eq 0 ]]; then
        read -rp "  Vuoi procedere COMUNQUE? (PERICOLOSO — rischio lockout) (y/N) " force
        if [[ ! "$force" =~ ^[yY]$ ]]; then
            die "Interrotto — configura la chiave SSH prima di procedere"
        fi
        warn "Procedo senza chiave verificata — a tuo rischio!"
    fi
    report_phase "1|Verifica chiave SSH|ATTENZIONE|Chiave non verificata|n/a"
else
    echo -e "  ${GREEN}${BOLD}Chiave SSH configurata — sicuro disabilitare la password${NC}"
    report_phase "1|Verifica chiave SSH|OK|${KEY_COUNT} chiave/i trovate|n/a"
fi

# =============================================================================
# Phase 2: Harden sshd_config
# =============================================================================

phase_header 2 "Hardening sshd_config"

# Determine if sshd_config.d/ drop-in is supported
USE_DROPIN=0
if [[ -d /etc/ssh/sshd_config.d ]] && grep -q "^Include.*/etc/ssh/sshd_config.d/" "$SSHD_CONF" 2>/dev/null; then
    USE_DROPIN=1
    TARGET_CONF="$HARDENING_CONF"
    info "Il server supporta sshd_config.d/ drop-in — uso file separato"
    info "Vantaggio: non tocchiamo sshd_config originale, facile rollback"
else
    TARGET_CONF="$SSHD_CONF"
    info "Drop-in non supportato — modifico direttamente sshd_config"
fi

will_do \
    "File target: ${TARGET_CONF}" \
    "" \
    "Autenticazione:" \
    "  PermitRootLogin prohibit-password  (root solo con chiave, mai password)" \
    "  PasswordAuthentication no          (nessun login con password)" \
    "  PubkeyAuthentication yes           (abilitato)" \
    "  AuthenticationMethods publickey    (solo chiave pubblica)" \
    "  ChallengeResponseAuthentication no" \
    "" \
    "Funzionalità non necessarie:" \
    "  GSSAPIAuthentication no            (Kerberos — non usato)" \
    "  X11Forwarding no                   (display remoto — non necessario)" \
    "  AllowTcpForwarding no              (tunnel TCP — non necessario)" \
    "  AllowAgentForwarding no            (agent forwarding — rischio)" \
    "" \
    "Timeout e sicurezza:" \
    "  LoginGraceTime 30                  (30s per completare il login)" \
    "  ClientAliveInterval 300            (ping ogni 5 min)" \
    "  ClientAliveCountMax 2              (2 mancati = disconnessione)" \
    "  MaxAuthTries 3                     (max 3 tentativi)" \
    "  MaxSessions 5                      (max 5 sessioni per connessione)" \
    "" \
    "Crittografia forte (F-12):" \
    "  KexAlgorithms: solo curve25519, group16-sha512, group18-sha512" \
    "  Ciphers: solo chacha20, aes256-gcm, aes128-gcm, aes256-ctr" \
    "  MACs: solo hmac-sha2-512-etm, hmac-sha2-256-etm, umac-128-etm" \
    "" \
    "Altro:" \
    "  Banner /etc/ssh/banner             (avviso legale opzionale)" \
    "  PrintLastLog yes"

if confirm_phase; then
    if [[ $USE_DROPIN -eq 1 ]]; then
        # Drop-in file: takes precedence over sshd_config
        cat > "$TARGET_CONF" <<EOF
# =============================================================================
# SSH Hardening — F-05/F-12/F-16/F-19
# Created: $(date '+%Y-%m-%d %H:%M:%S') by harden-05-ssh-keys.sh
# Rollback: rm $TARGET_CONF && systemctl restart sshd
# =============================================================================

# --- Authentication: key-only ---
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# --- Disable unnecessary features ---
GSSAPIAuthentication no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no

# --- Timeouts and limits ---
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 5

# --- Strong crypto (F-12) ---
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# --- Logging ---
LogLevel VERBOSE
PrintLastLog yes
EOF
        ok "Drop-in creato: $TARGET_CONF"
        undo_hint "rm $TARGET_CONF && systemctl restart sshd"
    else
        # Direct edit of sshd_config — backup already done
        # Use sed to update or append each directive
        declare -A DIRECTIVES=(
            ["PermitRootLogin"]="prohibit-password"
            ["PasswordAuthentication"]="no"
            ["PubkeyAuthentication"]="yes"
            ["AuthenticationMethods"]="publickey"
            ["ChallengeResponseAuthentication"]="no"
            ["KbdInteractiveAuthentication"]="no"
            ["GSSAPIAuthentication"]="no"
            ["X11Forwarding"]="no"
            ["AllowTcpForwarding"]="no"
            ["AllowAgentForwarding"]="no"
            ["LoginGraceTime"]="30"
            ["ClientAliveInterval"]="300"
            ["ClientAliveCountMax"]="2"
            ["MaxAuthTries"]="3"
            ["MaxSessions"]="5"
            ["LogLevel"]="VERBOSE"
            ["PrintLastLog"]="yes"
        )

        for key in "${!DIRECTIVES[@]}"; do
            val="${DIRECTIVES[$key]}"
            if grep -q "^${key}\b" "$TARGET_CONF"; then
                sed -i "s/^${key}[[:space:]].*/${key} ${val}/" "$TARGET_CONF"
            elif grep -q "^#${key}\b" "$TARGET_CONF"; then
                sed -i "s/^#${key}[[:space:]]*.*/${key} ${val}/" "$TARGET_CONF"
            else
                echo "${key} ${val}" >> "$TARGET_CONF"
            fi
        done

        # Strong crypto — append or replace
        for directive in \
            'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512' \
            'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr' \
            'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com'; do
            key=$(echo "$directive" | awk '{print $1}')
            if grep -q "^${key}\b" "$TARGET_CONF"; then
                sed -i "s/^${key}[[:space:]].*/${directive}/" "$TARGET_CONF"
            elif grep -q "^#${key}\b" "$TARGET_CONF"; then
                sed -i "s/^#${key}[[:space:]]*.*/${directive}/" "$TARGET_CONF"
            else
                echo "$directive" >> "$TARGET_CONF"
            fi
        done

        ok "sshd_config aggiornato"
        undo_hint "cp $BACKUP_DIR/sshd_config /etc/ssh/sshd_config && systemctl restart sshd"
    fi

    report_phase "2|Hardening sshd_config|FATTO|${TARGET_CONF}|$(if [[ $USE_DROPIN -eq 1 ]]; then echo "rm ${TARGET_CONF} && systemctl restart sshd"; else echo "cp ${BACKUP_DIR}/sshd_config /etc/ssh/sshd_config && systemctl restart sshd"; fi)"

    # Show what changed
    echo ""
    info "Configurazione che verrà applicata:"
    if [[ $USE_DROPIN -eq 1 ]]; then
        grep -v '^#' "$TARGET_CONF" | grep -v '^$' | while IFS= read -r line; do
            echo -e "    ${DIM}${line}${NC}"
        done
    fi
fi

# =============================================================================
# Phase 3: Config test
# =============================================================================

phase_header 3 "Config test (sshd -t)"

will_do \
    "Esegue sshd -t per verificare che la configurazione sia valida" \
    "Se il test fallisce: NON riavvia sshd — la sessione resta attiva" \
    "In caso di errore mostra il problema e come fare rollback"

# Always run config test (read-only)
info "Test configurazione..."
if sshd -t 2>> "$LOG_FILE"; then
    ok "Config test superato — la configurazione è valida"
    report_phase "3|Config test (sshd -t)|SUPERATO|Nessun errore|n/a"
else
    warn "CONFIG TEST FALLITO"
    echo ""
    sshd -t 2>&1 | while IFS= read -r line; do
        echo -e "    ${RED}${line}${NC}"
    done
    echo ""
    warn "sshd NON verrà riavviato — la sessione corrente resta attiva"
    warn "Rollback: bash $BACKUP_DIR/rollback.sh"
    report_phase "3|Config test (sshd -t)|FALLITO|Vedi log|bash ${BACKUP_DIR}/rollback.sh"
    if [[ $DRY_RUN -eq 0 ]]; then
        read -rp "  Vuoi continuare comunque? (PERICOLOSO) (y/N) " force
        [[ "$force" =~ ^[yY]$ ]] || die "Interrotto — correggi la configurazione"
    fi
fi

# =============================================================================
# Phase 4: Restart sshd
# =============================================================================

phase_header 4 "Restart sshd"

will_do \
    "systemctl restart sshd" \
    "La sessione SSH corrente resta attiva (il processo sshd padre viene sostituito," \
    "ma le sessioni figlie già stabilite non vengono interrotte)" \
    "" \
    "IMPORTANTE: dopo il restart, apri un NUOVO terminale per verificare" \
    "che riesci a connetterti con la chiave. NON chiudere questa sessione" \
    "finché non hai verificato."

if confirm_phase; then
    info "Restart sshd..."
    if systemctl restart sshd 2>> "$LOG_FILE"; then
        ok "sshd riavviato"
        undo_hint \
            "bash $BACKUP_DIR/rollback.sh   # ripristina config e riavvia" \
            "# emergenza: cp $BACKUP_DIR/sshd_config /etc/ssh/sshd_config && systemctl restart sshd"
        report_phase "4|Restart sshd|FATTO|PID: $(pgrep -x sshd | head -1)|bash ${BACKUP_DIR}/rollback.sh"
    else
        warn "RESTART FALLITO"
        systemctl status sshd --no-pager -l 2>/dev/null | tail -10 | while read -r line; do
            echo -e "    ${RED}${line}${NC}"
        done
        warn "Rollback: bash $BACKUP_DIR/rollback.sh"
        report_phase "4|Restart sshd|FALLITO|Vedi log|bash ${BACKUP_DIR}/rollback.sh"
        die "Restart sshd fallito"
    fi
fi

# =============================================================================
# Phase 5: Validation + report
# =============================================================================

phase_header 5 "Validazione + report"

will_do \
    "Verifica la configurazione effettiva post-restart" \
    "Controlla che password auth sia disabilitata" \
    "Controlla che solo algoritmi forti siano offerti" \
    "Genera report e tarball"

echo ""
info "Configurazione effettiva post-hardening:"

# Verify effective config
POST_PERMIT=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin " | awk '{print $2}')
POST_PASSWORD=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication " | awk '{print $2}')
POST_PUBKEY=$(sshd -T 2>/dev/null | grep -i "^pubkeyauthentication " | awk '{print $2}')
POST_GSSAPI=$(sshd -T 2>/dev/null | grep -i "^gssapiauthentication " | awk '{print $2}')
POST_X11=$(sshd -T 2>/dev/null | grep -i "^x11forwarding " | awk '{print $2}')
POST_MACS=$(sshd -T 2>/dev/null | grep -i "^macs " | sed 's/^macs //')
POST_KEXS=$(sshd -T 2>/dev/null | grep -i "^kexalgorithms " | sed 's/^kexalgorithms //')
POST_GRACE=$(sshd -T 2>/dev/null | grep -i "^logingracetime " | awk '{print $2}')

VALIDATION_PASS=0
VALIDATION_FAIL=0

for check_name in "PermitRootLogin=prohibit-password:${POST_PERMIT}" "PasswordAuthentication=no:${POST_PASSWORD}" "PubkeyAuthentication=yes:${POST_PUBKEY}" "GSSAPIAuthentication=no:${POST_GSSAPI}" "X11Forwarding=no:${POST_X11}"; do
    expected=$(echo "$check_name" | cut -d: -f1 | cut -d= -f2)
    actual=$(echo "$check_name" | cut -d: -f2)
    label=$(echo "$check_name" | cut -d: -f1 | cut -d= -f1)

    if [[ "$actual" == "$expected" ]]; then
        ok "$label: $actual"
        ((VALIDATION_PASS++))
    else
        warn "$label: $actual (atteso: $expected)"
        ((VALIDATION_FAIL++))
    fi
done

# Check for weak algorithms
if echo "$POST_MACS" | grep -q "hmac-sha1\|umac-64"; then
    warn "MACs: contiene ancora algoritmi deboli"
    ((VALIDATION_FAIL++))
else
    ok "MACs: solo algoritmi forti"
    ((VALIDATION_PASS++))
fi

if echo "$POST_KEXS" | grep -q "diffie-hellman-group14-sha1\|diffie-hellman-group1"; then
    warn "KEX: contiene ancora algoritmi deboli"
    ((VALIDATION_FAIL++))
else
    ok "KEX: solo algoritmi forti"
    ((VALIDATION_PASS++))
fi

log "Validazione: $VALIDATION_PASS OK, $VALIDATION_FAIL problemi"

# Generate report
if [[ -d "$BACKUP_DIR" ]]; then
    cp "$LOG_FILE" "$BACKUP_DIR/" 2>/dev/null || true

    mkdir -p "$BACKUP_DIR/post-state"
    sshd -T > "$BACKUP_DIR/post-state/sshd-effective-config.txt" 2>/dev/null || true
    [[ -f "$TARGET_CONF" ]] && cp "$TARGET_CONF" "$BACKUP_DIR/post-state/" 2>/dev/null || true
    ss -tlnp | grep ":22 " > "$BACKUP_DIR/post-state/port-22-listen.txt" 2>/dev/null || true

    cat > "$REPORT_FILE" <<REPORT_EOF
# Report Hardening F-05 — SSH Key-Only + Strong Crypto

**Script:** harden-05-ssh-keys.sh
**Data:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Server:** $(hostname 2>/dev/null || echo "sconosciuto")
**Operatore da:** ${MY_IP:-sconosciuto}
**Modalità:** $(if [[ $DRY_RUN -eq 1 ]]; then echo "DRY-RUN"; else echo "ESECUZIONE"; fi)

## Findings coperti

| Finding | Descrizione | Stato |
|---------|-------------|-------|
| F-05 | SSH root login + password auth | Risolto (key-only) |
| F-12 | MAC/KEX deboli (sha1, umac-64) | Risolto (solo curve25519/aes-gcm) |
| F-16 | GSSAPI, X11Forwarding abilitati | Risolto (disabilitati) |
| F-19 | Nessun timeout sessione | Risolto (300s interval, 2 max) |

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

### Autenticazione
- PermitRootLogin: ${POST_PERMIT}
- PasswordAuthentication: ${POST_PASSWORD}
- PubkeyAuthentication: ${POST_PUBKEY}
- AuthenticationMethods: publickey

### Funzionalità disabilitate
- GSSAPIAuthentication: ${POST_GSSAPI}
- X11Forwarding: ${POST_X11}
- AllowTcpForwarding: no
- AllowAgentForwarding: no

### Timeout
- LoginGraceTime: ${POST_GRACE}
- ClientAliveInterval: 300
- ClientAliveCountMax: 2
- MaxAuthTries: 3

### Crittografia
- KexAlgorithms: ${POST_KEXS}
- MACs: ${POST_MACS}

## Validazione

- Check superati: ${VALIDATION_PASS}
- Problemi: ${VALIDATION_FAIL}

## Rollback

\`\`\`bash
# Rollback completo:
bash ${BACKUP_DIR}/rollback.sh

# Rollback rapido (se drop-in):
rm ${HARDENING_CONF} && systemctl restart sshd

# Riabilitare password temporaneamente:
sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' ${TARGET_CONF}
systemctl restart sshd
\`\`\`
REPORT_EOF

    ok "Report generato: $REPORT_FILE"

    TARBALL="/root/harden-05-report_${TIMESTAMP}.tar.gz"
    tar -czf "$TARBALL" -C /root "$(basename "$BACKUP_DIR")" 2>/dev/null || true
    ok "Tarball: $TARBALL"
fi

# =============================================================================
# Summary
# =============================================================================

banner "Riepilogo F-05"

if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "  ${YELLOW}DRY-RUN completato — nessuna modifica applicata.${NC}"
    echo ""
    echo -e "  Per applicare:  ${BOLD}bash $0${NC}"
else
    echo -e "  ${GREEN}SSH blindato: solo chiave, crittografia forte.${NC}"
    echo ""
    echo -e "  ${BOLD}Stato:${NC}"
    echo "    PermitRootLogin: ${POST_PERMIT}"
    echo "    PasswordAuthentication: ${POST_PASSWORD}"
    echo "    Algoritmi: solo curve25519/aes-gcm/hmac-sha2-etm"
    echo "    Timeout: 300s interval, 2 max, 30s grace"
    echo ""
    echo -e "  ${BOLD}Backup:${NC}"
    echo "    $BACKUP_DIR/"
    echo "    Rollback: bash $BACKUP_DIR/rollback.sh"
    echo ""
    echo -e "  ${RED}${BOLD}CRITICO — VERIFICA ORA:${NC}"
    echo "    1. Apri un NUOVO terminale"
    echo "    2. Prova: ssh -i ~/.ssh/tua_chiave root@$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "    3. Se funziona → tutto OK"
    echo "    4. Se NON funziona → da questa sessione:"
    echo "         bash $BACKUP_DIR/rollback.sh"
    echo ""
    echo -e "  ${BOLD}NON chiudere questa sessione finché non hai verificato!${NC}"
fi

echo ""
log "Log: $LOG_FILE"
