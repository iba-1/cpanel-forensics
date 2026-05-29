<p align="center">
  <h1 align="center">cPanel Forensics Toolkit</h1>
  <p align="center">
    Toolkit Bash per incident response, ripristino e audit su server cPanel/WHM/CloudLinux.
    <br />
    Sviluppato durante un caso reale di ransomware (SorryGo, 2026) su un VPS con ~30 account cPanel
    <br />
    che ospitavano siti Symfony 1.x e 2.x.
  </p>
</p>

---

## Indice

- [Panoramica](#panoramica)
- [Prerequisiti](#prerequisiti)
- [Installazione](#installazione)
- [Script](#script)
  - [forensic_collect.sh](#forensic_collectsh) — Raccolta forense completa
  - [ransomware_detect.sh](#ransomware_detectsh) — Rilevamento ransomware
  - [restore_site.sh](#restore_sitesh) — Ripristino completo siti
  - [audit-restore.sh](#audit-restoresh) — Audit post-ripristino
  - [run-audit.sh](#run-auditsh) — Launcher remoto per audit
  - [check_logs.sh](#check_logssh) — Ricerca log per dominio
  - [fix_symfony_perms.sh](#fix_symfony_permssh) — Fix permessi Symfony 1.x
  - [switch_php_version.sh](#switch_php_versionsh) — Cambio versione PHP
  - [fix-restore.sh](#fix-restoresh) — Fix post-ripristino (legacy)
- [Workflow tipico](#workflow-tipico)
- [Contesto: incidente SorryGo](#contesto-incidente-sorrygo)
- [Licenza](#licenza)

---

## Panoramica

Il toolkit copre l'intero ciclo di risposta a un incidente su server cPanel:

```
Raccolta forense ──> Rilevamento ransomware ──> Ripristino siti ──> Audit post-ripristino
forensic_collect.sh   ransomware_detect.sh      restore_site.sh     audit-restore.sh
```

Ogni script e pensato per essere eseguito come `root` su un server CentOS/CloudLinux con cPanel/WHM. Possono essere usati singolarmente o in sequenza.

---

## Prerequisiti

- **Accesso root** sul server target
- **Bash 4+**
- Tool Linux standard (`find`, `grep`, `awk`, `ps`, `ss`/`netstat`, `lsof`)
- Compatibile con **CentOS 6/7**, **CloudLinux 6/7/8**, **AlmaLinux**, **RHEL**
- Usa `openssl dgst` invece di `sha256sum` (funziona su installazioni minimali)

## Installazione

```bash
# Clonare il repo
git clone https://github.com/iba-1/cpanel-forensics.git

# Caricare gli script sul server
scp cpanel-forensics/*.sh root@server:/root/

# Renderli eseguibili
ssh root@server 'chmod +x /root/*.sh'
```

---

## Script

### `forensic_collect.sh`

Raccolta completa di evidenze forensi. Cattura prima lo stato volatile (rete, processi), poi esporta tutto in un tarball per analisi offline.

#### Utilizzo

```bash
sudo bash forensic_collect.sh [output_dir]
```

| Argomento | Descrizione | Default |
|-----------|-------------|---------|
| `output_dir` | Directory di output | `/root/forensic_<hostname>_<data>` |

#### Fasi di raccolta (12)

| # | Cosa raccoglie | Motivazione |
|---|----------------|-------------|
| 1 | Connessioni di rete, processi, `/proc`, iptables | Volatile — cambia ogni secondo |
| 2 | `/var/log/`, domlogs Apache, log Apache | Evidenze di log di sistema |
| 3 | Log cPanel, configurazioni utente, sessioni | Traccia accessi WHM/cPanel |
| 4 | `last`/`lastb`, wtmp/btmp, eventi auth SSH | Cronologia login e brute force |
| 5 | `.bash_history`, `.mysql_history` di tutti gli utenti | Ricostruzione comandi attaccante |
| 6 | Tutti i crontab (utente + sistema) | Meccanismi di persistenza |
| 7 | `/etc/passwd`, `/etc/shadow`, chiavi SSH, sudoers | Manomissione account |
| 8 | Log auditd + analisi aureport | Evidenze syscall |
| 9 | Hash binari, `rpm -Va`, SUID scan | Rilevamento rootkit/trojan |
| 10 | Indicatori di esfiltrazione (MITRE ATT&CK) | Evidenze furto dati |
| 11 | CloudLinux CageFS, statistiche LVE | Breakout CageFS, crypto mining |
| 12 | Report riepilogativo + compressione tar.gz | Output pronto per l'analista |

#### Rilevamento esfiltrazione (mappatura MITRE ATT&CK)

| Tecnica | Descrizione |
|---------|-------------|
| T1041 | Canale C2 — porte insolite, analisi volume byte |
| T1048 | Protocolli alternativi — DNS tunneling, allegati SMTP |
| T1048.003 | Analisi lunghezza sottodomini DNS, query TXT/NULL |
| T1567.002 | Cloud storage — rilevamento rclone, aws, gcloud |
| T1537 | Trasferimento account cloud |
| T1029 | Trasferimento programmato — cron sospetti |
| T1074 | Staging — file in `/tmp`, `/dev/shm` |

Rileva anche: webshell, backdoor `.htaccess`.

**Output:** un `.tar.gz` con tutte le evidenze + `REPORT.txt` con alert di triage.

> **Nota:** Eseguire il prima possibile — la fase 1 cattura stato volatile che cambia ogni secondo.

---

### `ransomware_detect.sh`

Rilevamento ransomware standalone. Verifica artefatti di cifratura, note di riscatto, distruzione backup e integrita file.

#### Utilizzo

```bash
sudo bash ransomware_detect.sh [output_dir] [forensic_collect_dir]
```

| Argomento | Descrizione | Default |
|-----------|-------------|---------|
| `output_dir` | Directory di output | `/root/ransomware_scan_<hostname>_<data>` |
| `forensic_collect_dir` | Output di `forensic_collect.sh` (opzionale) | — |

Il secondo argomento permette di riutilizzare le shell history gia raccolte, evitando lavoro duplicato.

#### Fasi di analisi (8)

| # | Cosa controlla |
|---|----------------|
| 1 | File con nota di riscatto (40+ pattern + rilevamento `README.md` di Sorry/SorryGo) |
| 2 | URL `.onion`, indirizzi crypto wallet, ID qTox nei file di testo |
| 3 | Estensioni file cifrati (50+ pattern: `.sorry`, `.lockbit`, `.akira`, ...) |
| 4 | Modifica massiva file (>1000 file/ora = probabile cifratura) |
| 5 | Comandi di cifratura nella history (`openssl enc`, `gpg`, `shred`) |
| 6 | Distruzione backup (directory mancanti, comandi `rm` nella history) |
| 7 | Nomi processo ransomware noti (30+ famiglie) |
| 8 | Analisi header/magic byte (rileva `.jpg`/`.png`/`.pdf` cifrati) |

#### Rilevamento specifico Sorry/SorryGo (2026)

- Estensione `.sorry`
- `README.md` come nota di riscatto (pattern: `qtox`, `tox.id`, `taobao`, `decrypt`)
- Pattern nome processo SorryGo

---

### `restore_site.sh`

Pipeline completa di ripristino siti da backup cPanel `.tar.gz`. Rileva automaticamente il tipo di sito (Symfony 1.x o 2.x "area riservata") e applica tutte le fix necessarie.

#### Utilizzo

```bash
# Ripristino singolo sito
bash restore_site.sh /home/backup.tar.gz

# Ripristino batch (tutti i backup)
bash restore_site.sh /home/*.tar.gz

# Con switch PHP
bash restore_site.sh /home/backup.tar.gz --php 5.3

# Solo fix permessi (senza restore), auto-detect tipo
bash restore_site.sh --fix-only username

# Fix permessi multipli account, forzando tipo area-riservata
bash restore_site.sh --fix-only user1 user2 user3 --type ar
```

#### Opzioni

| Opzione | Descrizione |
|---------|-------------|
| `--php VERSION` | Cambia versione PHP (accetta: `5.3`, `53`, `php53`, `ea-php53`) |
| `--fix-mysql` | Disabilita MySQL `STRICT_TRANS_TABLES` |
| `--fix-only USER [...]` | Solo fix permessi, senza `/scripts/restorepkg` (accetta uno o piu username) |
| `--type ar\|site` | Forza tipo sito: `ar` (Symfony 2.x) o `site` (Symfony 1.x). Se omesso, auto-detect |
| `--skip-restore` | Salta `restorepkg`, applica solo le fix (richiede path `.tar.gz`) |
| `--dry-run` | Mostra cosa farebbe senza eseguire modifiche |

#### Fasi di ripristino (10)

| # | Fase | Descrizione |
|---|------|-------------|
| 1 | `restorepkg` | Ripristina l'account cPanel dal backup |
| 2 | Permessi | ACL setfacl per cache, log, spool, upload, files, moxiemanager |
| 3 | Cache | Pulizia cache Symfony (evita crash ClassCollectionLoader) |
| 4 | `.htaccess` | Commenta `ExpiresActive`/`ExpiresDefault` |
| 5 | Dev controllers | Aggiunge IP consentito a `frontend_dev.php`, `backend_dev.php`, etc. |
| 6 | `error_log` | Rimuove `error_log` dalla docroot pubblica |
| 7 | Log | Tronca log sovradimensionati (>100MB) |
| 8 | PHP | Switch versione PHP con copia automatica estensioni |
| 9 | MySQL | Fix strict mode (opzionale, con `--fix-mysql`) |
| 10 | Verifica | Controllo finale permessi |

#### Dettaglio fix permessi (fase 2)

Le fix usano `setfacl` per garantire accesso in scrittura sia all'utente cPanel che ad Apache (`nobody`).

**Symfony 2.x (area riservata):** `app/cache`, `app/logs`, `spool`, `var/cache`, `var/logs`, `var/sessions`, `public_html/uploads`, `public_html/bundles`, `public_html/media`, `public_html/files`

**Symfony 1.x (sito normale):** `cache/`, `log/`, `public_html/uploads`, `public_html/form_upload`, `public_html/export`, `public_html/download`, `public_html/repository`, `public_html/files`, plugin con sottodirectory numerate (es. `dgNewsPlugin/102/`)

**Entrambi:** directory `moxiemanager/data` (TinyMCE plugin — cache/sessioni runtime)

---

### `audit-restore.sh`

Audit post-ripristino di tutti gli account cPanel sul server. Verifica le stesse fix applicate da `restore_site.sh` e genera report CSV.

#### Utilizzo

```bash
# Eseguire sul VPS come root
bash audit-restore.sh
```

Non richiede argomenti — scansiona automaticamente tutti gli account in `/home/`.

#### Cosa verifica

- Permessi ACL (`setfacl` per utente + `nobody`)
- Ownership file PHP
- Directory cache e log
- Permessi `public_html`
- Controller di sviluppo (IP consentiti)
- `error_log` nella docroot
- Log sovradimensionati
- Directory `moxiemanager/data`
- Versione PHP corretta

#### Output

Una directory compressa con:
- `test_results.csv` — dettaglio per singolo test
- `site_summary.csv` — riepilogo per dominio con stato fix e problemi residui

---

### `run-audit.sh`

Launcher per eseguire `audit-restore.sh` su un VPS remoto via SSH e scaricare automaticamente i risultati.

#### Utilizzo

```bash
# Connessione standard
./run-audit.sh root@server-ip

# Porta SSH custom
./run-audit.sh root@server-ip -p 2222

# Chiave SSH custom
./run-audit.sh root@server-ip -i ~/.ssh/my_key
```

| Argomento | Descrizione |
|-----------|-------------|
| `ssh-target` | Target SSH (es. `root@192.168.1.100`) — **obbligatorio** |
| opzioni SSH | Qualsiasi opzione SSH aggiuntiva (`-p`, `-i`, etc.) |

Carica `audit-restore.sh` sul server, lo esegue, scarica il tarball nella directory locale `audits/`.

---

### `check_logs.sh`

Ricerca rapida e monitoraggio live dei log per un dominio specifico su server cPanel.

#### Utilizzo

```bash
bash check_logs.sh <dominio>
```

| Argomento | Descrizione |
|-----------|-------------|
| `dominio` | Nome dominio da cercare (es. `example.com`) — **obbligatorio** |

#### Cosa fa

1. Trova tutti i file log che corrispondono al dominio
2. Mostra le ultime 50 righe di ciascuno
3. Salva i percorsi trovati in `/tmp/logs_<dominio>.txt`
4. Chiede conferma prima di avviare `tail -f` per monitoraggio live
5. Salta automaticamente i log compressi `.gz`

---

### `fix_symfony_perms.sh`

Fix permessi per singolo account cPanel con sito Symfony 1.x. Ripristina ownership da `nobody` all'utente cPanel mantenendo le directory runtime scrivibili da Apache.

#### Utilizzo

```bash
# Backup ACL + fix permessi
bash fix_symfony_perms.sh --backup username

# Solo backup ACL (nessuna modifica)
bash fix_symfony_perms.sh --backup-only username

# Solo fix permessi (senza backup)
bash fix_symfony_perms.sh username
```

| Opzione | Descrizione |
|---------|-------------|
| `--backup` | Salva le ACL correnti prima di applicare le fix |
| `--backup-only` | Solo backup, nessuna modifica ai permessi |
| (nessuna) | Applica direttamente le fix |

#### Cosa corregge

| Directory | Ownership | Permessi | Motivazione |
|-----------|-----------|----------|-------------|
| `public_html/` | `user:user` | 755 | Docroot deve essere dell'utente |
| `log/`, `cache/` | `user:nobody` | 775 | Symfony richiede scrittura Apache |
| `uploads/`, `form_upload/` | `user:nobody` | 775 | Directory upload file |
| Plugin con sottodirectory numerate | `user:nobody` | 775 | Upload runtime (es. `dgNewsPlugin/102/`) |
| Asset statici (css, js, images) | `user:user` | 755 | Sola lettura, niente scrittura Apache |

Tronca anche log >100MB e rimuove `error_log` dalla docroot.

---

### `switch_php_version.sh`

Cambia la versione PHP di un dominio cPanel preservando tutte le estensioni installate.

#### Utilizzo

```bash
bash switch_php_version.sh <dominio> <versione_php>
```

| Argomento | Descrizione |
|-----------|-------------|
| `dominio` | Dominio cPanel (es. `tecnoidealsrl.com`) — **obbligatorio** |
| `versione_php` | Versione target — **obbligatorio** |

La versione accetta formati flessibili: `5.3`, `53`, `php53`, `ea-php53`.

#### Cosa fa

1. Rileva la versione PHP corrente del dominio
2. Elenca le estensioni installate sulla versione corrente
3. Installa le estensioni mancanti sulla versione target
4. Esegue lo switch tramite WHM API
5. Verifica che lo switch sia avvenuto

---

### `fix-restore.sh`

> **Legacy** — versione semplificata precedente a `restore_site.sh`. Mantenuto per compatibilita.

Fix post-ripristino per siti Symfony 1.x.

#### Utilizzo

```bash
# Fix standard
bash fix-restore.sh /home/sitecode

# Fix + disabilita MySQL strict mode
bash fix-restore.sh /home/sitecode --fix-mysql
```

| Argomento | Descrizione |
|-----------|-------------|
| `/home/sitecode` | Home directory del sito — **obbligatorio** |
| `--fix-mysql` | Disabilita `STRICT_TRANS_TABLES` |

---

## Workflow tipico

```
        FASE 1: INCIDENT RESPONSE
        ─────────────────────────
   ┌──────────────────────────────────┐
   │  1. forensic_collect.sh          │  Raccolta evidenze (eseguire SUBITO)
   │  2. ransomware_detect.sh         │  Analisi artefatti ransomware
   │  3. Scaricare tarball risultati  │  scp forensic_*.tar.gz .
   └──────────────────────────────────┘

        FASE 2: RIPRISTINO
        ──────────────────
   ┌──────────────────────────────────┐
   │  4. restore_site.sh              │  Ripristino batch da backup
   │     (--php, --fix-mysql)         │  Con fix PHP e MySQL se necessario
   └──────────────────────────────────┘

        FASE 3: VERIFICA
        ────────────────
   ┌──────────────────────────────────┐
   │  5. run-audit.sh                 │  Audit remoto + download CSV
   │  6. check_logs.sh                │  Debug specifico per dominio
   │  7. switch_php_version.sh        │  Correzione PHP singolo dominio
   │  8. fix_symfony_perms.sh         │  Correzione permessi singolo sito
   └──────────────────────────────────┘
```

### Esempio completo

```bash
# 1. Raccolta forense (il prima possibile!)
ssh root@server 'bash /root/forensic_collect.sh'

# 2. Scansione ransomware (riusa dati forensi)
ssh root@server 'bash /root/ransomware_detect.sh /root/ransom_scan /root/forensic_*'

# 3. Scaricare risultati per analisi offline
scp root@server:/root/forensic_*.tar.gz .
scp root@server:/root/ransomware_scan_*.tar.gz .

# 4. Ripristino batch di tutti i backup con PHP 5.3
ssh root@server 'bash /root/restore_site.sh /home/*.tar.gz --php 5.3'

# 5. Audit post-ripristino
./run-audit.sh root@server

# 6. Debug log di un dominio specifico
ssh root@server 'bash /root/check_logs.sh example.com'

# 7. Correzione PHP per singolo dominio
ssh root@server 'bash /root/switch_php_version.sh example.com 7.0'

# 8. Fix permessi singolo account (con backup)
ssh root@server 'bash /root/fix_symfony_perms.sh --backup username'
```

---

## Contesto: incidente SorryGo

Questo toolkit e stato sviluppato durante la risposta a un attacco ransomware **SorryGo** (maggio 2026) su un VPS con:

- **~30 account cPanel** su server CentOS/CloudLinux
- Siti **Symfony 1.x** (frontend pubblici) e **Symfony 2.x** (aree riservate)
- **suPHP** come handler PHP (richiede ACL specifiche per `nobody`)
- Backup disponibili come **archivi `.tar.gz` cPanel**

Il ransomware ha cifrato i file con estensione `.sorry` e lasciato note di riscatto come `README.md` con contatti qTox. Il toolkit ha permesso di:

1. Raccogliere evidenze forensi prima del ripristino
2. Ripristinare tutti i siti in batch da backup
3. Verificare automaticamente che ogni sito fosse funzionante post-ripristino

---

## Note operative

- Eseguire `forensic_collect.sh` **il prima possibile** — la fase 1 cattura stato volatile di rete e processi
- I tarball di output possono essere grandi (diversi GB) per i dump completi dei log
- Ogni riga di log include **motivo**, **percorso sorgente** e **percorso destinazione** per la catena di custodia
- I log di `restore_site.sh` vengono salvati in `/root/restore_logs/` con timestamp

## Licenza

Distribuito sotto licenza MIT. Vedi `LICENSE` per maggiori informazioni.
