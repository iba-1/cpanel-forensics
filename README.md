# cPanel Forensics Toolkit

Toolkit Bash per incident response, ripristino e audit su server cPanel/WHM/CloudLinux. Sviluppato durante un caso reale di ransomware (SorryGo, 2026) su un VPS con ~30 account cPanel che ospitavano siti Symfony 1.x e 2.x.

## Panoramica

Il toolkit copre l'intero ciclo di risposta a un incidente:

1. **Raccolta forense** e rilevamento ransomware
2. **Ripristino** automatizzato dei siti da backup cPanel
3. **Audit** post-ripristino per verificare che tutto funzioni

---

## Script

### `forensic_collect.sh`

Raccolta completa di evidenze forensi — cattura prima lo stato volatile, poi esporta tutto in un tarball per analisi offline.

```bash
sudo bash forensic_collect.sh [output_dir]
```

**Cosa raccoglie (12 fasi):**

| Fase | Cosa | Perche |
|------|------|--------|
| 1 | Connessioni di rete, processi, `/proc`, iptables | Volatile — cambia ogni secondo |
| 2 | `/var/log/`, domlogs Apache, log Apache | Evidenze di log di sistema |
| 3 | Log cPanel, configurazioni utente, sessioni di trasferimento | Traccia accessi WHM/cPanel |
| 4 | `last`/`lastb`, wtmp/btmp, eventi auth SSH | Cronologia login e brute force |
| 5 | `.bash_history`, `.mysql_history` di tutti gli utenti | Ricostruzione comandi attaccante |
| 6 | Tutti i crontab (utente + sistema) | Meccanismi di persistenza |
| 7 | `/etc/passwd`, `/etc/shadow`, chiavi SSH, sudoers | Manomissione account, chiavi non autorizzate |
| 8 | Log auditd + analisi aureport | Evidenze syscall |
| 9 | Hash binari (openssl), `rpm -Va`, SUID scan | Rilevamento rootkit/trojan |
| 10 | Indicatori di esfiltrazione (mappati MITRE ATT&CK) | Evidenze furto dati |
| 11 | CloudLinux CageFS, statistiche LVE | Breakout CageFS, crypto mining |
| 12 | Report riepilogativo + compressione tar.gz | Output pronto per l'analista |

**Rilevamento esfiltrazione dati:**

- **T1041** — Canale C2 (porte insolite, analisi volume byte)
- **T1048** — Protocolli alternativi (DNS tunneling, allegati SMTP grandi)
- **T1048.003** — Analisi lunghezza sottodomini DNS, query TXT/NULL
- **T1567.002** — Cloud storage (rilevamento rclone, aws, gcloud + raccolta credenziali)
- **T1537** — Trasferimento account cloud
- **T1029** — Trasferimento programmato (cron sospetti)
- **T1074** — Staging (file in `/tmp`, `/dev/shm`)
- Rilevamento e raccolta webshell
- Raccolta backdoor `.htaccess`

**Output:** Un singolo `.tar.gz` con tutto, piu un `REPORT.txt` con alert di triage rapido.

---

### `ransomware_detect.sh`

Rilevamento ransomware standalone — verifica artefatti di cifratura, note di riscatto, distruzione backup e integrita file.

```bash
sudo bash ransomware_detect.sh [output_dir] [forensic_collect_dir]
```

Il secondo argomento (opzionale) permette di riutilizzare le history gia raccolte da `forensic_collect.sh`.

**Cosa controlla (8 fasi):**

| Fase | Cosa |
|------|------|
| 1 | File con nota di riscatto (40+ pattern + rilevamento `README.md` di Sorry/SorryGo) |
| 2 | URL `.onion`, indirizzi crypto wallet, ID qTox nei file di testo |
| 3 | Estensioni file cifrati (50+ pattern inclusi `.sorry`, `.lockbit`, `.akira`) |
| 4 | Modifica massiva file (file modificati per ora — >1000/h = cifratura) |
| 5 | Comandi di cifratura nella history (`openssl enc`, `gpg`, `shred`) |
| 6 | Distruzione backup (directory mancanti, comandi `rm` nella history) |
| 7 | Nomi processo di ransomware noti (30+ famiglie) |
| 8 | Analisi header/magic byte (rileva `.jpg`/`.png`/`.pdf` cifrati senza header valido) |

**Include rilevamento specifico per Sorry/SorryGo (2026):**
- Estensione `.sorry`
- `README.md` come nota di riscatto (grep per `qtox`, `tox.id`, `taobao`, `decrypt`)
- Pattern nome processo SorryGo

---

### `restore_site.sh`

Pipeline completa di ripristino siti da backup cPanel. Rileva automaticamente il tipo di sito (Symfony 1.x "site" o Symfony 2.x "area riservata") e applica tutte le fix necessarie.

```bash
bash restore_site.sh /home/backup.tar.gz [--php 53] [--fix-mysql]
bash restore_site.sh /home/*.tar.gz --php 70          # ripristino batch
```

**Cosa fa (10 fasi):**

| Fase | Cosa |
|------|------|
| 1 | Esegue `/scripts/restorepkg` per ripristinare l'account cPanel |
| 2 | Fix permessi: ACL setfacl per cache, log, spool, upload, files, moxiemanager |
| 3 | Pulizia cache Symfony (evita crash ClassCollectionLoader) |
| 4 | Fix `.htaccess` (commenta ExpiresActive/ExpiresDefault) |
| 5 | Fix controller di sviluppo (aggiunge IP consentito) |
| 6 | Rimuove `error_log` dalla docroot pubblica |
| 7 | Tronca log sovradimensionati (>100MB) |
| 8 | Switch versione PHP (con copia automatica estensioni) |
| 9 | Fix MySQL strict mode (opzionale) |
| 10 | Verifica finale permessi |

**Dettagli permessi (fase 2):**

Per i siti **Symfony 2.x (AR):** fix ACL su `app/cache`, `app/logs`, `spool`, `var/cache`, `var/logs`, `var/sessions`, `public_html/uploads`, `public_html/bundles`, `public_html/media`, `public_html/files`.

Per i siti **Symfony 1.x:** fix ACL su `cache/`, `log/`, `public_html/uploads`, `public_html/form_upload`, `public_html/export`, `public_html/download`, `public_html/repository`, `public_html/files`, plugin con sottodirectory numerate.

In entrambi i casi: fix ACL su directory `moxiemanager/data` (TinyMCE plugin).

---

### `audit-restore.sh`

Audit post-ripristino di tutti gli account cPanel sul server. Verifica le stesse fix applicate da `restore_site.sh` e genera un report CSV con lo stato di ogni sito.

```bash
bash audit-restore.sh    # eseguire sul VPS come root
```

**Cosa verifica:**

- Permessi ACL (setfacl per utente + nobody)
- Ownership PHP files
- Directory cache e log
- Permessi `public_html`
- Controller di sviluppo (IP consentiti)
- `error_log` nella docroot
- Log sovradimensionati
- Directory `moxiemanager/data`
- Versione PHP corretta

**Output:** Directory con `test_results.csv` (dettaglio per test) e `site_summary.csv` (riepilogo per dominio), compressi in un tarball.

---

### `run-audit.sh`

Launcher per eseguire `audit-restore.sh` su un VPS remoto via SSH e scaricare i risultati in locale.

```bash
./run-audit.sh root@your-vps-ip
./run-audit.sh root@your-vps-ip -p 2222          # porta SSH custom
./run-audit.sh root@your-vps-ip -i ~/.ssh/key     # chiave SSH custom
```

Carica lo script sul server, lo esegue, scarica il tarball dei risultati nella directory locale `audits/`.

---

### `check_logs.sh`

Ricerca e monitoraggio rapido dei log per un dominio specifico su server cPanel.

```bash
bash check_logs.sh example.com
```

- Trova tutti i file log che corrispondono al dominio
- Mostra le ultime 50 righe di ciascuno
- Salva i percorsi trovati in `/tmp/logs_<dominio>.txt`
- Chiede prima di avviare `tail -f` per monitoraggio live
- Salta i log compressi `.gz`

---

### `fix_symfony_perms.sh`

Fix permessi Symfony 1.x per singolo account cPanel. Ripristina ownership da `nobody` all'utente cPanel mantenendo `log/`, `cache/` e directory upload scrivibili da Apache.

```bash
bash fix_symfony_perms.sh --backup tecnoid3vbay     # backup + fix
bash fix_symfony_perms.sh --backup-only tecnoid3vbay  # solo backup
bash fix_symfony_perms.sh tecnoid3vbay               # solo fix
```

---

### `switch_php_version.sh`

Cambia la versione PHP di un dominio cPanel preservando tutte le estensioni.

```bash
bash switch_php_version.sh tecnoidealsrl.com 5.3
bash switch_php_version.sh tecnoidealsrl.com ea-php70
```

Accetta formati flessibili (`5.3`, `53`, `php53`, `ea-php53`). Rileva automaticamente la versione corrente, elenca le estensioni, installa quelle mancanti sulla versione target, esegue lo switch e verifica.

---

### `fix-restore.sh`

Fix post-ripristino per siti Symfony 1.x (versione semplificata, precedente a `restore_site.sh`).

```bash
bash fix-restore.sh /home/sitecode              # fix standard
bash fix-restore.sh /home/sitecode --fix-mysql   # anche fix MySQL strict mode
```

---

## Utilizzo tipico

```bash
# 1. Raccolta forense (eseguire per primo — cattura stato volatile)
ssh root@server 'bash /root/forensic_collect.sh'

# 2. Scansione ransomware (puo riutilizzare dati forensi)
ssh root@server 'bash /root/ransomware_detect.sh /root/ransom_scan /root/forensic_*'

# 3. Scaricare risultati
scp root@server:/root/forensic_*.tar.gz .
scp root@server:/root/ransomware_scan_*.tar.gz .

# 4. Ripristino siti da backup
ssh root@server 'bash /root/restore_site.sh /home/*.tar.gz --php 53'

# 5. Audit post-ripristino
./run-audit.sh root@server

# 6. Controllo log di un dominio specifico
ssh root@server 'bash /root/check_logs.sh example.com'

# 7. Switch PHP per un singolo dominio
ssh root@server 'bash /root/switch_php_version.sh example.com 7.0'
```

## Requisiti

- Accesso root sul server target
- Bash 4+
- Tool Linux standard (`find`, `grep`, `awk`, `ps`, `ss`/`netstat`, `lsof`)
- Compatibile con CentOS 6/7, CloudLinux 6/7/8, AlmaLinux, RHEL
- Usa `openssl dgst` invece di `sha256sum` (funziona su installazioni minimali)

## Note

- Eseguire `forensic_collect.sh` **il prima possibile** — la fase 1 cattura stato volatile di rete/processi che cambia ogni secondo
- Idealmente montare il disco in sola lettura prima dell'esecuzione, ma gli script funzionano su sistemi live
- I tarball di output possono essere grandi (diversi GB) per i dump completi dei log — prevedere spazio disco e tempo di trasferimento
- Ogni riga di log include il **motivo** della raccolta, il **percorso sorgente** e il **percorso destinazione** per la documentazione della catena di custodia

## Licenza

MIT
