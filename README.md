# cPanel Forensics Toolkit

Bash scripts for incident response on cPanel/WHM/CloudLinux servers. Built for real-world forensic collection, exfiltration detection, and ransomware hunting.

## Scripts

### `forensic_collect.sh`

Full forensic evidence collection — captures volatile state first, then dumps everything into a tarball for offline analysis.

```bash
sudo bash forensic_collect.sh [output_dir]
```

**What it collects (12 phases):**

| Phase | What | Why |
|-------|------|-----|
| 1 | Network connections, processes, `/proc`, iptables | Volatile — changes every second |
| 2 | Full `/var/log/`, Apache domlogs, Apache logs | System-wide log evidence |
| 3 | cPanel logs, user configs, transfer sessions | WHM/cPanel access trail |
| 4 | `last`/`lastb`, wtmp/btmp, SSH auth events | Login history and brute force |
| 5 | All users' `.bash_history`, `.mysql_history`, etc. | Attacker command reconstruction |
| 6 | All crontabs (user + system) | Persistence mechanisms |
| 7 | `/etc/passwd`, `/etc/shadow`, SSH keys, sudoers | Account tampering, rogue keys |
| 8 | Auditd logs + aureport analysis | Syscall-level command evidence |
| 9 | Binary hashes (openssl), `rpm -Va`, SUID scan | Rootkit/trojan detection |
| 10 | Exfiltration indicators (MITRE ATT&CK mapped) | Data theft evidence |
| 11 | CloudLinux CageFS, LVE stats | CageFS breakout, crypto mining |
| 12 | Summary report + tar.gz compression | Analyst-ready output |

**Exfiltration detection covers:**

- **T1041** — C2 channel (unusual ports, byte volume analysis)
- **T1048** — Alternative protocols (DNS tunneling, SMTP large attachments)
- **T1048.003** — DNS subdomain length analysis, TXT/NULL queries
- **T1567.002** — Cloud storage (rclone, aws, gcloud detection + credential collection)
- **T1537** — Cloud account transfer
- **T1029** — Scheduled transfer (suspicious cron entries)
- **T1074** — Staging (files in `/tmp`, `/dev/shm`)
- Webshell detection and collection
- `.htaccess` backdoor collection

**Output:** A single `.tar.gz` with everything, plus a `REPORT.txt` with quick triage alerts.

---

### `ransomware_detect.sh`

Standalone ransomware detection — checks for encryption artifacts, ransom notes, backup destruction, and file integrity.

```bash
sudo bash ransomware_detect.sh [output_dir] [forensic_collect_dir]
```

The optional second argument lets it reuse shell histories already collected by `forensic_collect.sh`.

**What it checks (8 phases):**

| Phase | What |
|-------|------|
| 1 | Ransom note files (40+ filename patterns + Sorry/SorryGo `README.md` detection) |
| 2 | `.onion` URLs, crypto wallet addresses, qTox IDs in text files |
| 3 | Encrypted file extensions (50+ patterns including `.sorry`, `.lockbit`, `.akira`) |
| 4 | Mass file modification (files modified per hour — >1000/hr = encryption) |
| 5 | Encryption commands in shell histories (`openssl enc`, `gpg`, `shred`) |
| 6 | Backup destruction (missing backup dirs, `rm` commands in history) |
| 7 | Known ransomware process names (30+ families) |
| 8 | File header/magic byte analysis (detects encrypted `.jpg`/`.png`/`.pdf` without valid headers) |

**Includes specific detection for Sorry/SorryGo (2026):**
- `.sorry` file extension
- `README.md` as ransom note (greps for `qtox`, `tox.id`, `taobao`, `decrypt` keywords)
- SorryGo process name pattern

---

### `check_logs.sh`

Quick domain-specific log finder and watcher for cPanel servers.

```bash
bash check_logs.sh example.com
```

- Finds all log files matching the domain name
- Shows last 50 lines from each
- Saves found log paths to `/tmp/logs_<domain>.txt`
- Asks before starting `tail -f` to watch live
- Skips `.gz` compressed logs

---

### `fix_symfony_perms.sh`

Fix Symfony 1.x file permissions per cPanel account. Restores `public_html` ownership from `nobody` to the cPanel user while keeping `log/`, `cache/`, and upload directories writable by Apache.

```bash
bash fix_symfony_perms.sh --backup tecnoid3vbay    # backup + fix
bash fix_symfony_perms.sh --backup-only tecnoid3vbay # backup only
bash fix_symfony_perms.sh tecnoid3vbay              # fix only
```

**What it fixes:**

| Directory | Ownership | Permissions | Why |
|-----------|-----------|-------------|-----|
| `public_html/` | `user:user` | 755 | Docroot should be user-owned |
| `log/`, `cache/` | `user:nobody` | 775 | Symfony needs Apache write access |
| `uploads/`, `form_upload/` | `user:nobody` | 775 | File upload directories |
| Plugin dirs with numbered subdirs | `user:nobody` | 775 | Auto-detected runtime upload dirs (e.g. `dgNewsPlugin/102/`) |
| Static asset dirs (css, js, images) | `user:user` | 755 | Read-only, no Apache write needed |

Also truncates log files >100MB and removes `error_log` from the public docroot.

---

### `switch_php_version.sh`

Switch a cPanel domain to a different PHP version while preserving all extensions.

```bash
bash switch_php_version.sh tecnoidealsrl.com 5.3
bash switch_php_version.sh tecnoidealsrl.com ea-php70
```

Accepts flexible version formats (`5.3`, `53`, `php53`, `ea-php53`). Auto-detects current version, lists extensions, installs missing ones on target, switches, and verifies.

---

### `fix-restore.sh`

Fix common issues after restoring a cPanel backup for Symfony 1.x sites.

```bash
bash fix-restore.sh /home/sitecode              # standard fixes
bash fix-restore.sh /home/sitecode --fix-mysql   # also fix MySQL strict mode
```

**What it fixes:**
- Comments out `ExpiresActive`/`ExpiresDefault` in `.htaccess`
- Creates and fixes `log/` and `cache/` permissions
- Fixes `public_html` directory permissions for uploads
- Adds allowed IP to dev controllers (`frontend_dev.php`, `backend_dev.php`)
- Optionally disables MySQL `STRICT_TRANS_TABLES`
- Restarts Apache and MySQL

---

## Usage

```bash
# 1. Upload to server
scp *.sh root@your-server:/root/

# 2. Run forensic collection (run first — captures volatile state)
ssh root@your-server 'bash /root/forensic_collect.sh'

# 3. Run ransomware scan (can reuse forensic data)
ssh root@your-server 'bash /root/ransomware_detect.sh /root/ransom_scan /root/forensic_*'

# 4. Pull results
scp root@your-server:/root/forensic_*.tar.gz .
scp root@your-server:/root/ransomware_scan_*.tar.gz .

# 5. Check specific domain logs
ssh root@your-server 'bash /root/check_logs.sh example.com'

# 6. Fix Symfony permissions (with backup)
ssh root@your-server 'bash /root/fix_symfony_perms.sh --backup username'

# 7. Switch PHP version
ssh root@your-server 'bash /root/switch_php_version.sh example.com 7.0'

# 8. Fix after backup restore
ssh root@your-server 'bash /root/fix-restore.sh /home/username'
```

## Requirements

- Root access on the target server
- Bash 4+
- Standard Linux tools (`find`, `grep`, `awk`, `ps`, `ss`/`netstat`, `lsof`)
- Works on CentOS 6/7, CloudLinux 6/7/8, AlmaLinux, RHEL
- Uses `openssl dgst` instead of `sha256sum` (works on minimal installs)

## Notes

- Run `forensic_collect.sh` **as early as possible** — phase 1 captures volatile network/process state that changes every second
- Ideally mount the disk read-only before running, but the scripts work on live systems
- Output tarballs can be large (several GB) due to full log dumps — plan for disk space and transfer time
- Every log line includes the **reason** for collection, **source path**, and **destination path** for chain-of-custody documentation

## License

MIT
