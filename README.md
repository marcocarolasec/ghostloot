<div align="center">

```
   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓ ██▓     ▒█████   ▒█████  ▄▄▄█████▓
  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒▓██▒    ▒██▒  ██▒▒██▒  ██▒▓  ██▒ ▓▒
 ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░▒██░    ▒██░  ██▒▒██░  ██▒▒ ▓██░ ▒░
 ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░ ▒██░    ▒██   ██░▒██   ██░░ ▓██▓ ░
 ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ ░██████▒░ ████▓▒░░ ████▓▒░  ▒██▒ ░
```

# GhostLoot

**Real-time loot & ops dashboard for [Evilginx](https://github.com/kgretzky/evilginx2).**
Victim-deduplicated loot, one-click pass-the-cookie export, infra health monitoring and Telegram alerts — in a single Go binary.

![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux-333)
![Single binary](https://img.shields.io/badge/deploy-single%20binary-blueviolet)
![Status](https://img.shields.io/badge/status-active-success)

<sub>A <b>RedGhostOps</b> tool · authorized security assessments only</sub>

</div>

---

<img width="1512" height="858" alt="image" src="https://github.com/user-attachments/assets/cbb00f94-0e43-423c-a777-5313a76a5dad" />


> ⚠️ **For authorized security assessments only.** GhostLoot is a read-only viewer
> for data that Evilginx has already captured during a legitimate engagement.
> Using it against systems or people without explicit written permission is
> illegal. It does not include or distribute Evilginx or any phishlets.

## Why

Evilginx's console gives you a flat `sessions` list. At 200 hits — between bots and
duplicates — you can't see what matters: **who actually got caught and which loot
is replayable**. GhostLoot reads the `data.db` (buntdb) **on a copy** — never
touching the live file or Evilginx's lock — and turns it into an operable panel.

## Features

🎯 **Inbox for the campaign** — replayable accounts first, workflow
(open → bounced with cause → done). Captures newer than 15 minutes are
highlighted. Distinguishes Entra (`ESTSAUTH` / `ESTSAUTHPERSISTENT`) from
personal MSA (`__Host-MSAAUTHP`) and junk (`Disabled`, `estsfd`, `__Host-MSAAUTH=11`).

🍪 **Manual replay checklist** — VPN/exit, Copy UA, import host, then-open,
one Copy cookies. Accept-Language and the Cookie header sit behind More.
`c` copies Cookie-Editor JSON, `h` the Cookie header, `b` the replay brief, `u` marks done.

📊 **Report-ready** — masked CSV export, capture timeline, and per-lure
performance (visits → valid → conversion %).

🛰️ **Infra monitoring** — detects takedown/suspension of your domains; optional
Google Safe Browsing flag check (off by default, with an OPSEC warning).

🔗 **Lures** — landing URLs plus the ones you save, with service, visits → loot,
copy, and up/down. Period counts live as a strip on that tab.

🔔 **Telegram alerts** — new valid victim and domain down/recovered, with age
and a stable `#id`. Minimal (no-PII) mode. Configurable from the panel, no restart.

🩺 **Health** — is Evilginx running?, last capture, DB size, version.

🏷️ **Per-victim state** — mark as *used* and add notes.

🛡️ **Hardened** — read-only, CSRF protection, security headers, fail-closed off
localhost, bound to `127.0.0.1` by default.

## Quickstart

Two machines. One command a day after that.

**1. Server** (the box that already runs Evilginx)

```bash
git clone https://github.com/marcocarolasec/ghostloot.git && cd ghostloot
make build-linux
sudo ./install.sh
```

`install.sh` finds `data.db`, finds Evilginx if it is in a usual path, and
binds the panel to **127.0.0.1** on 8090 (or 8091–8094 if 8090 is taken).
It never publishes the panel.

**2. Laptop** (once)

```bash
./install-local.sh
ghostloot init user@your-server /path/to/ssh-key
```

**3. Every day**

```bash
ghostloot              # start whatever is down, open the inbox
ghostloot down         # stop the panel, close the tunnel (Evilginx stays up)
ghostloot help         # cheatsheet
```

Printable copy: [`CHEATSHEET.md`](CHEATSHEET.md). Config is
`/etc/ghostloot.conf` on the server and `~/.ghostloot/config` on the laptop —
nothing is hardcoded to a particular VPS.

Manual run: `sudo ./evilginx-dashboard -addr 127.0.0.1:8090`

## Security & OPSEC

- Built for `127.0.0.1` + SSH tunnel. **Do not expose it to the internet.**
- Off localhost without `-user/-pass` it **refuses to start** (`-insecure` to force).
- CSRF protection, security headers and server timeouts enabled.
- State files are `0600`. Encrypt the server disk and wipe loot when the
  engagement ends: `sudo rm -f /root/.evilginx-dashboard-*.json`
- **Safe Browsing** sends your URLs to Google: off by default. Never submit your
  URLs to third-party scanners (urlscan, VirusTotal) — that's how infra burns.

Full write-up in [`AUDIT.md`](AUDIT.md).

## Telegram

1. Create a bot with `@BotFather` (`/newbot`) → token.
2. Get your `chat_id`: message your bot and open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` (or use `@userinfobot`).
3. Panel → **Settings** → enable, paste token & chat, Save, "Send test".

## Options (CLI)

```
-addr          listen address (default 127.0.0.1:8090)
-db            path to data.db (default /root/.evilginx/data.db)
-user -pass    basic auth (required off localhost)
-insecure      allow off-localhost without auth (NOT recommended)
-tg-token/-tg-chat   Telegram seed (then edited in Settings)
-tg-interval   session-alert poll interval (15s)
-mon / -mon-auto / -mon-interval   domain monitor
-sb-key        Google Safe Browsing (see OPSEC note)
-urls-file / -settings-file / -vstate-file   persistence
```

## How it works

Evilginx stores each session as JSON in a buntdb (`~/.evilginx/data.db`).
GhostLoot copies that file, parses it, caches by mtime (only reloads when it
changes) and serves a read-only panel + API. `index.html` is embedded via
`go:embed` — a single self-contained binary, no runtime dependencies.

## Build

```bash
make build         # current host
make build-linux   # Linux amd64 (typical server)
```

Go 1.22+. Dependency: `github.com/tidwall/buntdb`.

## License

MIT — see [`LICENSE`](LICENSE).

<div align="center"><sub>Built to operate fast and clean. RedGhostOps.</sub></div>
