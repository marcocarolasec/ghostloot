# Security Audit — GhostLoot v1.0.0

Full review of security, robustness and product. Findings, severity and status
(fixed / accepted / pending).

## Security

| # | Finding | Sev | Status |
|---|---------|-----|--------|
| S1 | CSRF: state-changing endpoints (`/api/settings`, `/api/urls`, `/api/vstate`, `/api/test-telegram`) didn't validate origin. A malicious page open in the same browser could, e.g., change the Telegram token to the attacker's and hijack alerts. | High | **Fixed**: same-origin guard (`Origin` must match `Host` on POST/DELETE/PUT). |
| S2 | Fail-open: listening off localhost without auth only printed a warning but still served loot. | High | **Fixed**: refuses to start off localhost without `-user/-pass`, unless `-insecure` is explicit. |
| S3 | No security headers. | Medium | **Fixed**: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. |
| S4 | No server timeouts (Slowloris). | Low | **Fixed**: `ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout` (WriteTimeout intentionally off for large downloads). |
| S5 | State files with secrets on disk. | Info | **Accepted**: written `0600`; the Telegram token is stored in clear (required to use it). Encrypt the server disk. |
| S6 | Safe Browsing leaks your URLs to Google. | Medium | **Mitigated**: off by default; warning banner when enabled; shown in the footer. |
| S7 | The panel serves credentials and session cookies. | By design | **Accepted**: intended for `127.0.0.1` + SSH tunnel. Do not expose to the internet. |

## Robustness

| # | Finding | Status |
|---|---------|--------|
| R1 | If Evilginx was writing `data.db` while it was being copied, a reload could fail and return 500. | **Fixed**: on reload failure it serves the last good cached snapshot. |
| R2 | The domain monitor followed redirects: a phishing host root redirects to the real site, so it measured Microsoft instead of your host. | **Fixed**: redirects are not followed; a 3xx counts as "reachable". |
| R3 | Full copy+parse of `data.db` on every request. | **Fixed**: mtime cache; only reloads when it changes. |
| R4 | Concurrency over shared state. | **OK**: all mutex-guarded. |

## Product

- **Added** `/api/health`: is Evilginx running (scans `/proc`), last-capture age, DB size, session/valid-victim counts, version. Shown in the footer and the status dot.
- **Added** packaging: `systemd` service (auto-start + auto-restart), `install.sh`, `Makefile`.
- **Added** bulk loot export (zip), masked CSV export, per-victim state (used/notes), per-lure performance, capture timeline, multi-IP warning (possible conditional access), and an EN/ES language toggle.

## Residual risks / pending

- **Dead-man's switch**: the monitor runs on the same host; it cannot alert if the host itself goes down. Requires an external watcher (not included).
- **GeoIP**: not included (its library needs a dependency the build environment blocks); can be added by building locally with a **local** MaxMind database (no third-party calls).
- **Intervals** (alerts/monitor) are set via flags; changing them requires a restart.
- **Authentication**: basic auth via flag. For team use behind a proxy, put TLS + auth at the proxy.
