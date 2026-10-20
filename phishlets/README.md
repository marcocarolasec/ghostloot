# Phishlets

Evilginx 3.3.0 community templates for authorized assessments.

These files are generic. Substitute `EXAMPLE` before use.

## Okta (`okta.yaml`)

Replace **every** `EXAMPLE` with the Okta tenant slug:

```text
acme.okta.com  →  EXAMPLE = acme
```

```bash
sed -i 's/EXAMPLE/acme/g' okta.yaml
```

DNS: `EXAMPLE.<phish-domain>` → Evilginx host.

## Microsoft (`microsoft.yaml`)

Leave `login.microsoftonline.com` / `office.com` / `live.com` as they are — those are Microsoft's origins.

Set the lure parent domain at runtime:

```text
phishlets hostname microsoft EXAMPLE.com
```

Landing: `https://login.EXAMPLE.com/<lure>`

## Load

Copy into Evilginx's phishlets dir, then **restart the process**. Disable/enable does not reload YAML.

Do not leave `*.yaml.bak*` in the phishlets directory. Evilginx 3.3 matches `.yaml` unanchored in the filename and will load the backup as the real phishlet.
