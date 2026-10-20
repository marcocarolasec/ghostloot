# Phishlets

Evilginx 3.3.0 community templates for authorized assessments.

Replace **every** `EXAMPLE` with the Okta tenant slug before loading:

```text
acme.okta.com  →  EXAMPLE = acme
```

```bash
sed -i 's/EXAMPLE/acme/g' okta.yaml
# copy into Evilginx's phishlets dir, then restart the process
# (disable/enable does not reload YAML)
```

DNS: `EXAMPLE.<phish-domain>` → Evilginx host. No wildcard required.

Do not leave `*.yaml.bak*` in the phishlets directory. Evilginx 3.3 matches `.yaml` unanchored in the filename and will load the backup as `okta`, overwriting the real phishlet.
