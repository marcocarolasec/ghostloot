# Evilginx Loot Dashboard

Panel web de solo lectura para operar campañas de Evilginx: visualiza el loot
deduplicado por víctima, exporta cookies listas para pass-the-cookie, vigila la
salud de tu infra y te avisa por Telegram. Un binario Go autocontenido que lee
`data.db` (buntdb) **sobre una copia**, sin tocar el fichero vivo ni el lock de
Evilginx.

> Solo para engagements autorizados. Contiene credenciales y sesiones robadas:
> trátalo como material sensible.

## Características

**Loot**
- Vista **Víctimas**: una fila por persona (colapsa duplicados), con sus
  phishlets, nº de intentos, estado de sesión y cookies de la mejor captura.
- Vista **Todas las sesiones**: listado crudo con buscador, filtros y orden.
- Detección de **sesión válida**: token real reutilizable (ESTSAUTH /
  ESTSAUTHPERSISTENT / SignInStateCookie org; MSPAuth / RPSSecAuth /
  __Host-MSAAUTH personal). Descarta basura (`Disabled`, `estsfd`).
- **Copiar cookies** por víctima (formato Cookie-Editor / StorageAce) y
  **export masivo** en zip (un JSON por víctima + INDEX).
- **Export CSV** enmascarado (sin secretos) para el informe.
- **Estado por víctima**: marcar como *usada* y notas, persistente.
- Aviso **multi-IP** (misma cuenta desde varias IPs → la cookie puede rebotar
  por conditional access).

**Infra**
- **Monitor de dominios**: detecta takedown/suspensión (caída de conexión/DNS) y,
  opcional, flaggeo en Google Safe Browsing. Tira de estado en el panel.
- **Mis URLs**: guarda tus lures a mano, con estado activa/caída y filtro "solo
  activas".
- **Rendimiento por lure**: visitas, válidas y % de conversión por landing URL.
- **Timeline** de capturas válidas (14 días).
- **/api/health**: Evilginx corriendo, última captura, tamaño de DB, versión.

**Alertas Telegram** (configurables desde el panel > Ajustes)
- Aviso de nueva víctima con sesión válida y de dominio caído/recuperado/flaggeado.
- Modo **alertas mínimas**: sin usuario ni IP (OPSEC).

## Instalación rápida (systemd, recomendado)

En el servidor, junto al binario y `evilginx-dashboard.service`:

```bash
sudo ./install.sh
```

Arranca solo al reiniciar y se relanza si cae. Escucha en `127.0.0.1:8090`.

Desde tu equipo, túnel SSH y navegador:

```bash
ssh -i <clave> -o ServerAliveInterval=30 -L 8090:127.0.0.1:8090 <user>@<host>
# http://localhost:8090
```

### Arranque manual (sin systemd)

```bash
chmod +x evilginx-dashboard
sudo ./evilginx-dashboard -addr 127.0.0.1:8090
```

Para dejarlo en segundo plano: `sudo setsid ./evilginx-dashboard -addr 127.0.0.1:8090 >/tmp/dash.log 2>&1 </dev/null &`

## Modelo de seguridad

- Diseñado para `127.0.0.1` + túnel SSH. **No lo expongas a internet.**
- Si intentas escuchar fuera de localhost sin `-user/-pass`, **se niega a
  arrancar** (usa `-insecure` para forzarlo, bajo tu responsabilidad).
- Protección CSRF (mismo-origen) en los endpoints que cambian estado.
- Cabeceras de seguridad y timeouts activados.
- Ficheros de estado con permisos `0600`. Cifra el disco del server y limpia el
  loot al cerrar el engagement.

Ver `AUDIT.md` para la auditoría completa.

## Telegram

1. Crea un bot con `@BotFather` (`/newbot`) → token.
2. `chat_id`: escribe a tu bot y abre
   `https://api.telegram.org/bot<TOKEN>/getUpdates`, o usa `@userinfobot`.
3. Panel > **Ajustes**: activa, pega token y chat, Guardar, y "Enviar test".

## Opciones (CLI)

```
-addr          escucha (por defecto 127.0.0.1:8080)
-db            ruta al data.db (por defecto /root/.evilginx/data.db)
-user -pass    basic auth (obligatorio si escuchas fuera de localhost)
-insecure      permitir fuera de localhost sin auth (NO recomendado)
-tg-token      token del bot (seed; luego se edita en Ajustes) o env TG_TOKEN
-tg-chat       chat_id (seed) o env TG_CHAT
-tg-interval   frecuencia de alertas de sesiones (15s)
-mon           dominios a monitorear, coma-separados (vacío = auto)
-mon-auto      derivar dominios de los landing URLs (true)
-mon-interval  frecuencia de chequeo de dominios (5m)
-sb-key        API key de Google Safe Browsing (o env SB_KEY) — ver aviso OPSEC
-urls-file / -settings-file / -vstate-file   ficheros de persistencia
```

## OPSEC — Safe Browsing

`-sb-key` usa la Lookup API de Google, que **envía tus URLs completas a Google**
atadas a tu API key. Es exposición de infra: desactivado por defecto, con aviso.
Nunca metas tus URLs en scanners de terceros (urlscan, VirusTotal, previews):
eso las publica y es como se quema la infra.

## Compilar

```bash
make build         # host actual
make build-linux   # Linux amd64 (servidor típico)
```

Requiere Go 1.21+. `index.html` va embebido (go:embed): binario autocontenido.
Dependencia: github.com/tidwall/buntdb.

## Aviso legal

Herramienta para **pruebas de seguridad autorizadas** (red team, simulaciones de
phishing) únicamente. Usarla contra sistemas o personas sin permiso explícito por
escrito es ilegal. Los autores no se responsabilizan del mal uso. No se incluye
ni distribuye Evilginx ni ningún phishlet.

## Créditos

Trabaja sobre la base de datos (buntdb) de [Evilginx](https://github.com/kgretzky/evilginx2).
Formato de cookies compatible con Cookie-Editor / StorageAce.

