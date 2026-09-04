# Auditoría — Evilginx Loot Dashboard v1.0.0

Revisión completa de seguridad, robustez y producto. Se listan hallazgos,
severidad, y estado (corregido / aceptado / pendiente).

## Seguridad

| # | Hallazgo | Sev | Estado |
|---|----------|-----|--------|
| S1 | CSRF: los endpoints que cambian estado (`/api/settings`, `/api/urls`, `/api/vstate`, `/api/test-telegram`) no validaban origen. Una web maliciosa abierta en el mismo navegador podía, p.ej., cambiar el token de Telegram al del atacante y desviar las alertas. | Alta | **Corregido**: guard de mismo-origen (`Origin` debe coincidir con `Host` en POST/DELETE/PUT). |
| S2 | Fail-open: escuchar fuera de localhost sin auth solo mostraba un aviso pero servía el loot igual. | Alta | **Corregido**: se niega a arrancar fuera de localhost sin `-user/-pass`, salvo `-insecure` explícito. |
| S3 | Sin cabeceras de seguridad. | Media | **Corregido**: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. |
| S4 | Sin timeouts en el servidor (Slowloris). | Baja | **Corregido**: `ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout` (WriteTimeout off aposta para descargas grandes). |
| S5 | Ficheros con secretos (settings/urls/vstate) en disco. | Info | **Aceptado**: se escriben con permisos `0600`; el token de Telegram va en claro (necesario para usarlo). Cifra el disco del server. |
| S6 | Safe Browsing filtra tus URLs a Google. | Media | **Mitigado**: desactivado por defecto; banner de aviso al activarlo; visible en el pie del panel. |
| S7 | El panel sirve credenciales y cookies de sesión. | Por diseño | **Aceptado**: pensado para `127.0.0.1` + túnel SSH. No exponer a internet. |

## Robustez

| # | Hallazgo | Estado |
|---|----------|--------|
| R1 | Si Evilginx estaba escribiendo `data.db` cuando se copiaba, la recarga podía fallar y devolver 500. | **Corregido**: ante fallo de recarga se sirve la última copia buena en cache. |
| R2 | El monitor de dominios seguía redirecciones: el root de un host de phishing redirige al sitio real, midiendo Microsoft en vez de tu host. | **Corregido**: no se siguen redirecciones; un 3xx cuenta como "alcanzable". |
| R3 | Copia+parseo completo de `data.db` en cada petición. | **Corregido** (previo): cache por mtime; solo recarga cuando cambia. |
| R4 | Concurrencia sobre estado compartido. | **OK**: todo protegido con mutex. |

## Producto

- **Añadido** `/api/health`: Evilginx corriendo (scan de `/proc`), antigüedad de la última captura, tamaño de la DB, nº de sesiones/víctimas válidas, versión. Visible en el pie del panel y en el punto de estado.
- **Añadido** empaquetado: servicio `systemd` (arranque automático + relanzado), `install.sh`, `Makefile`.
- Export masivo de loot (zip), export CSV para informe, estado por víctima (usada/notas), rendimiento por lure, timeline, aviso multi-IP (posible conditional access).

## Riesgos residuales / pendiente

- **Dead-man's switch**: el monitor corre en la misma máquina; no puede avisar si el host entero cae. Requiere un vigilante externo (no incluido).
- **GeoIP**: no incluido (su librería necesita una dependencia que el entorno de build bloquea); se puede añadir compilando en local con una base MaxMind **local** (sin llamar a terceros).
- **Intervalos** (alertas/monitor) se configuran por flag; cambiarlos requiere reiniciar.
- **Autenticación**: basic auth por flag. Para uso en equipo detrás de proxy, poner TLS + auth en el proxy.
