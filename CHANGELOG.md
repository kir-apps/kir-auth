# Changelog

Todos los cambios notables de este paquete se documentan acá.

## [0.8.0] — sin publicar

**Guarda de origen: un par puede quedar atado a los emails que puede afirmar**
(kir-auth#8, kir-platform#571). `IDENTIDAD_SOLO_DESDE=<app>-oauth2,<par>=email`
(varios emails separados por `;`): desde ese par, otro email es `403` y no se
consulta la ACL, con un `warning` estructurado que lleva el par, la IP y sólo el
dominio del email. Un par sin `=` sigue afirmando cualquier email. Detalle en el
README, «Atar un par a los emails que puede afirmar».

### Compatibilidad hacia atrás

La lista de nombres de siempre se parsea igual y ningún par queda restringido;
sin la variable no cambia nada. Lo único que antes arrancaba y ahora no: un
valor que no se entiende (`par=` sin emails, `=email` sin par, un email donde va
un nombre, el mismo par dos veces con restricción). Un nombre con `@`, `;`, `=` o
espacios nunca resolvió por DNS, así que con la versión anterior esa app ya
rechazaba toda identidad; ahora no arranca y lo dice.

### Agregado

- `kir_auth.origen.pares_de` (el parser) y, en `GuardaDeOrigen`, `pares`,
  `par(ip)`, `emails_permitidos(par)` y `puede_afirmar(par, email)`.
- `identidad_solo_desde` acepta además un dict `{par: None | emails}`.
- El rechazo por par no confiable también lleva `extra` (`evento`, `motivo`, `ip`).

## [0.7.0] — sin publicar

**`kir_auth.errores`: reporte de errores a GlitchTip** (compatible con el SDK de
Sentry) con scrubbing de sueldos, montos, DNI/CUIL, headers de auth, cookies y
query strings. Opt-in por `GLITCHTIP_DSN` y por el extra `kir-auth[errores]`
(`sentry-sdk==2.72.0`); sin ellos no hace nada. Detalle en el README
(kir-auth#6, kir-platform#168).

### Agregado

- `kir_auth.errores.iniciar(app, *, dsn, environment, release)`.
- `kir_auth/errores_denylist.json`, pensado para compartirse con el helper de Node.
- Extra `errores` en `pyproject.toml`.

## [0.6.0] — 2026-10-26, tag `v0.6.0`

**Verificación opcional del ID token del proxy** (`IDENTIDAD_JWT_MODO`,
`IDENTIDAD_JWT_ISSUER`, `IDENTIDAD_JWT_AUDIENCIA`). Con
`pass_authorization_header = true` en oauth2-proxy, `KirAuth` verifica el
`Authorization: Bearer <id_token>` (firma RS256 contra el JWKS, `iss`, `aud`,
`exp`) y exige que el email del header sea el del token. Modo `observar` para
probarlo en producción sin rechazar a nadie. Detalle en el README.

### Compatibilidad hacia atrás

Apagado por default; sin la variable no cambia nada y no hace falta el extra.
Para prenderlo, `kir-auth[jwt]` (suma PyJWT y cryptography).

### Agregado

- `kir_auth.VerificadorIdToken`, `TokenInvalido`, `ErrorJWKS`.
- `KirAuth(..., verificador_jwt=..., jwt_modo=...)`.
- Extra `jwt` en `pyproject.toml`.

## [0.5.0] — 2026-10-26, tag `v0.5.0`

**Guarda de origen opcional** (`IDENTIDAD_SOLO_DESDE`). Con la variable (o el
parámetro `identidad_solo_desde`) configurada con el nombre DNS del proxy de
autenticación, los headers de identidad (`X-Forwarded-Email`,
`X-Auth-Request-Email`) sólo se aceptan si la IP del par TCP es la de ese proxy;
desde otra IP, `403` sin consultar la ACL. Detalle en el README, «Guarda de
origen».

### Compatibilidad hacia atrás

Sin configurar no cambia nada: se aceptan los headers como antes y se loguea un
aviso una vez por proceso (logger `kir_auth`). Ninguna app necesita tocar código
para actualizar. Las que la configuren tienen que revisar la lista del README
antes de prenderla (sobre todo: nada en el medio entre proxy y app, y nadie que
mande el header a propósito).

Única forma en que esta versión puede no arrancar: guarda configurada y
`FORWARDED_ALLOW_IPS=*` en el entorno, porque con eso la IP del par se falsea con
un header.

### Agregado

- `kir_auth.GuardaDeOrigen`.
- `KirAuth(..., identidad_solo_desde=...)`.

## [0.4.0] — 2026-09-23

Primera versión que las apps pueden consumir sin perder nada: las cinco copias
vendorizadas (obras, stock, seleccion, servicios, controldegestion) ya declaran
`0.4.0` y tienen el arreglo de #163. `v0.3.0` no lo tiene, así que migrarlas a
esa versión (como decía `kir-platform#268`) habría sido volver atrás en
seguridad. Además de lo que tienen las copias, esta versión suma `phone` y
`admin_sections` en `Identity`, dos campos nuevos con default.

**El fallback stale de la ACL está acotado** (`kir-platform#163`). Cuando el Hub
no responde, el SDK sigue sirviendo la copia cacheada — pero ahora sólo hasta
`stale_max_seconds` (default 900) después de vencido el TTL. Pasado ese punto
falla cerrado, igual que en la primera llamada sin cache.

Antes ese branch no miraba la expiración: a un usuario al que le revocaban el
acceso durante una caída larga del Hub le seguían valiendo sus roles viejos
mientras el proceso no reiniciara, o sea **sin límite**.

La asimetría es deliberada: un reinicio del Hub no puede echar a todo el mundo,
pero pasado un rato es preferible dejar afuera a alguien con acceso legítimo que
dejar adentro a alguien a quien se lo sacaron.

## [0.3.0] — publicada como tag `v0.3.0`

Corrige una deriva entre el repo canónico y las copias vendorizadas en las 5
apps (`kir-platform#164`): las cinco declaraban `__version__ = "0.2.0"` pero
no eran iguales — la de `obras` tenía de más el soporte de `admin_sections`,
que hoy usa el alcance por obra del Hub (`kir-platform#253` y siguientes) en
producción. Esta versión toma esa copia como base.

### Agregado

- `Identity.admin_sections: list[str]` — secciones delegadas del `/admin` del
  Hub (p. ej. `"obras"`), para que una app condicione paneles de
  administración propios por esa delegación. Default `[]`.
- `KirAuth._identity` ahora lee `admin_sections` del bloque `/platform/acl`
  del Hub (`acl.get("admin_sections", [])`) y lo pasa a `Identity`.
- README: documentado el campo `admin_sections`, y sección "Instalar"
  actualizada — el paquete se publica tag-versionado desde este repo en vez
  de vendorizarse.

### Compatibilidad hacia atrás

Cambio aditivo. Un Hub que todavía no manda `admin_sections` en el ACL sigue
andando igual: `acl.get("admin_sections", [])` devuelve `[]`, que es también
el default de `Identity.admin_sections`. Ninguna app que ya usa `0.2.x`
necesita cambiar código para actualizar.

### Nota de versión

`pyproject.toml` venía en `0.2.1` mientras `kir_auth/__version__` seguía en
`0.2.0` (deriva propia del repo, previa a esta migración). Esta versión
corrige el mismatch: ambos quedan en `0.3.0`.

## [0.2.1] / [0.2.0]

Sin CHANGELOG previo a esta versión.
