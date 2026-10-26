# Changelog

Todos los cambios notables de este paquete se documentan acá.

## [0.6.0] — sin publicar

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

## [0.5.0] — sin publicar

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
