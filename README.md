# kir_auth — SDK Python del Platform Hub

Le da a una mini-app FastAPI **identidad y control de acceso sin escribir auth**.

La autenticación la hace el sidecar `oauth2-proxy` (OIDC con Entra) antes de que
el request llegue a la app. El SDK lee la identidad del header que pone el
sidecar y consulta los roles al Hub.

## Instalar

El paquete se publica **tag-versionado** desde este repo — sin vendoring. Una
app lo pinea en su `requirements.txt`:

```
kir-auth @ https://github.com/kir-apps/kir-auth/archive/refs/tags/v0.5.0.tar.gz
```

(Migrar una app existente de su copia vendorizada a este paquete es un paso
aparte, de a una app por vez — no ocurre solo por publicar acá.)

Dependencias que la app debe tener: `httpx`, `fastapi`.

## Uso

```python
from fastapi import Depends, FastAPI
from kir_auth import KirAuth, Identity

app = FastAPI()

auth = KirAuth(
    app_slug="stock",
    hub_url="http://hub:8020",                  # el Hub dentro de kir_net
    platform_token=settings.PLATFORM_API_TOKEN, # el mismo token del Hub
)

@app.get("/")
def home(user: Identity = Depends(auth.require_login)):
    return {"hola": user.display_name}

@app.get("/panel")
def panel(user: Identity = Depends(auth.require_role("admin", "editor"))):
    return {"ok": True, "roles": user.roles}
```

## Dependencias disponibles

| Dependencia | Si no hay identidad | Si falta el rol |
|-------------|---------------------|-----------------|
| `auth.optional_user` | devuelve `None` | — |
| `auth.require_login` | `401` | — |
| `auth.require_role(*roles)` | `401` | `403` |

Los **platform admin** pasan cualquier `require_role`. Detrás de oauth2-proxy
nunca llega un request sin identidad — un `401` indica que falta el sidecar.

## El objeto `Identity`

```python
user.email              # "persona@kir.com.ar"
user.name               # nombre (del header del sidecar / del Hub)
user.display_name       # name o, si está vacío, email
user.is_platform_admin  # bool
user.roles              # ["admin", "viewer"] — roles en ESTA app
user.has_role("admin")  # bool (platform admin pasa siempre)
user.known              # False si el Hub nunca vio a este usuario
user.phone              # str | None — teléfono enriquecido desde Entra (Graph)
user.obras_general      # bool — ACL por obra (Fase 3): ve todas las obras
user.obras_codigos      # list[str] — ACL por obra: códigos puntuales habilitados
user.can_see_obra(cod)  # bool (platform admin y obras_general pasan siempre)
user.admin_sections     # list[str] — secciones delegadas del /admin del Hub
                         # (p. ej. "obras"), para apps que exponen paneles propios
                         # de administración condicionados por esa delegación
```

## Cómo consigue los roles

El SDK llama `GET {hub_url}/platform/acl?app=<slug>&email=<email>` con el header
`X-Platform-Token`. Cachea el resultado por email (TTL 60s) para no pegarle al
Hub en cada request. Si el Hub se cae, sirve la copia cacheada; sin cache,
falla cerrado (`503`) — nunca abre acceso por error.

## Guarda de origen (`IDENTIDAD_SOLO_DESDE`)

El header `X-Forwarded-Email` lo pone el sidecar después de validar la sesión,
pero la app no puede distinguirlo de uno que mandó cualquier otro proceso que
llega a su puerto. Con la guarda configurada, **los headers de identidad sólo se
aceptan si la IP del par TCP es la del sidecar**, resuelta por DNS:

```env
IDENTIDAD_SOLO_DESDE=<app>-oauth2          # nombre del servicio/contenedor del sidecar
```

También se puede pasar en código (`KirAuth(..., identidad_solo_desde="<app>-oauth2")`);
`identidad_solo_desde=None` la apaga aunque esté la variable. Acepta varios
nombres separados por coma.

| Pedido | Sin configurar (default) | Configurada |
|---|---|---|
| Con identidad, desde el sidecar | pasa | pasa |
| Con identidad, desde otra IP | pasa | **403**, sin consultar la ACL ni caer a `dev_email` |
| Sin identidad (healthcheck, `X-Platform-Token`) | sin cambios | sin cambios |

Sin configurar, el comportamiento es el de siempre y se loguea **un aviso por
proceso** (logger `kir_auth`). Es 403 y no 401 a propósito: algunos frontends
mandan a re-loguear ante un 401, y si la guarda rechazara a todos por un nombre
mal puesto sería un bucle.

Cómo resuelve: cachea las IPs del nombre 10 s; si llega una IP que no conoce,
re-resuelve una vez antes de rechazar (el sidecar recreado cambia de IP), con un
tope de una re-resolución por segundo. Si el nombre no resuelve, rechaza.
**Si el nombre resuelve a más de una IP de la misma familia, rechaza** y lo
loguea como error: en una red de Docker otro contenedor puede declarar un alias
con el mismo nombre, y aceptar cualquiera de las dos IPs dejaría pasar al
impostor.

Para habilitarla en una app hay que verificar antes:

1. **El sidecar le habla directo a la app.** Si hay algo en el medio (un nginx,
   el server de un frontend que reenvía al API), el par que ve la app es ese
   intermediario: hay que poner su nombre, y entonces cualquiera que llegue al
   intermediario puede inyectar headers. En ese caso la guarda por nombre no
   alcanza.
2. **Sidecar y app comparten una sola red.** Si comparten más de una, el sidecar
   puede llegar por cualquiera; calificá el nombre con cada red
   (`<app>-oauth2.<red>`, que Docker resuelve a la IP de esa red) y listá los dos.
3. **Una sola réplica del sidecar** (varias réplicas = varias IPs = rechazo).
4. **Uvicorn/gunicorn no confían en `X-Forwarded-For` de cualquiera.** El
   default (`--forwarded-allow-ips 127.0.0.1`) está bien. Con `*`, la IP del par
   sale de un header que manda el cliente: `KirAuth` no arranca si ve
   `FORWARDED_ALLOW_IPS=*` en el entorno (el flag de línea de comandos no lo
   puede ver; no lo uses).
5. **Nadie más manda headers de identidad a propósito** (un crawler o un script
   que le pega directo a la app presentándose como alguien): con la guarda va a
   recibir 403.
6. **Los tests/QA que le pegan directo a la app con el header** corren con la
   variable vacía.

Lo que la guarda **no** cubre: quien puede crear contenedores en la red puede
también detener el sidecar y tomar su nombre. Contra eso, la verificación del
token firmado del proveedor de identidad.

## Correr local sin sidecar

Para desarrollar la app sin oauth2-proxy delante, pasá `dev_email`:

```python
auth = KirAuth(..., dev_email="vos@kir.com.ar")  # None en producción
```
