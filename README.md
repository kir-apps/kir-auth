# kir_auth — SDK Python del Platform Hub

Le da a una mini-app FastAPI **identidad y control de acceso sin escribir auth**.

La autenticación la hace el sidecar `oauth2-proxy` (OIDC con Entra) antes de que
el request llegue a la app. El SDK lee la identidad del header que pone el
sidecar y consulta los roles al Hub.

## Instalar

El paquete se publica **tag-versionado** desde este repo — sin vendoring. Una
app lo pinea en su `requirements.txt`:

```
kir-auth @ git+https://github.com/kir-apps/kir-auth.git@v0.3.0
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

## Correr local sin sidecar

Para desarrollar la app sin oauth2-proxy delante, pasá `dev_email`:

```python
auth = KirAuth(..., dev_email="vos@kir.com.ar")  # None en producción
```
