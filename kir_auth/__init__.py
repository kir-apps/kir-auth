"""kir_auth — SDK cliente del KIR Platform Hub.

La autenticación la resuelve el sidecar oauth2-proxy (OIDC con Entra) ANTES de
que el request llegue a la app. El SDK solo:
  1. lee la identidad del header `X-Auth-Request-Email` que pone el sidecar;
  2. consulta los roles al Hub (`GET /platform/acl`, cacheado).

Con `IDENTIDAD_SOLO_DESDE` configurada, el header sólo se acepta si el par TCP es
el proxy de autenticación (ver `kir_auth.origen`).

Uso típico en una mini-app FastAPI:

    from kir_auth import KirAuth

    auth = KirAuth(
        app_slug="stock",
        hub_url="http://hub:8020",          # el Hub dentro de kir_net
        platform_token=settings.PLATFORM_API_TOKEN,
    )

    @app.get("/")
    def home(user = Depends(auth.require_login)):
        return f"Hola {user.display_name}"

    @app.get("/config")
    def config(user = Depends(auth.require_role("admin"))):
        ...
"""
from kir_auth.client import PlatformClient, PlatformError
from kir_auth.fastapi import KirAuth
from kir_auth.idtoken import ErrorJWKS, TokenInvalido, VerificadorIdToken
from kir_auth.models import Identity
from kir_auth.origen import GuardaDeOrigen

__all__ = [
    "ErrorJWKS",
    "GuardaDeOrigen",
    "Identity",
    "KirAuth",
    "PlatformClient",
    "PlatformError",
    "TokenInvalido",
    "VerificadorIdToken",
]
__version__ = "0.8.0"
