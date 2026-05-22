"""kir_auth — SDK cliente del KIR Platform Hub.

La autenticación la resuelve el sidecar oauth2-proxy (OIDC con Entra) ANTES de
que el request llegue a la app. El SDK solo:
  1. lee la identidad del header `X-Auth-Request-Email` que pone el sidecar;
  2. consulta los roles al Hub (`GET /platform/acl`, cacheado).

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
from kir_auth.models import Identity

__all__ = [
    "Identity",
    "KirAuth",
    "PlatformClient",
    "PlatformError",
]
__version__ = "0.2.0"
