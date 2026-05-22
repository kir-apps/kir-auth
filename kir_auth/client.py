"""Cliente de la API interna del Hub (`/platform/acl`).

Consulta los roles de un usuario en esta app. Cachea por email con TTL corto
para no pegarle al Hub en cada request. Si el Hub se cae, sirve la copia
cacheada mientras dure; sin cache, falla cerrado (deny).
"""
from __future__ import annotations

import time

import httpx


class PlatformError(Exception):
    """No se pudo consultar la ACL del Hub y no hay cache para degradar."""


class PlatformClient:
    def __init__(
        self,
        hub_url: str,
        app_slug: str,
        platform_token: str,
        *,
        cache_ttl_seconds: int = 60,
    ) -> None:
        self._hub = hub_url.rstrip("/")
        self._app = app_slug
        self._token = platform_token
        self._ttl = cache_ttl_seconds
        # email -> (expira_en, data)
        self._cache: dict[str, tuple[float, dict]] = {}

    def acl(self, email: str) -> dict:
        """Devuelve {email, name, is_platform_admin, roles, known} para el user."""
        now = time.time()
        cached = self._cache.get(email)
        if cached and cached[0] > now:
            return cached[1]
        try:
            resp = httpx.get(
                f"{self._hub}/platform/acl",
                params={"app": self._app, "email": email},
                headers={"X-Platform-Token": self._token},
                timeout=5.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            if cached:
                return cached[1]  # Hub caído: degradar con la copia cacheada.
            raise PlatformError(f"no se pudo consultar la ACL del Hub: {exc}") from exc
        self._cache[email] = (now + self._ttl, data)
        return data
