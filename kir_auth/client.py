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
        stale_max_seconds: int = 900,
    ) -> None:
        self._hub = hub_url.rstrip("/")
        self._app = app_slug
        self._token = platform_token
        self._ttl = cache_ttl_seconds
        # Cuánto se puede seguir sirviendo una ACL vencida cuando el Hub no
        # responde (#163). 15 minutos: suficiente para que un reinicio del Hub
        # o un pico de red no eche a todo el mundo, y acotado para que una
        # revocación no quede sin efecto por tiempo indefinido.
        self._stale_max = stale_max_seconds
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
            # Hub caído: se degrada con la copia cacheada, pero NO para siempre
            # (#163). Antes este branch no miraba la expiración: a un usuario al
            # que le revocaban el acceso durante una caída larga del Hub le
            # seguían valiendo sus roles viejos mientras el proceso no
            # reiniciara — o sea, sin límite.
            #
            # `cached[0]` es cuándo venció el TTL normal; se admite servirla
            # hasta `stale_max` DESPUÉS de eso. Pasado ese punto se falla
            # cerrado, igual que en la primera llamada sin cache: preferimos
            # dejar afuera a alguien con acceso legítimo a dejar adentro a
            # alguien a quien se lo sacaron.
            if cached and now - cached[0] <= self._stale_max:
                return cached[1]
            if cached:
                # Se descarta explícitamente para que un Hub que vuelve no
                # reviva una ACL vieja por una carrera.
                self._cache.pop(email, None)
            raise PlatformError(f"no se pudo consultar la ACL del Hub: {exc}") from exc
        self._cache[email] = (now + self._ttl, data)
        return data
