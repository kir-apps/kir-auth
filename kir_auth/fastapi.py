"""Integración FastAPI: dependencias para proteger rutas.

Como el sidecar oauth2-proxy ya garantiza que todo request está autenticado,
estas dependencias no redirigen — solo leen la identidad y chequean roles.
"""
from __future__ import annotations

from fastapi import HTTPException, Request, status

from kir_auth.client import PlatformClient, PlatformError
from kir_auth.models import Identity


class KirAuth:
    def __init__(
        self,
        *,
        app_slug: str,
        hub_url: str,
        platform_token: str,
        header_email: str = "x-forwarded-email",
        header_name: str = "x-forwarded-preferred-username",
        dev_email: str | None = None,
    ) -> None:
        """
        dev_email: solo para correr la app local sin sidecar oauth2-proxy.
                   Si está seteado y no llega el header, se usa esa identidad.
                   Dejar en None en producción.
        """
        self.app_slug = app_slug
        self.header_email = header_email
        self.header_name = header_name
        self.dev_email = dev_email
        self.client = PlatformClient(hub_url, app_slug, platform_token)

    def _identity(self, request: Request) -> Identity:
        # oauth2-proxy reverse-proxy manda X-Forwarded-*; X-Auth-Request-* es
        # de modo auth_request. Chequeamos ambos por robustez.
        email = request.headers.get(self.header_email) or request.headers.get(
            "x-auth-request-email"
        )
        name = (
            request.headers.get(self.header_name)
            or request.headers.get("x-auth-request-user")
            or ""
        )
        if not email and self.dev_email:
            email, name = self.dev_email, "Dev User"
        if not email:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "sin identidad — ¿la app está detrás del sidecar oauth2-proxy?",
            )
        try:
            acl = self.client.acl(email)
        except PlatformError:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "no se pudo verificar permisos con el Hub",
            ) from None
        # Bloque `obras` (Fase 3). Ausente si el Hub es viejo → defaults vacíos.
        obras = acl.get("obras") or {}
        return Identity(
            email=acl.get("email", email),
            name=acl.get("name") or name,
            is_platform_admin=bool(acl.get("is_platform_admin")),
            roles=list(acl.get("roles", [])),
            known=bool(acl.get("known", False)),
            obras_general=bool(obras.get("general")),
            obras_codigos=list(obras.get("codigos", [])),
        )

    # ── dependencias FastAPI ──────────────────────────────────────────────
    def optional_user(self, request: Request) -> Identity | None:
        """Identidad si hay sesión, None si no. No bloquea."""
        try:
            return self._identity(request)
        except HTTPException:
            return None

    def require_login(self, request: Request) -> Identity:
        """Exige usuario autenticado. (Detrás de oauth2-proxy siempre lo hay.)"""
        return self._identity(request)

    def require_role(self, *roles: str):
        """Devuelve una dependencia que exige alguno de `roles` en esta app."""

        def dependency(request: Request) -> Identity:
            identity = self._identity(request)
            if identity.has_role(*roles):
                return identity
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"requiere rol {list(roles)} en '{self.app_slug}'",
            )

        return dependency
