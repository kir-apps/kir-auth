"""Integración FastAPI: dependencias para proteger rutas.

Como el sidecar oauth2-proxy ya garantiza que todo request está autenticado,
estas dependencias no redirigen — solo leen la identidad y chequean roles.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Iterable

from fastapi import HTTPException, Request, status

from kir_auth.client import PlatformClient, PlatformError
from kir_auth.models import Identity
from kir_auth.origen import GuardaDeOrigen, nombres_de

log = logging.getLogger("kir_auth")

# Valor centinela: "leé la opción del entorno". `None` explícito la apaga.
_DEL_ENTORNO: object = object()

ENV_SOLO_DESDE = "IDENTIDAD_SOLO_DESDE"

# El aviso de "guarda apagada" sale una vez por proceso, no una por instancia:
# hay apps que crean varios KirAuth.
_avisado_sin_guarda = False


def _avisar_sin_guarda() -> None:
    global _avisado_sin_guarda
    if _avisado_sin_guarda:
        return
    _avisado_sin_guarda = True
    log.warning(
        "kir_auth: %s no está configurada; se aceptan los headers de identidad "
        "de cualquier par que llegue al puerto de la app. Configurala con el "
        "nombre del proxy de autenticación (ver README, «Guarda de origen»).",
        ENV_SOLO_DESDE,
    )


def _forwarded_allow_ips_abierto() -> bool:
    valor = os.environ.get("FORWARDED_ALLOW_IPS", "")
    return any(p.strip() == "*" for p in valor.split(","))


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
        identidad_solo_desde: str | Iterable[str] | None = _DEL_ENTORNO,  # type: ignore[assignment]
    ) -> None:
        """
        dev_email: solo para correr la app local sin sidecar oauth2-proxy.
                   Si está seteado y no llega el header, se usa esa identidad.
                   Dejar en None en producción.
        identidad_solo_desde: nombre(s) DNS del proxy de autenticación. Si está,
                   los headers de identidad sólo se aceptan cuando la IP del par
                   es la de ese proxy; si no, 403. Por default sale de la
                   variable de entorno IDENTIDAD_SOLO_DESDE (separada por comas);
                   `None` explícito la apaga. Sin configurar, el comportamiento
                   es el de siempre y se loguea un aviso una vez.
        """
        self.app_slug = app_slug
        self.header_email = header_email
        self.header_name = header_name
        self.dev_email = dev_email
        self.client = PlatformClient(hub_url, app_slug, platform_token)

        if identidad_solo_desde is _DEL_ENTORNO:
            identidad_solo_desde = os.environ.get(ENV_SOLO_DESDE, "")
        nombres = nombres_de(identidad_solo_desde)  # type: ignore[arg-type]
        self.guarda: GuardaDeOrigen | None = GuardaDeOrigen(nombres) if nombres else None
        if self.guarda is None:
            _avisar_sin_guarda()
        elif _forwarded_allow_ips_abierto():
            # Con FORWARDED_ALLOW_IPS=* uvicorn/gunicorn toman la IP del par de
            # X-Forwarded-For, que manda el cliente: la guarda se falsea con un
            # header. Mejor no arrancar que creer que hay guarda.
            raise ValueError(
                f"{ENV_SOLO_DESDE} está configurada pero FORWARDED_ALLOW_IPS=* "
                "deja falsear la IP del par con X-Forwarded-For; sacá el '*'."
            )
        if self.guarda is not None and dev_email:
            log.warning(
                "kir_auth: dev_email y %s están las dos configuradas; dev_email "
                "sólo aplica a pedidos sin headers de identidad.",
                ENV_SOLO_DESDE,
            )

    def _origen_valido(self, request: Request) -> bool:
        if self.guarda is None:
            return True
        ip = request.client.host if request.client else None
        if self.guarda.permite(ip):
            return True
        log.warning(
            "kir_auth: identidad rechazada; el pedido trae headers de identidad "
            "pero vino de %s, no del proxy (%s).",
            ip,
            ", ".join(self.guarda.nombres),
        )
        return False

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
        # Los headers de identidad sólo valen si los puso el proxy. 403 y no 401:
        # un 401 hace que algunos frontends manden a re-loguear, y si la guarda
        # rechaza a todos (nombre mal configurado) eso sería un bucle. Tampoco se
        # cae a dev_email: un header falso nunca se convierte en otra identidad.
        if email and not self._origen_valido(request):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "identidad rechazada: el pedido no vino del proxy de autenticación",
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
            phone=acl.get("phone"),
            admin_sections=list(acl.get("admin_sections", [])),
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
