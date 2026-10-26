"""Integración FastAPI: dependencias para proteger rutas.

Como el sidecar oauth2-proxy ya garantiza que todo request está autenticado,
estas dependencias no redirigen — solo leen la identidad y chequean roles.
"""
from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterable

from fastapi import HTTPException, Request, status

from kir_auth.client import PlatformClient, PlatformError
from kir_auth.models import Identity
from kir_auth.idtoken import ErrorJWKS, TokenInvalido, VerificadorIdToken, sanear
from kir_auth.origen import GuardaDeOrigen, nombres_de

log = logging.getLogger("kir_auth")

# Valor centinela: "leé la opción del entorno". `None` explícito la apaga.
_DEL_ENTORNO: object = object()

ENV_SOLO_DESDE = "IDENTIDAD_SOLO_DESDE"
ENV_JWT_MODO = "IDENTIDAD_JWT_MODO"
ENV_JWT_ISSUER = "IDENTIDAD_JWT_ISSUER"
ENV_JWT_AUDIENCIA = "IDENTIDAD_JWT_AUDIENCIA"
ENV_JWT_JWKS_URL = "IDENTIDAD_JWT_JWKS_URL"
ENV_JWT_CLAIMS_EMAIL = "IDENTIDAD_JWT_CLAIMS_EMAIL"

MODOS_JWT = ("observar", "exigir")
# En modo observar, cada motivo de falla se loguea a lo sumo una vez por este
# intervalo: si el proxy todavía no manda el token, fallan todos los pedidos.
_INTERVALO_AVISO_JWT = 300.0

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


def _verificador_del_entorno() -> VerificadorIdToken | None:
    if not os.environ.get(ENV_JWT_MODO, "").strip():
        return None
    issuer = os.environ.get(ENV_JWT_ISSUER, "").strip()
    audiencia = os.environ.get(ENV_JWT_AUDIENCIA, "").strip()
    if not issuer or not audiencia:
        raise ValueError(
            f"{ENV_JWT_MODO} está configurada pero faltan {ENV_JWT_ISSUER} y/o "
            f"{ENV_JWT_AUDIENCIA}"
        )
    kw = {}
    claims = os.environ.get(ENV_JWT_CLAIMS_EMAIL, "").strip()
    if claims:
        kw["claims_email"] = claims
    return VerificadorIdToken(
        issuer=issuer,
        audiencias=audiencia,
        jwks_url=os.environ.get(ENV_JWT_JWKS_URL, "").strip() or None,
        **kw,
    )


def _bearer(request: Request) -> str | None:
    valor = request.headers.get("authorization", "")
    esquema, _, token = valor.partition(" ")
    if esquema.lower() != "bearer":
        return None
    return token.strip() or None


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
        verificador_jwt: VerificadorIdToken | None = _DEL_ENTORNO,  # type: ignore[assignment]
        jwt_modo: str | None = _DEL_ENTORNO,  # type: ignore[assignment]
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
        verificador_jwt / jwt_modo: verificación del ID token que el proxy manda
                   en `Authorization: Bearer` (ver kir_auth.idtoken). Apagada por
                   default. Por default salen del entorno: IDENTIDAD_JWT_MODO
                   ("observar" | "exigir"), IDENTIDAD_JWT_ISSUER,
                   IDENTIDAD_JWT_AUDIENCIA y, opcionales, IDENTIDAD_JWT_JWKS_URL e
                   IDENTIDAD_JWT_CLAIMS_EMAIL. "observar" verifica y loguea pero
                   no rechaza; "exigir" rechaza.
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
        if jwt_modo is _DEL_ENTORNO:
            jwt_modo = os.environ.get(ENV_JWT_MODO, "")
        self.jwt_modo: str | None = (jwt_modo or "").strip().lower() or None  # type: ignore[union-attr]
        if self.jwt_modo is not None and self.jwt_modo not in MODOS_JWT:
            raise ValueError(f"{ENV_JWT_MODO} tiene que ser uno de {MODOS_JWT}")
        if verificador_jwt is _DEL_ENTORNO:
            verificador_jwt = _verificador_del_entorno() if self.jwt_modo else None
        self.verificador_jwt: VerificadorIdToken | None = verificador_jwt  # type: ignore[assignment]
        if self.jwt_modo and self.verificador_jwt is None:
            raise ValueError(f"{ENV_JWT_MODO}={self.jwt_modo} necesita un verificador")
        if self.verificador_jwt is not None and not self.jwt_modo:
            self.jwt_modo = "exigir"
        self._jwt_avisos: dict[str, float] = {}
        self._jwt_ok_avisado = False

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

    def _avisar_jwt(self, motivo: str, detalle: str | None = None) -> None:
        # `motivo` sale de una lista cerrada (ver kir_auth.idtoken.MOTIVOS y los
        # literales de `_email_del_token`): el dict queda acotado y el
        # rate-limit no se saltea variando el token. El detalle no es clave.
        ahora = time.monotonic()
        ultimo = self._jwt_avisos.get(motivo)
        if ultimo is not None and ahora - ultimo < _INTERVALO_AVISO_JWT:
            return
        self._jwt_avisos[motivo] = ahora
        log.warning(
            "kir_auth: ID token no válido (modo %s): %s%s",
            self.jwt_modo, motivo, f" [{detalle}]" if detalle else "",
        )

    def _email_del_token(self, token: str | None, email: str | None) -> tuple[str | None, str]:
        """(email, nombre del token) que vale para este pedido según el modo JWT.

        En "observar" nunca cambia el resultado: devuelve el email del header y
        sólo loguea lo que en "exigir" sería un rechazo.
        """
        exigir = self.jwt_modo == "exigir"
        assert self.verificador_jwt is not None

        def rechazo(
            motivo: str, codigo: int = status.HTTP_403_FORBIDDEN, detalle: str | None = None
        ) -> tuple[str | None, str]:
            # La respuesta lleva sólo el motivo fijo; el detalle, sólo el log.
            if exigir:
                log.warning(
                    "kir_auth: identidad rechazada por el ID token: %s%s",
                    motivo, f" [{detalle}]" if detalle else "",
                )
                raise HTTPException(codigo, f"identidad rechazada: {motivo}")
            self._avisar_jwt(motivo, detalle)
            return email, ""

        if not token:
            return rechazo("el pedido no trae el ID token del proxy (Authorization: Bearer)")
        try:
            claims = self.verificador_jwt.verificar(token)
        except TokenInvalido as exc:
            # Vencido es 401: un re-login trae un token nuevo. El resto, 403: un
            # re-login no arregla una firma o una audiencia, y sería un bucle.
            codigo = status.HTTP_401_UNAUTHORIZED if exc.vencido else status.HTTP_403_FORBIDDEN
            return rechazo(f"token: {exc.motivo}", codigo, exc.detalle)
        except ErrorJWKS as exc:
            if exigir:
                log.error("kir_auth: no se puede verificar el ID token: %s", sanear(exc))
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "no se pudo verificar la identidad con el proveedor",
                ) from None
            self._avisar_jwt("sin claves del proveedor", sanear(exc))
            return email, ""
        emails = self.verificador_jwt.emails(claims)
        if not emails:
            return rechazo("el token no trae ningún claim de email configurado")
        if email and email.strip().lower() not in emails:
            return rechazo("el email del header no es el del token")
        if not exigir and not self._jwt_ok_avisado:
            self._jwt_ok_avisado = True
            log.info("kir_auth: primer ID token verificado bien (modo observar)")
        nombre = claims.get("name") if isinstance(claims.get("name"), str) else ""
        return (email or emails[0]) if exigir else email, nombre

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
        token = _bearer(request) if self.verificador_jwt is not None else None
        if (email or token) and not self._origen_valido(request):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "identidad rechazada: el pedido no vino del proxy de autenticación",
            )
        # El ID token firmado por el proveedor: con él, un header forjado no
        # alcanza aunque el pedido llegue al puerto de la app. Sólo se mira si
        # el pedido dice traer identidad; los que no (healthchecks, llamadas con
        # X-Platform-Token) siguen igual.
        if self.verificador_jwt is not None and (email or token):
            email, nombre_token = self._email_del_token(token, email)
            name = name or nombre_token
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
