"""Verificación del ID token OIDC que el proxy de autenticación le pasa a la app.

oauth2-proxy con `pass_authorization_header = true` manda al upstream
`Authorization: Bearer <id_token>`: el ID token que el proveedor (p. ej. Entra
ID) firmó para el login de esa sesión. A diferencia de `X-Forwarded-Email`, ese
token no se puede fabricar sin la clave privada del proveedor, así que verificarlo
cierra la suplantación aunque alguien llegue al puerto de la app.

Qué se verifica: firma (RS256, contra el JWKS del proveedor), `iss` exacto,
`aud` dentro de las audiencias configuradas y `exp`/`nbf` con un margen
(`leeway`). El email sale de los claims configurados (por default `email` y
`preferred_username`, que es donde Entra pone el UPN cuando la cuenta no tiene
casilla).

Decisiones que no se deducen del código:

- **Algoritmos fijos (RS256).** El `alg` lo elige quien arma el token: aceptar el
  que venga en el header abre la confusión clásica (un HS256 firmado con la clave
  pública como secreto, o `none`).
- **JWKS cacheado, con re-descarga ante un `kid` desconocido** — así se sigue una
  rotación de claves del proveedor sin reiniciar — **con tope de una descarga por
  minuto**: si no, cualquiera que mande tokens con `kid` inventados dispara una
  descarga por pedido.
- **Si el JWKS no se puede descargar, se siguen usando las claves cacheadas** un
  tiempo acotado (`jwks_stale_max_seconds`); sin claves, se falla cerrado. Misma
  asimetría que la ACL: una caída del proveedor no echa a todos, pero no para
  siempre.
- **Requiere PyJWT** (`pip install 'kir-auth[jwt]'`). Es opcional para que las
  apps que no lo usan no sumen `cryptography`; se importa recién cuando se
  construye un verificador, y si falta, falla al arrancar, no en el primer pedido.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable
from typing import Any

import httpx

log = logging.getLogger("kir_auth")

Descargador = Callable[[str], dict]


class TokenInvalido(Exception):
    """El token no prueba la identidad. `vencido` distingue el caso que un
    re-login arregla (token viejo) de los que no (firma, emisor, audiencia)."""

    def __init__(self, motivo: str, *, vencido: bool = False) -> None:
        super().__init__(motivo)
        self.motivo = motivo
        self.vencido = vencido


class ErrorJWKS(Exception):
    """No hay claves del proveedor para verificar (ni descargadas ni en cache)."""


def descargar_json(url: str) -> dict:
    resp = httpx.get(url, timeout=5.0)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("la respuesta no es un objeto JSON")
    return data


def _lista(valor: str | Iterable[str] | None) -> tuple[str, ...]:
    if valor is None:
        return ()
    partes = valor.split(",") if isinstance(valor, str) else list(valor)
    return tuple(p.strip() for p in partes if p and p.strip())


class VerificadorIdToken:
    def __init__(
        self,
        *,
        issuer: str,
        audiencias: str | Iterable[str],
        jwks_url: str | None = None,
        claims_email: str | Iterable[str] = ("email", "preferred_username"),
        leeway_seconds: float = 60.0,
        jwks_ttl_seconds: float = 6 * 3600,
        jwks_min_redescarga_seconds: float = 60.0,
        jwks_stale_max_seconds: float = 24 * 3600,
        descargar: Descargador | None = None,
        reloj: Callable[[], float] = time.monotonic,
    ) -> None:
        try:
            import jwt  # noqa: F401  (PyJWT)
            from jwt.algorithms import RSAAlgorithm  # noqa: F401  (requiere cryptography)
        except ImportError as exc:
            raise RuntimeError(
                "la verificación del ID token necesita PyJWT con cryptography: "
                "instalá kir-auth con el extra [jwt]"
            ) from exc
        self.issuer = (issuer or "").strip()
        self.audiencias = _lista(audiencias)
        self.claims_email = _lista(claims_email)
        if not self.issuer:
            raise ValueError("VerificadorIdToken necesita el issuer")
        if not self.audiencias:
            raise ValueError("VerificadorIdToken necesita al menos una audiencia")
        if not self.claims_email:
            raise ValueError("VerificadorIdToken necesita al menos un claim de email")
        self.algoritmos = ("RS256",)
        self._jwks_url = (jwks_url or "").strip() or None
        self._leeway = leeway_seconds
        self._ttl = jwks_ttl_seconds
        self._min_redescarga = jwks_min_redescarga_seconds
        self._stale_max = jwks_stale_max_seconds
        self._descargar = descargar or descargar_json
        self._reloj = reloj
        self._claves: dict[str, Any] | None = None
        self._cargadas_en = 0.0
        self._ultimo_intento: float | None = None

    # ── JWKS ─────────────────────────────────────────────────────────────
    def _url_jwks(self) -> str:
        if self._jwks_url:
            return self._jwks_url
        conf = self._descargar(self.issuer.rstrip("/") + "/.well-known/openid-configuration")
        # El documento de discovery tiene que ser del mismo emisor que se exige
        # en los tokens: si no, el JWKS podría ser el de otro.
        if conf.get("issuer") != self.issuer:
            raise ErrorJWKS("el discovery del proveedor declara otro issuer")
        uri = conf.get("jwks_uri")
        if not isinstance(uri, str) or not uri:
            raise ErrorJWKS("el discovery del proveedor no trae jwks_uri")
        self._jwks_url = uri
        return uri

    def _parsear(self, jwks: dict) -> dict[str, Any]:
        from jwt.algorithms import RSAAlgorithm

        claves: dict[str, Any] = {}
        for jwk in jwks.get("keys") or []:
            if not isinstance(jwk, dict):
                continue
            kid = jwk.get("kid")
            if not kid or jwk.get("kty") != "RSA" or jwk.get("use", "sig") != "sig":
                continue
            try:
                claves[kid] = RSAAlgorithm.from_jwk(json.dumps(jwk))
            except Exception:  # noqa: BLE001 — una clave rota no invalida las demás
                log.warning("kir_auth: clave del JWKS ilegible (kid=%s); se ignora", kid)
        return claves

    def _refrescar(self) -> None:
        ahora = self._reloj()
        self._ultimo_intento = ahora
        try:
            claves = self._parsear(self._descargar(self._url_jwks()))
            if not claves:
                raise ErrorJWKS("el JWKS no trae claves RSA de firma")
        except (httpx.HTTPError, ValueError, ErrorJWKS) as exc:
            if self._claves and ahora - self._cargadas_en <= self._ttl + self._stale_max:
                log.warning("kir_auth: no se pudo refrescar el JWKS (%s); sigo con el cache", exc)
                return
            self._claves = None
            raise ErrorJWKS(f"no hay claves para verificar el token: {exc}") from exc
        self._claves = claves
        self._cargadas_en = ahora

    def _puede_redescargar(self) -> bool:
        return (
            self._ultimo_intento is None
            or self._reloj() - self._ultimo_intento >= self._min_redescarga
        )

    def _clave(self, kid: str) -> Any:
        ahora = self._reloj()
        vencidas = self._claves is None or ahora - self._cargadas_en >= self._ttl
        if vencidas and (self._claves is None or self._puede_redescargar()):
            self._refrescar()
        elif self._claves is not None and ahora - self._cargadas_en > self._ttl + self._stale_max:
            # Claves vencidas hace demasiado y sin poder re-descargar todavía.
            self._claves = None
            raise ErrorJWKS("las claves cacheadas del proveedor están demasiado viejas")
        assert self._claves is not None
        clave = self._claves.get(kid)
        if clave is None and self._puede_redescargar():
            # Rotación: el proveedor pudo empezar a firmar con una clave nueva.
            self._refrescar()
            clave = (self._claves or {}).get(kid)
        if clave is None:
            raise TokenInvalido("firmado con una clave (kid) que el proveedor no publica")
        return clave

    # ── verificación ─────────────────────────────────────────────────────
    def verificar(self, token: str) -> dict:
        """Claims del token si es válido; `TokenInvalido` o `ErrorJWKS` si no."""
        import jwt

        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            raise TokenInvalido("no es un JWT") from None
        alg = header.get("alg")
        if alg not in self.algoritmos:
            raise TokenInvalido(f"algoritmo {alg!r} no permitido")
        kid = header.get("kid")
        if not kid or not isinstance(kid, str):
            raise TokenInvalido("el token no dice con qué clave se firmó (kid)")
        clave = self._clave(kid)
        try:
            return jwt.decode(
                token,
                clave,
                algorithms=list(self.algoritmos),
                audience=list(self.audiencias),
                issuer=self.issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            raise TokenInvalido("vencido", vencido=True) from None
        except jwt.InvalidAudienceError:
            raise TokenInvalido("audiencia no aceptada") from None
        except jwt.InvalidIssuerError:
            raise TokenInvalido("emisor no aceptado") from None
        except jwt.InvalidSignatureError:
            raise TokenInvalido("firma inválida") from None
        except jwt.InvalidTokenError as exc:
            raise TokenInvalido(f"token inválido ({type(exc).__name__})") from None

    def emails(self, claims: dict) -> list[str]:
        """Emails que el token prueba, en el orden de `claims_email`, en minúsculas."""
        vistos: list[str] = []
        for claim in self.claims_email:
            valor = claims.get(claim)
            if isinstance(valor, str) and "@" in valor:
                email = valor.strip().lower()
                if email not in vistos:
                    vistos.append(email)
        return vistos
