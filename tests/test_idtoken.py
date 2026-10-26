"""Verificación del ID token del proxy (opt-in, `IDENTIDAD_JWT_MODO`).

Lo que se fija:
- firma, `iss`, `aud`, `exp` (con margen) y algoritmo fijo;
- JWKS por discovery o URL fija, cacheado, re-descargado ante un `kid` nuevo
  (rotación) con tope, y servido del cache si el proveedor no responde —acotado—;
- en `KirAuth`: "exigir" rechaza (403, 401 si venció, 503 sin claves), el email
  del header tiene que ser el del token, y "observar" nunca cambia el resultado.

Sin red: las claves se generan en el test y la descarga se inyecta.
"""
from __future__ import annotations

import json
import logging
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jwt.algorithms import RSAAlgorithm
from starlette.requests import Request

import kir_auth.fastapi as kfa
from kir_auth import KirAuth
from kir_auth.idtoken import ErrorJWKS, TokenInvalido, VerificadorIdToken

ISSUER = "https://idp.example.com/tenant-de-prueba/v2.0"
AUD = "cliente-de-prueba"
JWKS_URL = "https://idp.example.com/tenant-de-prueba/keys"
DISCOVERY = ISSUER + "/.well-known/openid-configuration"


def _clave():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


K1, K2, OTRA = _clave(), _clave(), _clave()


def _jwk(privada, kid: str) -> dict:
    d = json.loads(RSAAlgorithm.to_jwk(privada.public_key()))
    d.update(kid=kid, use="sig")
    return d


def _token(privada=K1, kid="k1", alg="RS256", **claims) -> str:
    ahora = int(time.time())
    base = {"iss": ISSUER, "aud": AUD, "iat": ahora, "nbf": ahora, "exp": ahora + 3600,
            "preferred_username": "Ana@Example.com", "name": "Ana"}
    base.update(claims)
    base = {k: v for k, v in base.items() if v is not None}
    return jwt.encode(base, privada, algorithm=alg, headers={"kid": kid} if kid else None)


class _IdP:
    """Proveedor falso: discovery + JWKS, con contador y apagado."""

    def __init__(self, claves: list[dict]) -> None:
        self.claves = claves
        self.caido = False
        self.descargas: list[str] = []
        self.discovery = {"issuer": ISSUER, "jwks_uri": JWKS_URL}

    def __call__(self, url: str) -> dict:
        self.descargas.append(url)
        if self.caido:
            raise httpx.ConnectError("idp caído")
        if url == DISCOVERY:
            return self.discovery
        if url == JWKS_URL:
            return {"keys": list(self.claves)}
        raise httpx.HTTPStatusError("404", request=httpx.Request("GET", url),
                                    response=httpx.Response(404))


class _Reloj:
    def __init__(self) -> None:
        self.t = 5000.0

    def __call__(self) -> float:
        return self.t


def _verificador(idp=None, **kw):
    idp = idp or _IdP([_jwk(K1, "k1")])
    reloj = _Reloj()
    v = VerificadorIdToken(issuer=ISSUER, audiencias=AUD, descargar=idp, reloj=reloj, **kw)
    return v, idp, reloj


# ── VerificadorIdToken ───────────────────────────────────────────────────────

def test_token_valido_devuelve_claims_y_emails():
    v, idp, _ = _verificador()
    claims = v.verificar(_token())
    assert claims["name"] == "Ana"
    assert v.emails(claims) == ["ana@example.com"]
    assert idp.descargas == [DISCOVERY, JWKS_URL]


def test_emails_en_el_orden_configurado_y_sin_repetir():
    v, _, _ = _verificador()
    claims = v.verificar(_token(email="ana.b@example.com"))
    assert v.emails(claims) == ["ana.b@example.com", "ana@example.com"]
    v2, _, _ = _verificador(claims_email="preferred_username")
    assert v2.emails(claims) == ["ana@example.com"]


@pytest.mark.parametrize("claims,motivo", [
    ({"aud": "otra-app"}, "audiencia"),
    ({"iss": "https://idp.example.com/otro-tenant/v2.0"}, "emisor"),
    ({"exp": None}, "inválido"),
    ({"iat": None}, "inválido"),
])
def test_claims_que_no_cuadran_se_rechazan(claims, motivo):
    v, _, _ = _verificador()
    with pytest.raises(TokenInvalido, match=motivo):
        v.verificar(_token(**claims))


def test_vencido_se_marca_como_vencido_y_el_margen_se_respeta():
    v, _, _ = _verificador(leeway_seconds=60)
    ahora = int(time.time())
    with pytest.raises(TokenInvalido) as exc:
        v.verificar(_token(exp=ahora - 120, iat=ahora - 4000, nbf=ahora - 4000))
    assert exc.value.vencido
    assert v.verificar(_token(exp=ahora - 30))  # dentro del margen


def test_firma_de_otra_clave_con_el_mismo_kid():
    v, _, _ = _verificador()
    with pytest.raises(TokenInvalido, match="firma"):
        v.verificar(_token(privada=OTRA, kid="k1"))


def test_alg_none_y_hs256_con_la_clave_publica_se_rechazan():
    """La confusión de algoritmos: el alg lo elige quien arma el token."""
    v, _, _ = _verificador()
    sin_firma = jwt.encode({"iss": ISSUER, "aud": AUD, "exp": int(time.time()) + 60},
                           None, algorithm="none", headers={"kid": "k1"})
    with pytest.raises(TokenInvalido, match="algoritmo"):
        v.verificar(sin_firma)
    import base64
    import hashlib
    import hmac
    cab = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": "k1"}).encode()).rstrip(b"=")
    cue = base64.urlsafe_b64encode(json.dumps({"iss": ISSUER, "aud": AUD}).encode()).rstrip(b"=")
    firma = base64.urlsafe_b64encode(
        hmac.new(json.dumps(_jwk(K1, "k1")).encode(), cab + b"." + cue, hashlib.sha256).digest()
    ).rstrip(b"=")
    with pytest.raises(TokenInvalido, match="algoritmo"):
        v.verificar(b".".join([cab, cue, firma]).decode())


def test_sin_kid_o_basura():
    v, _, _ = _verificador()
    with pytest.raises(TokenInvalido, match="kid"):
        v.verificar(_token(kid=None))
    with pytest.raises(TokenInvalido, match="no es un JWT"):
        v.verificar("esto-no-es-un-jwt")


def test_rotacion_kid_nuevo_re_descarga_una_vez():
    idp = _IdP([_jwk(K1, "k1")])
    v, _, reloj = _verificador(idp)
    v.verificar(_token())
    idp.claves.append(_jwk(K2, "k2"))
    reloj.t += 61
    assert v.verificar(_token(privada=K2, kid="k2"))
    assert idp.descargas.count(JWKS_URL) == 2


def test_kid_inventado_no_dispara_una_descarga_por_pedido():
    v, idp, reloj = _verificador()
    v.verificar(_token())
    for i in range(20):
        with pytest.raises(TokenInvalido, match="kid"):
            v.verificar(_token(privada=OTRA, kid=f"inventado-{i}"))
    assert idp.descargas.count(JWKS_URL) == 1
    reloj.t += 61
    with pytest.raises(TokenInvalido):
        v.verificar(_token(privada=OTRA, kid="inventado-x"))
    assert idp.descargas.count(JWKS_URL) == 2


def test_cache_de_claves_vence_por_ttl():
    v, idp, reloj = _verificador(jwks_ttl_seconds=3600)
    v.verificar(_token())
    reloj.t += 1800
    v.verificar(_token())
    assert idp.descargas.count(JWKS_URL) == 1
    reloj.t += 1801
    v.verificar(_token())
    assert idp.descargas.count(JWKS_URL) == 2


def test_proveedor_caido_sirve_el_cache_acotado():
    v, idp, reloj = _verificador(jwks_ttl_seconds=3600, jwks_stale_max_seconds=7200)
    v.verificar(_token())
    idp.caido = True
    reloj.t += 3600 + 100
    assert v.verificar(_token()), "una caída del proveedor no echa a todos"
    reloj.t += 7200
    with pytest.raises(ErrorJWKS):
        v.verificar(_token())


def test_sin_cache_y_proveedor_caido_falla_cerrado():
    idp = _IdP([_jwk(K1, "k1")])
    idp.caido = True
    v, _, _ = _verificador(idp)
    with pytest.raises(ErrorJWKS):
        v.verificar(_token())


def test_discovery_de_otro_emisor_no_se_usa():
    idp = _IdP([_jwk(K1, "k1")])
    idp.discovery = {"issuer": "https://otro.example.com/v2.0", "jwks_uri": JWKS_URL}
    v, _, _ = _verificador(idp)
    with pytest.raises(ErrorJWKS, match="otro issuer"):
        v.verificar(_token())
    assert JWKS_URL not in idp.descargas


def test_jwks_url_fija_saltea_el_discovery():
    v, idp, _ = _verificador(jwks_url=JWKS_URL)
    v.verificar(_token())
    assert idp.descargas == [JWKS_URL]


def test_claves_que_no_son_rsa_de_firma_se_ignoran():
    enc = dict(_jwk(K2, "k2"), use="enc")
    v, _, _ = _verificador(_IdP([enc, {"kty": "EC", "kid": "e"}, _jwk(K1, "k1")]))
    v.verificar(_token())
    with pytest.raises(TokenInvalido, match="kid"):
        v.verificar(_token(privada=K2, kid="k2"))


def test_varias_audiencias():
    v, _, _ = _verificador()
    v2 = VerificadorIdToken(issuer=ISSUER, audiencias="a, cliente-de-prueba",
                            descargar=_IdP([_jwk(K1, "k1")]))
    assert v2.verificar(_token())
    with pytest.raises(TokenInvalido):
        v.verificar(_token(aud="a"))


def test_config_incompleta_no_construye():
    with pytest.raises(ValueError):
        VerificadorIdToken(issuer="", audiencias=AUD)
    with pytest.raises(ValueError):
        VerificadorIdToken(issuer=ISSUER, audiencias=" , ")


def test_sin_pyjwt_falla_al_construir(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "jwt", None)
    with pytest.raises(RuntimeError, match=r"\[jwt\]"):
        VerificadorIdToken(issuer=ISSUER, audiencias=AUD)


# ── KirAuth ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _sin_env(monkeypatch):
    for var in ("IDENTIDAD_SOLO_DESDE", "FORWARDED_ALLOW_IPS", "IDENTIDAD_JWT_MODO",
                "IDENTIDAD_JWT_ISSUER", "IDENTIDAD_JWT_AUDIENCIA", "IDENTIDAD_JWT_JWKS_URL",
                "IDENTIDAD_JWT_CLAIMS_EMAIL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(kfa, "_avisado_sin_guarda", False)


def _request(headers: dict[str, str] | None = None, ip: str = "172.18.0.10") -> Request:
    return Request({
        "type": "http", "method": "GET", "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": (ip, 40000),
    })


def _auth(monkeypatch, modo="exigir", idp=None, **kw) -> KirAuth:
    v, _, _ = _verificador(idp)
    auth = KirAuth(app_slug="demo", hub_url="http://hub", platform_token="t",
                   verificador_jwt=v, jwt_modo=modo, identidad_solo_desde=None, **kw)
    monkeypatch.setattr(auth.client, "acl", lambda email: {
        "email": email, "name": "", "is_platform_admin": False, "roles": ["editor"], "known": True})
    return auth


def _con(token=None, email="ana@example.com"):
    h = {}
    if email:
        h["X-Forwarded-Email"] = email
    if token:
        h["Authorization"] = f"Bearer {token}"
    return _request(h)


def test_exigir_header_y_token_que_coinciden(monkeypatch):
    user = _auth(monkeypatch).require_login(_con(_token(), email="ANA@example.com"))
    assert user.email == "ANA@example.com"
    assert user.name == "Ana"


def test_exigir_header_sin_token_es_403_sin_consultar_la_acl(monkeypatch):
    """EL chequeo del issue: el header solo ya no alcanza."""
    auth = _auth(monkeypatch)
    llamadas = []
    monkeypatch.setattr(auth.client, "acl", lambda e: llamadas.append(e))
    with pytest.raises(HTTPException) as exc:
        auth.require_login(_con(None, email="jefe@example.com"))
    assert exc.value.status_code == 403
    assert llamadas == []


def test_exigir_token_valido_de_otra_persona_no_sirve_con_otro_header(monkeypatch):
    with pytest.raises(HTTPException) as exc:
        _auth(monkeypatch).require_login(_con(_token(), email="jefe@example.com"))
    assert exc.value.status_code == 403


def test_exigir_token_forjado_es_403(monkeypatch):
    with pytest.raises(HTTPException) as exc:
        _auth(monkeypatch).require_login(_con(_token(privada=OTRA)))
    assert exc.value.status_code == 403


def test_exigir_token_vencido_es_401_para_que_re_loguee(monkeypatch):
    ahora = int(time.time())
    with pytest.raises(HTTPException) as exc:
        _auth(monkeypatch).require_login(
            _con(_token(exp=ahora - 600, iat=ahora - 4000, nbf=ahora - 4000)))
    assert exc.value.status_code == 401


def test_exigir_sin_claves_del_proveedor_es_503(monkeypatch):
    idp = _IdP([_jwk(K1, "k1")])
    idp.caido = True
    with pytest.raises(HTTPException) as exc:
        _auth(monkeypatch, idp=idp).require_login(_con(_token()))
    assert exc.value.status_code == 503


def test_exigir_solo_token_toma_el_email_del_token(monkeypatch):
    user = _auth(monkeypatch).require_login(_con(_token(), email=None))
    assert user.email == "ana@example.com"


def test_exigir_sin_identidad_sigue_como_antes(monkeypatch):
    """Healthchecks y X-Platform-Token: ni header ni token, nada cambia."""
    auth = _auth(monkeypatch, dev_email="dev@example.com")
    assert auth.require_login(_request({"X-Platform-Token": "t"})).email == "dev@example.com"
    auth2 = _auth(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        auth2.require_login(_request())
    assert exc.value.status_code == 401


def test_otro_esquema_de_authorization_no_es_un_token(monkeypatch):
    with pytest.raises(HTTPException) as exc:
        _auth(monkeypatch).require_login(_request({"X-Forwarded-Email": "ana@example.com",
                                                   "Authorization": "Basic YTpi"}))
    assert exc.value.status_code == 403


def test_observar_nunca_cambia_el_resultado_y_loguea_acotado(monkeypatch, caplog):
    auth = _auth(monkeypatch, modo="observar")
    with caplog.at_level(logging.INFO, logger="kir_auth"):
        for _ in range(5):
            assert auth.require_login(_con(None, email="jefe@example.com")).email == "jefe@example.com"
        assert auth.require_login(_con(_token(privada=OTRA))).email == "ana@example.com"
        assert auth.require_login(_con(_token(), email="otro@example.com")).email == "otro@example.com"
        assert auth.require_login(_con(_token())).email == "ana@example.com"
        assert auth.require_login(_con(_token())).email == "ana@example.com"
    assert caplog.text.count("no trae el ID token") == 1
    assert "firma inválida" in caplog.text
    assert "no es el del token" in caplog.text
    assert caplog.text.count("primer ID token verificado bien") == 1


def test_observar_solo_token_no_inventa_identidad(monkeypatch):
    with pytest.raises(HTTPException) as exc:
        _auth(monkeypatch, modo="observar").require_login(_con(_token(), email=None))
    assert exc.value.status_code == 401


def test_jwt_y_guarda_juntas(monkeypatch):
    auth = _auth(monkeypatch)
    from kir_auth.origen import GuardaDeOrigen
    auth.guarda = GuardaDeOrigen(["proxy"], resolver=lambda n: ["172.18.0.10"])
    assert auth.require_login(_con(_token()))
    with pytest.raises(HTTPException) as exc:
        auth.require_login(_request({"Authorization": f"Bearer {_token()}"}, ip="172.18.0.66"))
    assert exc.value.status_code == 403


# ── configuración por entorno ────────────────────────────────────────────────

def _auth_env(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return KirAuth(app_slug="demo", hub_url="http://hub", platform_token="t")


def test_apagado_por_default(monkeypatch):
    auth = _auth_env(monkeypatch)
    assert auth.verificador_jwt is None and auth.jwt_modo is None


def test_entorno_completo(monkeypatch):
    auth = _auth_env(monkeypatch, IDENTIDAD_JWT_MODO="Observar", IDENTIDAD_JWT_ISSUER=ISSUER,
                     IDENTIDAD_JWT_AUDIENCIA=f"{AUD},otra", IDENTIDAD_JWT_JWKS_URL=JWKS_URL,
                     IDENTIDAD_JWT_CLAIMS_EMAIL="email")
    v = auth.verificador_jwt
    assert auth.jwt_modo == "observar"
    assert v.issuer == ISSUER and v.audiencias == (AUD, "otra") and v.claims_email == ("email",)


def test_modo_sin_issuer_o_audiencia_no_arranca(monkeypatch):
    with pytest.raises(ValueError, match="IDENTIDAD_JWT_AUDIENCIA"):
        _auth_env(monkeypatch, IDENTIDAD_JWT_MODO="exigir", IDENTIDAD_JWT_ISSUER=ISSUER)


def test_modo_invalido_no_arranca(monkeypatch):
    with pytest.raises(ValueError, match="observar"):
        _auth_env(monkeypatch, IDENTIDAD_JWT_MODO="si", IDENTIDAD_JWT_ISSUER=ISSUER,
                  IDENTIDAD_JWT_AUDIENCIA=AUD)


def test_construir_no_sale_a_la_red(monkeypatch):
    """El discovery y el JWKS se bajan en el primer pedido, no al importar la app."""
    def explota(*a, **k):
        raise AssertionError("salió a la red al construir")
    monkeypatch.setattr(httpx, "get", explota)
    _auth_env(monkeypatch, IDENTIDAD_JWT_MODO="exigir", IDENTIDAD_JWT_ISSUER=ISSUER,
              IDENTIDAD_JWT_AUDIENCIA=AUD)
