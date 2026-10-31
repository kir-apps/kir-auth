"""Guarda de origen: los headers de identidad sólo valen si vienen del proxy.

Lo que se fija:
- con la guarda configurada, un header de identidad desde otra IP es 403 y
  nunca llega a consultar la ACL (ni cae a `dev_email`);
- sin configurar, el comportamiento es el de antes y hay un aviso, una vez;
- la resolución DNS: TTL, re-resolución si el proxy cambió de IP (con tope),
  falla cerrado si no resuelve, y rechazo si el nombre es ambiguo (alias de red
  repetido en Docker);
- un par atado a emails (`par=email1;email2`, kir-auth#8) sólo puede afirmar
  esos: otro email es 403 sin consultar la ACL, el chequeo de par va primero,
  y una config que no se entiende no deja arrancar.

Corre con pytest (`pytest tests/`). Sin red: el resolvedor DNS se inyecta.
"""
from __future__ import annotations

import logging

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import kir_auth.fastapi as kfa
from kir_auth import KirAuth
from kir_auth.origen import GuardaDeOrigen, nombres_de, pares_de

PROXY_IP = "172.18.0.10"
OTRA_IP = "172.18.0.66"
BARRIDO_IP = "172.18.0.20"
BARRIDO_EMAIL = "barrido@example.com"
ACL = {"email": "a@example.com", "name": "A", "is_platform_admin": False,
       "roles": ["editor"], "known": True}


def _request(ip: str | None, headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": (ip, 40000) if ip else None,
    }
    return Request(scope)


class _DNS:
    """Resolvedor falso: nombre -> lista de IPs (o excepción)."""

    def __init__(self, tabla: dict[str, list[str] | Exception]) -> None:
        self.tabla = tabla
        self.consultas = 0

    def __call__(self, nombre: str) -> list[str]:
        self.consultas += 1
        valor = self.tabla.get(nombre, OSError("no resuelve"))
        if isinstance(valor, Exception):
            raise valor
        return valor


class _Reloj:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def _sin_env(monkeypatch):
    monkeypatch.delenv("IDENTIDAD_SOLO_DESDE", raising=False)
    monkeypatch.delenv("FORWARDED_ALLOW_IPS", raising=False)
    monkeypatch.setattr(kfa, "_avisado_sin_guarda", False)


def _auth(monkeypatch, *, dns: _DNS | None = None, **kw) -> KirAuth:
    auth = KirAuth(app_slug="demo", hub_url="http://hub", platform_token="t", **kw)
    if dns is not None and auth.guarda is not None:
        auth.guarda._resolver = dns
    llamadas: list[str] = []

    def acl(email):
        llamadas.append(email)
        return dict(ACL, email=email)

    monkeypatch.setattr(auth.client, "acl", acl)
    auth.llamadas_acl = llamadas  # type: ignore[attr-defined]
    return auth


# ── KirAuth con la guarda ────────────────────────────────────────────────────

def test_header_desde_el_proxy_pasa(monkeypatch):
    auth = _auth(monkeypatch, dns=_DNS({"demo-oauth2": [PROXY_IP]}),
                 identidad_solo_desde="demo-oauth2")
    user = auth.require_login(_request(PROXY_IP, {"X-Forwarded-Email": "a@example.com"}))
    assert user.email == "a@example.com"


def test_header_desde_otro_contenedor_es_403_y_no_consulta_la_acl(monkeypatch, caplog):
    """EL chequeo del issue: un header forjado no obtiene los roles de nadie."""
    auth = _auth(monkeypatch, dns=_DNS({"demo-oauth2": [PROXY_IP]}),
                 identidad_solo_desde="demo-oauth2")
    with caplog.at_level(logging.WARNING, logger="kir_auth"):
        with pytest.raises(HTTPException) as exc:
            auth.require_login(_request(OTRA_IP, {"X-Forwarded-Email": "jefe@example.com"}))
    assert exc.value.status_code == 403
    assert auth.llamadas_acl == []
    assert OTRA_IP in caplog.text


@pytest.mark.parametrize("header", ["X-Forwarded-Email", "X-Auth-Request-Email"])
def test_los_dos_headers_de_identidad_estan_cubiertos(monkeypatch, header):
    auth = _auth(monkeypatch, dns=_DNS({"demo-oauth2": [PROXY_IP]}),
                 identidad_solo_desde="demo-oauth2")
    with pytest.raises(HTTPException) as exc:
        auth.require_login(_request(OTRA_IP, {header: "jefe@example.com"}))
    assert exc.value.status_code == 403


def test_require_role_y_optional_user_tambien(monkeypatch):
    auth = _auth(monkeypatch, dns=_DNS({"demo-oauth2": [PROXY_IP]}),
                 identidad_solo_desde="demo-oauth2")
    falso = _request(OTRA_IP, {"X-Forwarded-Email": "jefe@example.com"})
    with pytest.raises(HTTPException) as exc:
        auth.require_role("editor")(falso)
    assert exc.value.status_code == 403
    assert auth.optional_user(falso) is None


def test_sin_headers_de_identidad_no_cambia_nada(monkeypatch):
    """Healthchecks y llamadas con X-Platform-Token no traen identidad: siguen igual."""
    auth = _auth(monkeypatch, dns=_DNS({"demo-oauth2": [PROXY_IP]}),
                 identidad_solo_desde="demo-oauth2")
    req = _request("127.0.0.1", {"X-Platform-Token": "t"})
    assert auth.optional_user(req) is None
    with pytest.raises(HTTPException) as exc:
        auth.require_login(req)
    assert exc.value.status_code == 401


def test_header_forjado_no_cae_a_dev_email(monkeypatch):
    auth = _auth(monkeypatch, dns=_DNS({"demo-oauth2": [PROXY_IP]}),
                 identidad_solo_desde="demo-oauth2", dev_email="dev@example.com")
    with pytest.raises(HTTPException) as exc:
        auth.require_login(_request(OTRA_IP, {"X-Forwarded-Email": "jefe@example.com"}))
    assert exc.value.status_code == 403
    # Sin headers, dev_email sigue funcionando como siempre (dev local).
    assert auth.require_login(_request(OTRA_IP)).email == "dev@example.com"


def test_sin_ip_de_par_se_rechaza(monkeypatch):
    auth = _auth(monkeypatch, dns=_DNS({"demo-oauth2": [PROXY_IP]}),
                 identidad_solo_desde="demo-oauth2")
    with pytest.raises(HTTPException) as exc:
        auth.require_login(_request(None, {"X-Forwarded-Email": "a@example.com"}))
    assert exc.value.status_code == 403


def test_varios_proxies_separados_por_coma(monkeypatch):
    auth = _auth(monkeypatch, dns=_DNS({"p1": ["10.0.0.1"], "p2": ["10.0.0.2"]}),
                 identidad_solo_desde=" p1 , p2 ,")
    assert auth.guarda.nombres == ("p1", "p2")
    assert auth.require_login(_request("10.0.0.2", {"X-Forwarded-Email": "a@example.com"}))


# ── configuración ────────────────────────────────────────────────────────────

def test_sale_del_entorno_por_default(monkeypatch):
    monkeypatch.setenv("IDENTIDAD_SOLO_DESDE", "demo-oauth2")
    auth = _auth(monkeypatch)
    assert auth.guarda is not None and auth.guarda.nombres == ("demo-oauth2",)


def test_none_explicito_apaga_aunque_haya_entorno(monkeypatch):
    monkeypatch.setenv("IDENTIDAD_SOLO_DESDE", "demo-oauth2")
    assert _auth(monkeypatch, identidad_solo_desde=None).guarda is None


def test_sin_configurar_es_el_comportamiento_de_antes_con_un_aviso(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger="kir_auth"):
        auth = _auth(monkeypatch)
        _auth(monkeypatch)
        _auth(monkeypatch, identidad_solo_desde="  ")
    assert auth.guarda is None
    assert caplog.text.count("IDENTIDAD_SOLO_DESDE no está configurada") == 1
    user = auth.require_login(_request(OTRA_IP, {"X-Forwarded-Email": "a@example.com"}))
    assert user.email == "a@example.com"


def test_forwarded_allow_ips_abierto_no_arranca(monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1,*")
    with pytest.raises(ValueError, match="FORWARDED_ALLOW_IPS"):
        _auth(monkeypatch, identidad_solo_desde="demo-oauth2")
    # Sin guarda no se exige nada: no se rompe a quien no la habilitó.
    assert _auth(monkeypatch).guarda is None


# ── GuardaDeOrigen: resolución DNS ───────────────────────────────────────────

def _guarda(tabla, **kw):
    dns = _DNS(tabla)
    reloj = _Reloj()
    return GuardaDeOrigen(["proxy"], resolver=dns, reloj=reloj, **kw), dns, reloj


def test_cachea_dentro_del_ttl():
    g, dns, reloj = _guarda({"proxy": [PROXY_IP]})
    assert g.permite(PROXY_IP)
    reloj.t += 5
    assert g.permite(PROXY_IP)
    assert dns.consultas == 1
    reloj.t += 6
    assert g.permite(PROXY_IP)
    assert dns.consultas == 2


def test_proxy_recreado_con_otra_ip_se_reconoce_sin_esperar_el_ttl():
    g, dns, reloj = _guarda({"proxy": [PROXY_IP]})
    assert g.permite(PROXY_IP)
    dns.tabla["proxy"] = ["172.18.0.11"]
    reloj.t += 2
    assert g.permite("172.18.0.11")
    # y la IP vieja deja de valer en cuanto se re-resolvió
    assert not g.permite(PROXY_IP)


def test_la_re_resolucion_forzada_tiene_tope():
    g, dns, reloj = _guarda({"proxy": [PROXY_IP]})
    g.permite(PROXY_IP)
    for _ in range(50):
        assert not g.permite(OTRA_IP)
    assert dns.consultas == 1, "una IP ajena no puede disparar un DNS por pedido"
    reloj.t += 1.5
    assert not g.permite(OTRA_IP)
    assert dns.consultas == 2


def test_nombre_que_no_resuelve_falla_cerrado(caplog):
    g, _, _ = _guarda({})
    with caplog.at_level(logging.WARNING, logger="kir_auth"):
        assert not g.permite(PROXY_IP)
    assert "no se pudo resolver" in caplog.text


def test_nombre_ambiguo_se_rechaza_aunque_la_ip_sea_la_del_proxy(caplog):
    """Otro contenedor declaró el nombre del proxy como alias de red: el nombre
    resuelve a dos IPs. Probado en Docker 29 el 2026-10-26: getaddrinfo devuelve las
    dos. Aceptar cualquiera dejaría pasar al impostor."""
    g, _, _ = _guarda({"proxy": [PROXY_IP, OTRA_IP]})
    with caplog.at_level(logging.ERROR, logger="kir_auth"):
        assert not g.permite(OTRA_IP)
        assert not g.permite(PROXY_IP)
    assert "varias IPs" in caplog.text


def test_una_ipv4_y_una_ipv6_tambien_son_ambiguas():
    """Separar por familia dejaría que un alias de la otra familia (un contenedor
    dual-stack que declara el nombre del proxy) pase como origen confiable."""
    g, _, _ = _guarda({"proxy": [PROXY_IP, "fd00::66"]})
    assert not g.permite("fd00::66")
    assert not g.permite(PROXY_IP)


def test_la_misma_ip_repetida_no_es_ambigua():
    """getaddrinfo devuelve una entrada por tipo de socket: la misma IP varias veces."""
    g, _, _ = _guarda({"proxy": [PROXY_IP, PROXY_IP, f"::ffff:{PROXY_IP}"]})
    assert g.permite(PROXY_IP)


def test_ipv4_mapeada_en_ipv6_se_normaliza():
    g, _, _ = _guarda({"proxy": [PROXY_IP]})
    assert g.permite(f"::ffff:{PROXY_IP}")


def test_basura_como_ip_se_rechaza():
    g, _, _ = _guarda({"proxy": [PROXY_IP]})
    assert not g.permite("testclient")
    assert not g.permite("")


def test_sin_nombres_no_se_puede_construir():
    with pytest.raises(ValueError):
        GuardaDeOrigen([" ", ""])


def test_nombres_de():
    assert nombres_de("a, b,a,,") == ("a", "b")
    assert nombres_de(["x", " y "]) == ("x", "y")
    assert nombres_de(None) == ()


def test_resolvedor_real_sin_red():
    """El resolvedor por default (getaddrinfo) con una IP literal: no sale a la red."""
    g = GuardaDeOrigen(["127.0.0.1"])
    assert g.permite("127.0.0.1")
    assert not g.permite(OTRA_IP)


# ── par atado a emails (kir-auth#8) ──────────────────────────────────────────
# El caso: el sidecar afirma cualquier email (validó la sesión); un cliente
# técnico que llega por la red interna con su propia identidad (un barrido)
# sólo puede afirmar la suya, no la de un platform admin.

CON_BARRIDO = f"demo-oauth2,barrido={BARRIDO_EMAIL}"


def _dns_con_barrido() -> _DNS:
    return _DNS({"demo-oauth2": [PROXY_IP], "barrido": [BARRIDO_IP]})


def _auth_barrido(monkeypatch, **kw) -> KirAuth:
    return _auth(monkeypatch, dns=_dns_con_barrido(), identidad_solo_desde=CON_BARRIDO, **kw)


@pytest.mark.parametrize("email", ["a@example.com", "jefe@example.com", BARRIDO_EMAIL])
def test_desde_el_sidecar_pasa_cualquier_email(monkeypatch, email):
    """Caso 1 de la card: el par sin restricción afirma cualquiera, como siempre."""
    auth = _auth_barrido(monkeypatch)
    user = auth.require_login(_request(PROXY_IP, {"X-Forwarded-Email": email}))
    assert user.email == email


@pytest.mark.parametrize("email", [BARRIDO_EMAIL, "  Barrido@EXAMPLE.com ", "BARRIDO@example.com"])
def test_desde_el_barrido_su_email_pasa(monkeypatch, email):
    """Caso 2: el par restringido con su email pasa, sin distinguir mayúsculas
    ni espacios alrededor."""
    auth = _auth_barrido(monkeypatch)
    user = auth.require_login(_request(BARRIDO_IP, {"X-Forwarded-Email": email}))
    assert user.email.strip().lower() == BARRIDO_EMAIL
    assert len(auth.llamadas_acl) == 1


@pytest.mark.parametrize("header", ["X-Forwarded-Email", "X-Auth-Request-Email"])
def test_desde_el_barrido_otro_email_es_403_sin_acl_y_con_log(monkeypatch, caplog, header):
    """Caso 3: otro email desde el par restringido es 403, no llega a la ACL, y
    el log dice el par y el dominio pero no la parte local del email."""
    auth = _auth_barrido(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="kir_auth"):
        with pytest.raises(HTTPException) as exc:
            auth.require_login(_request(BARRIDO_IP, {header: "jefe.admin@example.com"}))
    assert exc.value.status_code == 403
    assert "jefe" not in exc.value.detail
    assert auth.llamadas_acl == []
    registro = [r for r in caplog.records if getattr(r, "motivo", None)
                == "email_no_permitido_para_el_par"]
    assert len(registro) == 1
    r = registro[0]
    assert (r.evento, r.par, r.ip, r.email) == (
        "identidad_rechazada", "barrido", BARRIDO_IP, "***@example.com")
    assert "jefe.admin" not in caplog.text
    assert "barrido" in r.getMessage()


def test_desde_el_barrido_require_role_y_optional_user_tambien(monkeypatch):
    auth = _auth_barrido(monkeypatch)
    falso = _request(BARRIDO_IP, {"X-Forwarded-Email": "jefe@example.com"})
    with pytest.raises(HTTPException) as exc:
        auth.require_role("editor")(falso)
    assert exc.value.status_code == 403
    assert auth.optional_user(falso) is None
    assert auth.llamadas_acl == []


def test_desde_el_barrido_el_email_que_se_usa_es_el_que_se_chequeo(monkeypatch):
    """Con los dos headers, el que cuenta es X-Forwarded-Email: es el que se
    chequea y el que va a la ACL. El otro no se cuela."""
    auth = _auth_barrido(monkeypatch)
    user = auth.require_login(_request(BARRIDO_IP, {
        "X-Forwarded-Email": BARRIDO_EMAIL, "X-Auth-Request-Email": "jefe@example.com"}))
    assert user.email == BARRIDO_EMAIL
    assert auth.llamadas_acl == [BARRIDO_EMAIL]


def test_el_chequeo_de_par_va_primero(monkeypatch, caplog):
    """Desde una IP que no es de ningún par, el email permitido del barrido no
    alcanza: es 403 por el par, no pasa por ser un email conocido."""
    auth = _auth_barrido(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="kir_auth"):
        with pytest.raises(HTTPException) as exc:
            auth.require_login(_request(OTRA_IP, {"X-Forwarded-Email": BARRIDO_EMAIL}))
    assert exc.value.status_code == 403
    assert "no vino del proxy" in exc.value.detail
    assert auth.llamadas_acl == []
    motivos = [getattr(r, "motivo", None) for r in caplog.records]
    assert motivos == ["par_no_confiable"]


def test_el_sidecar_primero_no_resuelve_al_barrido(monkeypatch):
    """Los nombres se prueban en orden y se corta en el primero: el tráfico de
    la gente nunca consulta el DNS del barrido, que no existe la mayor parte
    del día."""
    dns = _DNS({"demo-oauth2": [PROXY_IP]})  # el barrido no está corriendo
    consultados: list[str] = []

    def resolver(nombre):
        consultados.append(nombre)
        return dns(nombre)

    auth = _auth(monkeypatch, dns=resolver, identidad_solo_desde=CON_BARRIDO)
    for _ in range(3):
        auth.require_login(_request(PROXY_IP, {"X-Forwarded-Email": "a@example.com"}))
    assert consultados == ["demo-oauth2"]
    # Y si el barrido no resuelve, desde su IP se falla cerrado.
    with pytest.raises(HTTPException) as exc:
        auth.require_login(_request(BARRIDO_IP, {"X-Forwarded-Email": BARRIDO_EMAIL}))
    assert exc.value.status_code == 403


@pytest.mark.parametrize("headers", [{}, {"X-Forwarded-Email": ""}, {"X-Forwarded-Email": "  "}])
def test_email_vacio_desde_el_barrido_no_es_identidad(monkeypatch, headers):
    """Sin email (o vacío) no hay identidad que afirmar: no llega a la ACL ni
    cae a dev_email con otro nombre."""
    auth = _auth_barrido(monkeypatch)
    with pytest.raises(HTTPException) as exc:
        auth.require_login(_request(BARRIDO_IP, headers))
    # Sin header o vacío: 401 (no hay identidad); sólo espacios: 403 (el par no
    # puede afirmar un email vacío). En ningún caso se consulta la ACL.
    assert exc.value.status_code == (403 if headers.get("X-Forwarded-Email") else 401)
    assert auth.llamadas_acl == []


class _VerificadorFalso:
    """Verificador de ID token que da por bueno cualquier token (con el email del
    platform admin): muestra que la restricción del par no se saltea por token."""

    def verificar(self, token):
        return {"email": "jefe@example.com", "name": "Jefe"}

    def emails(self, claims):
        return [claims["email"]]


def test_par_restringido_sin_header_de_email_con_token_es_403(monkeypatch):
    """Un par restringido que no manda email pero sí un token no puede tomar el
    email del token: la restricción se mira antes, y sin email es 403."""
    auth = _auth_barrido(monkeypatch, verificador_jwt=_VerificadorFalso(), jwt_modo="exigir")
    req = _request(BARRIDO_IP, {"Authorization": "Bearer x.y.z"})
    with pytest.raises(HTTPException) as exc:
        auth.require_login(req)
    assert exc.value.status_code == 403
    assert auth.llamadas_acl == []
    # Desde el sidecar, el mismo pedido pasa con el email del token (lo de siempre).
    assert auth.require_login(
        _request(PROXY_IP, {"Authorization": "Bearer x.y.z"})).email == "jefe@example.com"


def test_varios_emails_por_par(monkeypatch):
    auth = _auth(monkeypatch, dns=_dns_con_barrido(),
                 identidad_solo_desde="demo-oauth2, barrido = uno@example.com ; Dos@Example.com ;")
    for email in ("uno@example.com", "dos@example.com"):
        assert auth.require_login(_request(BARRIDO_IP, {"X-Forwarded-Email": email}))
    with pytest.raises(HTTPException) as exc:
        auth.require_login(_request(BARRIDO_IP, {"X-Forwarded-Email": "tres@example.com"}))
    assert exc.value.status_code == 403


def test_restriccion_desde_el_entorno(monkeypatch):
    monkeypatch.setenv("IDENTIDAD_SOLO_DESDE", CON_BARRIDO)
    auth = _auth(monkeypatch, dns=_dns_con_barrido())
    assert auth.guarda.nombres == ("demo-oauth2", "barrido")
    assert auth.guarda.emails_permitidos("demo-oauth2") is None
    assert auth.guarda.emails_permitidos("barrido") == frozenset({BARRIDO_EMAIL})
    with pytest.raises(HTTPException):
        auth.require_login(_request(BARRIDO_IP, {"X-Forwarded-Email": "jefe@example.com"}))


def test_restriccion_en_codigo_como_lista_o_dict(monkeypatch):
    for config in ([" demo-oauth2", f"barrido={BARRIDO_EMAIL}"],
                   {"demo-oauth2": None, "barrido": [BARRIDO_EMAIL]},
                   {"demo-oauth2": None, "barrido": BARRIDO_EMAIL}):
        auth = _auth(monkeypatch, dns=_dns_con_barrido(), identidad_solo_desde=config)
        assert auth.guarda.pares == {"demo-oauth2": None,
                                     "barrido": frozenset({BARRIDO_EMAIL})}, config


# ── la config: compatibilidad y falla cerrado ────────────────────────────────

@pytest.mark.parametrize("valor, esperado", [
    ("demo-oauth2", {"demo-oauth2": None}),
    (" p1 , p2 ,", {"p1": None, "p2": None}),
    ("a, b,a,,", {"a": None, "b": None}),
    ("p.red1,p.red2", {"p.red1": None, "p.red2": None}),
    ("127.0.0.1", {"127.0.0.1": None}),
    ("A,a", {"A": None, "a": None}),
    ("", {}),
    ("  , ,", {}),
])
def test_sintaxis_de_antes_sin_cambios(valor, esperado):
    """Compatibilidad hacia atrás: la lista de nombres de siempre se parsea igual
    y ningún par queda restringido."""
    assert pares_de(valor) == esperado
    assert nombres_de(valor) == tuple(esperado)


def test_par_sin_restriccion_repetido_se_cuenta_una_vez():
    assert pares_de("demo-oauth2,barrido=x@d.com,demo-oauth2") == {
        "demo-oauth2": None, "barrido": frozenset({"x@d.com"})}


@pytest.mark.parametrize("valor", [
    "barrido=x@d.com,barrido=y@d.com",      # ¿se suman o gana una?
    "barrido=x@d.com,barrido",              # la sin restricción abriría todo
    "barrido,barrido=x@d.com",
    "barrido=x@d.com,BARRIDO=x@d.com",      # DNS no distingue mayúsculas
    "Barrido,barrido=x@d.com",
])
def test_par_repetido_con_restriccion_no_arranca(monkeypatch, valor):
    with pytest.raises(ValueError, match="más de una vez"):
        pares_de(valor)
    monkeypatch.setenv("IDENTIDAD_SOLO_DESDE", valor)
    with pytest.raises(ValueError):
        _auth(monkeypatch)


@pytest.mark.parametrize("valor", [
    "demo-oauth2,barrido=",                 # '=' sin emails: ¿nadie o cualquiera?
    "demo-oauth2,barrido= ; ;",
    "demo-oauth2,=x@d.com",                 # emails sin par
    "demo-oauth2,barrido=no-es-un-email",
    "demo-oauth2,barrido=@d.com",
    "demo-oauth2,barrido=x@",
    "demo-oauth2,barrido=x@d.com@e.com",
    "demo-oauth2,barrido=x@d.com=y@d.com",
    "demo-oauth2,barrido=x @d.com",
    "demo-oauth2,x@d.com",                  # un email donde va un par
    "demo-oauth2,barrido x@d.com",
    "demo-oauth2;barrido",                  # separador de emails entre pares
])
def test_config_mal_escrita_no_arranca(monkeypatch, valor):
    """Caso 4 de la card: no se interpreta, no se ignora: ValueError al
    construir KirAuth, sea por entorno o por parámetro."""
    with pytest.raises(ValueError, match="IDENTIDAD_SOLO_DESDE"):
        _auth(monkeypatch, identidad_solo_desde=valor)
    monkeypatch.setenv("IDENTIDAD_SOLO_DESDE", valor)
    with pytest.raises(ValueError, match="IDENTIDAD_SOLO_DESDE"):
        _auth(monkeypatch)


@pytest.mark.parametrize("config", [
    {"barrido": ""},
    {"barrido": []},
    {"": "x@d.com"},
    ["demo-oauth2", 5],
])
def test_config_en_codigo_mal_escrita_no_arranca(config):
    with pytest.raises(ValueError):
        GuardaDeOrigen(config)


def test_guarda_puede_afirmar():
    g = GuardaDeOrigen(CON_BARRIDO, resolver=_dns_con_barrido())
    assert g.par(PROXY_IP) == "demo-oauth2"
    assert g.par(BARRIDO_IP) == "barrido"
    assert g.par(OTRA_IP) is None
    assert g.puede_afirmar("demo-oauth2", "cualquiera@example.com")
    assert g.puede_afirmar("barrido", " BARRIDO@example.com")
    assert not g.puede_afirmar("barrido", "jefe@example.com")
    assert not g.puede_afirmar("barrido", None)
    assert not g.puede_afirmar("barrido", "")
