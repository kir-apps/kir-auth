"""Guarda de origen: los headers de identidad sólo valen si vienen del proxy.

Lo que se fija:
- con la guarda configurada, un header de identidad desde otra IP es 403 y
  nunca llega a consultar la ACL (ni cae a `dev_email`);
- sin configurar, el comportamiento es el de antes y hay un aviso, una vez;
- la resolución DNS: TTL, re-resolución si el proxy cambió de IP (con tope),
  falla cerrado si no resuelve, y rechazo si el nombre es ambiguo (alias de red
  repetido en Docker).

Corre con pytest (`pytest tests/`). Sin red: el resolvedor DNS se inyecta.
"""
from __future__ import annotations

import logging

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import kir_auth.fastapi as kfa
from kir_auth import KirAuth
from kir_auth.origen import GuardaDeOrigen, nombres_de

PROXY_IP = "172.18.0.10"
OTRA_IP = "172.18.0.66"
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


def test_una_ipv4_y_una_ipv6_del_mismo_proxy_no_son_ambiguas():
    g, _, _ = _guarda({"proxy": [PROXY_IP, "fd00::10"]})
    assert g.permite(PROXY_IP)
    assert g.permite("fd00::10")


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


def test_resolvedor_real_con_localhost():
    """El resolvedor por default (getaddrinfo) sin red: localhost sale de /etc/hosts."""
    g = GuardaDeOrigen(["localhost"])
    assert g.permite("127.0.0.1")
    assert not g.permite(OTRA_IP)
