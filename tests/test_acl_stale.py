"""El fallback stale de la ACL está acotado (kir-platform#163).

Lo que se fija es una asimetría deliberada: ante un Hub caído, servir una ACL
vencida un rato es **preferible** a echar a todo el mundo por un reinicio; pero
pasado un límite, es **preferible** dejar afuera a alguien con acceso legítimo
que dejar adentro a alguien a quien se lo revocaron.

Sin límite, un usuario dado de baja durante una caída larga del Hub conservaba
sus roles viejos mientras el proceso no reiniciara — o sea, indefinidamente.

Corre con pytest (`pytest tests/`). No necesita red: el transporte se sustituye.
"""
from __future__ import annotations

import httpx
import pytest

from kir_auth.client import PlatformClient, PlatformError

ACL_OK = {"email": "a@kir.com.ar", "name": "A", "is_platform_admin": False,
          "roles": ["gerencial"], "known": True}


class _Hub:
    """Hub simulado: responde bien hasta que se lo apaga."""

    def __init__(self) -> None:
        self.caido = False
        self.llamadas = 0

    def get(self, *_a, **_kw):
        self.llamadas += 1
        if self.caido:
            raise httpx.ConnectError("hub caído")
        return httpx.Response(200, json=ACL_OK,
                              request=httpx.Request("GET", "http://hub/platform/acl"))


@pytest.fixture()
def hub(monkeypatch):
    h = _Hub()
    monkeypatch.setattr(httpx, "get", h.get)
    return h


def _cliente(**kw) -> PlatformClient:
    return PlatformClient("http://hub:8020", "cdg", "tok", **kw)


def test_con_hub_arriba_cachea_y_no_repregunta(hub):
    c = _cliente(cache_ttl_seconds=60)
    assert c.acl("a@kir.com.ar")["roles"] == ["gerencial"]
    c.acl("a@kir.com.ar")
    assert hub.llamadas == 1, "el TTL vigente tiene que evitar la segunda llamada"


def test_hub_caido_dentro_de_la_ventana_degrada_con_el_cache(hub, monkeypatch):
    c = _cliente(cache_ttl_seconds=60, stale_max_seconds=900)
    c.acl("a@kir.com.ar")

    # TTL vencido hace 5 minutos, dentro de los 15 de gracia.
    reloj = [0.0]
    monkeypatch.setattr("kir_auth.client.time.time", lambda: reloj[0])
    c._cache["a@kir.com.ar"] = (0.0, ACL_OK)
    reloj[0] = 300.0
    hub.caido = True

    assert c.acl("a@kir.com.ar")["roles"] == ["gerencial"], \
        "un reinicio del Hub no puede echar a todo el mundo"


def test_pasada_la_ventana_falla_cerrado(hub, monkeypatch):
    """EL chequeo del issue: la revocación no puede quedar sin efecto."""
    c = _cliente(cache_ttl_seconds=60, stale_max_seconds=900)
    reloj = [0.0]
    monkeypatch.setattr("kir_auth.client.time.time", lambda: reloj[0])
    c._cache["a@kir.com.ar"] = (0.0, ACL_OK)
    reloj[0] = 901.0
    hub.caido = True

    with pytest.raises(PlatformError):
        c.acl("a@kir.com.ar")


def test_pasada_la_ventana_el_cache_se_descarta(hub, monkeypatch):
    """Que no reviva por una carrera cuando el Hub vuelve."""
    c = _cliente(cache_ttl_seconds=60, stale_max_seconds=900)
    reloj = [0.0]
    monkeypatch.setattr("kir_auth.client.time.time", lambda: reloj[0])
    c._cache["a@kir.com.ar"] = (0.0, ACL_OK)
    reloj[0] = 901.0
    hub.caido = True
    with pytest.raises(PlatformError):
        c.acl("a@kir.com.ar")

    assert "a@kir.com.ar" not in c._cache


def test_sin_cache_sigue_fallando_cerrado(hub):
    c = _cliente()
    hub.caido = True
    with pytest.raises(PlatformError):
        c.acl("nadie@kir.com.ar")
