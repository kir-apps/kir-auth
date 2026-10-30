"""Contrato de kir_auth.errores: sin red (transport falso) y sin romper la app."""
from __future__ import annotations

import logging
import sys

import pytest

sentry_sdk = pytest.importorskip("sentry_sdk")
from sentry_sdk.transport import Transport  # noqa: E402

from kir_auth import errores  # noqa: E402

DSN = "https://clave@glitchtip.invalido.test/1"


_INIT_REAL = sentry_sdk.init


class TransporteFalso(Transport):
    enviados: list = []

    def capture_envelope(self, envelope):
        ev = envelope.get_event()
        if ev is not None:
            TransporteFalso.enviados.append(ev)

    def flush(self, *a, **k):
        pass

    def kill(self):
        pass


@pytest.fixture(autouse=True)
def _limpio(monkeypatch):
    for v in ("GLITCHTIP_DSN", "KIR_ENV", "KIR_RELEASE"):
        monkeypatch.delenv(v, raising=False)
    TransporteFalso.enviados = []
    yield
    _INIT_REAL()  # apaga el cliente


@pytest.fixture
def init_capturado(monkeypatch):
    """Intercepta sentry_sdk.init: guarda los kwargs e inyecta el transport falso."""
    real = _INIT_REAL
    capturado = {}

    def falso(**kw):
        capturado.update(kw)
        return real(**{**kw, "transport": TransporteFalso})

    monkeypatch.setattr(sentry_sdk, "init", falso)
    return capturado


def test_sin_dsn_es_noop(init_capturado):
    assert errores.iniciar("x") is False
    assert init_capturado == {}


def test_sin_el_extra_es_noop(monkeypatch, init_capturado, caplog):
    original = sys.modules["sentry_sdk"]
    sys.modules["sentry_sdk"] = None  # import -> ImportError
    try:
        with caplog.at_level(logging.WARNING, logger="kir_auth.errores"):
            assert errores.iniciar("x", dsn=DSN) is False
    finally:
        sys.modules["sentry_sdk"] = original
    assert init_capturado == {}


def test_configuracion_por_defecto(monkeypatch, init_capturado):
    monkeypatch.setenv("GLITCHTIP_DSN", DSN)
    monkeypatch.setenv("KIR_RELEASE", "abc123")
    assert errores.iniciar("compensaciones") is True
    c = init_capturado
    assert c["dsn"] == DSN and c["release"] == "abc123"
    assert c["environment"] == "produccion"
    assert c["send_default_pii"] is False
    assert c["include_local_variables"] is False
    assert c["max_request_body_size"] == "never"
    assert c["traces_sample_rate"] == 0
    assert c["before_send"] is errores.before_send
    assert c["before_breadcrumb"] is errores.before_breadcrumb


def test_argumentos_pisan_el_entorno(monkeypatch, init_capturado):
    monkeypatch.setenv("KIR_ENV", "staging")
    errores.iniciar("x", dsn=DSN, environment="dev", release="r1")
    assert init_capturado["environment"] == "dev"
    assert init_capturado["release"] == "r1"
    monkeypatch.setenv("GLITCHTIP_DSN", DSN)
    errores.iniciar("x")
    assert init_capturado["environment"] == "staging"


def test_falla_del_sdk_al_iniciar_no_rompe(monkeypatch, caplog):
    def explota(**kw):
        raise RuntimeError("dsn roto")

    monkeypatch.setattr(sentry_sdk, "init", explota)
    with caplog.at_level(logging.WARNING, logger="kir_auth.errores"):
        assert errores.iniciar("x", dsn=DSN) is False
    assert "no se pudo iniciar" in caplog.text


def test_evento_de_punta_a_punta_sale_limpio(monkeypatch, init_capturado):
    monkeypatch.setenv("GLITCHTIP_DSN", DSN)
    assert errores.iniciar("compensaciones")
    sentry_sdk.set_context("liquidacion", {"Sueldo_Bruto": 1234567.5, "legajo": 12})
    sentry_sdk.add_breadcrumb(
        category="http", message="GET /x?dni=12345678", data={"url": "http://h/x?cuil=20-12345678-9"}
    )
    try:
        raise ValueError("falló el DNI 12345678 y el CUIL 20-12345678-9")
    except ValueError:
        sentry_sdk.capture_exception()
    assert len(TransporteFalso.enviados) == 1
    texto = repr(TransporteFalso.enviados[0])
    for filtrado in ("12345678", "1234567.5", "20-12345678-9", "cuil" + "=", "dni" + "="):
        assert filtrado not in texto, filtrado
    assert TransporteFalso.enviados[0]["contexts"]["liquidacion"]["Sueldo_Bruto"] == "[Filtered]"
    assert TransporteFalso.enviados[0]["contexts"]["liquidacion"]["legajo"] == 12


def test_before_send_limpia_sueldo_dni_headers_y_query():
    evento = {
        "message": "error con DNI 12.345.678? no: 30123456 y 20-30123456-7",
        "extra": {"detalle": {"Sueldo": 900000, "items": [{"MONTO": 5}, {"ok": "hola"}]}},
        "user": {"email": "a@kir.com.ar"},
        "request": {
            "url": "https://app.kir.test/comp?nombre=Juan&monto=100",
            "query_string": "nombre=Juan&monto=100",
            "data": {"salario": 1},
            "cookies": {"s": "v"},
            "headers": {
                "Authorization": "Bearer abc",
                "Cookie": "s=v",
                "X-Forwarded-Email": "a@kir.com.ar",
                "X-Platform-Token": "t",
                "User-Agent": "curl",
            },
        },
        "breadcrumbs": {"values": [{"data": {"url": "http://h/p?token=1", "password": "x"}}]},
    }
    out = errores.before_send(evento)
    assert out["message"] == "error con DNI 12.345.678? no: [dni] y [cuil]"
    assert out["extra"]["detalle"]["Sueldo"] == "[Filtered]"
    assert out["extra"]["detalle"]["items"][0]["MONTO"] == "[Filtered]"
    assert out["extra"]["detalle"]["items"][1]["ok"] == "hola"
    assert "user" not in out
    r = out["request"]
    assert r["url"] == "https://app.kir.test/comp"
    assert r["query_string"] == "" and "data" not in r and "cookies" not in r
    h = r["headers"]
    assert h["User-Agent"] == "curl"
    assert all(h[k] == "[Filtered]" for k in ("Authorization", "Cookie", "X-Forwarded-Email", "X-Platform-Token"))
    crumb = out["breadcrumbs"]["values"][0]["data"]
    assert crumb == {"url": "http://h/p", "password": "[Filtered]"}


def test_before_breadcrumb_limpia():
    c = errores.before_breadcrumb({"message": "dni 12345678", "data": {"importe": 3}})
    assert c == {"message": "dni [dni]", "data": {"importe": "[Filtered]"}}


def test_excepcion_dentro_de_before_send_no_rompe(monkeypatch, caplog):
    def explota(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(errores, "limpiar_evento", explota)
    with caplog.at_level(logging.WARNING, logger="kir_auth.errores"):
        assert errores.before_send({"message": "x"}) is None  # se descarta, no se manda sin limpiar
    assert "falló el scrubbing" in caplog.text


def test_la_denylist_empaquetada_cubre_lo_pedido():
    claves = errores.cargar_denylist()["claves"]
    for k in ("sueldo", "salario", "remuneracion", "bruto", "neto", "monto", "importe", "bono",
              "dni", "cuil", "cuit", "documento", "password", "token", "secret", "authorization",
              "cookie", "x-forwarded-email", "x-platform-token"):
        assert k in claves
