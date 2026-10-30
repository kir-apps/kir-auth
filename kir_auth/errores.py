"""Reporte de errores a GlitchTip (compatible con el SDK de Sentry), con scrubbing.

Uso en una app (antes de crear el `FastAPI()`):

    from kir_auth.errores import iniciar
    iniciar("compensaciones")

Sin el extra `kir-auth[errores]` o sin `GLITCHTIP_DSN`, `iniciar()` no hace nada.
Nada de lo que hace este módulo puede tumbar la app: si el SDK falla al iniciar
se loguea un warning y la app sigue sin reporte de errores.

Qué se limpia (`errores_denylist.json`, pensado para compartirse con Node):
claves sensibles (sin distinguir mayúsculas, por substring, en cualquier nivel),
query strings de las URLs y, en cualquier string, valores con forma de DNI/CUIL
(con o sin separadores), email y montos con moneda. Los headers del request van
por allowlist: sólo los inofensivos. Si el scrubbing mismo falla, el evento se DESCARTA: preferimos perder un
reporte antes que mandar uno sin limpiar.
"""
from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache
from importlib import resources
from typing import Any

log = logging.getLogger("kir_auth.errores")

_MAX_PROFUNDIDAD = 40


_QUERY = re.compile(r"\?[^\s=?#\"'<>]+=[^\s\"'<>]*")


@lru_cache(maxsize=1)
def cargar_denylist() -> dict[str, Any]:
    """Lee y compila la denylist empaquetada (cacheada)."""
    crudo = json.loads(
        resources.files("kir_auth").joinpath("errores_denylist.json").read_text("utf-8")
    )
    return {
        "reemplazo": crudo.get("reemplazo", "[Filtered]"),
        "claves": tuple(c.lower() for c in crudo["claves"]),
        "valores": tuple(
            (re.compile(v["regex"]), v.get("reemplazo", "[Filtered]"))
            for v in crudo.get("valores", [])
        ),
        "headers_permitidos": frozenset(h.lower() for h in crudo["headers_permitidos"]),
        "quitar_query": bool(crudo.get("quitar_query_string", True)),
    }


def _clave_sensible(clave: Any, claves: tuple[str, ...]) -> bool:
    if not isinstance(clave, str):
        return False
    k = clave.lower()
    return any(c in k for c in claves)


def _limpiar_string(s: str, cfg: dict[str, Any]) -> str:
    if cfg["quitar_query"]:
        s = _QUERY.sub("", s)
    for patron, reemplazo in cfg["valores"]:
        s = patron.sub(reemplazo, s)
    return s


def _limpiar(obj: Any, cfg: dict[str, Any], nivel: int = 0) -> Any:
    if nivel > _MAX_PROFUNDIDAD:
        return cfg["reemplazo"]
    if isinstance(obj, str):
        return _limpiar_string(obj, cfg)
    if isinstance(obj, dict):
        salida = {}
        for k, v in obj.items():
            if _clave_sensible(k, cfg["claves"]):
                salida[k] = cfg["reemplazo"]
            else:
                salida[k] = _limpiar(v, cfg, nivel + 1)
        return salida
    if isinstance(obj, (list, tuple)):
        # Headers como pares [nombre, valor].
        if len(obj) == 2 and _clave_sensible(obj[0], cfg["claves"]):
            return [obj[0], cfg["reemplazo"]]
        return [_limpiar(v, cfg, nivel + 1) for v in obj]
    return obj


def _solo_permitidos(headers: Any, permitidos: frozenset[str]) -> Any:
    """Allowlist: sólo viajan los headers inofensivos; el resto se descarta."""
    if isinstance(headers, dict):
        return {k: v for k, v in headers.items() if isinstance(k, str) and k.lower() in permitidos}
    if isinstance(headers, (list, tuple)):
        return [
            [p[0], p[1]]
            for p in headers
            if isinstance(p, (list, tuple)) and len(p) == 2
            and isinstance(p[0], str) and p[0].lower() in permitidos
        ]
    return {}


def _limpiar_request(req: dict[str, Any], cfg: dict[str, Any]) -> None:
    # Nunca viajan bodies, cookies ni la query string completa; headers por allowlist.
    req.pop("data", None)
    req.pop("cookies", None)
    if "headers" in req:
        req["headers"] = _solo_permitidos(req["headers"], cfg["headers_permitidos"])
    if "query_string" in req:
        req["query_string"] = ""


def limpiar_evento(event: dict[str, Any]) -> dict[str, Any]:
    """Devuelve el evento sin datos sensibles. Puede lanzar: ver `before_send`."""
    cfg = cargar_denylist()
    request = event.get("request")
    if isinstance(request, dict):
        _limpiar_request(request, cfg)
    event.pop("user", None)
    return _limpiar(event, cfg)


def before_send(event: dict[str, Any], hint: Any = None) -> dict[str, Any] | None:
    try:
        return limpiar_evento(event)
    except Exception as exc:  # noqa: BLE001 - nunca romper la app
        log.warning("errores: falló el scrubbing, se descarta el evento (%s)", exc)
        return None


def before_breadcrumb(crumb: dict[str, Any], hint: Any = None) -> dict[str, Any] | None:
    try:
        return _limpiar(crumb, cargar_denylist())
    except Exception as exc:  # noqa: BLE001
        log.warning("errores: falló el scrubbing del breadcrumb, se descarta (%s)", exc)
        return None


def _integraciones() -> list[Any]:
    integraciones: list[Any] = []
    for modulo, clase in (
        ("sentry_sdk.integrations.starlette", "StarletteIntegration"),
        ("sentry_sdk.integrations.fastapi", "FastApiIntegration"),
    ):
        try:
            mod = __import__(modulo, fromlist=[clase])
            integraciones.append(getattr(mod, clase)())
        except Exception:  # noqa: BLE001 - falta el framework: sin esa integración
            continue
    return integraciones


def iniciar(
    app: str,
    *,
    dsn: str | None = None,
    environment: str | None = None,
    release: str | None = None,
) -> bool:
    """Inicia el reporte de errores. Devuelve True si quedó activo.

    No-op (False) sin DSN (`GLITCHTIP_DSN`) o sin `sentry-sdk` instalado.
    """
    try:
        dsn = dsn or os.environ.get("GLITCHTIP_DSN") or None
        if not dsn:
            return False
        try:
            import sentry_sdk
        except ImportError:
            log.warning("errores: GLITCHTIP_DSN definido pero falta el extra kir-auth[errores]")
            return False
        cargar_denylist()  # si el JSON está roto, que falle acá y no en cada evento
        sentry_sdk.init(
            dsn=dsn,
            environment=environment or os.environ.get("KIR_ENV") or "produccion",
            release=release or os.environ.get("KIR_RELEASE") or None,
            server_name=app,
            send_default_pii=False,
            include_local_variables=False,
            max_request_body_size="never",
            traces_sample_rate=0,
            integrations=_integraciones(),
            before_send=before_send,
            before_breadcrumb=before_breadcrumb,
        )
        sentry_sdk.set_tag("app", app)
        return True
    except Exception as exc:  # noqa: BLE001 - la app arranca igual
        log.warning("errores: no se pudo iniciar el reporte de errores (%s)", exc)
        return False
