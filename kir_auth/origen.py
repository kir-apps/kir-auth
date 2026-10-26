"""Guarda de origen: los headers de identidad sólo valen si vienen del proxy.

El proxy de autenticación (oauth2-proxy) pone `X-Forwarded-Email` después de
validar la sesión. Pero la app no tiene forma de saber, mirando el header, si lo
puso el proxy o cualquier otro proceso que le pudo hablar directo al puerto. Esta
guarda compara la IP del par TCP (`request.client.host`) con las IPs a las que
resuelven, por DNS, los nombres configurados del proxy.

Decisiones que no se deducen del código:

- **TTL corto (10 s) y una re-resolución antes de rechazar.** Si el proxy se
  recrea, cambia de IP; y su IP vieja puede quedar asignada a otro contenedor.
  Un cache largo seguiría aceptando headers desde la IP vieja.
- **Un nombre que resuelve a más de una IP (de la misma familia) es ambiguo, y
  ambiguo es rechazo.** En una red de Docker, otro contenedor puede declarar un
  alias de red con el mismo nombre que el proxy, y el nombre pasa a resolver a
  las dos IPs. Aceptar cualquiera de ellas dejaría pasar al impostor; rechazar
  convierte la suplantación en una denegación, que se ve en el log. Si el proxy
  comparte con la app más de una red, el nombre se califica con la red
  (`proxy.red`), que resuelve a una sola IP.
- **Falla cerrado.** Si el nombre no resuelve (proxy caído, nombre mal escrito),
  ningún pedido con headers de identidad pasa.

Supuesto del que depende: `request.client.host` tiene que ser la IP real del
socket. Uvicorn y gunicorn la reemplazan por la de `X-Forwarded-For` cuando el
par está en `--forwarded-allow-ips` (default `127.0.0.1`); con `*` la guarda se
puede falsear con un header, y por eso `KirAuth` se niega a arrancar si ve
`FORWARDED_ALLOW_IPS=*` en el entorno.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import time
from collections.abc import Callable, Iterable

log = logging.getLogger("kir_auth")

Resolvedor = Callable[[str], Iterable[str]]


def resolver_dns(nombre: str) -> set[str]:
    """IPs a las que resuelve `nombre` (todas las familias)."""
    return {info[4][0] for info in socket.getaddrinfo(nombre, None)}


def _normalizar(ip: str) -> str | None:
    """Forma canónica de una IP; las IPv4 mapeadas en IPv6 vuelven a IPv4."""
    try:
        direccion = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(direccion, ipaddress.IPv6Address) and direccion.ipv4_mapped:
        direccion = direccion.ipv4_mapped
    return str(direccion)


def nombres_de(valor: str | Iterable[str] | None) -> tuple[str, ...]:
    """`"a, b"` o `["a", "b"]` → `("a", "b")`, sin vacíos ni repetidos."""
    if valor is None:
        return ()
    partes = valor.split(",") if isinstance(valor, str) else list(valor)
    vistos: list[str] = []
    for parte in partes:
        nombre = parte.strip()
        if nombre and nombre not in vistos:
            vistos.append(nombre)
    return tuple(vistos)


class GuardaDeOrigen:
    """Decide si una IP de origen es la del proxy de autenticación."""

    def __init__(
        self,
        nombres: Iterable[str],
        *,
        ttl_seconds: float = 10.0,
        min_reresolucion_seconds: float = 1.0,
        resolver: Resolvedor | None = None,
        reloj: Callable[[], float] = time.monotonic,
    ) -> None:
        self.nombres = nombres_de(nombres)
        if not self.nombres:
            raise ValueError("GuardaDeOrigen necesita al menos un nombre de proxy")
        self._ttl = ttl_seconds
        # Tope a las re-resoluciones forzadas: sin él, cualquiera que mande
        # pedidos desde una IP ajena dispara un DNS por pedido.
        self._min_reres = min_reresolucion_seconds
        self._resolver = resolver or resolver_dns
        self._reloj = reloj
        # nombre -> (resuelto_en, ips aceptables)
        self._cache: dict[str, tuple[float, frozenset[str]]] = {}

    def _resolver_nombre(self, nombre: str) -> frozenset[str]:
        try:
            crudas = self._resolver(nombre)
        except OSError as exc:
            log.warning("kir_auth: no se pudo resolver el proxy %r: %s", nombre, exc)
            return frozenset()
        ips = {ip for ip in (_normalizar(c) for c in crudas) if ip}
        v4 = {ip for ip in ips if ":" not in ip}
        v6 = ips - v4
        if len(v4) > 1 or len(v6) > 1:
            log.error(
                "kir_auth: el proxy %r resuelve a varias IPs (%s); se rechaza la "
                "identidad hasta que resuelva a una sola. ¿Otro contenedor declaró "
                "ese nombre como alias de red?",
                nombre,
                ", ".join(sorted(ips)),
            )
            return frozenset()
        return frozenset(ips)

    def _ips(self, nombre: str, *, forzar: bool) -> frozenset[str]:
        ahora = self._reloj()
        hit = self._cache.get(nombre)
        if hit:
            edad = ahora - hit[0]
            if edad < self._ttl and not forzar:
                return hit[1]
            if forzar and edad < self._min_reres:
                return hit[1]
        ips = self._resolver_nombre(nombre)
        self._cache[nombre] = (ahora, ips)
        return ips

    def permite(self, ip: str | None) -> bool:
        """True si `ip` es la de alguno de los proxies configurados."""
        ip = _normalizar(ip) if ip else None
        if not ip:
            return False
        if any(ip in self._ips(n, forzar=False) for n in self.nombres):
            return True
        # El proxy pudo recrearse con otra IP: una re-resolución antes de rechazar.
        return any(ip in self._ips(n, forzar=True) for n in self.nombres)
