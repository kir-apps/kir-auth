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
- **Un nombre que resuelve a más de una IP (de cualquier familia) es ambiguo, y
  ambiguo es rechazo.** En una red de Docker, otro contenedor puede declarar un
  alias de red con el mismo nombre que el proxy, y el nombre pasa a resolver a
  las dos IPs. Aceptar cualquiera de ellas dejaría pasar al impostor; rechazar
  convierte la suplantación en una denegación, que se ve en el log. Un proxy
  dual-stack (una IPv4 y una IPv6) también se rechaza: es el precio de no dejar
  que una dirección de la otra familia se cuele como confiable. Si el proxy
  comparte con la app más de una red, el nombre se califica con la red
  (`proxy.red`), que resuelve a una sola IP.
- **Falla cerrado.** Si el nombre no resuelve (proxy caído, nombre mal escrito),
  ningún pedido con headers de identidad pasa.
- **Un par puede quedar atado a los emails que puede afirmar**
  (`nombre=email1;email2`). El sidecar valida la sesión y puede afirmar
  cualquiera; un cliente técnico que manda su propia identidad (un barrido, un
  monitor) no tiene por qué poder presentarse como otra persona. Sin `=`, el par
  afirma cualquier email, como siempre.
- **Los nombres se prueban en orden y gana el primero que coincide.** El sidecar
  va primero: el tráfico de la gente nunca resuelve los nombres que siguen, que
  pueden no existir la mayor parte del día.
- **Una config que no se entiende no arranca.** Un par con `=` y sin emails, un
  email sin `@`, o el mismo par listado dos veces con restricción tiran
  `ValueError` al construir: interpretarlos de alguna manera sería adivinar en
  qué dirección se abrió el permiso.

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
from collections.abc import Callable, Iterable, Mapping

log = logging.getLogger("kir_auth")

Resolvedor = Callable[[str], Iterable[str]]
# par -> emails que puede afirmar (normalizados), o None = cualquiera.
Pares = dict[str, frozenset[str] | None]
ConfigPares = str | Iterable[str] | Mapping[str, str | Iterable[str] | None]

SEPARADOR_PARES = ","
SEPARADOR_PAR_EMAILS = "="
SEPARADOR_EMAILS = ";"


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


def normalizar_email(email: str) -> str:
    """Forma en que se comparan los emails: sin espacios alrededor y en minúsculas."""
    return email.strip().lower()


def _email_valido(email: str) -> bool:
    local, arroba, dominio = email.partition("@")
    return bool(
        arroba
        and local
        and dominio
        and "@" not in dominio
        and not any(c.isspace() or c in ",;=" for c in email)
    )


def _nombre_valido(nombre: str) -> bool:
    return not any(c.isspace() or c in "@;=" for c in nombre)


def _emails_de(nombre: str, crudo: str | Iterable[str]) -> frozenset[str]:
    partes = crudo.split(SEPARADOR_EMAILS) if isinstance(crudo, str) else list(crudo)
    emails: set[str] = set()
    for parte in partes:
        if not isinstance(parte, str):
            raise ValueError(f"IDENTIDAD_SOLO_DESDE: el par {nombre!r} tiene un email que no es texto")
        email = normalizar_email(parte)
        if not email:
            continue
        if not _email_valido(email):
            raise ValueError(
                f"IDENTIDAD_SOLO_DESDE: {email!r} (par {nombre!r}) no es un email válido"
            )
        emails.add(email)
    if not emails:
        # `par=` sin emails: ¿nadie o cualquiera? Ninguna de las dos es segura de
        # suponer, así que no se arranca.
        raise ValueError(
            f"IDENTIDAD_SOLO_DESDE: el par {nombre!r} tiene '=' pero ningún email; "
            f"poné los emails separados por '{SEPARADOR_EMAILS}' o sacá el '='"
        )
    return frozenset(emails)


def pares_de(valor: ConfigPares | None) -> Pares:
    """Parsea la config de la guarda: par -> emails que puede afirmar.

    `"a, b=x@d;y@d"` → `{"a": None, "b": frozenset({"x@d", "y@d"})}`, en el orden
    en que vinieron. También acepta una lista de esas entradas o un dict
    `{par: None | "x@d;y@d" | [emails]}`. Sin `=` el par afirma cualquier email.
    Vacíos se ignoran y un par sin restricción repetido se cuenta una vez (como
    antes de que hubiera restricciones). Tira `ValueError` si algo no se
    entiende: par sin nombre, `=` sin emails, email sin `@`, o el mismo par
    (sin distinguir mayúsculas) dos veces con alguna restricción.
    """
    if valor is None:
        return {}
    entradas: list[tuple[str, str | Iterable[str] | None]] = []
    if isinstance(valor, Mapping):
        entradas = list(valor.items())
    else:
        partes = valor.split(SEPARADOR_PARES) if isinstance(valor, str) else list(valor)
        for parte in partes:
            if not isinstance(parte, str):
                raise ValueError(f"IDENTIDAD_SOLO_DESDE: entrada que no es texto: {parte!r}")
            if not parte.strip():
                continue
            nombre, igual, emails = parte.partition(SEPARADOR_PAR_EMAILS)
            entradas.append((nombre, emails if igual else None))

    pares: Pares = {}
    for nombre_crudo, emails_crudos in entradas:
        if not isinstance(nombre_crudo, str):
            raise ValueError(f"IDENTIDAD_SOLO_DESDE: par que no es texto: {nombre_crudo!r}")
        nombre = nombre_crudo.strip()
        if not nombre:
            if emails_crudos is None:
                continue
            raise ValueError("IDENTIDAD_SOLO_DESDE: hay emails sin nombre de par ('=...')")
        if not _nombre_valido(nombre):
            raise ValueError(
                f"IDENTIDAD_SOLO_DESDE: {nombre!r} no es un nombre de par; la forma es "
                f"'par' o 'par=email{SEPARADOR_EMAILS}email', separados por '{SEPARADOR_PARES}'"
            )
        emails = None if emails_crudos is None else _emails_de(nombre, emails_crudos)
        # DNS no distingue mayúsculas: `Barrido` y `barrido` son el mismo par.
        previos = [n for n in pares if n.lower() == nombre.lower()]
        if previos:
            if emails is None and all(pares[n] is None for n in previos):
                # Repetido sin restricción: el comportamiento de siempre.
                pares.setdefault(nombre, None)
                continue
            # Repetido con restricción en alguna de las dos: ¿se suman, gana una,
            # la de sin restricción abre todo? No se adivina.
            raise ValueError(
                f"IDENTIDAD_SOLO_DESDE: el par {nombre!r} está más de una vez y con "
                f"restricción de emails; listalo una sola vez con todos sus emails "
                f"separados por '{SEPARADOR_EMAILS}'"
            )
        pares[nombre] = emails
    return pares


def nombres_de(valor: ConfigPares | None) -> tuple[str, ...]:
    """`"a, b"` o `["a", "b"]` → `("a", "b")`, sin vacíos ni repetidos.

    Con restricciones (`"a,b=x@d"`) devuelve sólo los nombres de par.
    """
    return tuple(pares_de(valor))


class GuardaDeOrigen:
    """Decide si una IP de origen es la de un par confiable, y qué puede afirmar.

    `nombres` es la config de `pares_de`: nombres sueltos (afirman cualquier
    email) o `par=email1;email2` (sólo esos).
    """

    def __init__(
        self,
        nombres: ConfigPares,
        *,
        ttl_seconds: float = 10.0,
        min_reresolucion_seconds: float = 1.0,
        resolver: Resolvedor | None = None,
        reloj: Callable[[], float] = time.monotonic,
    ) -> None:
        self.pares: Pares = pares_de(nombres)
        self.nombres: tuple[str, ...] = tuple(self.pares)
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
        # Más de una dirección, sea de la familia que sea, es ambiguo. Separar
        # por familia (una v4 + una v6 = un contenedor dual-stack) dejaría que
        # un alias de otra familia pase a ser origen confiable.
        if len(ips) > 1:
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

    def par(self, ip: str | None) -> str | None:
        """El primer par configurado (en orden) cuya IP es `ip`, o None.

        Corta en el primero que coincide: los nombres que siguen no se resuelven.
        """
        ip = _normalizar(ip) if ip else None
        if not ip:
            return None
        for nombre in self.nombres:
            if ip in self._ips(nombre, forzar=False):
                return nombre
        # El proxy pudo recrearse con otra IP: una re-resolución antes de rechazar.
        for nombre in self.nombres:
            if ip in self._ips(nombre, forzar=True):
                return nombre
        return None

    def permite(self, ip: str | None) -> bool:
        """True si `ip` es la de alguno de los pares configurados."""
        return self.par(ip) is not None

    def emails_permitidos(self, par: str) -> frozenset[str] | None:
        """Los emails que `par` puede afirmar (normalizados), o None = cualquiera."""
        return self.pares[par]

    def puede_afirmar(self, par: str, email: str | None) -> bool:
        """True si `par` puede afirmar `email`. Un par restringido sin email, no."""
        permitidos = self.pares[par]
        if permitidos is None:
            return True
        if not email:
            return False
        return normalizar_email(email) in permitidos
