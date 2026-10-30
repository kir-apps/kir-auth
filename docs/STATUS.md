# STATUS — kir-auth

> Empezá por acá. Estado de `kir-auth` y decisiones que no se deducen del código.
> Este repo es **público**: acá van decisiones de diseño de la librería, no
> nombres de hosts, ids ni topología de ninguna instalación.

## Reporte de errores con scrubbing (kir-auth#6, 2026-10-30 · risk:low)

**Por qué.** Las apps manejan sueldos y DNI; un traceback con variables locales
o una query string con filtros los lleva al servidor de errores. Por eso el helper
parte de «no mandar nada» y agrega sólo lo necesario.

**Decisiones.**
- **Si el scrubbing falla, el evento se descarta**, no se manda sin limpiar. Se
  pierde un reporte, no se filtra un dato.
- **La denylist es un JSON empaquetado**, no código: el helper de Node puede
  cargar el mismo archivo y las dos implementaciones no divergen. Las claves
  matchean por substring y sin mayúsculas (`Sueldo_Bruto`, `monto_total`):
  sobre-limpia a propósito; el costo es un `[Filtered]` de más.
- **El regex de DNI (7-8 dígitos) también agarra parte de números más largos**
  (`1234567.5` queda `[dni].5`). Preferimos el falso positivo.
- **`sentry-sdk` pineado exacto** (2.72.0, con más de dos semanas de publicada):
  el scrubbing depende de la forma de los eventos; la 3.x todavía es beta.
- **Headers por allowlist, no por denylist**: una denylist deja pasar el header de identidad que nadie pensó (x-auth-request-*, x-forwarded-user...). Lo no listado se descarta.
- **DNI/CUIL con puntos, espacios o guiones, email y montos con `$`/ARS/USD** se limpian en cualquier string (mensajes, extra, breadcrumbs de logging incluidos).
- **No se manda `user`** ni el body ni las cookies; el sidecar pone el email en
  headers que están en la denylist.
- El import de `sentry_sdk` es perezoso: sin el extra o sin DSN, no-op.

## Verificación del ID token del proxy, opt-in (kir-platform#571, 2026-10-26 · risk:high)

**Por qué.** La guarda de origen depende de la red: quien pueda crear
contenedores puede detener el proxy y quedarse con su nombre. El ID token que el
proveedor firma no se puede fabricar sin su clave privada; si el proxy lo
reenvía (`pass_authorization_header`), la app puede probar la identidad sola.

**Decisiones.**
- **ID token, no access token.** El access token de Entra suele ser para otra
  audiencia (Graph) y no está pensado para que lo valide un tercero; el ID token
  tiene `aud` = el client id de la app, que es justo lo que hay que exigir.
- **El email del header tiene que estar entre los del token**, en vez de tomar el
  del token y listo: el header es el que la app usó siempre (y el que el Hub
  tiene en la ACL), y según `oidc_email_claim` del proxy sale de `email` o de
  `preferred_username`. Se aceptan los dos claims por default.
- **Modo `observar`.** Lo que no se puede verificar sin producción —que el
  Bearer que manda el proxy sea el ID token esperado, con qué claims, y que se
  renueve antes de vencer— se mira con la verificación prendida pero sin
  rechazar, y con avisos acotados (uno por motivo cada 5 min) para que un proxy
  todavía sin el header no llene el log.
- **401 sólo para el token vencido**; el resto 403. Un re-login trae un token
  nuevo; no arregla una firma ni una audiencia, y sería un bucle.
- **Algoritmo fijo RS256**, `kid` obligatorio, JWKS por discovery con el
  `issuer` del documento comparado contra el configurado.
- **Tope de una re-descarga del JWKS por minuto** ante `kid` desconocidos, y
  cache servido hasta 24 h si el proveedor no responde (misma asimetría que la
  ACL: no echar a todos por una caída, pero no para siempre).
- **PyJWT como extra**, importado al construir: la app que prende el modo sin el
  extra no arranca; las demás no suman `cryptography`.
- **Los motivos de rechazo son una lista cerrada** (`kir_auth.idtoken.MOTIVOS`).
  La primera versión armaba el motivo con datos del token
  (`f"algoritmo {alg!r} no permitido"`) y lo usaba como clave del throttle de
  avisos y como texto de la respuesta. La revisión de seguridad marcó que así un
  atacante, variando `alg`/`kid`, agrandaba el dict sin límite, se salteaba el
  rate-limit del log y metía texto suyo en la respuesta. Ahora el motivo es fijo
  y lo que vino en el token va en `detalle`, saneado (sólo imprimibles) y
  truncado a 80, **sólo al log**. Un test manda 1000 `alg` distintos y 1000
  `kid` inventados: dos claves en el dict, dos líneas de log.
- **Nada de la instalación en el código ni en los tests**: tenant, client id y
  URLs salen del entorno; los tests usan claves generadas en el momento.

## Guarda de origen de la identidad (kir-platform#571, 2026-10-26 · risk:high)

**Por qué.** `KirAuth` aceptaba `X-Forwarded-Email` sin mirar quién lo mandaba.
El header lo pone el proxy de autenticación, pero cualquier proceso que llegue
al puerto de la app puede mandar el mismo header. Una app ya lo había resuelto
por su cuenta comparando la IP del par con la del proxy; esto lo lleva a la
librería con el mismo nombre de variable (`IDENTIDAD_SOLO_DESDE`), para que esa
app pueda soltar su copia sin cambiar el `.env`.

**Decisiones.**
- **Opt-in, con un aviso si falta.** Prenderla por default rompería a toda app
  que tenga algo en el medio o un cliente que mande el header a propósito, y
  ninguna se enteraría hasta el deploy. Sin configurar, el comportamiento es el
  de siempre y hay un `warning` una vez por proceso (no por instancia: hay apps
  que crean varios `KirAuth`).
- **Un nombre ambiguo es rechazo.** Se probó en Docker 29 (2026-10-26, red de
  prueba aislada): un contenedor que declara `--network-alias <nombre-del-proxy>`
  hace que el nombre resuelva a **las dos** IPs, y una guarda que acepta
  «cualquier IP del nombre» deja pasar al impostor. Por eso, más de una IP
  = se rechaza todo y se loguea error: la suplantación pasa a ser
  una denegación visible. **Cualquier familia**: la primera versión separaba
  IPv4 de IPv6 (una de cada una = un contenedor dual-stack, aceptable), y la
  revisión de seguridad marcó que así un alias de la otra familia quedaba como
  origen confiable. Ahora más de una dirección en total es rechazo; un proxy
  dual-stack no se puede usar con la guarda (las redes donde corren estas apps
  son IPv4). También se probó que un contenedor en dos redes
  compartidas resuelve a **una** IP (la de una de las redes) pero puede llegar
  por cualquiera de las dos: de ahí la recomendación de calificar `nombre.red`,
  que Docker resuelve a la IP de esa red.
- **TTL 10 s + una re-resolución antes de rechazar, con tope de una por
  segundo.** El proxy recreado cambia de IP y la vieja puede reasignarse a otro
  contenedor (probado: un contenedor creado justo después se quedó con la IP del
  que se borró). El tope evita que una IP ajena dispare un DNS por pedido.
- **403, no 401.** Algunos frontends mandan a re-loguear ante un 401: si la
  guarda rechazara a todos por un nombre mal puesto, sería un bucle de logins.
- **Un header forjado nunca cae a `dev_email`.** Sin headers, `dev_email` sigue
  igual (dev local).
- **No arranca con `FORWARDED_ALLOW_IPS=*`.** Uvicorn y gunicorn reemplazan la
  IP del par por la de `X-Forwarded-For` cuando confían en el par; con `*`, la
  guarda se falsea con un header (probado: con el default, un `X-Forwarded-For`
  con la IP del proxy desde otro contenedor sigue siendo 403). El flag de línea
  de comandos no se ve desde la librería: queda documentado.
- **Lo que no cubre**: quien puede crear contenedores puede detener el proxy y
  quedarse con su nombre (una sola IP, la suya). Eso lo cierra verificar el
  token firmado del proveedor de identidad, no la red.
