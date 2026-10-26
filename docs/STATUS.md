# STATUS — kir-auth

> Empezá por acá. Estado de `kir-auth` y decisiones que no se deducen del código.
> Este repo es **público**: acá van decisiones de diseño de la librería, no
> nombres de hosts, ids ni topología de ninguna instalación.

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
  «cualquier IP del nombre» deja pasar al impostor. Por eso, más de una IP de la
  misma familia = se rechaza todo y se loguea error: la suplantación pasa a ser
  una denegación visible. También se probó que un contenedor en dos redes
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
