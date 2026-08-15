# Changelog

Todos los cambios notables de este paquete se documentan acá.

## [0.3.0] — sin publicar

Corrige una deriva entre el repo canónico y las copias vendorizadas en las 5
apps (`kir-platform#164`): las cinco declaraban `__version__ = "0.2.0"` pero
no eran iguales — la de `obras` tenía de más el soporte de `admin_sections`,
que hoy usa el alcance por obra del Hub (`kir-platform#253` y siguientes) en
producción. Esta versión toma esa copia como base.

### Agregado

- `Identity.admin_sections: list[str]` — secciones delegadas del `/admin` del
  Hub (p. ej. `"obras"`), para que una app condicione paneles de
  administración propios por esa delegación. Default `[]`.
- `KirAuth._identity` ahora lee `admin_sections` del bloque `/platform/acl`
  del Hub (`acl.get("admin_sections", [])`) y lo pasa a `Identity`.
- README: documentado el campo `admin_sections`, y sección "Instalar"
  actualizada — el paquete se publica tag-versionado desde este repo en vez
  de vendorizarse.

### Compatibilidad hacia atrás

Cambio aditivo. Un Hub que todavía no manda `admin_sections` en el ACL sigue
andando igual: `acl.get("admin_sections", [])` devuelve `[]`, que es también
el default de `Identity.admin_sections`. Ninguna app que ya usa `0.2.x`
necesita cambiar código para actualizar.

### Nota de versión

`pyproject.toml` venía en `0.2.1` mientras `kir_auth/__version__` seguía en
`0.2.0` (deriva propia del repo, previa a esta migración). Esta versión
corrige el mismatch: ambos quedan en `0.3.0`.

## [0.2.1] / [0.2.0]

Sin CHANGELOG previo a esta versión.
