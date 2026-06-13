"""Modelo de la identidad de un usuario autenticado."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Identity:
    """Una persona autenticada por oauth2-proxy, con sus roles en esta app."""

    email: str
    name: str
    is_platform_admin: bool
    roles: list[str] = field(default_factory=list)
    # False si el Hub no conoce al usuario (nunca entró / no provisionado).
    known: bool = True
    # ACL por obra (Fase 3). Defaults vacíos => las apps con el SDK viejo o que
    # no leen el bloque `obras` no se ven afectadas.
    obras_general: bool = False
    obras_codigos: list[str] = field(default_factory=list)
    # Teléfono enriquecido del perfil de Entra (Graph mobilePhone/businessPhones).
    # None si el Hub no lo tiene. Para canales como el aviso por WhatsApp.
    phone: str | None = None

    def has_role(self, *roles: str) -> bool:
        """True si el user tiene alguno de `roles` en esta app. Los platform
        admin pasan siempre."""
        if self.is_platform_admin:
            return True
        return any(role in self.roles for role in roles)

    def can_see_obra(self, codigo) -> bool:
        """True si el user puede ver la obra. Platform admin y permiso general ven todas."""
        if self.is_platform_admin or self.obras_general:
            return True
        return str(codigo) in self.obras_codigos

    @property
    def display_name(self) -> str:
        return self.name or self.email
