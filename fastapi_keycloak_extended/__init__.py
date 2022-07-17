"""Keycloak API Client for integrating authentication and authorization with FastAPI"""

__version__ = "1.0.8"

from fastapi_keycloak_extended.api import FastAPIKeycloak
from fastapi_keycloak.model import (
    HTTPMethod,
    KeycloakError,
    KeycloakIdentityProvider,
    KeycloakRole,
    UsernamePassword,
)
from fastapi_keycloak_extended.model import (
    KeycloakToken,
    KeycloakGroup,
    OIDCUser,
    KeycloakUser,
    KeycloakRefreshToken,
)

__all__ = [
    FastAPIKeycloak.__name__,
    OIDCUser.__name__,
    UsernamePassword.__name__,
    HTTPMethod.__name__,
    KeycloakError.__name__,
    KeycloakUser.__name__,
    KeycloakToken.__name__,
    KeycloakRole.__name__,
    KeycloakIdentityProvider.__name__,
    KeycloakGroup.__name__,
    KeycloakRefreshToken.__name__,
]
