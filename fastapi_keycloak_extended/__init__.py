"""Keycloak API Client for integrating authentication and authorization with FastAPI"""

__version__ = "0.1.0"

from fastapi_keycloak.api import FastAPIKeycloak
from fastapi_keycloak.model import (
    HTTPMethod,
    KeycloakError,
    KeycloakIdentityProvider,
    KeycloakRole,
    OIDCUser,
    UsernamePassword)
from fastapi_keycloak_extended.model import (
    KeycloakUser,
    KeycloakToken,
    KeycloakGroup,
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