from typing import Optional

from pydantic import BaseModel
from fastapi_keycloak import model


class KeycloakUser(model.KeycloakUser):
    """ Represents a user object of Keycloak.

    Attributes:
        groups (List[str]):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    groups: Optional[list[str]]


class OIDCUser(model.OIDCUser):
    """ Represents a user object of Keycloak, parsed from access token

    Attributes:
        groups (Optional[str]):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    groups: list[str]


class KeycloakToken(model.KeycloakToken):
    """Keycloak representation of a token object

    Attributes:
        token_type (str): A token type
        refresh_token (str): A refresh token
        expires_in (int): An expires time
        refresh_expires_in (int): A refresh expires time
        session_state (str): A session state
        scope (str): A scope session
    """

    token_type: str
    refresh_token: str
    expires_in: int
    refresh_expires_in: int
    session_state: str
    scope: str

    def __str__(self):
        """String representation of KeycloakToken"""
        return f"{self.token_type} {self.access_token}"


class KeycloakRefreshToken(BaseModel):
    """Keycloak representation of a token object after refresh

    Attributes:
        access_token (str): An access token
        token_type (str): A token type
        refresh_token (str): A refresh token
        expires_in (int): An expires time
    """

    access_token: str
    token_type: str
    refresh_token: str
    expires_in: int

    def __str__(self):
        """String representation of KeycloakToken"""
        return f"{self.token_type} {self.access_token}"


class KeycloakGroup(model.KeycloakGroup):
    """Keycloak representation of a group

    Attributes:
        attributes (Optional[dict]):
    """
    attributes: Optional[dict]


KeycloakGroup.update_forward_refs()
