from __future__ import annotations
from typing import Optional, List

from pydantic import BaseModel, Field
from fastapi_keycloak import model


class KeycloakUser(model.KeycloakUser):
    """Represents a user object of Keycloak.

    Attributes:
        groups (Optional[list[str]]):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    id: str
    createdTimestamp: int
    username: str
    enabled: bool
    totp: bool
    emailVerified: bool
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[str] = None
    disableableCredentialTypes: List[str]
    requiredActions: List[str]
    realmRoles: Optional[List[str]] = None
    notBefore: int
    access: Optional[dict] = None
    attributes: Optional[dict] = None
    groups: Optional[list[str]] = None


class OIDCUser(model.OIDCUser):
    """Represents a user object of Keycloak, parsed from access token

    Attributes:
        groups (Optional[list[str]]):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    sub: str
    iat: int
    exp: int
    email_verified: bool
    extra_fields: dict = Field(default_factory=dict)
    azp: Optional[str] = None
    scope: Optional[str] = None
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    email: Optional[str] = None
    preferred_username: Optional[str] = None
    realm_access: Optional[dict] = None
    resource_access: Optional[dict] = None
    groups: Optional[list[str]] = None


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

    id: str
    name: str
    path: Optional[str] = None
    realmRoles: Optional[List[str]] = None
    subGroups: Optional[List["KeycloakGroup"]] = None

    attributes: Optional[dict] = None


KeycloakGroup.model_rebuild()
