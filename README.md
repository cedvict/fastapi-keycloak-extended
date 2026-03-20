# FastAPI Keycloak Integration

---


Welcome to `fastapi-keycloak`. This projects goal is to ease the integration of Keycloak (OpenID Connect) with Python, especially FastAPI. FastAPI is not necessary but is
encouraged due to specific features. Currently, this package supports only the `password` and the `authorization_code`. However, the `get_current_user()` method accepts any JWT
that was signed using Keycloak´s private key.

## Docs

Refer to [https://fastapi-keycloak.code-specialist.com/](https://fastapi-keycloak.code-specialist.com/).

Adding some features:
 - KeycloakToken with more datas (refresh token, expires_in, etc.)
 - KeycloakRefreshToken represents the response after refresh token
 - KeycloakGroup with field `attributes`
 - Function to retrieve groups by attribute
 - Update call api GET (for users and groups) with param briefRepresentation as false. This allows to get the full representation of the object.
 - Update create_user and create_group
 - Function to refresh token
 - Override user_login to take an account more details
 - Update OIDCUser to add field from attributes

This exposes all fastapi_keycloak features under fastapi_keycloak_extended.

## Keycloak version
Module tested with version of keycloak:
- 16.0 (server uri must end with /auth )
- 22.0
- 26.5

## Build and publish

Refer to [https://packaging.python.org/en/latest/tutorials/packaging-projects/](https://packaging.python.org/en/latest/tutorials/packaging-projects/)

Step:
- python -m build
- python -m twine upload --repository pypi dist/*

# Change Log
## [1.0.11] - 2026-03-20
### Added
- Add support for Keycloak 26.5
- Add support for Python 3.14
- Add support for FastAPI 0.135.1
- Fix subGroups in Group representation by adding a recursive function to retrieve all subgroups (*_with_children*). This allows to get the full representation of the group with all its subgroups.
## [1.0.10.1] - 2024-06-30
### Added
- KeycloakToken with more datas (refresh token, expires_in, etc.)
- KeycloakRefreshToken represents the response after refresh token
- KeycloakGroup with field `attributes`
- Function to retrieve groups by attribute
- Update call api GET (for users and groups) with param briefRepresentation as false. This allows to get the full representation of the object.
- Update create_user and create_group
- Function to refresh token
- Override user_login to take an account more details
- Update OIDCUser to add field from attributes
