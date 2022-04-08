from typing import Any, Union

import requests
from fastapi_keycloak import api
from fastapi_keycloak_extended.model import KeycloakGroup, KeycloakRefreshToken


class FastAPIKeycloak(api.FastAPIKeycloak):
    """Instance to wrap the Keycloak API with FastAPI

    Attributes: _admin_token (KeycloakToken): A KeycloakToken instance, containing the access token that is used for
    any admin related request

    Example:
        ```python
        app = FastAPI()
        idp = KeycloakFastAPI(
            server_url="https://auth.some-domain.com/auth",
            client_id="some-test-client",
            client_secret="some-secret",
            admin_client_secret="some-admin-cli-secret",
            realm="Test",
            callback_uri=f"http://localhost:8081/callback"
        )
        idp.add_swagger_config(app)
        ```
    """

    @api.result_or_error(response_model=KeycloakGroup, is_list=True)
    def get_all_groups(self) -> list[KeycloakGroup]:
        """Get all base groups of the Keycloak realm

        Returns:
            List[KeycloakGroup]: All base groups of the realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.groups_uri}?briefRepresentation=false", method=api.HTTPMethod.GET)

    @api.result_or_error(response_model=KeycloakGroup)
    def get_group_by_attribute(
            self, attribute: str, value: Any, search_in_subgroups=True
    ) -> list[KeycloakGroup]:
        """Return Group based on attribute

        Args:
            attribute (str): Attribute that should be looked up
            value (str): Value that should be looked up
            search_in_subgroups (bool): Whether to search in subgroups

        Returns:
            KeycloakGroup: Full entries stored at Keycloak. Or None if the path not found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        groups = self.get_all_groups()

        result = []
        for group in groups:
            if attribute in group.attributes and group.attributes[attribute] == value:
                result.append(group)
            elif search_in_subgroups and group.subGroups:
                for sub_group in group.subGroups:
                    if attribute in sub_group.attributes and sub_group.attributes[attribute] == value:
                        result.append(sub_group)
        return result

    @api.result_or_error(response_model=KeycloakGroup)
    def get_group(self, group_id: str) -> KeycloakGroup or None:
        """Return Group based on group id

        Args:
            group_id (str): Group id to be found

        Returns:
             KeycloakGroup: Keycloak object by id. Or None if the id is invalid

        Notes:
            - The Keycloak RestAPI will only identify GroupRepresentations that
              use name AND id which is the only reason for existence of this function

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.groups_uri}/{group_id}?briefRepresentation=false",
            method=api.HTTPMethod.GET,
        )

    @api.result_or_error(response_model=KeycloakGroup)
    def create_group(
            self, group_name: str, parent: Union[KeycloakGroup, str] = None, attributes: dict = None,
    ) -> KeycloakGroup:
        """Create a group on the realm

        Args:
            group_name (str): Name of the new group
            parent (Union[KeycloakGroup, str]): Can contain an instance or object id
            attributes (dict): Custom datas of the new group

        Returns:
            KeycloakGroup: If creation succeeded, else it will return the error

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """

        # If it's an object id get an instance of the object
        if isinstance(parent, str):
            parent = self.get_group(parent)

        if parent is not None:
            groups_uri = f"{self.groups_uri}/{parent.id}/children"
            path = f"{parent.path}/{group_name}"
        else:
            groups_uri = self.groups_uri
            path = f"/{group_name}"

        data = {"name": group_name}
        if attributes:
            data.update(attributes=attributes)

        response = self._admin_request(
            url=groups_uri, data=data, method=api.HTTPMethod.POST
        )
        if response.status_code == 201:
            return self.get_group_by_path(path=path, search_in_subgroups=True)
        else:
            return response

    @api.result_or_error(response_model=api.KeycloakUser)
    def create_user(
            self,
            first_name: str,
            last_name: str,
            username: str,
            email: str,
            password: str,
            enabled: bool = True,
            initial_roles: list[str] = None,
            send_email_verification: bool = True,
            attributes: dict = None,
    ) -> api.KeycloakUser:
        """

        Args:
            first_name (str): The first name of the new user
            last_name (str): The last name of the new user
            username (str): The username of the new user
            email (str): The email of the new user
            password (str): The password of the new user
            initial_roles (List[str]): The roles the user should posses. Defaults to `None`
            enabled (bool): True if the user should be able to be used. Defaults to `True`
            send_email_verification (bool): If true, the email verification will be added as an required
                                            action and the email triggered - if the user was created successfully.
                                            Defaults to `True`
            attributes (dict): The custom fields of new user

        Returns:
            KeycloakUser: If the creation succeeded

        Notes:
            - Also triggers the email verification email

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        data = {
            "email": email,
            "username": username,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "credentials": [
                {"temporary": False, "type": "password", "value": password}
            ],
            "requiredActions": ["VERIFY_EMAIL" if send_email_verification else None],
        }
        if attributes:
            data.update(attributes=attributes)
        response = self._admin_request(
            url=self.users_uri, data=data, method=api.HTTPMethod.POST
        )
        if response.status_code != 201:
            return response
        user = self.get_user(query=f"username={username}")
        if send_email_verification:
            self.send_email_verification(user.id)
        if initial_roles:
            self.add_user_roles(initial_roles, user.id)
            user = self.get_user(user_id=user.id)
        return user

    @api.result_or_error(response_model=api.KeycloakUser, is_list=True)
    def get_all_users(self) -> list[api.KeycloakUser]:
        """Returns all users of the realm

        Returns:
            List[KeycloakUser]: All Keycloak users of the realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.users_uri}?briefRepresentation=false", method=api.HTTPMethod.GET)

    @api.result_or_error(response_model=KeycloakRefreshToken)
    def refresh_token(self, refresh_token: str) -> KeycloakRefreshToken:
        """
        Try to retrieve a new valid token from refresh token

        Args:
            refresh_token (str): refresh token

        Returns:
            KeycloakToken: If the exchange succeeds
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        response = requests.post(url=self.token_uri, headers=headers, data=data)
        return response
