from typing import Any, Union

import requests
from fastapi.security import OAuth2PasswordBearer
from fastapi_keycloak import api
from fastapi_keycloak_extended.model import (
    KeycloakGroup,
    KeycloakRefreshToken,
    KeycloakToken,
    OIDCUser,
    KeycloakUser,
)


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

    def get_current_user(self, required_roles: list[str] = None) -> OIDCUser:
        """Returns the current user based on an access token in the HTTP-header. Optionally verifies roles are possessed
        by the user

        Args:
            required_roles List[str]: List of role names required for this endpoint

        Returns:
            OIDCUser: Decoded JWT content

        Raises:
            ExpiredSignatureError: If the token is expired (exp > datetime.now())
            JWTError: If decoding fails or the signature is invalid
            JWTClaimsError: If any claim is invalid
            HTTPException: If any role required is not contained within the roles of the users
        """

        def current_user(
            token: OAuth2PasswordBearer = api.Depends(self.user_auth_scheme),
        ) -> OIDCUser:
            """Decodes and verifies a JWT to get the current user

            Args:
                token OAuth2PasswordBearer: Access token in `Authorization` HTTP-header

            Returns:
                OIDCUser: Decoded JWT content

            Raises:
                ExpiredSignatureError: If the token is expired (exp > datetime.now())
                JWTError: If decoding fails or the signature is invalid
                JWTClaimsError: If any claim is invalid
                HTTPException: If any role required is not contained within the roles of the users
            """
            decoded_token = self._decode_token(token=token, audience="account")
            user = OIDCUser.parse_obj(decoded_token)
            if required_roles:
                for role in required_roles:
                    if role not in user.roles:
                        raise api.HTTPException(
                            status_code=403,
                            detail=f'Role "{role}" is required to perform this action',
                        )
            return user

        return current_user

    @api.result_or_error(response_model=KeycloakToken)
    def user_login(self, username: str, password: str) -> KeycloakToken:
        """Models the password OAuth2 flow. Exchanges username and password for an access token. Will raise detailed
        errors if login fails due to requiredActions

        Args:
            username (str): Username used for login
            password (str): Password of the user

        Returns:
            KeycloakToken: If the exchange succeeds

        Raises:
            HTTPException: If the credentials did not match any user
            MandatoryActionException: If the login is not possible due to mandatory actions
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299, != 400, != 401)
            UpdateUserLocaleException: If the credentials we're correct but the has requiredActions of which the first one is to update his locale
            ConfigureTOTPException: If the credentials we're correct but the has requiredActions of which the first one is to configure TOTP
            VerifyEmailException: If the credentials we're correct but the has requiredActions of which the first one is to verify his email
            UpdatePasswordException: If the credentials we're correct but the has requiredActions of which the first one is to update his password
            UpdateProfileException: If the credentials we're correct but the has requiredActions of which the first one is to update his profile

        Notes:
            - To avoid calling this multiple times, you may want to check all requiredActions of the user if it fails due to a (sub)instance of an MandatoryActionException
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password,
            "grant_type": "password",
        }
        response = requests.post(url=self.token_uri, headers=headers, data=data)
        if response.status_code == 401:
            raise api.HTTPException(status_code=401, detail="Invalid user credentials")
        if response.status_code == 400:
            user: KeycloakUser = self.get_user(query=f"username={username}")
            if len(user.requiredActions) > 0:
                reason = user.requiredActions[0]
                exception = {
                    "update_user_locale": api.UpdateUserLocaleException(),
                    "CONFIGURE_TOTP": api.ConfigureTOTPException(),
                    "VERIFY_EMAIL": api.VerifyEmailException(),
                    "UPDATE_PASSWORD": api.UpdatePasswordException(),
                    "UPDATE_PROFILE": api.UpdateProfileException(),
                }.get(
                    reason,  # Try to return the matching exception
                    # On custom or unknown actions return a MandatoryActionException by default
                    api.MandatoryActionException(
                        detail=f"This user can't login until the following action has been "
                        f"resolved: {reason}"
                    ),
                )
                raise exception
        return response

    @api.result_or_error(response_model=KeycloakGroup, is_list=True)
    def get_all_groups(self) -> list[KeycloakGroup]:
        """Get all base groups of the Keycloak realm

        Returns:
            List[KeycloakGroup]: All base groups of the realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.groups_uri}?briefRepresentation=false",
            method=api.HTTPMethod.GET,
        )

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
                    if (
                        attribute in sub_group.attributes
                        and sub_group.attributes[attribute] == value
                    ):
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
        self,
        group_name: str,
        parent: Union[KeycloakGroup, str] = None,
        attributes: dict = None,
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

    @api.result_or_error(response_model=KeycloakUser)
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
    ) -> KeycloakUser:
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

    @api.result_or_error(response_model=KeycloakUser)
    def get_user(self, user_id: str = None, query: str = "") -> KeycloakUser:
        """Queries the keycloak API for a specific user either based on its ID or any **native** attribute

        Args:
            user_id (str): The user ID of interest
            query: Query string. e.g. `email=testuser@codespecialist.com` or `username=codespecialist`

        Returns:
            KeycloakUser: If the user was found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if user_id is None:
            response = self._admin_request(
                url=f"{self.users_uri}?{query}&briefRepresentation=false",
                method=api.HTTPMethod.GET,
            )
            return KeycloakUser(**response.json()[0])
        else:
            response = self._admin_request(
                url=f"{self.users_uri}/{user_id}?briefRepresentation=false",
                method=api.HTTPMethod.GET,
            )
            return KeycloakUser(**response.json())

    @api.result_or_error(response_model=KeycloakUser)
    def update_user(self, user: KeycloakUser):
        """Updates a user. Requires the whole object.

        Args:
            user (KeycloakUser): The (new) user object

        Returns:
            KeycloakUser: The updated user

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)

        Notes: - You may alter any aspect of the user object, also the requiredActions for instance. There is no
        explicit function for updating those as it is a user update in essence
        """
        response = self._admin_request(
            url=f"{self.users_uri}/{user.id}",
            data=user.__dict__,
            method=api.HTTPMethod.PUT,
        )
        if response.status_code == 204:  # Update successful
            return self.get_user(user_id=user.id)
        return response

    @api.result_or_error(response_model=KeycloakUser, is_list=True)
    def get_all_users(self) -> list[KeycloakUser]:
        """Returns all users of the realm

        Returns:
            List[KeycloakUser]: All Keycloak users of the realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_uri}?briefRepresentation=false", method=api.HTTPMethod.GET
        )

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
