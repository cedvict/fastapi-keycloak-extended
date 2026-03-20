import pytest

from fastapi_keycloak_extended import FastAPIKeycloak


class BaseTestClass:
    @pytest.fixture
    def idp(self):
        return FastAPIKeycloak(
            server_url="http://localhost:8080",
            client_id="demo-client",
            client_secret="demo-client-secret-123456",
            admin_client_id="admin-cli",
            admin_client_secret="admin-client-secret-abcdef",
            realm="demo-realm",
            callback_uri="http://localhost:3000/callback",
        )
