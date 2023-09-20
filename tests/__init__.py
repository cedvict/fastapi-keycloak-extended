import pytest

from fastapi_keycloak import FastAPIKeycloak


class BaseTestClass:
    @pytest.fixture
    def idp(self):
        return FastAPIKeycloak(
            server_url="http://dev-keycloak.mydomain.test",
            client_id="test-client",
            client_secret="M48lQhr3xQs71LWOa4gVRDA3VYlwOyTw",
            admin_client_id="admin-cli",
            admin_client_secret="FOG8Q9iWLiIN6W8sE2v5pwuShKFO21fc",
            realm="test",
            callback_uri="http://localhost:8081/callback",
        )
