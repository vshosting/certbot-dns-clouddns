"""Tests for certbot_dns_clouddns.dns_clouddns."""
from certbot import errors
import pytest

from certbot_dns_clouddns import dns_clouddns


@pytest.fixture(scope="session")
def access_token(login_server):
    return login_server.RequestHandlerClass.ACCESS_TOKEN


@pytest.fixture(scope="session")
def clientid(api_server):
    return api_server.RequestHandlerClass.CLIENT_ID


@pytest.fixture(scope="session")
def domain_id(api_server):
    return api_server.RequestHandlerClass.DOMAIN_ID


@pytest.fixture(scope="session")
def email(login_server):
    return login_server.RequestHandlerClass.EMAIL


@pytest.fixture(scope="session")
def password(login_server):
    return login_server.RequestHandlerClass.PASSWORD


@pytest.fixture(scope="session")
def record_content(api_server):
    return api_server.RequestHandlerClass.RECORD_CONTENT


@pytest.fixture(scope="session")
def record_id(api_server):
    return api_server.RequestHandlerClass.RECORD_ID


@pytest.fixture(scope="session")
def record_name(api_server):
    return api_server.RequestHandlerClass.RECORD_NAME


@pytest.fixture(scope="session")
def record_ttl():
    return 300


@pytest.fixture()
def client(clientid, email, password, login_server, api_server):
    mock_client = dns_clouddns._CloudDNSClient(clientid, email, password)

    # Set endpoind for mock login server
    host, port = login_server.server_address
    mock_client.login_api = "http://{0}:{1}/api/public/auth/login".format(host, port)

    # Set endpoind for mock api server
    host, port = api_server.server_address
    mock_client.dns_api = "http://{0}:{1}/clouddns".format(host, port)

    return mock_client


class TestCloudDNSClient(object):
    def test_login(self, client, access_token):
        # GIVEN a set of correct credentials
        # WHEN logging into CloudDNS
        client._login()

        # THEN we should get a access token
        assert client.access_token == access_token

    def test_login_wrong_email(self, client, access_token):
        # GIVEN an incorrect email
        # WHEN logging into CloudDNS
        client.password = "wrong email"

        # THEN a PluginError should be raised
        with pytest.raises(errors.PluginError):
            client._login()

    def test_login_wrong_password(self, client, access_token):
        # GIVEN an incorrect password
        # WHEN logging into CloudDNS
        client.password = "wrong password"

        # THEN a PluginError should be raised
        with pytest.raises(errors.PluginError):
            client._login()

    def test_add_txt_record(self, client, record_name, record_content, record_ttl):
        # GIVEN an ACME challenge record
        # WHEN adding it from CloudDNS
        client.add_txt_record(record_name, record_name, record_content, record_ttl)
        # THEN it should complete without error

    def test_add_txt_record_failed_auth(
        self, client, record_name, record_content, record_ttl
    ):
        # GIVEN an invalid accessToken
        client.access_token = "invalid_token"

        # WHEN adding an ACME challenge record to CloudDNS
        # THEN a PluginError should be raised
        with pytest.raises(errors.PluginError):
            client.add_txt_record(record_name, record_name, record_content, record_ttl)

    def test_add_txt_record_invalid_domain(
        self, client, record_name, record_content, record_ttl
    ):
        # GIVEN an invalid record name
        record_name = "_acme-challenge.invalid.domain"

        # WHEN adding it to CloudDNS
        # THEN a PluginError should be raised
        with pytest.raises(errors.PluginError):
            client.add_txt_record(record_name, record_name, record_content, record_ttl)

    def test_del_txt_record(self, client, record_name, record_content, record_ttl):
        # GIVEN an ACME challenge record
        # WHEN deleteing it from CloudDNS
        client.del_txt_record(record_name, record_name, record_content, record_ttl)
        # THEN it should complete without error

    def test_del_txt_record_failed_auth(
        self, client, record_name, record_content, record_ttl
    ):
        # GIVEN an invalid accessToken
        client.access_token = "invalid_token"

        # WHEN deleting an ACME challenge record from CloudDNS
        # THEN a PluginError should be raised
        with pytest.raises(errors.PluginError):
            client.del_txt_record(record_name, record_name, record_content, record_ttl)

    def test_del_txt_record_invalid_domain(
        self, client, record_name, record_content, record_ttl
    ):
        # GIVEN an invalid record name
        record_name = "_acme-challenge.invalid.domain"

        # WHEN removing it from CloudDNS
        # THEN a PluginError should be raised
        with pytest.raises(errors.PluginError):
            client.del_txt_record(record_name, record_name, record_content, record_ttl)

    def test_get_record_id(self, client, domain_id, record_name, record_id):
        # GIVEN a record_name and associated domain id
        # WHEN trying to get the record's id from CloudDNS
        returned_record_id = client.get_record_id(domain_id, record_name)

        # THEN we should get the correct id
        assert record_id == returned_record_id

    def test_get_record_id_invalid_domain_id(
        self, client, domain_id, record_name, record_id
    ):
        # GIVEN an invalid domain id
        domain_id = "invalid_domain_id"
        # WHEN trying to get the record's id from CloudDNS
        # THEN a PluginError should be raised
        with pytest.raises(errors.PluginError):
            client.get_record_id(domain_id, record_name)
