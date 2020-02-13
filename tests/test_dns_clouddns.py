"""Tests for certbot_dns_clouddns.dns_clouddns."""
from certbot.compat import os
from certbot.plugins import dns_test_common
import pytest

from certbot_dns_clouddns import dns_clouddns


@pytest.fixture(scope="session")
def clientid():
    return "123456789123456789123456"


@pytest.fixture(scope="session")
def email():
    return "user@email.example"


@pytest.fixture(scope="session")
def password():
    return "password"


@pytest.fixture(scope="session")
def record():
    return "_acme-challenge.domain.example"


@pytest.fixture(scope="session")
def record_content():
    return "fake_record_content"


@pytest.fixture(scope="session")
def record_ttl():
    return 300


@pytest.fixture()
def credentials_file(tmpdir, clientid, email, password):
    path = os.path.join(tmpdir, "credentials.ini")
    dns_test_common.write(
        {
            "ispconfig_username": clientid,
            "ispconfig_password": email,
            "ispconfig_endpoint": password,
        },
        path,
    )
    return path


@pytest.fixture()
def client(clientid, email, password):
    return dns_clouddns._CloudDNSClient(clientid, email, password)


class TestCloudDNSClient(object):

    def test_login(self, client, requests_mock):
        response_json = {"auth": {"accessToken": "cxvgs43nejfslfsj"}}
        requests_mock.post(client.login_api, json=response_json)
        client._login()
        assert client.access_token != None

    def test_add_txt_record(self, client, record, record_content, record_ttl, requests_mock):
        response_json = {"auth": {"accessToken": "cxvgs43nejfslfsj"}}
        requests_mock.post(client.login_api, json=response_json)

        url = "{0}/domain/search".format(client.dns_api)
        domain_id = "fake_domain_id"
        response_json = {
            "items": [
                {"id": domain_id},
                {"id": "wrong_id"}
            ]
        }
        requests_mock.post(url, json=response_json)

        url = "{0}/record-txt".format(client.dns_api)
        requests_mock.post(url, json={"message": "ok"})

        domain_id = "fake_domain_id"
        url = "{0}/domain/{1}/publish".format(client.dns_api, domain_id)
        requests_mock.put(url, json={"message": "domain added ok"})

        client.add_txt_record(record, record, record_content, record_ttl)

    def test_del_txt_record(self, client, record, requests_mock):
        response_json = {"auth": {"accessToken": "cxvgs43nejfslfsj"}}
        requests_mock.post(client.login_api, json=response_json)

        url = "{0}/domain/search".format(client.dns_api)
        domain_id = "fake_domain_id"
        response_json = {
            "items": [
                {"id": domain_id},
                {"id": "wrong_id"}
            ]
        }
        requests_mock.post(url, json=response_json)

        domain_id = "fake_domain_id"
        record_id = "fake_record_id"
        response_json = {
            "lastDomainRecordList": [
                {
                    "name": "wrong.domain.example",
                    "type": "TXT",
                    "id": "wrongid"
                },
                {
                    "name": record,
                    "type": "TXT",
                    "id": record_id
                }
            ]
        }
        url = "{0}/domain/{1}".format(client.dns_api, domain_id)
        requests_mock.get(url, json=response_json)

        url = "{0}/record/{1}".format(client.dns_api, record_id)
        requests_mock.delete(url, json={"message": "ok"})

        domain_id = "fake_domain_id"
        url = "{0}/domain/{1}/publish".format(client.dns_api, domain_id)
        requests_mock.put(url, json={"message": "domain added ok"})

    def test_get_record_id(self, client, record, requests_mock):
        response_json = {"auth": {"accessToken": "cxvgs43nejfslfsj"}}
        requests_mock.post(client.login_api, json=response_json)

        domain_id = "fake_domain_id"
        record_id = "fake_record_id"
        response_json = {
            "lastDomainRecordList": [
                {
                    "name": "wrong.domain.example",
                    "type": "TXT",
                    "id": "wrongid"
                },
                {
                    "name": record,
                    "type": "TXT",
                    "id": record_id
                }
            ]
        }
        url = "{0}/domain/{1}".format(client.dns_api, domain_id)
        requests_mock.get(url, json=response_json)

        response = client.get_record_id(domain_id, record)
        assert response == record_id
