"""DNS Authenticator for CloudDNS."""
import json
import logging

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for CloudDNS

    This Authenticator uses the CloudDNS Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using CloudDNS for DNS)."
    ttl = 300

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=60
        )
        add("credentials", help="CloudDNS credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the CloudDNS Remote REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "CloudDNS credentials INI file",
            {
                "clientId": "clientID for CloudDNS Remote API.",
                "email": "Email for CloudDNS Remote API.",
                "password": "Password for CloudDNS Remote API.",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_clouddns_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_clouddns_client().del_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _get_clouddns_client(self):
        return _CloudDNSClient(
            self.credentials.conf("clientId"),
            self.credentials.conf("email"),
            self.credentials.conf("password"),
        )


class _CloudDNSClient(object):
    """
    Encapsulates all communication with the CloudDNS Remote REST API.
    """

    dns_api = "https://admin.vshosting.cloud/clouddns"
    login_api = "https://admin.vshosting.cloud/api/public/auth/login"

    def __init__(self, clientid, email, password):
        logger.debug("creating clouddnsclient")
        self.access_token = None
        self.clientid = clientid
        self.email = email
        self.password = password
        self.session = requests.Session()

    def _login(self):
        if self.access_token is not None:
            return
        logger.debug("logging in")
        logindata = {"email": self.email, "password": self.password}
        resp = self._request("POST", self.login_api, logindata)
        self.access_token = resp["auth"]["accessToken"]
        logger.debug("accessToken is %s", self.clientid)

    def _api_request(self, method, endpoint, data=None):
        if self.access_token is None:
            raise errors.PluginError("Cannot make API request, accessToken missing")
        headers = {"Authorization": "Bearer {0}".format(self.access_token)}
        url = self._get_url(endpoint)
        return self._request(method, url, data, headers)

    def _request(self, method, url, data=None, headers=None):
        resp = self.session.request(method, url, json=data, headers=headers)
        logger.debug("API Request to URL: %s", url)
        if resp.status_code != 200:
            breakpoint()
            raise errors.PluginError("HTTP Error {0}".format(resp.status_code))
        try:
            result = resp.json()
        except json.JSONDecodeError:
            raise errors.PluginError(
                "API response with non JSON: {0}".format(resp.text)
            )
        else:
            return result

    def _get_url(self, endpoint):
        return "{0}/{1}".format(self.dns_api, endpoint)

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the CloudDNS API
        """
        self._login()
        o_record_name = record_name
        record_name = "{0}.".format(o_record_name)
        domain_id, domain_name = self._find_domain_id(domain, record_name)
        if domain_id is None:
            raise errors.PluginError("Domain not known")
        logger.debug("domain found: %s with id: %s", domain_name, domain_id)
        data = self._prepare_record_data(domain_id, record_name, record_content)
        logger.debug("insert txt record with data: %s", data)
        self._api_request("POST", "record-txt", data)
        self._publish_dns_changes(domain_id, record_ttl)

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the CloudDNS API
        """
        self._login()
        o_record_name = record_name
        record_name = "{0}.".format(o_record_name)
        domain_id, domain_name = self._find_domain_id(domain, record_name)
        if domain_id is None:
            raise errors.PluginError("Domain not known")
        logger.debug("domain found: %s with id: %s", domain_name, domain_id)
        record_id = self.get_record_id(domain_id, record_name)
        if record_id is not None:
            logger.debug("delete TXT record with id: %s", record_id)
            endpoint = "record/{0}".format(record_id)
            self._api_request("DELETE", endpoint)
            self._publish_dns_changes(domain_id, record_ttl)

    def _prepare_record_data(self, domain_id, record_name, record_content):
        data = {
            "domainId": domain_id,
            "name": record_name,
            "value": record_content,
            "type": "TXT",
        }
        return data

    def _prepare_domain_search(self, domain_name):
        data = {
            "search": [
                {"name": "clientId", "operator": "eq", "value": self.clientid},
                {"name": "domainName", "operator": "eq", "value": domain_name},
            ]
        }
        return data

    def _publish_dns_changes(self, domain_id, record_ttl):
        data = {"soaTtl": record_ttl}
        endpoint = "domain/{0}/publish".format(domain_id)
        self._api_request("PUT", endpoint, data)

    def _find_domain_id(self, domain, record_name):
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :returns: The ID of the managed zone, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if the managed zone cannot be found.
        """

        domain_dns_name_guesses = [record_name] + dns_common.base_domain_name_guesses(
            domain
        )

        for domain_name in domain_dns_name_guesses:
            # Get the domain id
            try:
                logger.debug("looking for domain: %s", domain_name)
                if not domain_name.endswith("."):
                    domain_name = "{0}.".format(domain_name)
                domain_search = self._prepare_domain_search(domain_name)
                resp = self._api_request("POST", "domain/search", domain_search)
                domain_id = resp["items"][0]["id"]
                return domain_id, domain_name
            except IndexError:
                pass
        return None

    def get_record_id(self, domain_id, record_name):
        """
        Get record id for the ACME challenge TXT record.

        If an error occurs, it is suppressed and None is returned.

        :param str zone_id: The ID of the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').

        :returns: record id or None
        :rtype: `string` or `None`
        """
        self._login()
        endpoint = "domain/{0}".format(domain_id)
        domain_data = self._api_request("GET", endpoint)["lastDomainRecordList"]
        for entry in domain_data:
            if entry["name"] == record_name and entry["type"] == "TXT":
                return entry["id"]
        return None
