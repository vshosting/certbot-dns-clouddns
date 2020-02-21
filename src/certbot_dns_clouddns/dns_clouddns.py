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
            add, default_propagation_seconds=100
        )
        add("credentials", help="CloudDNS credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the CloudDNS Remote REST API."
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

    def _perform(self, domain, validation_name, validation):
        self._get_clouddns_client().add_txt_record(
            domain, validation_name, validation, self.ttl
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


class _CloudDNSClient(object):
    """
    Encapsulates all communication with the CloudDNS Remote REST API.
    """

    dns_api = "https://admin.vshosting.cloud/clouddns"
    login_api = "https://admin.vshosting.cloud/api/public/auth/login"

    def __init__(self, clientid, email, password):
        logger.debug("Creating CloudDNSClient")
        self.access_token = None
        self.clientid = clientid
        self.email = email
        self.password = password
        self.session = requests.Session()

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the CloudDNS API
        """
        o_record_name = record_name
        record_name = self._format_record_name(o_record_name)

        domain_id, domain_name = self._find_domain_id(domain, record_name)
        logger.debug("Domain found: %s with id: %s", domain_name, domain_id)

        data = self._prepare_record_data(domain_id, record_name, record_content)
        logger.debug("Insert TXT record with data: %s", data)
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
        o_record_name = record_name
        record_name = self._format_record_name(o_record_name)

        domain_id, domain_name = self._find_domain_id(domain, record_name)
        logger.debug("Domain found: %s with id: %s", domain_name, domain_id)

        record_id = self.get_record_id(domain_id, record_name)
        if record_id is not None:
            logger.debug("Delete TXT record with id: %s", record_id)
            endpoint = "record/{0}".format(record_id)
            self._api_request("DELETE", endpoint)
            self._publish_dns_changes(domain_id, record_ttl)

    def get_record_id(self, domain_id, record_name):
        """
        Get record id for the ACME challenge TXT record.

        If an error occurs, it is suppressed and None is returned.

        :param str zone_id: The ID of the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').

        :returns: record id or None
        :rtype: `string` or `None`
        """
        endpoint = "domain/{0}".format(domain_id)
        domain_data = self._api_request("GET", endpoint)["lastDomainRecordList"]
        for entry in domain_data:
            if entry["name"] == record_name and entry["type"] == "TXT":
                logger.debug("Record id found: %s", entry["id"])
                return entry["id"]
        return None

    def _api_request(self, method, endpoint, data=None):
        """
        Make a request against CloudDNS API.

        :param str method: HTTP method to use.
        :param str endpoint: API endpoint to call.
        :param dict data: Dictionary to send a JSON data.
        :returns: Dictionary of the JSON response.
        :rtype: dict
        """
        if self.access_token is None:
            self._login()
        headers = {"Authorization": "Bearer {0}".format(self.access_token)}
        url = self._get_url(endpoint)
        return self._request(method, url, data, headers)

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
                logger.debug("Looking for domain: %s", domain_name)
                domain_name = self._format_record_name(domain_name)
                domain_search = self._prepare_domain_search(domain_name)
                resp = self._api_request("POST", "domain/search", domain_search)
                domain_id = resp["items"][0]["id"]
                logger.debug("Found domain %s for domain %s", domain_id, domain_name)
                return domain_id, domain_name
            except IndexError:
                pass
        raise errors.PluginError("Domain not found")

    def _format_record_name(self, record_name):
        """
        Format record to canonical form.

        :param str record_name: A DNS record name.
        :returns: The DNS record name in canonical form.
        :rtype: str
        """
        if not record_name.endswith("."):
            record_name = "{0}.".format(record_name)
        return record_name

    def _get_url(self, endpoint):
        """
        Get API URL for given endpoint.

        :param str endpoint: API endpoint.
        :returns: Full API URL.
        :rtype: str
        """
        return "{0}/{1}".format(self.dns_api, endpoint)

    def _login(self):
        """
        Login to CloudDNS with given credentials (typically saved in credentias.ini).
        """
        if self.access_token is not None:
            return
        logger.debug("Logging in")
        logindata = {"email": self.email, "password": self.password}
        resp = self._request("POST", self.login_api, logindata)
        self.access_token = resp["auth"]["accessToken"]
        logger.debug("accessToken is %s", self.clientid)

    def _prepare_domain_search(self, domain_name):
        """
        Prepare JSON for domain search.

        :param str domain_name: Domain name that we are looking for.
        :returns: Dictionary of search JSON.
        :rtype: dict
        """
        data = {
            "search": [
                {"name": "clientId", "operator": "eq", "value": self.clientid},
                {"name": "domainName", "operator": "eq", "value": domain_name},
            ]
        }
        return data

    def _prepare_record_data(self, domain_id, record_name, record_content):
        """
        Prepare JSON for record data.

        :param str domain_id: Domain id of the zone.
        :param str record_name: Record name to add.
        :param str record_content: Record content to add.
        :returns: Dictionary of record JSON.
        :rtype: dict
        """
        data = {
            "domainId": domain_id,
            "name": record_name,
            "value": record_content,
            "type": "TXT",
        }
        return data

    def _publish_dns_changes(self, domain_id, record_ttl):
        """
        Pushed changes to DNS zone.

        :param str domain_id: Id of the DNS zone with unpublished changes.
        :param int record_ttl: TTL to set.
        """
        data = {"soaTtl": record_ttl}
        endpoint = "domain/{0}/publish".format(domain_id)
        self._api_request("PUT", endpoint, data)

    def _request(self, method, url, data=None, headers=None):
        """
        Make HTTP request.

        :param str method: HTTP method to use.
        :param str url: URL to call.
        :param dict data: Dictionary with data to send as JSON.
        :param dict headers: Headers to send.
        :returns: Dictionary of the JSON response.
        :rtype: dict
        :raises certbot.errors.PluginError: In case of HTTP error.
        """
        resp = self.session.request(method, url, json=data, headers=headers)
        logger.debug("API Request to URL: %s", url)
        if resp.status_code != 200:
            raise errors.PluginError("HTTP Error {0}".format(resp.status_code))
        try:
            result = resp.json()
        except json.JSONDecodeError:
            raise errors.PluginError(
                "API response with non JSON: {0}".format(resp.text)
            )
        else:
            return result
