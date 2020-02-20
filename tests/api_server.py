try:
    from http import server
except ImportError:
    import BaseHTTPServer as server
import json
import re


class MockApiServer(server.BaseHTTPRequestHandler):
    ACCESS_TOKEN = "access_token"
    CLIENT_ID = "fake_client_id_length_24"
    DOMAIN_ID = "domain_id"
    DOMAIN_NAME = "domain.example"
    RECORD_CONTENT = "record_content"
    RECORD_ID = "record_id"
    RECORD_NAME = "_acme-challenge.domain.example."

    ADD_TXT_RECORD_ENDPOINT = "/record-txt"
    DOMAIN_ENDPOINT = "/domain/domain_id"
    DOMAIN_SEARCH_ENDPOINT = "/domain/search"
    PUBLISH_ENDPOINT = re.compile(r"^/domain/domaid_id/publish$")
    DELETE_RECORD_ENDPOINT = re.compile(r"^/record/[^/]+$")

    def _check_access_token(self):
        return self.ACCESS_TOKEN in self.headers["Authorization"]

    def _get_data(self):
        content_length = int(self.headers["Content-Length"])
        try:
            raw_data = self.rfile.read(content_length).decode("utf-8")
        except AttributeError:
            raw_data = self.rfile.read(content_length)
        return json.loads(raw_data)

    def _respond_add_txt_record(self, data):
        if data["domainId"] != self.DOMAIN_ID:
            self._send_response(400, {"code": 4108, "message": "Domain not found"})
        if data["name"] != self.RECORD_NAME:
            self._send_response(
                400,
                {
                    "code": 4142,
                    "message": "Invalid characters in record name. Valid hostname required.",
                },
            )
            return
        if data["value"] != self.RECORD_CONTENT:
            self._send_response(400, {"code": 400, "message": "wrong user input"})
            return
        self._send_response(200, [])

    def _respond_domain_search(self, data):
        client_search = data["search"][0]
        client_id = (
            client_search["name"] == "clientId"
            and client_search["operator"] == "eq"
            and client_search["value"] == self.CLIENT_ID
        )
        domain_search = data["search"][1]
        domain_id = (
            domain_search["name"] == "domainName"
            and domain_search["operator"] == "eq"
            and domain_search["value"]
        )
        if domain_search["value"] != self.RECORD_NAME:
            self._send_response(
                200, {"offset": 0, "limit": 10000, "totalHits": 0, "items": []}
            )
            return
        if not (client_id and domain_id):
            self._send_response(500, {"code": 500, "message": "clientId"})
            return
        self._send_response(200, {"items": [{"id": self.DOMAIN_ID}]})

    def _send_data(self, data):
        response_content = json.dumps(data)
        self.wfile.write(response_content.encode("utf-8"))

    def _send_headers(self):
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()

    def _send_response(self, code, data):
        self.send_response(code)
        self._send_headers()
        self._send_data(data)

    def do_DELETE(self):
        if not self._check_access_token():
            self._send_response(401, {"code": 401, "message": "Not authorized"})
            return
        if re.search(self.DELETE_RECORD_ENDPOINT, self.path):
            self._send_response(400, {"code": 4108, "message": "Domain not found"})
            return
        self._send_response(200, {"code": 200, "message": "ok"})
        return

    def do_GET(self):
        if not self._check_access_token():
            self._send_response(401, {"code": 401, "message": "Not authorized"})
            return
        if not re.search(self.DOMAIN_ENDPOINT, self.path):
            self._send_response(400, {"code": 4108, "message": "Domain not found"})
            return
        response = {
            "lastDomainRecordList": [
                {"name": self.RECORD_NAME, "type": "TXT", "id": self.RECORD_ID}
            ]
        }
        self._send_response(200, response)
        return

    def do_POST(self):
        data = self._get_data()
        if not self._check_access_token():
            self._send_response(401, {"code": 401, "message": "Not authorized"})
            return
        if re.search(self.ADD_TXT_RECORD_ENDPOINT, self.path):
            self._respond_add_txt_record(data)
            return
        if re.search(self.DOMAIN_SEARCH_ENDPOINT, self.path):
            self._respond_domain_search(data)
            return
        self._send_response(404, {"code": 404, "message": "Not Found"})
        return

    def do_PUT(self):
        data = self._get_data()
        if not self._check_access_token():
            self._send_response(401, {"code": 401, "message": "Not authorized"})
            return
        if re.search(self.PUBLISH_ENDPOINT, self.path):
            self._send_response(400, {"code": 4108, "message": "Domain not found"})
            return
        if type(data.get("soaTtl")) != int:
            self._send_response(400, {"code": 400, "message": "invalid user input"})
        self._send_response(200, {"code": 200, "message": "ok"})
        return
