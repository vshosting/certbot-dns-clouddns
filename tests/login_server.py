try:
    from http import server
except ImportError:
    import BaseHTTPServer as server
import json
import re

import requests


class MockLoginServer(server.BaseHTTPRequestHandler):
    ACCESS_TOKEN = "access_token"
    EMAIL = "user@email.example"
    LOGIN_ENDPOINT = re.compile(r"^/api/public/auth/login$")
    PASSWORD = "password"

    def _get_data(self):
        content_length = int(self.headers["Content-Length"])
        try:
            raw_data = self.rfile.read(content_length).decode("utf-8")
        except AttributeError:
            raw_data = self.rfile.read(content_length)
        return json.loads(raw_data)

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

    def do_POST(self):
        data = self._get_data()
        if not re.search(self.LOGIN_ENDPOINT, self.path):
            self._send_response(404, {"code": 404, "message": "Not Found"})
            return
        if data["email"] != self.EMAIL or data["password"] != self.PASSWORD:
            self._send_response(
                400, {"code": 2001, "message": "Invalid user credentials"}
            )
            return
        self._send_response(
            requests.codes.ok, {"auth": {"accessToken": self.ACCESS_TOKEN}}
        )
        return
