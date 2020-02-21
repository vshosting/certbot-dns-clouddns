import re

from tests.servers import mock_server


class MockLoginServer(mock_server.BaseMockServer):
    ACCESS_TOKEN = "access_token"
    EMAIL = "user@email.example"
    LOGIN_ENDPOINT = re.compile(r"^/api/public/auth/login$")
    PASSWORD = "password"

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
        self._send_response(200, {"auth": {"accessToken": self.ACCESS_TOKEN}})
        return
