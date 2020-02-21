try:
    from http import server
except ImportError:
    import BaseHTTPServer as server
import json


class BaseMockServer(server.BaseHTTPRequestHandler):
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
