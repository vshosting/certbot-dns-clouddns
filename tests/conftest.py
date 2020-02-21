try:
    from http import server
except ImportError:
    import BaseHTTPServer as server
import socket
import threading

import pytest

from tests.servers import login_server as login_mock
from tests.servers import api_server as api_mock


@pytest.fixture(scope="session")
def login_server_port():
    s = socket.socket(socket.AF_INET, type=socket.SOCK_STREAM)
    s.bind(("localhost", 0))
    address, port = s.getsockname()
    s.close()
    return port


@pytest.fixture(scope="session")
def login_server(login_server_port):
    mock_server = server.HTTPServer(
        ("localhost", login_server_port), login_mock.MockLoginServer
    )
    mock_server_thread = threading.Thread(target=mock_server.serve_forever)
    mock_server_thread.setDaemon(True)
    mock_server_thread.start()
    return mock_server


@pytest.fixture(scope="session")
def api_server_port():
    s = socket.socket(socket.AF_INET, type=socket.SOCK_STREAM)
    s.bind(("localhost", 0))
    address, port = s.getsockname()
    s.close()
    return port


@pytest.fixture(scope="session")
def api_server(api_server_port):
    mock_server = server.HTTPServer(
        ("localhost", api_server_port), api_mock.MockApiServer
    )
    mock_server_thread = threading.Thread(target=mock_server.serve_forever)
    mock_server_thread.setDaemon(True)
    mock_server_thread.start()
    return mock_server
