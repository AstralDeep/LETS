from __future__ import annotations

import base64
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from lets.client import LETSClient, RetryPolicy

_PEM = {
    "ca-cert.pem": (
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJsVENDQVR1Z0F3SUJBZ0lVVEVPRzR5SGZZemVa"
        "NEluZ25aa01TVjYxd004d0NnWUlLb1pJemowRUF3SXcKRnpFVk1CTUdBMVVFQXd3TVRFVlVVeTEwWlhO"
        "MExVTkJNQ0FYRFRJMk1EZ3dPVEV5TXpNeE5Gb1lEekl4TWpZdwpOekUyTVRJek16RTBXakFYTVJVd0V3"
        "WURWUVFEREF4TVJWUlRMWFJsYzNRdFEwRXdXVEFUQmdjcWhrak9QUUlCCkJnZ3Foa2pPUFFNQkJ3TkNB"
        "QVJaYWFmbEdsYWxXRzJTMCsrOTJ0ZTlUTytQbnNWTzZqb2lJZTRpaDJ3M21paDEKdjJOUlRRcUR1TTFD"
        "c0VKUmNzRjVVSEdzMkFaYStMdUZEYVJTeXB5Mm8yTXdZVEFkQmdOVkhRNEVGZ1FVOWlqNQprOTR4OWVq"
        "RW5HdzRFR2MyTjhsMnlqa3dId1lEVlIwakJCZ3dGb0FVOWlqNWs5NHg5ZWpFbkd3NEVHYzJOOGwyCnlq"
        "a3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0NnWUlLb1pJemowRUF3"
        "SUQKU0FBd1JRSWhBTi9VNmg5eDNDTllER0xaemJuU3lDdTRjR1FETi9qMnFSSzNLcXNwWm9Wd0FpQUhr"
        "Wm1WUld1UwppSnkwWm5CVHF1MGFlNjIwQXk0Y3R3N01VdHR2NnJWV0hRPT0KLS0tLS1FTkQgQ0VSVElG"
        "SUNBVEUtLS0tLQo="
    ),
    "server-cert.pem": (
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJyekNDQVZXZ0F3SUJBZ0lCQWpBS0JnZ3Foa2pP"
        "UFFRREFqQVhNUlV3RXdZRFZRUUREQXhNUlZSVExYUmwKYzNRdFEwRXdJQmNOTWpZd09EQTVNVEl6TkRR"
        "MldoZ1BNakV5TmpBM01UWXhNak0wTkRaYU1CUXhFakFRQmdOVgpCQU1NQ1d4dlkyRnNhRzl6ZERCWk1C"
        "TUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkRqc1E1ZlhpTWlOCjZQa1BpR2I5QUlwbERxWEZr"
        "a21xUDhhRjJVUHF5a251ajFNMGdnTFhJV0dJOE04R0Q0djl0YUhLb0kxcDVVc1EKc0c0KzF2U0toUWVq"
        "Z1pJd2dZOHdEQVlEVlIwVEFRSC9CQUl3QURBT0JnTlZIUThCQWY4RUJBTUNBNGd3RXdZRApWUjBsQkF3"
        "d0NnWUlLd1lCQlFVSEF3RXdHZ1lEVlIwUkJCTXdFWUlKYkc5allXeG9iM04waHdSL0FBQUJNQjBHCkEx"
        "VWREZ1FXQkJUOHo5MHhoMWV1YTdHdituMElZaHVyNndMQzRqQWZCZ05WSFNNRUdEQVdnQlQyS1BtVDNq"
        "SDEKNk1TY2JEZ1FaelkzeVhiS09UQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQlJnNXhXdkgvdDRJTzJ5"
        "RXRacjR0NwpiK2I5MUtxbTlCdmNaNUE3NzJLU2ZBSWhBT1BObHJTcUc5MlI2VTdzM1B1WU0ySmRobEhz"
        "SUp0REM5QTVjUDBHCm5KSUcKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
    ),
    "server-key.pem": (
        "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUhvR1o0V3p1VDdtNndORHJFanNp"
        "QXp3Rm5oNDRZUGJoaUFSTGhyUk9ZeTdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFT094RGw5ZUl5STNv"
        "K1ErSVp2MEFpbVVPcGNXU1Nhby94b1haUStyS1NlNlBVelNDQXRjaApZWWp3endZUGkvMjFvY3FnaldubF"
        "N4Q3diajdXOUlxRkJ3PT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
    ),
    "client-cert.pem": (
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJtRENDQVQ2Z0F3SUJBZ0lCQXpBS0JnZ3Foa2pP"
        "UFFRREFqQVhNUlV3RXdZRFZRUUREQXhNUlZSVExYUmwKYzNRdFEwRXdJQmNOTWpZd09EQTVNVEl6TkRR"
        "MldoZ1BNakV5TmpBM01UWXhNak0wTkRaYU1Cc3hHVEFYQmdOVgpCQU1NRUV4RlZGTXRkR1Z6ZEMxamJH"
        "bGxiblF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVQ1CjB2RXFQRkllbXI3bnA3c0Rn"
        "QW41cnpZZEl0aUEyU2NrRnhGOTliTThtdXhSYlJYZVpCY3Q3NGlTelI2V0RJS2IKR2o1T3VMU09pNThi"
        "dVE2bVlzTG1vM1V3Y3pBTUJnTlZIUk1CQWY4RUFqQUFNQTRHQTFVZER3RUIvd1FFQXdJSApnREFUQmdO"
        "VkhTVUVEREFLQmdnckJnRUZCUWNEQWpBZEJnTlZIUTRFRmdRVTZVVmNMdXNjNnpTVG5KQ05UcFFFCnBl"
        "WEZQcDB3SHdZRFZSMGpCQmd3Rm9BVTlpajVrOTR4OWVqRW5HdzRFR2MyTjhsMnlqa3dDZ1lJS29aSXpq"
        "MEUKQXdJRFNBQXdSUUloQUpGZ0FVZDhsYzFwc3JyUXhPYVQ2MTJTcHlJeXdnNjJGNlRrcGZlcXpSZXhB"
        "aUFLbUc2SgpEL2lyMHpsVXNPaVBmS2kvVkVUOUJSSis2Q0RkVGdxUENZd0lHQT09Ci0tLS0tRU5EIENF"
        "UlRJRklDQVRFLS0tLS0K"
    ),
    "client-key.pem": (
        "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUlhTGZndXFVeXZDMEZTQmtwcVhk"
        "dzdGNmRTN09oU0Jid0Jsclprem5sZmFvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFK2RMeEtqeFNIcHEr"
        "NTZlN0E0QUorYTgySFNMWWdOa25KQmNSZmZXelBKcnNVVzBWM21RWApMZStJa3MwZWxneUNteG8rVHJp"
        "MGpvdWZHN2tPcG1MQzVnPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
    ),
}


class _LiveHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/health/live":
            self.send_error(404)
            return
        body = b'{"status":"live"}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def _materialize(tmp_path: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for name, encoded in _PEM.items():
        path = tmp_path / name
        path.write_bytes(base64.b64decode(encoded, validate=True))
        result[name] = path
    return result


@pytest.mark.parametrize("explicit_context", [False, True])
def test_ca_path_and_client_certificate_complete_a_real_mtls_request(
    tmp_path: Path,
    explicit_context: bool,
) -> None:
    material = _materialize(tmp_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LiveHandler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(material["server-cert.pem"], material["server-key.pem"])
    server_context.load_verify_locations(cafile=material["ca-cert.pem"])
    server_context.verify_mode = ssl.CERT_REQUIRED
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    verify: str | ssl.SSLContext = str(material["ca-cert.pem"])
    if explicit_context:
        verify = ssl.create_default_context(cafile=material["ca-cert.pem"])
    client = LETSClient(
        f"https://127.0.0.1:{server.server_port}",
        verify=verify,
        cert=(str(material["client-cert.pem"]), str(material["client-key.pem"])),
        timeout=2,
        total_timeout_s=2,
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        assert client.liveness() == {"status": "live"}
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(2)
    assert not thread.is_alive()


def test_real_mtls_server_rejects_a_client_without_its_certificate(tmp_path: Path) -> None:
    material = _materialize(tmp_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LiveHandler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(material["server-cert.pem"], material["server-key.pem"])
    server_context.load_verify_locations(cafile=material["ca-cert.pem"])
    server_context.verify_mode = ssl.CERT_REQUIRED
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = LETSClient(
        f"https://127.0.0.1:{server.server_port}",
        verify=str(material["ca-cert.pem"]),
        timeout=2,
        total_timeout_s=2,
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(httpx.TransportError):
            client.liveness()
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(2)
    assert not thread.is_alive()
