import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("AEGIS_API_KEY", "test-key-do-not-use-in-prod")

from src.api import main as aegis_main  # noqa: E402  (env var must be set first)


@pytest.fixture()
def client():
    with TestClient(aegis_main.app) as c:
        yield c


def test_protected_endpoint_rejects_missing_key(client):
    # Regression test: the original API had no authentication at all -
    # every endpoint was reachable by anyone who could route to the port.
    resp = client.get("/api/stats")
    assert resp.status_code == 401


def test_protected_endpoint_rejects_wrong_key(client):
    resp = client.get("/api/stats", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401


def test_protected_endpoint_accepts_correct_key(client):
    resp = client.get("/api/stats", headers={"X-API-Key": os.environ["AEGIS_API_KEY"]})
    assert resp.status_code == 200


def test_dashboard_root_is_reachable_without_a_key(client):
    # The dashboard HTML itself stays open (it's what bootstraps the key
    # into the page via window.AEGIS_API_KEY); only the *data* endpoints
    # require auth.
    resp = client.get("/")
    assert resp.status_code == 200


def test_dashboard_root_injects_api_key_for_the_bundled_js(client):
    resp = client.get("/")
    assert os.environ["AEGIS_API_KEY"] in resp.text


def test_cors_does_not_combine_wildcard_origin_with_credentials():
    # Regression test: the original config used allow_origins=["*"] AND
    # allow_credentials=True simultaneously, which is an invalid/unsafe CORS
    # configuration (rejected by browsers, and a red flag to any reviewer).
    origins = aegis_main.cors_origins
    allow_credentials = aegis_main.allow_credentials
    if "*" in origins:
        assert allow_credentials is False


def test_websocket_rejects_missing_api_key(client):
    from starlette.websockets import WebSocketDisconnect
    # Connecting without `?api_key=` must be rejected. The TestClient's
    # websocket_connect() doesn't raise on connect alone (the ASGI-level
    # close is only surfaced once something tries to use the socket), so
    # this drives a receive to actually observe the rejection.
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws") as ws:
            ws.receive_text()
    assert exc_info.value.code == 4401


def test_websocket_rejects_wrong_api_key(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws?api_key=wrong") as ws:
            ws.receive_text()
    assert exc_info.value.code == 4401


def test_websocket_accepts_correct_api_key(client):
    key = os.environ["AEGIS_API_KEY"]
    with client.websocket_connect(f"/ws?api_key={key}") as ws:
        ws.send_json({"action": "ping"})
        msg = ws.receive_json()
        assert msg["type"] == "pong"


def test_capture_status_endpoint_requires_auth(client):
    resp = client.get("/api/capture/status")
    assert resp.status_code == 401


def test_capture_status_endpoint_reports_real_state(client):
    resp = client.get("/api/capture/status", headers={"X-API-Key": os.environ["AEGIS_API_KEY"]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["requested_mode"] == "simulation"
    assert data["capture_thread_alive"] is True


def test_capture_mode_endpoint_rejects_bad_mode(client):
    resp = client.post(
        "/api/capture/mode",
        headers={"X-API-Key": os.environ["AEGIS_API_KEY"]},
        json={"mode": "teleport"},
    )
    assert resp.status_code == 422


def test_capture_mode_switch_to_live_fails_without_real_interface(client):
    # In this test environment there's no real interface/root capability,
    # so switching to live must fail with a clear error - not silently
    # report success while nothing changed (the original dashboard bug).
    resp = client.post(
        "/api/capture/mode",
        headers={"X-API-Key": os.environ["AEGIS_API_KEY"]},
        json={"mode": "live", "interface": "definitely-not-a-real-iface0"},
    )
    assert resp.status_code == 422
    assert "detail" in resp.json()

    # And simulation must still be the mode actually running.
    status = client.get("/api/capture/status", headers={"X-API-Key": os.environ["AEGIS_API_KEY"]}).json()
    assert status["requested_mode"] == "simulation"
    assert status["capture_thread_alive"] is True


def test_capture_mode_switch_failure_does_not_leave_l2_sidecar_out_of_sync(client):
    # Regression test: an earlier version of this endpoint switched the L2
    # sidecar to "live" unconditionally, even when the primary capture's
    # switch failed and the endpoint returned an error - leaving L2 running
    # live while the API reported the whole switch as failed.
    resp = client.post(
        "/api/capture/mode",
        headers={"X-API-Key": os.environ["AEGIS_API_KEY"]},
        json={"mode": "live", "interface": "definitely-not-a-real-iface0"},
    )
    assert resp.status_code == 422

    status = client.get("/api/capture/status", headers={"X-API-Key": os.environ["AEGIS_API_KEY"]}).json()
    assert status["l2_requested_mode"] == "simulation"
    resp = client.post(
        "/api/capture/mode",
        headers={"X-API-Key": os.environ["AEGIS_API_KEY"]},
        json={"mode": "simulation"},
    )
    assert resp.status_code == 200
    assert resp.json()["mode"] == "simulation"
