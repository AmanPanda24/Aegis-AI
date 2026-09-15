import types
from src.capture.packet_capture import PacketCapture
from src.capture.l2_capture import L2Capture
from src.core.state import AegisState


def _FakeState():
    # PacketCapture._process_packet touches state.stats (not just
    # state.config), so tests that leave the simulation loop running in
    # the background while switch_mode() is exercised need the real
    # AegisState shape, not a partial stub - otherwise the background
    # thread throws AttributeError on every packet (still test-run-safe,
    # since exceptions in daemon threads don't fail the test itself, but
    # it's noisy and masks real failures in the actual test output).
    return AegisState()


def test_switch_to_live_fails_cleanly_without_scapy(monkeypatch):
    # Simulate an environment without scapy / without permission by forcing
    # SCAPY_AVAILABLE False, and confirm switch_mode reports a real error
    # instead of silently "succeeding" while nothing changed.
    import src.capture.packet_capture as pc_module
    monkeypatch.setattr(pc_module, "SCAPY_AVAILABLE", False)

    capture = PacketCapture(state=_FakeState(), mode="simulation")
    ok, err = capture.switch_mode("live")

    assert ok is False
    assert err is not None
    assert capture.mode == "simulation"  # unchanged - failed switch must not tear down the working mode


def test_switch_to_live_with_bad_interface_reports_error_and_keeps_simulation_running(monkeypatch):
    import src.capture.packet_capture as pc_module

    def fake_sniff(**kwargs):
        raise OSError(f"No such device: {kwargs.get('iface')}")

    monkeypatch.setattr(pc_module, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(pc_module, "sniff", fake_sniff)

    capture = PacketCapture(state=_FakeState(), mode="simulation")
    capture.start()
    try:
        ok, err = capture.switch_mode("live", interface="nonexistent0")
        assert ok is False
        assert "nonexistent0" in err
        # Must not have torn down simulation capture on a failed switch.
        assert capture.mode == "simulation"
        assert capture.running is True
    finally:
        capture.stop()


def test_switch_to_live_succeeds_when_preflight_passes(monkeypatch):
    import src.capture.packet_capture as pc_module

    def fake_sniff(**kwargs):
        return None  # simulate a clean, permitted capture check

    monkeypatch.setattr(pc_module, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(pc_module, "sniff", fake_sniff)

    capture = PacketCapture(state=_FakeState(), mode="simulation")
    capture.start()
    try:
        ok, err = capture.switch_mode("live", interface="eth0")
        assert ok is True
        assert err is None
        assert capture.mode == "live"
        assert capture.interface == "eth0"
    finally:
        capture.stop()


def test_switch_mode_rejects_unknown_mode():
    capture = PacketCapture(state=_FakeState(), mode="simulation")
    ok, err = capture.switch_mode("teleport")
    assert ok is False
    assert "teleport" in err


def test_l2_switch_mode_same_contract(monkeypatch):
    import src.capture.l2_capture as l2_module

    def fake_sniff(**kwargs):
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(l2_module, "SCAPY_AVAILABLE", True)
    monkeypatch.setattr(l2_module, "sniff", fake_sniff)

    l2 = L2Capture(state=_FakeState(), mode="simulation")
    l2.start()
    try:
        ok, err = l2.switch_mode("live")
        assert ok is False
        assert "Permission" in err or "permission" in err
        assert l2.mode == "simulation"
    finally:
        l2.stop()
