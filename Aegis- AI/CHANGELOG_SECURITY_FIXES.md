# CHANGELOG — Security & Correctness Remediation Pass

This pass fixed every bug identified in a full-codebase review (every file
in `src/`, `scripts/`, `tests/`, `config/`, `docker-compose.yml`,
`Dockerfile`, `README.md`). Each fix below was verified with an actual
executed test (in `tests/`, or an ad-hoc script during the fix), not just
re-reading the code. All 57 tests pass (35 pre-existing + 22 new).

## Critical

**1. Flow-assembly bug — attack traffic never reached detection**
(`src/capture/packet_capture.py`)
- `PacketCapture.flows` was keyed by the *literal* per-packet
  `(src_ip,dst_ip,src_port,dst_port,protocol)`, so a response packet
  (swapped src/dst/ports) could never land in the same bucket as its
  request — every flow was structurally one-directional, and
  `total_bwd_packets`/`down_up_ratio`/etc. were dead code for every flow,
  live or simulated.
- Flows were also only ever forwarded to detection once they had `>= 2`
  packets, silently discarding every single-packet flow (a lone scan
  probe, a DNS query, an ICMP ping) once `_flush_old_flows()` expired it
  60s later.
- **Fix:** canonical (direction-independent) flow keying so both
  directions of a real conversation share one flow, and idle-timeout-based
  finalization (a flow is "ready" once it has `>=2` packets OR has been
  idle for `flow_idle_timeout_seconds`, default 2s) so single-packet flows
  still reach detection instead of vanishing.
- **Verified:** before the fix, 0–29% of packets in each simulated attack
  scenario ever reached the ML/DPI pipeline (port_scan and slow_apt: 0%).
  After the fix: 100% across every scenario (`tests/test_flow_assembly.py`).

**2. Stored XSS in the dashboard, chained with default wildcard CORS**
(`src/dashboard/js/app.js`, `config/config.yaml`)
- DPI-parsed, attacker-controlled fields (`http_host`, `dns_query`,
  `tls_sni`) were written into `innerHTML` unescaped. An attacker whose
  traffic got captured could execute JS in the analyst's authenticated
  session (which has the API key in `window.AEGIS_API_KEY`).
- The default `cors_origins: ["*"]` meant a stolen key could be replayed
  from any origin.
- **Fix:** added an `escapeHtml()` helper, applied to every DPI-derived
  field plus alert/flow-table fields defensively; changed the default CORS
  origin list to same-origin only.
- **Verified:** payload `<img src=x onerror=...>` confirmed neutralized
  (no raw `<img` in output); `node --check` confirms valid JS.

## High

**3. No real port-scan detection existed anywhere**
(`src/processing/scan_detector.py` — new file)
- The only "scan" heuristic (`dpi_engine.py`'s `PORT_SCAN_PATTERN`)
  required `>10` packets in a *single* 5-tuple flow — structurally
  incapable of seeing a scan, which is defined by one source touching many
  *different* ports. Nothing aggregated across flows.
- **Fix:** new `ScanDetector` tracks distinct destination ports/hosts and
  connection rate per source IP over a sliding window, wired into
  `main.py`'s processing loop as an "L3" alert category, independent of
  per-flow ML/DPI. `dpi_engine.py`'s heuristic is kept as a secondary
  burst indicator with its docstring corrected.
- **Verified:** `tests/test_scan_detector.py`; full pipeline smoke test
  raised a real `PORT_SCAN` alert from simulated scan traffic.

## Medium-High / Medium

**4. VLAN-tagged trunk frames broke STP/CDP/VTP/DTP parsing**
(`src/capture/l2_capture.py`)
- BPDU/SNAP parsing hardcoded a 14-byte (bare Ethernet) offset. A single
  802.1Q tag (18-byte header) misaligned every field read — not a clean
  failure, but corrupted-but-plausible field values (confirmed via a real
  scapy-constructed tagged frame: garbage `root_id`/`root_cost`).
- **Fix:** compute the real offset from the actual VLAN tag count.
- **Verified:** `tests/test_l2_analyzer_fixes.py::test_bpdu_parses_correctly_through_single_vlan_tag`.

**5. STP baseline permanently poisoned after one hijack**
(`src/processing/l2_analyzer.py`)
- Once an attacker's forged (lower) root id became the trusted baseline,
  a real switch re-electing its legitimate (higher) root id could never
  be relearned — the detector's ground truth stayed stale forever.
- **Fix:** added a confirmation-based recovery mechanism — a sustained
  (default 3 consecutive), non-superior root id claim is silently
  relearned as the new baseline (no alert, since it isn't attack
  behavior); a single stray BPDU doesn't reset tracking.
- **Verified:** `tests/test_l2_analyzer_fixes.py` (hijack alert still
  fires immediately; baseline recovers after 3 confirmations; a fresh
  hijack after recovery still alerts correctly).

**6. Unbounded memory growth in the flood detectors**
(`src/processing/l2_analyzer.py`)
- `_known_macs` (set) and `_cdp_events`/`_dtp_last_alert` (per-mac dicts)
  never expired — under the exact sustained-flood traffic they exist to
  catch, memory grew without bound.
- **Fix:** hourly pruning of entries older than `state_retention_seconds`
  (default 3600s).
- **Verified:** simulated 5-hour sustained flood — memory now caps at
  ~2 retention windows' worth instead of growing linearly forever
  (`tests/test_l2_analyzer_fixes.py::test_known_macs_are_pruned_and_stay_bounded`).

**7. LSTM layer silently non-functional, but still weighted 20%**
(`src/ml/lstm_detector.py`, `src/ml/threat_scorer.py`)
- TensorFlow wasn't in `requirements.txt`, so every default install used
  the untrained fallback, which computed variance *within* one feature
  vector (across differently-scaled features) — a number with no temporal
  meaning — yet it still carried a fixed 20% weight in every threat score.
- **Fix:** fallback now computes variance *across timesteps* (directionally
  correct, if still unscaled); `ThreatScorer` dynamically drops the
  sequence component's weight to 0 (redistributing to
  anomaly/classification, 0.375/0.625) unless a real trained model is
  loaded. Added `requirements-optional.txt` documenting the TensorFlow
  path honestly instead of omitting it silently.
- **Verified:** `tests/test_threat_scorer_lstm_weighting.py`.

## Low / Low-Medium

**8. WebSocket told unauthenticated clients "connected" before rejecting them**
(`src/api/main.py`)
- `websocket.accept()` was called before the API-key check, contradicting
  `auth.py`'s own documented design. **Fix:** reordered to check before
  accept(). Covered by existing `tests/test_api_auth.py`.

**9. SQLite lock contention under concurrent writers**
(`src/core/database.py`)
- Every DB call opened a fresh connection with default (DELETE) journal
  mode and no explicit busy timeout. **Fix:** WAL mode + 30s busy timeout.
- **Verified:** 10 threads × 50 writes (500 total) succeeded with zero
  lock errors in a stress test.

**10. Global MAC-flood alert cooldown could mask a second attacker**
(`src/processing/l2_analyzer.py`) — shortened cooldown from a full window
to half (no fully general fix exists: the attack itself randomizes the
only field available to key a per-attacker cooldown on).

**11. IPv4-only live capture** (`src/capture/packet_capture.py`,
`config/config.yaml`) — added IPv6/ICMPv6 extraction and updated the
default BPF filter to include `ip6`.

**12. (Found during remediation) scikit-learn version skew**
(`requirements.txt`) — shipped `.pkl` models were pickled with
scikit-learn 1.8.0 but `requirements.txt` pinned 1.5.2, producing an
`InconsistentVersionWarning` and no guarantee of correct behavior. Pinned
to 1.8.0; confirmed clean load with no warning.

**13. (Found during remediation) A stray backtick in an added HTML
comment inside a JS template literal broke `app.js` syntax** — caught by
`node --check` during final verification and fixed before packaging.

## What was intentionally left alone
Everything the original review found to already be correct: real API-key
auth with timing-safe comparison, parameterized SQL throughout (no
injection risk anywhere), the CORS wildcard+credentials fix, the
unprivileged Docker setup, and — confirmed by direct inspection, not just
documentation — an ML classifier legitimately trained on 882,339 real
labeled flows (CIC-IDS2017/2018, CIC-Darknet2020).
