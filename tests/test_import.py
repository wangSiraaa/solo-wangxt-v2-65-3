"""Config-import closed loop: parse -> draft -> diagnose -> atomic adopt.

Covers the acceptance criteria:
* valid dual-stack file imports and replays;
* one illegal ge/le line -> no half-snapshot, mainline untouched;
* reordered-but-equivalent file -> empty semantic change set;
* duplicate submission generates exactly one session;
* adopt after mainline moved -> 409 conflict; draft/diagnostics/raw text
  survive a refresh.
"""
import pytest

from app import importer


# --------------------------------------------------------------------------
# parser unit tests
# --------------------------------------------------------------------------

def test_parse_rule_ge_le_and_comments():
    text = (
        "! edge prefix filter\n"
        "ip prefix-list EDGE-IN seq 10 permit 192.168.0.0/16 ge 17 le 24\n"
        "\n"
        "ip prefix-list EDGE-IN description local edge\n"
        "ipv6 prefix-list EDGE-IN6 seq 5 deny 2001:db8::/32 le 48\n"
        "router bgp 64512\n"
    )
    res = importer.parse_config(text)
    kinds = [l.kind for l in res.lines]
    assert kinds == ["comment", "rule", "blank", "description", "rule",
                     "unparsed"]
    assert [l.line_no for l in res.lines] == [1, 2, 3, 4, 5, 6]

    r = res.lines[1]
    assert (r.seq, r.action, r.prefix, r.ge, r.le) == \
        (10, "permit", "192.168.0.0/16", 17, 24)
    assert r.ok

    # unparsed directive preserved verbatim with a warning
    u = res.lines[5]
    assert u.raw == "router bgp 64512"
    assert u.diagnostics[0].code == "unparsed"
    assert u.diagnostics[0].severity == "warning"

    # two drafts: (EDGE-IN, v4) and (EDGE-IN6, v6)
    assert {(d.name, d.family) for d in res.drafts} == \
        {("EDGE-IN", 4), ("EDGE-IN6", 6)}
    v4 = next(d for d in res.drafts if d.family == 4)
    assert v4.rules[0]["ge"] == 17 and v4.rules[0]["le"] == 24
    # every draft flags the missing default until confirmed
    assert any(d.code == "missing-default" for d in v4.diagnostics)


def test_parse_auto_seq_frr_style():
    res = importer.parse_config(
        "ip prefix-list A permit 10.0.0.0/8\n"
        "ip prefix-list A permit 11.0.0.0/8\n")
    assert [l.seq for l in res.lines] == [5, 10]
    assert all(l.diagnostics[0].code == "auto-seq" for l in res.lines)


def test_parse_error_categories_are_distinct():
    text = (
        "ip prefix-list M seq 5 permit 10.0.0.0/8 le 4\n"      # le < base
        "ip prefix-list M seq 5 permit 11.0.0.0/8\n"           # dup seq
        "ip prefix-list M seq 15 permit 2001:db8::/32\n"       # v6 under ip
        "ip prefix-list M seq 20 permit 10.1.2.3/8\n"          # host bits
    )
    res = importer.parse_config(text)
    codes = [(l.diagnostics[-1].code if l.diagnostics else None)
             for l in res.lines]
    assert codes == ["bad-ge-le", None, "family-mismatch", "bad-prefix"]
    assert res.lines[1].ok                      # the good line still parses
    draft = res.drafts[0]
    assert any(d.code == "duplicate-seq" for d in draft.diagnostics)
    # only the one fully-valid line made it into the normalized rules
    assert [r["prefix"] for r in draft.rules] == ["11.0.0.0/8"]


def test_ge_only_window_matches_engine():
    res = importer.parse_config(
        "ip prefix-list G seq 5 permit 10.0.0.0/8 ge 16\n")
    assert res.lines[0].ok and res.lines[0].ge == 16 and res.lines[0].le is None


# --------------------------------------------------------------------------
# API helpers
# --------------------------------------------------------------------------

def _upload(client, text, filename="frr.conf"):
    r = client.post("/api/imports", json={"filename": filename, "text": text})
    assert r.status_code in (200, 201), r.text
    return r.json()


def _confirm_and_adopt(client, session, draft, expected_revision=None,
                       default="deny"):
    did = draft["id"]
    r = client.put(f"/api/imports/{session['id']}/drafts/{did}", json={
        "default_action": default, "confirm_default": True})
    assert r.status_code == 200, r.text
    body = {}
    if expected_revision is not None:
        body["expected_revision"] = expected_revision
    return client.post(f"/api/imports/{session['id']}/drafts/{did}/adopt",
                       json=body)


DUAL_STACK = """! dual-stack edge filters
ip prefix-list EDGE-V4 seq 10 deny 192.168.100.0/24
ip prefix-list EDGE-V4 seq 20 permit 192.168.0.0/16 le 24
ip prefix-list EDGE-V4 seq 30 permit 10.0.0.0/8 ge 16
ipv6 prefix-list EDGE-V6 seq 10 deny 2001:db8:bad::/48
ipv6 prefix-list EDGE-V6 seq 20 permit 2001:db8::/32 le 48
"""


# --------------------------------------------------------------------------
# acceptance: valid dual-stack config imports and replays
# --------------------------------------------------------------------------

def test_dual_stack_import_adopt_replay(client):
    before = client.get("/api/imports").json()
    up = _upload(client, DUAL_STACK)
    assert up["status"] == "draft"
    assert len(up["drafts"]) == 2
    fams = {d["family"] for d in up["drafts"]}
    assert fams == {4, 6}
    # nothing touched the mainline yet
    assert client.get("/api/policies").json() == [] or all(
        p["name"] not in ("EDGE-V4", "EDGE-V6")
        for p in client.get("/api/policies").json())

    for d in up["drafts"]:
        # default not confirmed -> not ready
        assert not d["readiness"]["ready"]
        assert any(b["code"] == "missing-default"
                   for b in d["readiness"]["blocking"] + d["readiness"]["warnings"])
        r = _confirm_and_adopt(client, up, d)
        assert r.status_code == 201, r.text

    # both drafts adopted -> session adopted; one snapshot per new policy
    after = client.get(f"/api/imports/{up['id']}").json()
    assert after["status"] == "adopted"
    assert all(d["status"] == "adopted" for d in after["drafts"])

    pols = {p["name"]: p for p in client.get("/api/policies").json()}
    assert pols["EDGE-V4"]["default_action"] == "deny"
    assert [r["seq"] for r in pols["EDGE-V4"]["rules"]] == [10, 20, 30]

    # replay the created snapshot: ordered probes, deterministic results
    snap_id = next(d["adopted_snapshot_id"] for d in after["drafts"]
                   if d["family"] == 4)
    rep = client.post(f"/api/snapshots/{snap_id}/replay", json={
        "probes": ["192.168.5.0/24", "192.168.100.0/24",
                   "10.1.0.0/16", "11.0.0.0/15", "8.8.8.8/32"]}).json()
    assert [r["final_action"] for r in rep["results"]] == \
        ["permit", "deny", "permit", "deny", "deny"]
    assert [r["order"] for r in rep["results"]] == [0, 1, 2, 3, 4]

    snap6 = next(d["adopted_snapshot_id"] for d in after["drafts"]
                 if d["family"] == 6)
    rep6 = client.post(f"/api/snapshots/{snap6}/replay", json={
        "probes": ["2001:db8:1::/48", "2001:db8:bad::/48"]}).json()
    assert [r["final_action"] for r in rep6["results"]] == ["permit", "deny"]

    # mapping history recorded
    hist = client.get("/api/adoptions").json()
    assert len(hist) >= 2
    assert {h["new_version"] for h in hist[:2]} == {1}


# --------------------------------------------------------------------------
# acceptance: one illegal ge/le -> no half-snapshot
# --------------------------------------------------------------------------

def test_illegal_ge_le_blocks_adoption_no_half_snapshot(client):
    text = (
        "ip prefix-list BROKEN seq 10 permit 10.0.0.0/8 le 16\n"
        "ip prefix-list BROKEN seq 20 permit 192.168.0.0/16 le 4\n"  # illegal
    )
    up = _upload(client, text)
    draft = up["drafts"][0]
    # line-level error is explained and pinned to line 2
    errs = [b for b in draft["readiness"]["blocking"]]
    assert any(b["code"] == "bad-ge-le" and b["line_no"] == 2 for b in errs)
    assert not draft["readiness"]["ready"]

    r = _confirm_and_adopt(client, up, draft)
    assert r.status_code == 422

    # no snapshot, no policy, no half state anywhere
    assert all(p["name"] != "BROKEN"
               for p in client.get("/api/policies").json())
    again = client.get(f"/api/imports/{up['id']}").json()
    assert again["status"] == "draft"
    assert again["drafts"][0]["status"] == "draft"
    assert again["drafts"][0]["adopted_snapshot_id"] is None

    # fix the draft in place (edited rules supersede the parsed ones), then
    # adoption succeeds atomically
    fixed = [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit", "le": 16},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
    ]
    r = client.put(f"/api/imports/{up['id']}/drafts/{draft['id']}",
                   json={"rules": fixed, "default_action": "deny",
                         "confirm_default": True})
    assert r.status_code == 200, r.text
    assert r.json()["readiness"]["ready"]
    r = client.post(f"/api/imports/{up['id']}/drafts/{draft['id']}/adopt",
                    json={})
    assert r.status_code == 201, r.text
    assert r.json()["snapshot"]["version"] == 1


# --------------------------------------------------------------------------
# acceptance: reordered but semantically equivalent -> no behavior change
# --------------------------------------------------------------------------

def test_reordered_equivalent_shows_no_change(client):
    r = client.post("/api/policies", json={
        "name": "REORDER-ME", "family": 4, "default_action": "deny"})
    pid = r.json()["id"]
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit", "le": 16},
        {"seq": 20, "prefix": "172.16.0.0/12", "action": "deny", "le": 24},
        {"seq": 30, "prefix": "192.168.0.0/16", "action": "permit"},
    ]})
    client.post(f"/api/policies/{pid}/snapshots", json={"label": "current"})

    # same rules, different seq order/numbering, plus comments and a stray
    # directive: textually very different, semantically identical
    text = (
        "! re-sequenced by the network team\n"
        "ip prefix-list REORDER-ME seq 100 permit 192.168.0.0/16\n"
        "ip prefix-list REORDER-ME seq 50 deny 172.16.0.0/12 le 24\n"
        "ip prefix-list REORDER-ME seq 200 permit 10.0.0.0/8 le 16\n"
        "router bgp 65000\n"
    )
    up = _upload(client, text)
    draft = up["drafts"][0]
    assert draft["target_policy_id"] == pid        # auto-mapped by name
    diff = draft["diff"]
    assert diff["witness_count"] == 0
    assert diff["newly_permitted"] == [] and diff["newly_denied"] == []


def test_semantic_diff_reports_real_changes(client):
    r = client.post("/api/policies", json={
        "name": "WILL-CHANGE", "family": 4, "default_action": "deny"})
    pid = r.json()["id"]
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
    ]})
    text = "ip prefix-list WILL-CHANGE seq 10 permit 192.168.0.0/16 le 23\n"
    up = _upload(client, text)
    diff = up["drafts"][0]["diff"]
    assert diff["witness_count"] == 1
    assert diff["newly_denied"][0]["prefix"] == "192.168.0.0/24"
    assert diff["newly_denied"][0]["change"] == "permit->deny"


# --------------------------------------------------------------------------
# acceptance: duplicate submission generates only one session
# --------------------------------------------------------------------------

def test_duplicate_submission_is_idempotent(client):
    text = "ip prefix-list IDEM seq 5 permit 10.0.0.0/8\n"
    before = len(client.get("/api/imports").json())
    first = _upload(client, text)
    second = _upload(client, text)
    assert first["id"] == second["id"]
    assert second.get("deduplicated") is True
    after = client.get("/api/imports").json()
    assert len(after) == before + 1
    # same hash, one set of drafts
    assert len(second["drafts"]) == 1


# --------------------------------------------------------------------------
# acceptance: adopt after mainline moved -> 409; draft survives refresh
# --------------------------------------------------------------------------

def test_adopt_conflict_when_mainline_moved(client):
    r = client.post("/api/policies", json={
        "name": "MOVING", "family": 4, "default_action": "deny"})
    pid = r.json()["id"]
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit"},
    ]})
    rev1 = client.get(f"/api/policies/{pid}").json()["revision"]

    text = "ip prefix-list MOVING seq 10 permit 10.0.0.0/8 le 24\n"
    up = _upload(client, text)
    draft = up["drafts"][0]
    assert draft["base_revision"] == rev1

    # mainline moves after the preview
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit"},
        {"seq": 20, "prefix": "11.0.0.0/8", "action": "deny"},
    ]})

    client.put(f"/api/imports/{up['id']}/drafts/{draft['id']}",
               json={"default_action": "deny", "confirm_default": True})
    r = client.post(f"/api/imports/{up['id']}/drafts/{draft['id']}/adopt",
                    json={"expected_revision": rev1})
    assert r.status_code == 409
    assert "revision" in r.json()["detail"]

    # refresh: draft, diagnostics and original text are all still intact
    again = client.get(f"/api/imports/{up['id']}").json()
    d = again["drafts"][0]
    assert d["status"] == "draft"
    assert d["stale"] is True
    assert d["current_revision"] == rev1 + 1
    assert again["raw_text"] == text
    assert any(l["kind"] == "rule" and l["raw"].endswith("le 24")
               for l in again["lines"])
    # mainline untouched by the failed adopt
    pol = client.get(f"/api/policies/{pid}").json()
    assert [x["seq"] for x in pol["rules"]] == [10, 20]
    assert client.get(f"/api/policies/{pid}/snapshots").json() == []

    # re-preview (retarget refreshes the base revision), then adopt works
    client.put(f"/api/imports/{up['id']}/drafts/{draft['id']}",
               json={"retarget": True, "target_policy_id": pid})
    r = client.post(f"/api/imports/{up['id']}/drafts/{draft['id']}/adopt",
                    json={"expected_revision": rev1 + 1})
    assert r.status_code == 201, r.text
    assert r.json()["snapshot"]["version"] == 1


# --------------------------------------------------------------------------
# diagnostics: each category explained separately
# --------------------------------------------------------------------------

def test_diagnostic_categories_distinct(client):
    text = (
        "ip prefix-list DIAG seq 5 permit 10.0.0.0/8\n"
        "ip prefix-list DIAG seq 5 permit 11.0.0.0/8\n"          # dup seq
        "ipv6 prefix-list DIAG seq 10 permit 10.0.0.0/8\n"       # v4 under ipv6
        "ip prefix-list DIAG seq 20 permit 172.16.0.0/12 ge 8\n"  # ge <= base
    )
    up = _upload(client, text)
    drafts = {(d["name"], d["family"]): d for d in up["drafts"]}
    v4 = drafts[("DIAG", 4)]
    v6 = drafts[("DIAG", 6)]

    v4_blocking = {b["code"] for b in v4["readiness"]["blocking"]}
    assert "duplicate-seq" in v4_blocking
    assert "bad-ge-le" in v4_blocking
    assert any(b["code"] == "missing-default"
               for b in v4["readiness"]["warnings"])

    v6_blocking = {b["code"] for b in v6["readiness"]["blocking"]}
    assert "family-mismatch" in v6_blocking

    # line-level view keeps the raw text next to each diagnostic
    lines = {l["line_no"]: l for l in up["lines"]}
    assert lines[4]["diagnostics"][-1]["code"] == "bad-ge-le"
    assert lines[4]["raw"].endswith("ge 8")
    assert lines[3]["diagnostics"][-1]["code"] == "family-mismatch"


def test_cross_validate_draft_requires_reachable_frr(client):
    up = _upload(client, "ip prefix-list CV seq 5 permit 10.0.0.0/8 le 16\n")
    did = up["drafts"][0]["id"]
    r = client.post(f"/api/imports/{up['id']}/drafts/{did}/cross-validate",
                    json={"probes": ["10.1.0.0/16"], "node": "a"})
    # containers are not running in CI -> 503; if a lab IS up, must match
    assert r.status_code in (200, 503)
    if r.status_code == 200:
        assert r.json()["status"] == "match"
