"""Acceptance tests for the source-fidelity config import closed loop.

Covers:
* parser: seq/action/prefix/ge-le parsing, line fidelity (comments, blanks,
  unrecognized directives), and the four separately-explained diagnostics
  (duplicate seq / mixed family / invalid range / missing default);
* dual-stack file imports and replays;
* one illegal ge/le -> adoption refused, no half-snapshot;
* reordered-but-equivalent file -> empty semantic witness set;
* same file submitted twice -> exactly one session (idempotent);
* mainline updated after preview -> 409 version conflict, and the draft,
  diagnostics and raw text all survive a refresh.
"""
import pytest

from app.importer import parse_config


# --------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------

DUAL_STACK = """\
! DC edge prefix filters
! imported from router-a 2026-09-25
ip prefix-list EDGE-IN seq 5 deny 10.1.0.0/16
ip prefix-list EDGE-IN seq 10 permit 10.0.0.0/8 ge 16 le 24
ip prefix-list EDGE-IN seq 15 permit 192.168.0.0/16 le 24
ipv6 prefix-list EDGE-IN-V6 seq 5 deny 2001:db8:ffff::/48
ipv6 prefix-list EDGE-IN-V6 seq 10 permit 2001:db8::/32 le 48
"""

BAD_GELE = """\
ip prefix-list BROKEN seq 5 permit 10.0.0.0/8 le 24
ip prefix-list BROKEN seq 10 permit 172.16.0.0/12 ge 8 le 32
"""

DUP_TEXT = """\
ip prefix-list DUP1 seq 5 permit 10.0.0.0/8
ipv6 prefix-list DUP2 seq 5 permit 2001:db8::/32
"""


def _upload(client, text, filename="test.conf", expect=201):
    r = client.post("/api/imports", json={"filename": filename, "text": text})
    assert r.status_code == expect, r.text
    return r.json()


def _draft(detail, name):
    return next(d for d in detail["drafts"] if d["name"] == name)


def _policy(client, name):
    return next((p for p in client.get("/api/policies").json()
                 if p["name"] == name), None)


def _adopt(client, session_id, draft_id, token=None, expect=201, **kw):
    r = client.post(f"/api/imports/{session_id}/adopt", json={
        "draft_id": draft_id, "expected_base_updated_at": token, **kw})
    assert r.status_code == expect, r.text
    return r.json()


# --------------------------------------------------------------------------
# parser unit tests
# --------------------------------------------------------------------------

def test_parser_rule_fields_and_normalization():
    res = parse_config(
        "ip prefix-list P seq 10 permit 10.1.2.0/24 ge 25 le 32\n"
        "ipv6 prefix-list Q seq 5 deny 2001:DB8::/32 le 48\n")
    assert len(res.drafts) == 2
    p = next(d for d in res.drafts if d.name == "P")
    assert p.rules[0] == {"seq": 10, "prefix": "10.1.2.0/24",
                          "action": "permit", "ge": 25, "le": 32, "remark": ""}
    q = next(d for d in res.drafts if d.name == "Q")
    assert q.family == 6 and q.rules[0]["prefix"] == "2001:db8::/32"  # canonical


def test_parser_preserves_comments_blanks_and_unrecognized():
    text = ("! a comment\n"
            "\n"
            "router bgp 65001\n"
            "ip prefix-list P seq 5 permit 10.0.0.0/8\n")
    res = parse_config(text)
    kinds = [l.kind for l in res.lines]
    assert kinds == ["comment", "blank", "unrecognized", "rule"]
    assert res.lines[0].raw == "! a comment" and res.lines[0].line_no == 1
    assert res.lines[2].raw == "router bgp 65001"
    unrec = [d for d in res.diagnostics if d.kind == "unrecognized"]
    assert len(unrec) == 1 and unrec[0].severity == "warning"
    assert unrec[0].line_no == 3


def test_parser_four_diagnostics_explained_separately():
    text = ("ip prefix-list P seq 5 permit 10.0.0.0/8\n"
            "ip prefix-list P seq 5 deny 10.0.0.0/8 le 24\n"      # dup seq
            "ipv6 prefix-list P seq 10 permit 10.0.0.0/8\n"       # mixed family
            "ip prefix-list P seq 15 permit 172.16.0.0/12 ge 8\n"  # bad range
            )
    res = parse_config(text)
    kinds = {d.kind for d in res.diagnostics}
    assert {"duplicate_seq", "mixed_family", "invalid_range",
            "missing_default"} <= kinds
    dup = next(d for d in res.diagnostics if d.kind == "duplicate_seq")
    assert dup.severity == "error" and dup.line_no == 2 and "5" in dup.message
    mix = next(d for d in res.diagnostics if d.kind == "mixed_family")
    assert mix.line_no == 3 and "IPv4" in mix.message
    rng = next(d for d in res.diagnostics if d.kind == "invalid_range")
    assert rng.line_no == 4 and "ge" in rng.message
    miss = next(d for d in res.diagnostics if d.kind == "missing_default")
    assert miss.severity == "warning" and "隐式默认" in miss.message
    # errored lines are excluded from the draft's candidate rules
    p = next(d for d in res.drafts if d.family == 4)
    assert [r["seq"] for r in p.rules] == [5]


def test_parser_missing_default_absent_with_catchall():
    res = parse_config("ip prefix-list P seq 5 permit 0.0.0.0/0 le 32\n")
    assert not any(d.kind == "missing_default" for d in res.diagnostics)


def test_parser_auto_seq_assignment():
    res = parse_config("ip prefix-list P permit 10.0.0.0/8\n"
                       "ip prefix-list P permit 11.0.0.0/8\n")
    p = res.drafts[0]
    assert [r["seq"] for r in p.rules] == [5, 10]
    assert sum(1 for d in res.diagnostics if d.kind == "seq_assigned") == 2


def test_parser_shorthand_prefix_normalized():
    res = parse_config("ip prefix-list P seq 5 permit 10/8 le 24\n")
    assert res.drafts[0].rules[0]["prefix"] == "10.0.0.0/8"
    assert not any(d.severity == "error" for d in res.diagnostics)


# --------------------------------------------------------------------------
# acceptance: dual-stack import + replay
# --------------------------------------------------------------------------

def test_dual_stack_import_and_replay(client):
    detail = _upload(client, DUAL_STACK, "edge.conf")
    assert detail["status"] == "ready"
    assert {d["name"] for d in detail["drafts"]} == {"EDGE-IN", "EDGE-IN-V6"}
    # both lists carry the missing-default warning (no catch-all entries)
    assert any(d["kind"] == "missing_default" for d in detail["diagnostics"])
    # comments preserved with original line numbers
    comments = [l for l in detail["lines"] if l["kind"] == "comment"]
    assert [c["line_no"] for c in comments] == [1, 2]

    for name, count in (("EDGE-IN", 3), ("EDGE-IN-V6", 2)):
        draft = _draft(detail, name)
        out = _adopt(client, detail["id"], draft["id"], token=None)
        assert out["rule_count"] == count

    # replay the freshly created snapshots, v4 and v6
    for name, probes, expect in (
        ("EDGE-IN", ["10.1.2.0/24", "10.1.0.0/16", "192.168.9.0/24",
                     "203.0.113.0/24"],
         ["permit", "deny", "permit", "deny"]),
        ("EDGE-IN-V6", ["2001:db8:1::/48", "2001:db8:ffff::/48",
                        "2001:db8:1:2::/64"],
         ["permit", "deny", "deny"]),
    ):
        pol = _policy(client, name)
        assert pol is not None
        snaps = client.get(f"/api/policies/{pol['id']}/snapshots").json()
        assert len(snaps) == 1
        rep = client.post(f"/api/snapshots/{snaps[0]['id']}/replay",
                          json={"probes": probes}).json()
        assert [r["final_action"] for r in rep["results"]] == expect
        assert [r["order"] for r in rep["results"]] == list(range(len(probes)))


# --------------------------------------------------------------------------
# acceptance: one illegal ge/le -> no half snapshot
# --------------------------------------------------------------------------

def test_invalid_gele_blocks_adoption_no_half_snapshot(client):
    detail = _upload(client, BAD_GELE, "broken.conf")
    assert detail["status"] == "pending"
    errs = [d for d in detail["diagnostics"] if d["severity"] == "error"]
    assert len(errs) == 1 and errs[0]["kind"] == "invalid_range"
    assert errs[0]["line_no"] == 2

    draft = _draft(detail, "BROKEN")
    r = client.post(f"/api/imports/{detail['id']}/adopt",
                    json={"draft_id": draft["id"],
                          "expected_base_updated_at": None})
    assert r.status_code == 422 and "未处理" in r.json()["detail"]

    # nothing leaked into the mainline: no policy/rules/snapshot for BROKEN
    assert _policy(client, "BROKEN") is None
    # resolve the error (drop the bad line), then adoption is atomic & complete
    detail = client.post(f"/api/imports/{detail['id']}/resolve",
                         json={"diagnostic_id": errs[0]["id"],
                               "action": "drop"}).json()
    assert detail["status"] == "ready"
    assert any(d["resolved"] and d["resolution"] == "dropped"
               for d in detail["diagnostics"])

    out = _adopt(client, detail["id"], draft["id"], token=None)
    assert out["rule_count"] == 1          # only the good line
    pol = _policy(client, "BROKEN")
    assert [r["seq"] for r in pol["rules"]] == [5]
    snaps = client.get(f"/api/policies/{pol['id']}/snapshots").json()
    assert len(snaps) == 1 and len(snaps[0]["payload"]["rules"]) == 1


def test_adoption_is_atomic_on_conflict(client):
    """A failing adoption (stale token) must not touch rules or snapshots."""
    pid = client.post("/api/policies", json={
        "name": "ATOMIC", "family": 4, "default_action": "deny"}).json()["id"]
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 5, "prefix": "10.0.0.0/8", "action": "permit"}]})
    before = client.get(f"/api/policies/{pid}").json()

    detail = _upload(client,
                     "ip prefix-list ATOMIC seq 9 permit 192.0.2.0/24 le 32\n")
    draft = _draft(detail, "ATOMIC")
    r = client.post(f"/api/imports/{detail['id']}/adopt", json={
        "draft_id": draft["id"], "expected_base_updated_at": "stale-token"})
    assert r.status_code == 409
    after = client.get(f"/api/policies/{pid}").json()
    assert [r["seq"] for r in after["rules"]] == \
           [r["seq"] for r in before["rules"]]
    assert client.get(f"/api/policies/{pid}/snapshots").json() == []


# --------------------------------------------------------------------------
# acceptance: reordered but semantically equivalent -> no behavior change
# --------------------------------------------------------------------------

def test_reordered_equivalent_shows_no_behavior_change(client):
    pid = client.post("/api/policies", json={
        "name": "REORD", "family": 4, "default_action": "deny"}).json()["id"]
    # non-overlapping rules: swapping their order cannot change behavior
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 5, "prefix": "10.0.0.0/8", "action": "permit", "le": 24},
        {"seq": 10, "prefix": "172.16.0.0/12", "action": "deny", "le": 32},
        {"seq": 15, "prefix": "192.168.0.0/16", "action": "permit"},
    ]})
    client.post(f"/api/policies/{pid}/snapshots", json={"label": "v1"})

    reordered = ("ip prefix-list REORD seq 5 permit 192.168.0.0/16\n"
                 "ip prefix-list REORD seq 10 deny 172.16.0.0/12 le 32\n"
                 "ip prefix-list REORD seq 15 permit 10.0.0.0/8 le 24\n")
    detail = _upload(client, reordered)
    prev = client.get(f"/api/imports/{detail['id']}/preview").json()
    entry = prev["drafts"][0]
    assert entry["target_policy_id"] == pid
    assert entry["witness_count"] == 0
    assert entry["newly_permitted"] == [] and entry["newly_denied"] == []


def test_preview_reports_real_behavior_change(client):
    pid = client.post("/api/policies", json={
        "name": "TIGHTEN", "family": 4, "default_action": "deny"}).json()["id"]
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 5, "prefix": "10.0.0.0/8", "action": "permit", "le": 24}]})
    detail = _upload(
        client, "ip prefix-list TIGHTEN seq 5 permit 10.0.0.0/8 le 16\n")
    prev = client.get(f"/api/imports/{detail['id']}/preview").json()
    entry = prev["drafts"][0]
    assert entry["witness_count"] == 1
    assert entry["newly_denied"][0]["prefix"] == "10.0.0.0/17"


# --------------------------------------------------------------------------
# acceptance: duplicate submission is idempotent
# --------------------------------------------------------------------------

def test_duplicate_upload_generates_one_session(client):
    first = _upload(client, DUP_TEXT, "dup.conf")
    r = client.post("/api/imports",
                    json={"filename": "dup-copy.conf", "text": DUP_TEXT})
    assert r.status_code == 200                      # not 201
    second = r.json()
    assert second["deduplicated"] is True
    assert second["id"] == first["id"]
    sessions = client.get("/api/imports").json()
    assert len([s for s in sessions
                if s["content_hash"] == first["content_hash"]]) == 1
    # and the deduplicated session still carries everything
    assert len(second["lines"]) == len(DUP_TEXT.splitlines())
    assert len(second["drafts"]) == 2


# --------------------------------------------------------------------------
# acceptance: version conflict on adopt; state survives refresh
# --------------------------------------------------------------------------

def test_version_conflict_and_state_survives_refresh(client):
    pid = client.post("/api/policies", json={
        "name": "MAIN", "family": 4, "default_action": "deny"}).json()["id"]
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 5, "prefix": "10.0.0.0/8", "action": "permit", "le": 24}]})

    text = ("! planned change\n"
            "ip prefix-list MAIN seq 5 permit 10.0.0.0/8 le 24\n"
            "ip prefix-list MAIN seq 10 permit 192.0.2.0/24\n")
    detail = _upload(client, text, "main.conf")
    prev = client.get(f"/api/imports/{detail['id']}/preview").json()
    token = prev["drafts"][0]["base_updated_at"]
    assert token

    # mainline moves after the preview
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 5, "prefix": "10.0.0.0/8", "action": "permit", "le": 24},
        {"seq": 7, "prefix": "198.51.100.0/24", "action": "deny"}]})

    draft = _draft(detail, "MAIN")
    r = client.post(f"/api/imports/{detail['id']}/adopt", json={
        "draft_id": draft["id"], "expected_base_updated_at": token})
    assert r.status_code == 409
    body = r.json()["detail"]
    assert "已被更新" in body["message"]
    assert body["current_updated_at"] and body["current_updated_at"] != token

    # refresh: draft, diagnostics and raw text are all still there
    again = client.get(f"/api/imports/{detail['id']}").json()
    assert again["raw_text"] == text
    assert _draft(again, "MAIN")["status"] == "ready"
    assert any(d["kind"] == "missing_default" for d in again["diagnostics"])
    assert [l["raw"] for l in again["lines"]] == text.splitlines()

    # re-preview against the new mainline, then adopt with the fresh token
    prev2 = client.get(f"/api/imports/{detail['id']}/preview").json()
    fresh = prev2["drafts"][0]["base_updated_at"]
    assert fresh == body["current_updated_at"]
    out = _adopt(client, detail["id"], draft["id"], token=fresh)
    assert out["rule_count"] == 2
    pol = client.get(f"/api/policies/{pid}").json()
    assert [r["seq"] for r in pol["rules"]] == [5, 10]
    # adopted draft is terminal; a second adopt is refused
    r = client.post(f"/api/imports/{detail['id']}/adopt", json={
        "draft_id": draft["id"], "expected_base_updated_at": fresh})
    assert r.status_code == 409


def test_import_history_lists_sessions(client):
    _upload(client, "ip prefix-list H1 seq 5 permit 10.0.0.0/8\n", "h1.conf")
    _upload(client, "ipv6 prefix-list H2 seq 5 permit 2001:db8::/32\n",
            "h2.conf")
    sessions = client.get("/api/imports").json()
    names = {d["name"] for s in sessions for d in s["drafts"]}
    assert {"H1", "H2"} <= names
    for s in sessions:
        assert s["status"] in ("pending", "ready", "partial", "adopted")
