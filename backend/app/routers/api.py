"""HTTP API."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from .. import db as dbmod, import_service, service
from ..engine import PolicyError
from ..import_service import ConflictError
from ..schemas import (
    ClassifyIn, DiffIn, ImportAdoptIn, ImportCrossValidateIn, ImportResolveIn,
    ImportUploadIn, NeighborIn, PolicyIn, PolicyRulesIn, ProbesIn,
    ScenarioIn, SnapshotIn,
)
from ..service import ValidationError
from ..treeview import policy_trie, hit_path, coverage_map
from ..validate import cross_validate_snapshot
from ..frr_bridge import FRRBridge, FRRUnavailable

router = APIRouter(prefix="/api")


def get_db():
    s = dbmod.SessionLocal()
    try:
        yield s
    finally:
        s.close()


def _get_policy(db: Session, pid: int) -> dbmod.Policy:
    p = db.get(dbmod.Policy, pid)
    if p is None:
        raise HTTPException(404, f"policy {pid} not found")
    return p


@router.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------- policies
@router.get("/policies")
def list_policies(db: Session = Depends(get_db)):
    ps = db.query(dbmod.Policy).order_by(dbmod.Policy.name).all()
    return [service.policy_payload(p) for p in ps]


@router.post("/policies", status_code=201)
def create_policy(body: PolicyIn, db: Session = Depends(get_db)):
    if db.query(dbmod.Policy).filter_by(name=body.name).first():
        raise HTTPException(409, f"policy {body.name!r} already exists")
    try:
        ipaddress.ip_network("0.0.0.0/0" if body.family == 4 else "::/0")
    except ValueError:
        raise HTTPException(422, "bad family")
    p = dbmod.Policy(
        name=body.name, family=body.family,
        default_action=body.default_action, description=body.description,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return service.policy_payload(p)


@router.get("/policies/{pid}")
def get_policy(pid: int, db: Session = Depends(get_db)):
    return service.policy_payload(_get_policy(db, pid))


@router.put("/policies/{pid}")
def update_policy_meta(pid: int, body: PolicyIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    p.default_action = body.default_action
    p.description = body.description
    db.commit()
    db.refresh(p)
    return service.policy_payload(p)


@router.delete("/policies/{pid}", status_code=204)
def delete_policy(pid: int, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    db.delete(p)
    db.commit()


@router.put("/policies/{pid}/rules")
def set_rules(pid: int, body: PolicyRulesIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    if body.default_action is not None:
        p.default_action = body.default_action
    try:
        service.replace_rules(db, p, [r.model_dump() for r in body.rules])
    except (ValidationError, PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))
    db.refresh(p)
    return service.policy_payload(p)


@router.get("/policies/{pid}/analyze")
def analyze(pid: int, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    try:
        return service.analyze(db, p)
    except PolicyError as e:
        raise HTTPException(422, str(e))


@router.post("/policies/{pid}/classify")
def classify(pid: int, body: ClassifyIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    ep = service.engine_policy(p)
    try:
        return hit_path(ep, body.prefix)
    except (PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


@router.post("/policies/{pid}/classify/batch")
def classify_batch(pid: int, body: ProbesIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    ep = service.engine_policy(p)
    out = []
    for i, pfx in enumerate(body.probes):
        try:
            d = ep.classify(pfx).to_dict()
            d["order"] = i
            out.append(d)
        except (PolicyError, ValueError) as e:
            out.append({"order": i, "prefix": pfx, "error": str(e)})
    return {"results": out}


@router.get("/policies/{pid}/trie")
def get_trie(pid: int, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    return policy_trie(service.engine_policy(p))


@router.get("/policies/{pid}/coverage")
def get_coverage(pid: int, depth: int = 8,
                 start: int = 0, count: int = 256,
                 db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    depth = max(0, min(depth, 12 if p.family == 4 else 40))
    count = max(1, min(count, 1024))
    return coverage_map(service.engine_policy(p), depth, (start, count))


# -------------------------------------------------------------- snapshots
@router.get("/policies/{pid}/snapshots")
def list_snapshots(pid: int, db: Session = Depends(get_db)):
    _get_policy(db, pid)
    snaps = db.query(dbmod.Snapshot).filter_by(policy_id=pid) \
        .order_by(dbmod.Snapshot.version.desc()).all()
    return [service.snapshot_dict(s) for s in snaps]


@router.post("/policies/{pid}/snapshots", status_code=201)
def take_snapshot(pid: int, body: SnapshotIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    snap = service.create_snapshot(db, p, label=body.label, created_by=body.created_by)
    return service.snapshot_dict(snap)


@router.get("/snapshots/{sid}")
def get_snapshot(sid: int, db: Session = Depends(get_db)):
    s = db.get(dbmod.Snapshot, sid)
    if s is None:
        raise HTTPException(404, "snapshot not found")
    return service.snapshot_dict(s)


@router.post("/snapshots/diff")
def diff_snapshots(body: DiffIn, db: Session = Depends(get_db)):
    try:
        return service.snapshot_diff(db, body.old_snapshot_id, body.new_snapshot_id)
    except (ValidationError, PolicyError) as e:
        raise HTTPException(422, str(e))


@router.post("/snapshots/{sid}/replay")
def replay(sid: int, body: ProbesIn, db: Session = Depends(get_db)):
    try:
        return service.replay(db, sid, body.probes)
    except ValidationError as e:
        raise HTTPException(404, str(e))
    except (PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


# ----------------------------------------------------- FRR cross-validation
@router.get("/frr/status")
def frr_status():
    out = {}
    for node in ("a", "b"):
        try:
            ok = FRRBridge(node=node, timeout=4).ping()
        except Exception:
            ok = False
        out[node] = {"reachable": ok}
    return out


@router.post("/snapshots/{sid}/cross-validate")
def cross_validate(sid: int, body: ProbesIn, db: Session = Depends(get_db)):
    s = db.get(dbmod.Snapshot, sid)
    if s is None:
        raise HTTPException(404, "snapshot not found")
    try:
        return cross_validate_snapshot(db, sid, body.probes, node=body.node)
    except FRRUnavailable as e:
        raise HTTPException(503, str(e))
    except (PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


@router.get("/runs")
def list_runs(limit: int = 50, db: Session = Depends(get_db)):
    runs = db.query(dbmod.Run).order_by(dbmod.Run.created_at.desc()).limit(limit).all()
    return [{
        "id": r.id, "snapshot_id": r.snapshot_id, "node": r.node,
        "status": r.status, "detail": r.detail,
        "created_at": r.created_at.isoformat(),
    } for r in runs]


# --------------------------------------------------------------- neighbors
@router.get("/neighbors")
def list_neighbors(db: Session = Depends(get_db)):
    ns = db.query(dbmod.Neighbor).order_by(dbmod.Neighbor.name).all()
    return [{"id": n.id, "name": n.name, "ip": n.ip, "family": n.family,
             "asn": n.asn, "inbound_policy": n.inbound_policy,
             "outbound_policy": n.outbound_policy, "description": n.description}
            for n in ns]


@router.post("/neighbors", status_code=201)
def create_neighbor(body: NeighborIn, db: Session = Depends(get_db)):
    try:
        net = ipaddress.ip_network(body.ip, strict=False)
    except ValueError as e:
        raise HTTPException(422, f"bad neighbor ip: {e}")
    if net.version != body.family:
        raise HTTPException(422, f"ip family does not match family={body.family}")
    n = dbmod.Neighbor(**body.model_dump())
    db.add(n)
    db.commit()
    db.refresh(n)
    return {"id": n.id, **body.model_dump()}


# --------------------------------------------------------------- scenarios
@router.get("/scenarios")
def list_scenarios(db: Session = Depends(get_db)):
    return [{"id": s.id, "name": s.name, "description": s.description,
             "from_snapshot_id": s.from_snapshot_id,
             "to_snapshot_id": s.to_snapshot_id, "probes": s.probes,
             "results": s.results, "created_at": s.created_at.isoformat()}
            for s in db.query(dbmod.Scenario).order_by(dbmod.Scenario.id).all()]


@router.post("/scenarios", status_code=201)
def create_scenario(body: ScenarioIn, db: Session = Depends(get_db)):
    if db.query(dbmod.Scenario).filter_by(name=body.name).first():
        raise HTTPException(409, f"scenario {body.name!r} exists")
    results = {}
    if body.from_snapshot_id:
        try:
            results["from"] = service.replay(db, body.from_snapshot_id, body.probes)
        except ValidationError:
            pass
    if body.to_snapshot_id:
        try:
            results["to"] = service.replay(db, body.to_snapshot_id, body.probes)
        except ValidationError:
            pass
    sc = dbmod.Scenario(**body.model_dump(), results=results)
    db.add(sc)
    db.commit()
    db.refresh(sc)
    return {"id": sc.id, "name": sc.name, "results": sc.results}


@router.get("/scenarios/{scid}")
def get_scenario(scid: int, db: Session = Depends(get_db)):
    s = db.get(dbmod.Scenario, scid)
    if s is None:
        raise HTTPException(404, "scenario not found")
    return {"id": s.id, "name": s.name, "description": s.description,
            "from_snapshot_id": s.from_snapshot_id,
            "to_snapshot_id": s.to_snapshot_id, "probes": s.probes,
            "results": s.results}


@router.post("/scenarios/{scid}/replay")
def replay_scenario(scid: int, db: Session = Depends(get_db)):
    """Replay the stored ordered inputs against both snapshots deterministically."""
    s = db.get(dbmod.Scenario, scid)
    if s is None:
        raise HTTPException(404, "scenario not found")
    out = {"probes": s.probes, "from": None, "to": None, "diff": None}
    if s.from_snapshot_id:
        out["from"] = service.replay(db, s.from_snapshot_id, s.probes)
    if s.to_snapshot_id:
        out["to"] = service.replay(db, s.to_snapshot_id, s.probes)
    if s.from_snapshot_id and s.to_snapshot_id:
        out["diff"] = service.snapshot_diff(
            db, s.from_snapshot_id, s.to_snapshot_id)
    s.results = out
    db.commit()
    return out


# ---------------------------------------------------------------- imports
def _get_import(db: Session, iid: int) -> dbmod.ImportSession:
    imp = db.get(dbmod.ImportSession, iid)
    if imp is None:
        raise HTTPException(404, f"import session {iid} not found")
    return imp


@router.post("/imports", status_code=201)
def upload_import(body: ImportUploadIn, response: Response,
                  db: Session = Depends(get_db)):
    """Upload FRR prefix-list text.  Idempotent: the same file content maps to
    one session (sha256); re-submission returns it with deduplicated=true."""
    if not body.text.strip():
        raise HTTPException(422, "empty configuration text")
    imp, created = import_service.create_import_session(
        db, body.filename, body.text)
    out = import_service.session_detail(imp)
    out["deduplicated"] = not created
    if not created:
        response.status_code = 200
    return out


@router.get("/imports")
def list_imports(db: Session = Depends(get_db)):
    imps = db.query(dbmod.ImportSession) \
        .order_by(dbmod.ImportSession.created_at.desc(),
                  dbmod.ImportSession.id.desc()).all()
    return [import_service.session_summary(i) for i in imps]


@router.get("/imports/{iid}")
def get_import(iid: int, db: Session = Depends(get_db)):
    """Full session: raw text, per-line mapping, drafts, diagnostics."""
    return import_service.session_detail(_get_import(db, iid))


@router.get("/imports/{iid}/preview")
def preview_import(iid: int, db: Session = Depends(get_db)):
    """Semantic diff (minimal witness set) of each normalized draft against
    the current mainline, plus the version tokens needed for adoption."""
    imp = _get_import(db, iid)
    try:
        return import_service.preview(db, imp)
    except PolicyError as e:
        raise HTTPException(422, str(e))


@router.post("/imports/{iid}/resolve")
def resolve_import(iid: int, body: ImportResolveIn, db: Session = Depends(get_db)):
    """Handle one error diagnostic (drop the offending line).  Adoption is
    blocked until every error in the session is resolved."""
    imp = _get_import(db, iid)
    try:
        imp = import_service.resolve_diagnostic(db, imp, body.diagnostic_id,
                                                body.action)
    except ValidationError as e:
        raise HTTPException(422, str(e))
    return import_service.session_detail(imp)


@router.post("/imports/{iid}/adopt", status_code=201)
def adopt_import(iid: int, body: ImportAdoptIn, db: Session = Depends(get_db)):
    """Atomically replace the mainline rules with the draft and create the
    policy snapshot in one transaction.  409 if the mainline moved since the
    client's preview (optimistic concurrency)."""
    imp = _get_import(db, iid)
    try:
        return import_service.adopt_draft(
            db, imp, body.draft_id,
            expected_base_updated_at=body.expected_base_updated_at,
            default_action=body.default_action,
            label=body.label, created_by=body.created_by)
    except ConflictError as e:
        raise HTTPException(409, detail={
            "message": str(e), "current_updated_at": e.current_updated_at})
    except (ValidationError, PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


@router.post("/imports/{iid}/cross-validate")
def cross_validate_import(iid: int, body: ImportCrossValidateIn,
                          db: Session = Depends(get_db)):
    """Limited cross-validation of a draft against the local FRR container
    (no snapshot required; the run is recorded with snapshot_id=null)."""
    imp = _get_import(db, iid)
    try:
        return import_service.cross_validate_draft(
            db, imp, body.draft_id, body.probes, node=body.node)
    except FRRUnavailable as e:
        raise HTTPException(503, str(e))
    except (ValidationError, PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))
