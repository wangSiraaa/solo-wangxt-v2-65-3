"""Service layer: DB objects <-> engine Policy, snapshots, replay helpers."""
from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db as dbmod
from .engine import (
    Action, Policy as EnginePolicy, Rule as EngineRule, PolicyError,
    policy_from_dicts,
)


class ValidationError(Exception):
    pass


# --------------------------------------------------------------------------
# Serialization / validation
# --------------------------------------------------------------------------

def engine_policy(db_pol: dbmod.Policy) -> EnginePolicy:
    return EnginePolicy(
        name=db_pol.name,
        rules=[
            EngineRule(
                id=r.id, seq=r.seq, prefix=r.prefix,
                action=Action(r.action), ge=r.ge, le=r.le, remark=r.remark or "",
            ) for r in db_pol.rules
        ],
        default_action=Action(db_pol.default_action),
        family=db_pol.family,
    )


def policy_payload(db_pol: dbmod.Policy) -> dict:
    ep = engine_policy(db_pol)
    return {
        "id": db_pol.id,
        "name": db_pol.name,
        "family": db_pol.family,
        "default_action": db_pol.default_action,
        "description": db_pol.description,
        "draft": db_pol.draft,
        "rules": [
            {
                "id": r.id, "seq": r.seq, "prefix": r.prefix,
                "action": r.action, "ge": r.ge, "le": r.le, "remark": r.remark or "",
            } for r in db_pol.rules
        ],
        "frr_config": ep.to_frr_prefix_list(),
        "updated_at": db_pol.updated_at.isoformat() if db_pol.updated_at else None,
    }


def validate_rule_dicts(family: int, rules: List[dict]) -> List[EngineRule]:
    """Parse every rule through ipaddress; reject cross-family / bad ge/le."""
    out = []
    seen_seq = set()
    for d in rules:
        r = EngineRule(
            seq=int(d["seq"]), prefix=d["prefix"].strip(),
            action=Action(d["action"]), ge=d.get("ge"), le=d.get("le"),
            remark=d.get("remark", ""),
        )
        if r.family != family:
            raise ValidationError(
                f"seq {r.seq}: {r.prefix} is IPv{r.family} but policy is IPv{family}; "
                "families must not be mixed"
            )
        if r.seq in seen_seq:
            raise ValidationError(f"duplicate seq {r.seq}")
        seen_seq.add(r.seq)
        out.append(r)
    return out


def replace_rules(session: Session, db_pol: dbmod.Policy,
                  rules: List[dict]) -> dbmod.Policy:
    validate_rule_dicts(db_pol.family, rules)
    # delete-then-insert in one flush order (SQLite otherwise reorders
    # cascade inserts ahead of deletes and trips the (policy_id, seq) key)
    session.query(dbmod.Rule).filter_by(policy_id=db_pol.id).delete(
        synchronize_session=False)
    session.flush()
    session.expire_all()
    db_pol = session.get(dbmod.Policy, db_pol.id)
    db_pol.rules = [
        dbmod.Rule(
            seq=int(r["seq"]), prefix=r["prefix"].strip(),
            action=r["action"], ge=r.get("ge"), le=r.get("le"),
            remark=r.get("remark", ""),
        ) for r in sorted(rules, key=lambda x: int(x["seq"]))
    ]
    # bump the optimistic-concurrency token: import adoption compares this
    # timestamp to detect "mainline moved since preview"
    db_pol.updated_at = dbmod.utcnow()
    session.add(db_pol)
    session.commit()
    session.refresh(db_pol)
    return db_pol


# --------------------------------------------------------------------------
# Snapshots
# --------------------------------------------------------------------------

def create_snapshot(session: Session, db_pol: dbmod.Policy,
                    label: str = "", created_by: str = "lab") -> dbmod.Snapshot:
    ep = engine_policy(db_pol)
    last = session.scalar(
        select(dbmod.Snapshot)
        .where(dbmod.Snapshot.policy_id == db_pol.id)
        .order_by(dbmod.Snapshot.version.desc())
    )
    version = (last.version + 1) if last else 1
    snap = dbmod.Snapshot(
        policy_id=db_pol.id,
        version=version,
        label=label or f"v{version}",
        payload={
            "name": db_pol.name,
            "family": db_pol.family,
            "default_action": db_pol.default_action,
            "rules": [
                {"seq": r.seq, "prefix": r.prefix, "action": r.action,
                 "ge": r.ge, "le": r.le, "remark": r.remark or ""}
                for r in db_pol.rules
            ],
        },
        frr_config=ep.to_frr_prefix_list(),
        created_by=created_by,
    )
    session.add(snap)
    session.commit()
    session.refresh(snap)
    return snap


def engine_policy_from_snapshot(snap: dbmod.Snapshot) -> EnginePolicy:
    p = snap.payload
    return policy_from_dicts(
        name=p["name"], rules=p["rules"],
        default_action=p["default_action"], family=p["family"],
    )


def snapshot_dict(snap: dbmod.Snapshot) -> dict:
    return {
        "id": snap.id,
        "policy_id": snap.policy_id,
        "version": snap.version,
        "label": snap.label,
        "payload": snap.payload,
        "frr_config": snap.frr_config,
        "created_by": snap.created_by,
        "created_at": snap.created_at.isoformat(),
    }


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def analyze(session: Session, db_pol: dbmod.Policy) -> dict:
    ep = engine_policy(db_pol)
    shadows = [s.to_dict() for s in ep.shadowed()]
    return {
        "policy_id": db_pol.id,
        "rule_count": len(ep.rules),
        "fully_shadowed": [s["rule"]["seq"] for s in shadows if s["fully_shadowed"]],
        "partial_overlaps": {
            str(s["rule"]["seq"]): s["partial_shadowed_by"]
            for s in shadows if s["partial_shadowed_by"]
        },
        "shadow_detail": shadows,
    }


def snapshot_diff(session: Session, old_snap_id: int, new_snap_id: int) -> dict:
    old_snap = session.get(dbmod.Snapshot, old_snap_id)
    new_snap = session.get(dbmod.Snapshot, new_snap_id)
    if old_snap is None or new_snap is None:
        raise ValidationError("snapshot not found")
    oldp = engine_policy_from_snapshot(old_snap)
    newp = engine_policy_from_snapshot(new_snap)
    if oldp.family != newp.family:
        raise ValidationError("snapshots belong to different address families")
    witnesses = [w.to_dict() for w in oldp.witness_diff(newp)]

    permits = [w for w in witnesses if w["change"] == "deny->permit"]
    denies = [w for w in witnesses if w["change"] == "permit->deny"]
    return {
        "old_snapshot_id": old_snap_id,
        "new_snapshot_id": new_snap_id,
        "witness_count": len(witnesses),
        "newly_permitted": permits,
        "newly_denied": denies,
        "witnesses": witnesses,
        "old_default": oldp.default_action.value,
        "new_default": newp.default_action.value,
    }


def replay(session: Session, snapshot_id: int, probes: List[str]) -> dict:
    """Deterministic replay of an ordered probe list against one snapshot."""
    snap = session.get(dbmod.Snapshot, snapshot_id)
    if snap is None:
        raise ValidationError("snapshot not found")
    ep = engine_policy_from_snapshot(snap)
    results = []
    for i, prefix in enumerate(probes):
        hit = ep.classify(prefix)
        d = hit.to_dict()
        d["order"] = i
        results.append(d)
    return {
        "snapshot_id": snapshot_id,
        "version": snap.version,
        "frr_config": snap.frr_config,
        "results": results,
    }
