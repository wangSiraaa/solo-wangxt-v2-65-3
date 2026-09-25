"""
Import orchestration: upload (idempotent) -> isolated draft -> preview ->
resolve errors -> atomic adoption.

Guarantees
----------
* **Idempotent upload**: sessions are keyed by sha256 of the raw text;
  re-submitting the same file returns the existing session, never a duplicate.
* **Isolation**: an import only writes import_* tables.  Mainline policy
  rules are untouched until adoption.
* **Atomic adoption**: rule replacement + snapshot creation + draft/session
  status happen in ONE transaction.  Any failure rolls everything back —
  the mainline can never be half-overwritten.
* **Optimistic concurrency**: adoption requires the `updated_at` token the
  client saw at preview time.  If the mainline moved, adoption is refused
  with 409 and the draft (plus raw text and diagnostics) stays intact.
"""
from __future__ import annotations

import hashlib
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db as dbmod
from .engine import Policy as EnginePolicy, PolicyError, policy_from_dicts
from .importer import ERROR, parse_config
from .service import ValidationError, engine_policy


class ConflictError(Exception):
    """Mainline changed since the client previewed it (HTTP 409)."""

    def __init__(self, message: str, current_updated_at: Optional[str] = None):
        super().__init__(message)
        self.current_updated_at = current_updated_at


# ---------------------------------------------------------------------------
# upload (idempotent)
# ---------------------------------------------------------------------------

def create_import_session(session: Session, filename: str,
                          text: str) -> tuple[dbmod.ImportSession, bool]:
    """Parse and persist an import session.  Returns (session, created)."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    existing = session.scalar(
        select(dbmod.ImportSession)
        .where(dbmod.ImportSession.content_hash == digest))
    if existing is not None:
        return existing, False

    parsed = parse_config(text)
    imp = dbmod.ImportSession(
        filename=filename or "upload.conf",
        content_hash=digest, raw_text=text, status="pending",
    )
    session.add(imp)
    session.flush()                       # imp.id for children

    drafts_by_key = {}
    for spec in parsed.drafts:
        pol = session.scalar(
            select(dbmod.Policy).where(dbmod.Policy.name == spec.name))
        draft = dbmod.ImportDraft(
            session_id=imp.id, name=spec.name, family=spec.family,
            description=spec.description, default_action=spec.default_action,
            rules_json=spec.rules,
            status="pending",
            base_policy_id=pol.id if pol else None,
            base_updated_at=(pol.updated_at.isoformat()
                             if pol and pol.updated_at else None),
        )
        session.add(draft)
        session.flush()
        drafts_by_key[(spec.name, spec.family)] = draft

    for ln in parsed.lines:
        owner = None
        if ln.kind in ("rule", "description") and ln.list_name is not None:
            owner = drafts_by_key.get((ln.list_name, ln.family))
        session.add(dbmod.ImportLine(
            session_id=imp.id, line_no=ln.line_no, raw=ln.raw, kind=ln.kind,
            draft_id=owner.id if owner else None,
            parsed_json=ln.to_dict() if ln.kind == "rule" else None,
        ))

    for d in parsed.diagnostics:
        owner = (drafts_by_key.get((d.list_name, d.family))
                 if d.list_name is not None else None)
        session.add(dbmod.ImportDiagnostic(
            session_id=imp.id, draft_id=owner.id if owner else None,
            line_no=d.line_no, severity=d.severity, kind=d.kind,
            message=d.message,
        ))

    session.flush()
    _refresh_status(session, imp)
    session.commit()
    session.refresh(imp)
    return imp, True


def _refresh_status(session: Session, imp: dbmod.ImportSession) -> None:
    """Recompute draft + session status from unresolved diagnostics."""
    diags = session.query(dbmod.ImportDiagnostic) \
        .filter_by(session_id=imp.id).all()
    open_errors = [d for d in diags
                   if d.severity == ERROR and not d.resolved]
    for draft in imp.drafts:
        if draft.status == "adopted":
            continue
        mine = [d for d in open_errors
                if d.draft_id == draft.id or d.draft_id is None]
        draft.status = "pending" if mine else "ready"
    if open_errors:
        imp.status = "pending"
    elif imp.drafts and all(d.status == "adopted" for d in imp.drafts):
        imp.status = "adopted"
    elif any(d.status == "adopted" for d in imp.drafts):
        imp.status = "partial"
    else:
        imp.status = "ready"
    session.add(imp)


# ---------------------------------------------------------------------------
# serialization
# ---------------------------------------------------------------------------

def session_summary(imp: dbmod.ImportSession) -> dict:
    diags = imp.diagnostics
    return {
        "id": imp.id,
        "filename": imp.filename,
        "content_hash": imp.content_hash,
        "status": imp.status,
        "created_at": imp.created_at.isoformat(),
        "drafts": [{
            "id": d.id, "name": d.name, "family": d.family,
            "status": d.status, "rule_count": len(d.rules_json),
            "adopted_snapshot_id": d.adopted_snapshot_id,
        } for d in imp.drafts],
        "error_count": sum(1 for d in diags
                           if d.severity == ERROR and not d.resolved),
        "warning_count": sum(1 for d in diags if d.severity == "warning"),
    }


def session_detail(imp: dbmod.ImportSession) -> dict:
    out = session_summary(imp)
    out["raw_text"] = imp.raw_text
    out["lines"] = [{
        "line_no": l.line_no, "raw": l.raw, "kind": l.kind,
        "draft_id": l.draft_id, "parsed": l.parsed_json,
    } for l in imp.lines]
    out["drafts"] = [_draft_dict(d) for d in imp.drafts]
    out["diagnostics"] = [_diag_dict(d) for d in imp.diagnostics]
    return out


def _draft_dict(d: dbmod.ImportDraft) -> dict:
    return {
        "id": d.id, "name": d.name, "family": d.family,
        "description": d.description, "default_action": d.default_action,
        "rules": d.rules_json, "status": d.status,
        "base_policy_id": d.base_policy_id,
        "base_updated_at": d.base_updated_at,
        "adopted_snapshot_id": d.adopted_snapshot_id,
        "adopted_at": d.adopted_at.isoformat() if d.adopted_at else None,
    }


def _diag_dict(d: dbmod.ImportDiagnostic) -> dict:
    return {
        "id": d.id, "draft_id": d.draft_id, "line_no": d.line_no,
        "severity": d.severity, "kind": d.kind, "message": d.message,
        "resolved": d.resolved, "resolution": d.resolution,
    }


# ---------------------------------------------------------------------------
# preview: semantic diff of the normalized draft against the mainline
# ---------------------------------------------------------------------------

def _draft_engine_policy(draft: dbmod.ImportDraft,
                         default_action: str) -> EnginePolicy:
    return policy_from_dicts(
        name=draft.name, rules=draft.rules_json,
        default_action=default_action, family=draft.family)


def preview(session: Session, imp: dbmod.ImportSession) -> dict:
    """Per-draft minimal witness set: current mainline -> normalized draft.

    This is a semantic diff, not a text diff: reordered-but-equivalent files
    produce an empty witness set ("no behavior change").
    """
    entries = []
    for draft in imp.drafts:
        pol = session.scalar(
            select(dbmod.Policy).where(dbmod.Policy.name == draft.name))
        entry = {
            "draft_id": draft.id, "name": draft.name, "family": draft.family,
            "status": draft.status,
            "target_policy_id": pol.id if pol else None,
            # token the client must echo back at adoption time
            "base_updated_at": (pol.updated_at.isoformat()
                                if pol and pol.updated_at else None),
        }
        if pol is not None and pol.family != draft.family:
            entry["error"] = (
                f"现有策略 {pol.name!r} 是 IPv{pol.family}，草稿是 "
                f"IPv{draft.family}；地址族不一致，无法比较或采纳")
            entries.append(entry)
            continue

        # effective post-adoption default: keep the mainline's, drafts carry
        # their own (deny) only for brand-new policies
        new_default = pol.default_action if pol else draft.default_action
        if pol is not None:
            current = engine_policy(pol)
            cur_default = pol.default_action
            cur_rules = len(pol.rules)
        else:
            current = policy_from_dicts(draft.name, [], "deny", draft.family)
            cur_default, cur_rules = "deny", 0
        candidate = _draft_engine_policy(draft, new_default)
        try:
            witnesses = [w.to_dict() for w in current.witness_diff(candidate)]
        except PolicyError as e:
            entry["error"] = str(e)
            entries.append(entry)
            continue
        entry.update({
            "current_rule_count": cur_rules,
            "draft_rule_count": len(draft.rules_json),
            "current_default": cur_default,
            "new_default": new_default,
            "witness_count": len(witnesses),
            "newly_permitted": [w for w in witnesses
                                if w["change"] == "deny->permit"],
            "newly_denied": [w for w in witnesses
                             if w["change"] == "permit->deny"],
            "witnesses": witnesses,
        })
        entries.append(entry)
    return {"session_id": imp.id, "status": imp.status, "drafts": entries}


# ---------------------------------------------------------------------------
# resolve errors (each error must be consciously handled before adoption)
# ---------------------------------------------------------------------------

def resolve_diagnostic(session: Session, imp: dbmod.ImportSession,
                       diagnostic_id: int, action: str) -> dbmod.ImportSession:
    diag = session.get(dbmod.ImportDiagnostic, diagnostic_id)
    if diag is None or diag.session_id != imp.id:
        raise ValidationError("diagnostic not found in this import session")
    if diag.severity != ERROR:
        raise ValidationError("只有 error 级诊断需要处理；warning/info 不阻塞采纳")
    if action != "drop":
        raise ValidationError("unsupported resolution action (only 'drop')")
    if not diag.resolved:
        diag.resolved = True
        diag.resolution = "dropped"
        session.add(diag)
    _refresh_status(session, imp)
    session.commit()
    session.refresh(imp)
    return imp


# ---------------------------------------------------------------------------
# adoption: atomic mainline replacement + snapshot, with version check
# ---------------------------------------------------------------------------

def adopt_draft(session: Session, imp: dbmod.ImportSession, draft_id: int,
                expected_base_updated_at: Optional[str] = None,
                default_action: Optional[str] = None,
                label: str = "", created_by: str = "import") -> dict:
    draft = session.get(dbmod.ImportDraft, draft_id)
    if draft is None or draft.session_id != imp.id:
        raise ValidationError("draft not found in this import session")
    if draft.status == "adopted":
        raise ConflictError(f"draft {draft.name!r} 已被采纳"
                            f"（快照 #{draft.adopted_snapshot_id}）")

    # every error in the session must be handled first: no half-imports
    open_errors = [d for d in imp.diagnostics
                   if d.severity == ERROR and not d.resolved]
    if open_errors:
        raise ValidationError(
            f"仍有 {len(open_errors)} 条未处理的错误诊断"
            f"（第 {', '.join(str(d.line_no) for d in open_errors[:5])} 行等）；"
            "全部处理后才能采纳，绝不生成半个快照")

    pol = session.scalar(
        select(dbmod.Policy).where(dbmod.Policy.name == draft.name))
    if pol is not None:
        if pol.family != draft.family:
            raise ValidationError(
                f"现有策略 {pol.name!r} 是 IPv{pol.family}，草稿是 "
                f"IPv{draft.family}；拒绝覆盖")
        token = pol.updated_at.isoformat() if pol.updated_at else None
        if expected_base_updated_at != token:
            raise ConflictError(
                "主线策略在预览后已被更新，采纳已取消（草稿、诊断与原始文本"
                "均保留；请刷新预览后以新版本为基线重新采纳）",
                current_updated_at=token)
    elif expected_base_updated_at:
        raise ConflictError(
            f"主线策略 {draft.name!r} 已不存在（可能被删除）；"
            "请刷新预览后重新采纳", current_updated_at=None)

    new_default = default_action or (pol.default_action if pol
                                     else draft.default_action)
    # defense in depth: re-validate the normalized rules through the engine
    candidate = _draft_engine_policy(draft, new_default)

    try:
        if pol is None:
            pol = dbmod.Policy(name=draft.name, family=draft.family,
                               default_action=new_default,
                               description=draft.description[:256])
            session.add(pol)
            session.flush()
        else:
            pol.default_action = new_default
            if draft.description:
                pol.description = draft.description[:256]
            session.query(dbmod.Rule).filter_by(policy_id=pol.id).delete(
                synchronize_session=False)
            session.flush()
        for r in candidate.rules:
            session.add(dbmod.Rule(
                policy_id=pol.id, seq=r.seq, prefix=r.prefix,
                action=r.action.value, ge=r.ge, le=r.le, remark=""))
        pol.updated_at = dbmod.utcnow()
        session.flush()

        last = session.scalar(
            select(dbmod.Snapshot)
            .where(dbmod.Snapshot.policy_id == pol.id)
            .order_by(dbmod.Snapshot.version.desc()))
        version = (last.version + 1) if last else 1
        snap = dbmod.Snapshot(
            policy_id=pol.id, version=version,
            label=label or f"import:{imp.id}/{draft.name} v{version}",
            payload={
                "name": pol.name, "family": pol.family,
                "default_action": pol.default_action,
                "rules": [{"seq": r.seq, "prefix": r.prefix,
                           "action": r.action.value, "ge": r.ge, "le": r.le,
                           "remark": ""} for r in candidate.rules],
            },
            frr_config=candidate.to_frr_prefix_list(),
            created_by=created_by,
        )
        session.add(snap)
        session.flush()

        draft.status = "adopted"
        draft.adopted_snapshot_id = snap.id
        draft.adopted_at = dbmod.utcnow()
        session.add(draft)
        _refresh_status(session, imp)
        session.commit()          # single commit: rules+snapshot+status are atomic
    except Exception:
        session.rollback()        # nothing half-applied
        raise

    return {
        "session_id": imp.id, "draft_id": draft.id,
        "policy_id": pol.id, "policy": pol.name,
        "snapshot_id": snap.id, "version": snap.version,
        "rule_count": len(candidate.rules),
        "default_action": pol.default_action,
        "session_status": imp.status,
    }


# ---------------------------------------------------------------------------
# limited FRR cross-validation straight from a draft (no snapshot needed)
# ---------------------------------------------------------------------------

def cross_validate_draft(session: Session, imp: dbmod.ImportSession,
                         draft_id: int, probes: List[str],
                         node: str = "a") -> dict:
    from .validate import cross_validate

    draft = session.get(dbmod.ImportDraft, draft_id)
    if draft is None or draft.session_id != imp.id:
        raise ValidationError("draft not found in this import session")
    open_errors = [d for d in imp.diagnostics
                   if d.severity == ERROR and not d.resolved]
    if open_errors:
        raise ValidationError("存在未处理的错误诊断，拒绝交叉验证")
    policy = _draft_engine_policy(draft, draft.default_action)
    result = cross_validate(policy, probes, node=node)
    run = dbmod.Run(
        snapshot_id=None, node=node, status=result["status"],
        detail={"import_session_id": imp.id, "draft_id": draft.id,
                "mismatch_count": result["mismatch_count"],
                "probes": probes, "mismatches": result["mismatches"],
                "setup_error": result.get("setup_error")},
    )
    session.add(run)
    session.commit()
    result["run_id"] = run.id
    return result
