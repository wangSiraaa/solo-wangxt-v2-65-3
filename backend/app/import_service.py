"""
Import closed-loop: upload -> isolated draft -> diagnose/resolve -> atomic
adoption as an immutable snapshot.

Guarantees:

* Idempotency — sessions are content-addressed (sha256 of the raw text);
  re-uploading the same file returns the existing session unchanged.
* Isolation — importing never touches mainline policies.  A draft only
  becomes visible to the mainline through `adopt_draft`.
* Atomicity — `adopt_draft` performs readiness checks, rule replacement,
  snapshot creation and mapping-history bookkeeping in ONE transaction;
  any failure rolls everything back, so a half-written snapshot or a
  partially overwritten rule set is impossible.
* Optimistic concurrency — adoption is checked against the mainline
  `Policy.revision` captured at preview time; if the mainline moved, the
  adopt call fails with a conflict and the draft (plus raw text and
  diagnostics) stays intact for a refreshed retry.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import db as dbmod, importer, service
from .engine import Policy as EnginePolicy, PolicyError, policy_from_dicts
from .service import ValidationError


class ConflictError(Exception):
    """Mainline revision moved since the draft was previewed (HTTP 409)."""


# ---------------------------------------------------------------------------
# Session creation (idempotent)
# ---------------------------------------------------------------------------

def create_import_session(session: Session, filename: str,
                          text: str) -> Tuple[dbmod.ImportSession, bool]:
    """Persist a parsed import session; returns (session, created).

    The same file content always maps to the same session — duplicate
    submissions generate exactly one session.
    """
    chash = importer.ParseResult.content_hash(text)
    existing = session.scalar(
        dbmod.select(dbmod.ImportSession).where(
            dbmod.ImportSession.content_hash == chash))
    if existing is not None:
        return existing, False

    parsed = importer.parse_config(text)
    imp = dbmod.ImportSession(
        content_hash=chash, filename=filename or "", raw_text=text)
    session.add(imp)
    session.flush()

    for pl in parsed.lines:
        session.add(dbmod.ImportLine(
            session_id=imp.id, line_no=pl.line_no, raw=pl.raw, kind=pl.kind,
            list_name=pl.list_name, keyword_family=pl.keyword_family,
            seq=pl.seq, action=pl.action, prefix=pl.prefix,
            ge=pl.ge, le=pl.le,
            diagnostics=[d.to_dict() for d in pl.diagnostics],
        ))

    for spec in parsed.drafts:
        # auto-map onto an existing mainline policy with the same name+family
        target = session.scalar(
            dbmod.select(dbmod.Policy).where(
                dbmod.Policy.name == spec.name,
                dbmod.Policy.family == spec.family))
        session.add(dbmod.ImportDraft(
            session_id=imp.id, name=spec.name, family=spec.family,
            rules=spec.rules,
            target_policy_id=target.id if target else None,
            base_revision=target.revision if target else None,
        ))
    session.commit()
    session.refresh(imp)
    return imp, True


# ---------------------------------------------------------------------------
# Preview (read-only): lines + drafts + semantic diff vs current mainline
# ---------------------------------------------------------------------------

def _draft_list_diagnostics(draft: dbmod.ImportDraft) -> List[dict]:
    """Recompute list-level diagnostics from the CURRENT draft rules."""
    diags: List[dict] = []
    seqs = {}
    for r in draft.rules:
        seqs.setdefault(int(r["seq"]), 0)
        seqs[int(r["seq"])] += 1
    for seq, n in sorted(seqs.items()):
        if n > 1:
            diags.append({"code": "duplicate-seq", "severity": "error",
                          "message": f"序号重复：seq {seq} 出现 {n} 次；"
                                     "首条匹配语义要求序号唯一"})
    if not draft.rules:
        diags.append({"code": "empty-list", "severity": "error",
                      "message": "该列表没有可用规则；空 prefix-list 在 FRR 中"
                                 "等价于全部放行，拒绝导入"})
    if not draft.default_confirmed:
        diags.append({"code": "missing-default", "severity": "warning",
                      "message": "文件未携带默认行为：未命中条目将按隐式默认"
                                 "动作处理，采纳前必须显式确认 default_action"})
    return diags


def _draft_line_errors(session: Session, draft: dbmod.ImportDraft) -> List[dict]:
    """Error-severity line diagnostics belonging to this draft's list."""
    out = []
    for ln in session.query(dbmod.ImportLine).filter_by(
            session_id=draft.session_id).all():
        if ln.kind != "rule":
            continue
        if ln.list_name != draft.name or ln.keyword_family != draft.family:
            continue
        for d in ln.diagnostics or []:
            if d.get("severity") == "error":
                out.append({"line_no": ln.line_no, **d})
    return out


def draft_readiness(session: Session, draft: dbmod.ImportDraft) -> dict:
    """What still blocks adoption, computed from current state."""
    list_diags = _draft_list_diagnostics(draft)
    line_errors = [] if draft.rules_edited else _draft_line_errors(session, draft)
    try:
        service.validate_rule_dicts(draft.family, list(draft.rules))
        rules_valid = True
        rules_error = None
    except (ValidationError, PolicyError, ValueError, KeyError) as e:
        rules_valid = False
        rules_error = str(e)
    blocking = ([d for d in list_diags if d["severity"] == "error"]
                + line_errors
                + ([{"code": "invalid-rules", "severity": "error",
                     "message": rules_error}] if not rules_valid else []))
    ready = (not blocking and draft.default_confirmed
             and draft.status != "adopted")
    return {
        "ready": ready,
        "blocking": blocking,
        "warnings": [d for d in list_diags if d["severity"] != "error"],
        "rules_valid": rules_valid,
    }


def _draft_diff(session: Session, draft: dbmod.ImportDraft) -> Optional[dict]:
    """Semantic (not textual) minimal change set vs the current mainline."""
    try:
        newp = policy_from_dicts(
            name=draft.name, rules=list(draft.rules),
            default_action=draft.default_action, family=draft.family)
    except (PolicyError, ValueError, KeyError):
        return None                       # rules invalid -> readiness explains
    target = (session.get(dbmod.Policy, draft.target_policy_id)
              if draft.target_policy_id else None)
    if target is not None:
        oldp = service.engine_policy(target)
        base_revision = target.revision
        baseline = f"policy:{target.name} (working rules)"
    else:
        oldp = EnginePolicy(name=draft.name, rules=[], family=draft.family)
        base_revision = None
        baseline = "(new policy — empty mainline, implicit deny)"
    witnesses = [w.to_dict() for w in oldp.witness_diff(newp)]
    return {
        "baseline": baseline,
        "base_revision": base_revision,
        "old_default": oldp.default_action.value,
        "new_default": newp.default_action.value,
        "witness_count": len(witnesses),
        "newly_permitted": [w for w in witnesses if w["change"] == "deny->permit"],
        "newly_denied": [w for w in witnesses if w["change"] == "permit->deny"],
        "witnesses": witnesses,
    }


def draft_dict(session: Session, draft: dbmod.ImportDraft) -> dict:
    target = (session.get(dbmod.Policy, draft.target_policy_id)
              if draft.target_policy_id else None)
    readiness = draft_readiness(session, draft)
    diff = _draft_diff(session, draft)
    current_revision = target.revision if target else None
    return {
        "id": draft.id,
        "session_id": draft.session_id,
        "name": draft.name,
        "family": draft.family,
        "status": draft.status,
        "default_action": draft.default_action,
        "default_confirmed": draft.default_confirmed,
        "target_policy_id": draft.target_policy_id,
        "target_policy_name": target.name if target else None,
        "base_revision": draft.base_revision,
        "current_revision": current_revision,
        "stale": (draft.status != "adopted" and target is not None
                  and draft.base_revision is not None
                  and current_revision != draft.base_revision),
        "rules": draft.rules,
        "rules_edited": draft.rules_edited,
        "readiness": readiness,
        "diff": diff,
        "adopted_snapshot_id": draft.adopted_snapshot_id,
        "created_at": draft.created_at.isoformat(),
        "adopted_at": draft.adopted_at.isoformat() if draft.adopted_at else None,
    }


def session_dict(session: Session, imp: dbmod.ImportSession,
                 detail: bool = True) -> dict:
    out = {
        "id": imp.id,
        "filename": imp.filename,
        "content_hash": imp.content_hash,
        "status": imp.status,
        "created_at": imp.created_at.isoformat(),
        "draft_count": len(imp.drafts),
    }
    if detail:
        out.update({
            "raw_text": imp.raw_text,
            "lines": [
                {"line_no": ln.line_no, "raw": ln.raw, "kind": ln.kind,
                 "list_name": ln.list_name, "keyword_family": ln.keyword_family,
                 "seq": ln.seq, "action": ln.action, "prefix": ln.prefix,
                 "ge": ln.ge, "le": ln.le, "diagnostics": ln.diagnostics}
                for ln in imp.lines
            ],
            "drafts": [draft_dict(session, d) for d in imp.drafts],
        })
    return out


# ---------------------------------------------------------------------------
# Draft resolution (edit rules / confirm default / retarget)
# ---------------------------------------------------------------------------

def update_draft(session: Session, draft: dbmod.ImportDraft, *,
                 default_action: Optional[str] = None,
                 confirm_default: Optional[bool] = None,
                 target_policy_id: Optional[int] = None,
                 retarget: bool = False,
                 rules: Optional[List[dict]] = None) -> dbmod.ImportDraft:
    if draft.status == "adopted":
        raise ValidationError("draft already adopted; imports are immutable "
                              "after adoption")
    if default_action is not None:
        if default_action not in ("permit", "deny"):
            raise ValidationError("default_action must be permit|deny")
        draft.default_action = default_action
    if confirm_default is not None:
        draft.default_confirmed = bool(confirm_default)
    if retarget:
        if target_policy_id is not None:
            target = session.get(dbmod.Policy, target_policy_id)
            if target is None:
                raise ValidationError(f"policy {target_policy_id} not found")
            if target.family != draft.family:
                raise ValidationError(
                    f"target policy {target.name!r} is IPv{target.family}, "
                    f"draft is IPv{draft.family}; families must not be mixed")
            draft.target_policy_id = target.id
            draft.base_revision = target.revision
        else:
            draft.target_policy_id = None
            draft.base_revision = None
    if rules is not None:
        # validate through the same path as mainline edits; on success the
        # edited rule set supersedes the parsed one (line-level errors are
        # considered handled by the edit)
        normalized = service.validate_rule_dicts(draft.family, list(rules))
        draft.rules = [
            {"seq": r.seq, "prefix": r.prefix, "action": r.action.value,
             "ge": r.ge, "le": r.le, "remark": r.remark}
            for r in sorted(normalized, key=lambda r: r.seq)
        ]
        draft.rules_edited = True
    session.commit()
    session.refresh(draft)
    return draft


# ---------------------------------------------------------------------------
# Atomic adoption
# ---------------------------------------------------------------------------

def adopt_draft(session: Session, imp: dbmod.ImportSession,
                draft: dbmod.ImportDraft,
                expected_revision: Optional[int] = None,
                created_by: str = "import") -> dict:
    if draft.status == "adopted":
        raise ConflictError("draft already adopted")

    readiness = draft_readiness(session, draft)
    if not readiness["ready"]:
        raise ValidationError(
            "draft has unresolved blocking diagnostics: "
            + "; ".join(d["message"] for d in readiness["blocking"]))

    target = (session.get(dbmod.Policy, draft.target_policy_id)
              if draft.target_policy_id else None)
    if target is not None and target.family != draft.family:
        raise ValidationError("target policy address family != draft family")

    # ---- optimistic concurrency: mainline must not have moved ----
    expected = expected_revision if expected_revision is not None \
        else draft.base_revision
    if target is not None and expected is not None \
            and target.revision != expected:
        raise ConflictError(
            f"mainline policy {target.name!r} moved: revision is "
            f"{target.revision}, draft was previewed against {expected}. "
            "Refresh the preview and re-adopt; the draft, diagnostics and "
            "original text are preserved.")

    if target is None:
        clash = session.scalar(
            dbmod.select(dbmod.Policy).where(dbmod.Policy.name == draft.name))
        if clash is not None:
            raise ConflictError(
                f"a policy named {draft.name!r} now exists (revision "
                f"{clash.revision}); retarget the draft or refresh")

    # semantic delta vs the state we are about to replace (for history)
    diff = _draft_diff(session, draft)
    witness_count = diff["witness_count"] if diff else 0

    try:
        if target is None:
            target = dbmod.Policy(
                name=draft.name, family=draft.family,
                default_action=draft.default_action, draft=False,
                description=f"imported from {imp.filename or imp.content_hash[:12]}")
            session.add(target)
            session.flush()
        target.default_action = draft.default_action
        target.draft = False

        service.replace_rules(session, target, list(draft.rules), commit=False)
        label = f"import:{imp.filename or imp.content_hash[:12]}:{draft.name}"
        snap = service.create_snapshot(
            session, target, label=label, created_by=created_by, commit=False)

        adoption = dbmod.ImportAdoption(
            session_id=imp.id, draft_id=draft.id, policy_id=target.id,
            snapshot_id=snap.id, base_revision=expected,
            new_version=snap.version, witness_count=witness_count)
        session.add(adoption)

        draft.status = "adopted"
        draft.adopted_snapshot_id = snap.id
        draft.adopted_at = dbmod.utcnow()
        draft.base_revision = target.revision
        session.add(draft)

        imp.status = ("adopted" if all(d.status == "adopted" for d in imp.drafts)
                      else "partially-adopted")
        session.add(imp)
        session.commit()
    except IntegrityError as e:
        session.rollback()
        raise ConflictError(f"adoption would violate a uniqueness "
                            f"constraint; nothing was written: {e.orig}") from e
    except Exception:
        session.rollback()
        raise

    return {
        "draft_id": draft.id,
        "policy_id": target.id,
        "policy": service.policy_payload(target),
        "snapshot": service.snapshot_dict(snap),
        "witness_count": witness_count,
        "session_status": imp.status,
    }


# ---------------------------------------------------------------------------
# FRR cross-validation of a draft (limited: probes against local containers)
# ---------------------------------------------------------------------------

def cross_validate_draft(session: Session, draft: dbmod.ImportDraft,
                         probes: List[str], node: str = "a") -> dict:
    from .validate import cross_validate          # local import: avoids cycle
    readiness = draft_readiness(session, draft)
    if not readiness["rules_valid"]:
        raise ValidationError("draft rules are not valid; fix diagnostics "
                              "before cross-validation")
    policy = policy_from_dicts(
        name=draft.name, rules=list(draft.rules),
        default_action=draft.default_action, family=draft.family)
    result = cross_validate(policy, probes, node=node)
    run = dbmod.Run(
        snapshot_id=None, node=node, status=result["status"],
        detail={"import_draft_id": draft.id,
                "import_session_id": draft.session_id,
                "mismatch_count": result["mismatch_count"],
                "probes": probes,
                "mismatches": result["mismatches"],
                "setup_error": result.get("setup_error")})
    session.add(run)
    session.commit()
    result["run_id"] = run.id
    return result
