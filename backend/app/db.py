"""SQLAlchemy models: neighbors, policies + ordered rules, snapshots, runs."""
from __future__ import annotations

import datetime as dt
from typing import List

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine, select,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session,
)

from .config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Neighbor(Base):
    __tablename__ = "neighbors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    ip: Mapped[str] = mapped_column(String(64))
    family: Mapped[int] = mapped_column(Integer, default=4)
    asn: Mapped[int] = mapped_column(Integer, nullable=True)
    inbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    family: Mapped[int] = mapped_column(Integer, default=4)       # 4 or 6
    default_action: Mapped[str] = mapped_column(String(8), default="deny")
    description: Mapped[str] = mapped_column(String(256), default="")
    draft: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)

    rules: Mapped[List["Rule"]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="Rule.seq",
    )
    snapshots: Mapped[List["Snapshot"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan",
        order_by="Snapshot.version.desc()",
    )


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("policy_id", "seq", name="uq_policy_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    prefix: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(8))                  # permit/deny
    ge: Mapped[int | None] = mapped_column(Integer, nullable=True)
    le: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remark: Mapped[str] = mapped_column(String(256), default="")

    policy: Mapped[Policy] = relationship(back_populates="rules")


class Snapshot(Base):
    """
    Immutable configuration snapshot.  payload is the exact, replayable
    policy body: ordered rules + default action + family, plus FRR-rendered
    config and metadata.  Replays never depend on later edits.
    """
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(String(128), default="")
    payload: Mapped[dict] = mapped_column(JSON)
    frr_config: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="lab")

    policy: Mapped[Policy] = relationship(back_populates="snapshots")
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


class Scenario(Base):
    """Saved replay bundle: from/to snapshots, probe inputs, observed results."""
    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    from_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    to_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    probes: Mapped[list] = mapped_column(JSON, default=list)   # ordered prefix list
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Run(Base):
    """One cross-validation run against a local FRR container."""
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    node: Mapped[str] = mapped_column(String(16), default="a")      # router-a/b
    status: Mapped[str] = mapped_column(String(16), default="ok")   # ok/mismatch/error
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


# ---------------------------------------------------------------------------
# Config import: source-fidelity upload -> isolated draft -> atomic adoption
# ---------------------------------------------------------------------------

class ImportSession(Base):
    """
    One uploaded FRR prefix-list file.  The raw text is stored verbatim so a
    session (with its drafts, diagnostics and line mapping) survives refreshes
    and can be reviewed/adopted later.  content_hash makes re-uploading the
    same file idempotent: the existing session is returned instead.
    """
    __tablename__ = "import_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(256), default="")
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    raw_text: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="pending")
    # pending (unresolved errors) / ready / partial (some drafts adopted) / adopted
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    drafts: Mapped[List["ImportDraft"]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
        order_by="ImportDraft.id")
    lines: Mapped[List["ImportLine"]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
        order_by="ImportLine.line_no")
    diagnostics: Mapped[List["ImportDiagnostic"]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
        order_by="ImportDiagnostic.id")


class ImportDraft(Base):
    """
    One parsed prefix-list (name, family) inside a session: the isolated
    staging area.  rules_json holds the normalized candidate rules (canonical
    prefixes, sorted by seq); mainline rules are only replaced atomically at
    adoption time, together with the snapshot, in a single transaction.
    """
    __tablename__ = "import_drafts"
    __table_args__ = (
        UniqueConstraint("session_id", "name", "family", name="uq_import_draft"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("import_sessions.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    family: Mapped[int] = mapped_column(Integer)                    # 4 or 6
    description: Mapped[str] = mapped_column(String(512), default="")
    default_action: Mapped[str] = mapped_column(String(8), default="deny")
    rules_json: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    # pending (has unresolved errors) / ready / adopted
    # mainline state observed at import time (informational baseline)
    base_policy_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    base_updated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    adopted_snapshot_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    adopted_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)

    session: Mapped[ImportSession] = relationship(back_populates="drafts")


class ImportLine(Base):
    """Mapping history: original line -> kind -> parsed rule / owning draft."""
    __tablename__ = "import_lines"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("import_sessions.id", ondelete="CASCADE"))
    line_no: Mapped[int] = mapped_column(Integer)
    raw: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(16))      # rule/description/comment/...
    draft_id: Mapped[int | None] = mapped_column(
        ForeignKey("import_drafts.id", ondelete="SET NULL"), nullable=True)
    parsed_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    session: Mapped[ImportSession] = relationship(back_populates="lines")


class ImportDiagnostic(Base):
    """One typed finding.  Errors block adoption until resolved (dropped)."""
    __tablename__ = "import_diagnostics"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("import_sessions.id", ondelete="CASCADE"))
    draft_id: Mapped[int | None] = mapped_column(
        ForeignKey("import_drafts.id", ondelete="CASCADE"), nullable=True)
    line_no: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(8))   # error/warning/info
    kind: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(Text, default="")
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolution: Mapped[str | None] = mapped_column(String(32), nullable=True)

    session: Mapped[ImportSession] = relationship(back_populates="diagnostics")


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_session() -> Session:
    return SessionLocal()
