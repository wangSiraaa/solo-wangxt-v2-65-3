"""SQLAlchemy models: neighbors, policies + ordered rules, snapshots, runs,
and config-import sessions (drafts + adoption/mapping history)."""
from __future__ import annotations

import datetime as dt
from typing import List

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine, inspect, select, text,
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
    # optimistic-concurrency counter: bumped on every rule/default change so
    # import drafts can detect "mainline moved since preview" (409 on adopt)
    revision: Mapped[int] = mapped_column(Integer, default=1)
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
# Config import: source-faithful sessions -> isolated drafts -> atomic adopt
# ---------------------------------------------------------------------------

class ImportSession(Base):
    """
    One uploaded FRR config file.  Content-addressed (sha256 of the raw
    text) so re-uploading the same file is idempotent: the existing session
    is returned instead of duplicating drafts.  The raw text is stored
    verbatim for source fidelity — drafts/diagnostics can always be traced
    back to the exact bytes the network team provided.
    """
    __tablename__ = "import_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(256), default="")
    raw_text: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default="draft")
    # draft -> partially-adopted -> adopted
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    lines: Mapped[List["ImportLine"]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
        order_by="ImportLine.line_no")
    drafts: Mapped[List["ImportDraft"]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
        order_by="ImportDraft.id")


class ImportLine(Base):
    """One original line, classified, with parse results and diagnostics."""
    __tablename__ = "import_lines"
    __table_args__ = (UniqueConstraint("session_id", "line_no",
                                       name="uq_import_line"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("import_sessions.id", ondelete="CASCADE"))
    line_no: Mapped[int] = mapped_column(Integer)
    raw: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(16), default="unparsed")
    # rule|comment|blank|description|unparsed
    list_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    keyword_family: Mapped[int | None] = mapped_column(Integer, nullable=True)
    seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str | None] = mapped_column(String(8), nullable=True)
    prefix: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ge: Mapped[int | None] = mapped_column(Integer, nullable=True)
    le: Mapped[int | None] = mapped_column(Integer, nullable=True)
    diagnostics: Mapped[list] = mapped_column(JSON, default=list)

    session: Mapped[ImportSession] = relationship(back_populates="lines")


class ImportDraft(Base):
    """
    One parsed prefix-list (name + family) inside a session.  Isolated from
    the mainline policy until explicitly adopted; adoption is atomic and
    guarded by the mainline revision captured at preview time.
    """
    __tablename__ = "import_drafts"
    __table_args__ = (UniqueConstraint("session_id", "name", "family",
                                       name="uq_import_draft"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("import_sessions.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    family: Mapped[int] = mapped_column(Integer)
    default_action: Mapped[str] = mapped_column(String(8), default="deny")
    default_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    target_policy_id: Mapped[int | None] = mapped_column(
        ForeignKey("policies.id"), nullable=True)
    base_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="draft")
    # draft -> ready -> adopted
    rules: Mapped[list] = mapped_column(JSON, default=list)   # normalized
    rules_edited: Mapped[bool] = mapped_column(Boolean, default=False)
    adopted_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    adopted_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)

    session: Mapped[ImportSession] = relationship(back_populates="drafts")


class ImportAdoption(Base):
    """Mapping history: which draft became which snapshot of which policy."""
    __tablename__ = "import_adoptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("import_sessions.id", ondelete="CASCADE"))
    draft_id: Mapped[int] = mapped_column(
        ForeignKey("import_drafts.id", ondelete="CASCADE"))
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"))
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("snapshots.id", ondelete="CASCADE"))
    base_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    new_version: Mapped[int] = mapped_column(Integer)
    witness_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


def init_db() -> None:
    Base.metadata.create_all(engine)
    _migrate()


def _migrate() -> None:
    """Idempotent column additions for databases created by older versions."""
    cols = {c["name"] for c in inspect(engine).get_columns("policies")}
    if "revision" not in cols:
        with engine.begin() as conn:
            conn.execute(text(
                "ALTER TABLE policies ADD COLUMN revision "
                "INTEGER NOT NULL DEFAULT 1"))


def get_session() -> Session:
    return SessionLocal()
