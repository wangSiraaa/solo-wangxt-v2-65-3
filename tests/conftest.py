"""Pytest configuration: backend on sys.path, temp DB."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

_tmpdir = tempfile.mkdtemp(prefix="rlab-test-")
os.environ["RLAB_DATA"] = _tmpdir
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_tmpdir) / 'test.db'}"
# env must be set before any app.* import reads config.py


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    from app import db as dbmod
    dbmod.init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db():
    from app import db as dbmod
    dbmod.init_db()
    s = dbmod.SessionLocal()
    # clean slate for ordering-sensitive tests
    for tbl in (dbmod.Run, dbmod.Scenario, dbmod.Snapshot,
                dbmod.Rule, dbmod.Policy, dbmod.Neighbor,
                dbmod.ImportLine, dbmod.ImportDiagnostic,
                dbmod.ImportDraft, dbmod.ImportSession):
        s.query(tbl).delete()
    s.commit()
    yield s
    s.close()
