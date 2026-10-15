import pytest
import database.db as dbmod


@pytest.mark.asyncio
async def test_db_initializes(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "DATABASE_PATH", str(tmp_path / "test.db"))
    await dbmod.init_db()
    assert (tmp_path / "test.db").exists()
