import pytest

from app.core.config import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(mode="demo", db_path=str(tmp_path / "t.db"))
