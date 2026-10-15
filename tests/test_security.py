from utils.security import is_developer


def test_developer_is_not_authorized_without_id(monkeypatch):
    # Config is imported by utils.security; with the normal placeholder ID 0,
    # arbitrary user IDs must not be considered the developer.
    assert is_developer(-1) is False
