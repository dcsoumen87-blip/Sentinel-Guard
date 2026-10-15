from config import BOT_NAME, DEFAULT_PREFIX


def test_default_config():
    assert BOT_NAME == "Sentinel Guard"
    assert DEFAULT_PREFIX
