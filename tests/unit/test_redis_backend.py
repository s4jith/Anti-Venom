import pytest
from unittest.mock import MagicMock, patch


def test_redis_import_error_without_library():
    with patch.dict("sys.modules", {"redis": None}):
        import importlib
        import antivenom.cache.backends.redis as redis_mod
        importlib.reload(redis_mod)
        with pytest.raises(ImportError, match="pip install antivenom\\[redis\\]"):
            redis_mod.RedisBackend()


def test_redis_backend_get_set_delete():
    mock_redis = MagicMock()
    mock_client = MagicMock()
    mock_redis.from_url.return_value = mock_client

    import json
    mock_client.get.return_value = json.dumps({"key": "value"})

    with patch("antivenom.cache.backends.redis._redis", mock_redis):
        import importlib
        import antivenom.cache.backends.redis as redis_mod
        backend = redis_mod.RedisBackend()

        backend.set("mykey", {"key": "value"}, ttl=60)
        mock_client.set.assert_called_once_with("mykey", json.dumps({"key": "value"}), ex=60)

        result = backend.get("mykey")
        assert result == {"key": "value"}

        backend.delete("mykey")
        mock_client.delete.assert_called_once_with("mykey")


def test_redis_backend_clear():
    mock_redis = MagicMock()
    mock_client = MagicMock()
    mock_redis.from_url.return_value = mock_client

    with patch("antivenom.cache.backends.redis._redis", mock_redis):
        import antivenom.cache.backends.redis as redis_mod
        backend = redis_mod.RedisBackend()
        backend.clear()
        mock_client.flushdb.assert_called_once()


def test_redis_backend_ping_true():
    mock_redis = MagicMock()
    mock_client = MagicMock()
    mock_client.ping.return_value = True
    mock_redis.from_url.return_value = mock_client

    with patch("antivenom.cache.backends.redis._redis", mock_redis):
        import antivenom.cache.backends.redis as redis_mod
        backend = redis_mod.RedisBackend()
        assert backend.ping() is True


def test_redis_backend_ping_false_on_exception():
    mock_redis = MagicMock()
    mock_client = MagicMock()
    mock_client.ping.side_effect = Exception("connection refused")
    mock_redis.from_url.return_value = mock_client

    with patch("antivenom.cache.backends.redis._redis", mock_redis):
        import antivenom.cache.backends.redis as redis_mod
        backend = redis_mod.RedisBackend()
        assert backend.ping() is False


def test_redis_no_ttl_when_zero():
    mock_redis = MagicMock()
    mock_client = MagicMock()
    mock_redis.from_url.return_value = mock_client

    import json
    with patch("antivenom.cache.backends.redis._redis", mock_redis):
        import antivenom.cache.backends.redis as redis_mod
        backend = redis_mod.RedisBackend()
        backend.set("k", "v", ttl=0)
        mock_client.set.assert_called_once_with("k", json.dumps("v"))
