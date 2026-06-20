import pytest
from antivenom.cache.hash_cache import HashCache
from antivenom.cache.backends.memory import InMemoryBackend
from antivenom.core.result import ScanResult, Severity


def _make_result(poisoned: bool = False) -> ScanResult:
    if poisoned:
        return ScanResult.poisoned("abc123", 0.95, [])
    return ScanResult.clean("abc123")


def test_cache_miss_returns_none():
    cache = HashCache(backend=InMemoryBackend())
    assert cache.get("some text") is None


def test_cache_hit_after_set():
    cache = HashCache(backend=InMemoryBackend())
    result = _make_result(poisoned=True)
    cache.set("inject text", result)
    cached = cache.get("inject text")
    assert cached is not None
    assert cached.is_poisoned is True
    assert cached.from_cache is True


def test_cache_preserves_severity():
    cache = HashCache(backend=InMemoryBackend())
    result = _make_result(poisoned=True)
    cache.set("text", result)
    cached = cache.get("text")
    assert cached is not None
    assert cached.severity == Severity.MALICIOUS


def test_different_texts_different_keys():
    cache = HashCache(backend=InMemoryBackend())
    cache.set("text A", _make_result(poisoned=True))
    cache.set("text B", _make_result(poisoned=False))
    assert cache.get("text A").is_poisoned is True
    assert cache.get("text B").is_poisoned is False


def test_hit_rate_tracking():
    cache = HashCache(backend=InMemoryBackend())
    cache.set("hello", _make_result())
    cache.get("hello")  # hit
    cache.get("hello")  # hit
    cache.get("miss")   # miss
    assert abs(cache.hit_rate - 2/3) < 0.01


def test_clear_resets_cache():
    cache = HashCache(backend=InMemoryBackend())
    cache.set("data", _make_result())
    cache.clear()
    assert cache.get("data") is None
