"""Basit sabit-pencere rate limiter.

Redis varsa atomik INCR+EXPIRE ile dağıtık çalışır (birden çok API
kopyası aynı sayacı paylaşır); Redis yoksa süreç-içi bellek sözlüğüne
düşer (tek kopya için yeterli, fail-open değil). Login brute-force'unu
yavaşlatmak için kullanılır.
"""
import threading
import time

from app.core.config import settings

_local_lock = threading.Lock()
_local_buckets: dict[str, tuple[int, float]] = {}  # key -> (count, window_start)

_redis = None
_redis_tried = False


def _get_redis():
    global _redis, _redis_tried
    if _redis_tried:
        return _redis
    _redis_tried = True
    try:
        import redis  # type: ignore
        client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
        client.ping()
        _redis = client
    except Exception:
        _redis = None
    return _redis


def check_rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    """True = izin verildi, False = limit aşıldı. Hata durumunda izin verir
    (fail-open) — rate limiter bir DoS vektörüne dönüşmesin."""
    client = _get_redis()
    if client is not None:
        try:
            redis_key = f"ratelimit:{key}"
            count = client.incr(redis_key)
            if count == 1:
                client.expire(redis_key, window_seconds)
            return count <= limit
        except Exception:
            pass  # Redis düştüyse belleğe düş

    now = time.time()
    with _local_lock:
        count, start = _local_buckets.get(key, (0, now))
        if now - start >= window_seconds:
            count, start = 0, now
        count += 1
        _local_buckets[key] = (count, start)
        return count <= limit
