"""CORS origin'lerinin CORS_ORIGINS env'inden okunması (deploy sertleştirme)."""
import importlib
import os


def test_cors_origins_default(monkeypatch):
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    import app.main as main
    importlib.reload(main)
    assert "http://localhost:5173" in main._cors_origins


def test_cors_origins_from_env(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "https://nabs.corp, https://alt.corp")
    import app.main as main
    importlib.reload(main)
    assert "https://nabs.corp" in main._cors_origins
    assert "https://alt.corp" in main._cors_origins
    # temizle: default'a döndür (diğer testler main'i yeniden yüklerse)
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    importlib.reload(main)
