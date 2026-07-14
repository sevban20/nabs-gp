"""Git engine boş-depo davranışı (request f296d74a... regresyonu)."""
import pytest

from app.services.git_engine import GitConfigEngine


@pytest.fixture()
def empty_engine(tmp_path):
    return GitConfigEngine(base_repo_path=str(tmp_path / "repo"))


def test_history_on_empty_repo_returns_empty(empty_engine):
    # Hiç commit yokken 'refs/heads/master does not exist' fırlatmamalı
    assert empty_engine.get_history("EDGE-01") == []


def test_diff_on_empty_repo_returns_empty(empty_engine):
    assert empty_engine.get_diff("EDGE-01", "abc", "def") == ""


def test_history_after_first_commit(empty_engine):
    sha = empty_engine.save_and_commit("SW-01", "hostname SW-01\n", "TEST")
    assert sha
    history = empty_engine.get_history("SW-01")
    assert len(history) == 1
    assert history[0]["commit"] == sha


def test_diff_invalid_commit_raises_valueerror(empty_engine):
    empty_engine.save_and_commit("SW-02", "hostname SW-02\n", "TEST")
    with pytest.raises(ValueError, match="Geçersiz commit"):
        empty_engine.get_diff("SW-02", "olmayan-sha", "HEAD")


def test_diff_between_two_commits(empty_engine):
    a = empty_engine.save_and_commit("SW-03", "hostname SW-03\nsnmp v2\n", "TEST")
    b = empty_engine.save_and_commit("SW-03", "hostname SW-03\nsnmp v3\n", "TEST")
    diff = empty_engine.get_diff("SW-03", a, b)
    assert "-snmp v2" in diff and "+snmp v3" in diff
