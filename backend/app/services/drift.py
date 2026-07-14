"""Config drift tespiti: mevcut config'i golden (referans) config'le
karşılaştırır. Saf/test edilebilir fonksiyonlar; DB/git orkestrasyonu
tasks.py'de.
"""
import difflib
import hashlib


def normalize(config: str) -> list[str]:
    """Karşılaştırma öncesi normalize: satır sonu boşluklarını kırp, tamamen
    boş satırları at (biçimsel farklar drift sayılmasın)."""
    return [line.rstrip() for line in config.splitlines() if line.strip()]


def content_hash(config: str) -> str:
    """Normalize edilmiş içeriğin SHA-256 özeti (hızlı eşitlik kontrolü)."""
    return hashlib.sha256("\n".join(normalize(config)).encode()).hexdigest()


def compute_drift(baseline: str, current: str, context: int = 2) -> dict:
    """Golden'a göre sapmayı hesaplar. in_sync=True ise sapma yok.
    added = golden'da olmayan yeni satır, removed = golden'da olup gitmiş satır."""
    b, c = normalize(baseline), normalize(current)
    diff_lines = list(difflib.unified_diff(
        b, c, fromfile="golden", tofile="current", lineterm="", n=context))
    added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))
    return {
        "in_sync": added == 0 and removed == 0,
        "added": added,
        "removed": removed,
        "diff": "\n".join(diff_lines),
    }
