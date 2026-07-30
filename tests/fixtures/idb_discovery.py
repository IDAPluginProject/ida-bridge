from dataclasses import dataclass
from pathlib import Path
import re

_IDBS_DIR = Path(__file__).resolve().parent / "idbs"
_HEAVY_DIR = _IDBS_DIR / "heavy"


@dataclass(frozen=True)
class IdbFixture:
    name: str
    path: Path


def _safe_name(stem: str) -> str:
    """Identifier-safe fixture name (used in test IDs and generated symbols)."""
    return re.sub(r"[^0-9A-Za-z_]", "_", stem)


def _scan(directory: Path) -> list[IdbFixture]:
    if not directory.is_dir():
        return []
    return [IdbFixture(name=_safe_name(p.stem), path=p) for p in sorted(directory.glob("*.i64"))]


def available(include_heavy: bool = False) -> list[IdbFixture]:
    """Return discovered IDB fixtures; include idbs/heavy/ when *include_heavy*."""
    fixtures = _scan(_IDBS_DIR)
    if include_heavy:
        fixtures += _scan(_HEAVY_DIR)
    return fixtures


def default_fixture() -> IdbFixture:
    """The IDB for tests that assert something independent of IDB contents.

    Stable and always part of the selected set: the base scan is sorted and heavy
    fixtures are appended after it, so this does not move when --e2e-heavy is on.
    """
    return available()[0]
