"""
Skill system for bundled and explicitly approved user extensions.

Bundled skills ship with Clicky and must match the signed source manifest. User
Python files under ~/.clicky/skills are
disabled unless their filename and SHA-256 digest appear in allowlist.json:

    {"version": 1, "approved": {"my_skill.py": "<64 lowercase hex chars>"}}

Changing a user skill changes its digest and disables it until re-approved.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Optional


_loaded: list[dict] = []
_MAX_BUNDLED_SKILL_BYTES = 256 * 1024
_MAX_USER_SKILL_BYTES = 256 * 1024
_MAX_ALLOWLIST_BYTES = 64 * 1024
_BUNDLED_MANIFEST_NAME = "manifest.json"
# Package infrastructure is imported normally and covered by the application
# package.  It must never be compiled and executed as a Developer Python Skill.
_BUNDLED_INFRASTRUCTURE_MODULES = frozenset(
    {"registry.py", "schema.py"}
)
# This immutable trust anchor is embedded in the PyInstaller executable/PYZ.
# The external manifest is retained for transparency, but cannot authorize a
# different sidecar skill even if both files are replaced together.
_BUNDLED_SKILL_DIGESTS = MappingProxyType(
    {
        "example_self_mode.py": (
            "a360d83d8b67774078b46b0caaebcbdf9bbe8c5373cdf6f85c0fc7fd5acced19"
        )
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _bundled_skill_manifest_path() -> Path:
    return Path(__file__).parent / _BUNDLED_MANIFEST_NAME


def _verified_bundled_skill_sources() -> list[tuple[Path, bytes, str]]:
    """Return bundled skill bytes only when the complete manifest matches."""
    directory = Path(__file__).parent
    manifest_path = _bundled_skill_manifest_path()
    try:
        if (
            manifest_path.is_symlink()
            or manifest_path.stat().st_size > _MAX_ALLOWLIST_BYTES
        ):
            return []
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("version") != 1:
            return []
        manifest = payload.get("files")
        if not isinstance(manifest, dict) or not manifest:
            return []
        approved: dict[str, str] = {}
        for filename, digest in manifest.items():
            if (
                not isinstance(filename, str)
                or Path(filename).name != filename
                or filename.startswith("_")
                or not filename.endswith(".py")
                or not isinstance(digest, str)
                or not _SHA256_RE.fullmatch(digest.lower())
            ):
                return []
            approved[filename] = digest.lower()

        bundled = {
            path.name: path
            for path in directory.glob("*.py")
            if (
                not path.name.startswith("_")
                and path.name not in _BUNDLED_INFRASTRUCTURE_MODULES
            )
        }
        if set(bundled) != set(approved):
            return []
        if dict(approved) != dict(_BUNDLED_SKILL_DIGESTS):
            return []

        verified: list[tuple[Path, bytes, str]] = []
        for filename in sorted(bundled):
            path = bundled[filename]
            if path.is_symlink() or path.stat().st_size > _MAX_BUNDLED_SKILL_BYTES:
                return []
            source = path.read_bytes()
            if len(source) > _MAX_BUNDLED_SKILL_BYTES:
                return []
            actual = hashlib.sha256(source).hexdigest()
            if not hmac.compare_digest(actual, approved[filename]):
                return []
            verified.append((path, source, actual))
        return verified
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []


def _user_skills_dir() -> Path:
    """User-level skills directory. Files here are not trusted by default."""
    return Path.home() / ".clicky" / "skills"


def _user_skill_allowlist_path() -> Path:
    return _user_skills_dir() / "allowlist.json"


def _approved_user_skills() -> dict[str, str]:
    """Load a strict filename-to-SHA-256 approval map; malformed means none."""
    path = _user_skill_allowlist_path()
    try:
        if path.is_symlink() or path.stat().st_size > _MAX_ALLOWLIST_BYTES:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("version") != 1:
            return {}
        approved = payload.get("approved")
        if not isinstance(approved, dict):
            return {}
        result: dict[str, str] = {}
        for filename, digest in approved.items():
            if (
                isinstance(filename, str)
                and Path(filename).name == filename
                and filename.endswith(".py")
                and isinstance(digest, str)
                and _SHA256_RE.fullmatch(digest.lower())
            ):
                result[filename] = digest.lower()
        return result
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}


def load_all() -> list[dict]:
    """Load bundled skills and hash-approved user skills."""
    global _loaded
    _loaded = []

    for skill_path, source, digest in _verified_bundled_skill_sources():
        _try_import(
            skill_path,
            source=source,
            digest=digest,
            origin="bundled",
        )

    user_dir = _user_skills_dir()
    approvals = _approved_user_skills()
    if user_dir.is_dir() and approvals:
        for skill_path in sorted(user_dir.glob("*.py")):
            expected = approvals.get(skill_path.name)
            if not expected or skill_path.is_symlink():
                continue
            try:
                if skill_path.stat().st_size > _MAX_USER_SKILL_BYTES:
                    continue
                source = skill_path.read_bytes()
            except OSError:
                continue
            if len(source) > _MAX_USER_SKILL_BYTES:
                continue
            actual = hashlib.sha256(source).hexdigest()
            if not hmac.compare_digest(actual, expected):
                continue
            # Execute the exact bytes that were hashed, avoiding a second read.
            _try_import(
                skill_path,
                source=source,
                digest=actual,
                origin="user_approved",
            )

    return _loaded


def _try_import(
    path: Path,
    *,
    source: bytes | None = None,
    digest: str = "",
    origin: str = "unknown",
) -> None:
    module_name = f"clicky_skill_{path.stem}_{digest[:12] or 'bundled'}"
    try:
        if source is None:
            source = path.read_bytes()
        spec = importlib.util.spec_from_file_location(module_name, str(path))
        if not spec:
            return
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        code = compile(source, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
        skill = getattr(module, "SKILL", None)
        if not isinstance(skill, dict):
            sys.modules.pop(module_name, None)
            return
        if not all(key in skill for key in ("name", "trigger", "handler")):
            sys.modules.pop(module_name, None)
            return
        if not isinstance(skill["name"], str) or not isinstance(skill["trigger"], str):
            sys.modules.pop(module_name, None)
            return
        if not callable(skill["handler"]):
            sys.modules.pop(module_name, None)
            return
        skill.setdefault("description", "")
        skill["_compiled"] = re.compile(skill["trigger"], re.IGNORECASE)
        # Registry/UI metadata never claims that hash approval makes Python
        # safe.  The handler remains arbitrary code with the user's authority.
        skill["_developer_skill"] = True
        skill["_developer_source_filename"] = path.name
        skill["_developer_source_digest"] = digest
        skill["_developer_origin"] = origin
        _loaded.append(skill)
    except Exception as exc:
        sys.modules.pop(module_name, None)
        print(f"[skills] failed to load {path.name}: {exc}")


def match(transcript: str) -> Optional[dict]:
    """Return the first skill whose trigger matches the user's utterance."""
    for skill in _loaded:
        if skill["_compiled"].search(transcript):
            return skill
    return None


def list_skills() -> list[dict]:
    return list(_loaded)
