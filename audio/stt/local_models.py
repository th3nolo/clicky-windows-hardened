"""Resolve and verify speech models without network acquisition."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from pathlib import Path
from typing import Iterable, Optional


class LocalModelUnavailable(RuntimeError):
    """Raised when a required, verified local model cannot be used."""


_SAFE_MODEL_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_FASTER_REQUIRED_FILES = ("config.json", "model.bin", "tokenizer.json")
_FASTER_DIGEST_DOMAIN = b"clicky-faster-whisper-directory-v1\0"
_MAX_FASTER_MODEL_FILES = 4096


def validate_sha256(value: str, variable_name: str) -> str:
    """Return a normalized caller-supplied digest or fail closed."""
    digest = (value or "").strip()
    if not digest:
        raise LocalModelUnavailable(
            f"{variable_name} is required. Set it to the verified 64-character "
            "SHA-256 digest before loading this model."
        )
    if not _SHA256.fullmatch(digest):
        raise LocalModelUnavailable(
            f"{variable_name} must contain exactly 64 hexadecimal characters."
        )
    return digest.lower()


def file_sha256(path: Path) -> str:
    """Hash one local file without loading it all into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as model_file:
        for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_file_sha256(path: Path, expected: str, variable_name: str) -> None:
    """Require a strict configured SHA-256 using constant-time comparison."""
    normalized = validate_sha256(expected, variable_name)
    try:
        actual = file_sha256(path)
    except OSError as exc:
        raise LocalModelUnavailable(f"Could not hash local model file {path}: {exc}") from exc
    if not hmac.compare_digest(actual, normalized):
        raise LocalModelUnavailable(
            f"SHA-256 mismatch for {path}. Refusing to load it because it does "
            f"not match {variable_name}."
        )


def _expanded_path(value: str) -> Path:
    return Path(os.path.expandvars(value)).expanduser()


def _looks_like_path(value: str) -> bool:
    return (
        value.startswith((".", "~"))
        or "/" in value
        or "\\" in value
        or (len(value) > 1 and value[1] == ":")
    )


def _nonempty_file(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _valid_faster_directory(path: Path) -> bool:
    return path.is_dir() and all(
        _nonempty_file(path / filename) for filename in _FASTER_REQUIRED_FILES
    )


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def faster_whisper_directory_sha256(path: Path) -> str:
    """Hash every regular file in a faster-whisper directory deterministically."""
    try:
        if _is_link_or_junction(path):
            raise LocalModelUnavailable(
                "Faster-whisper model directories cannot be links or "
                f"junctions: {path}"
            )
        resolved = path.resolve(strict=True)
        files: list[Path] = []
        pending_directories = [resolved]
        while pending_directories:
            directory = pending_directories.pop()
            for candidate in directory.iterdir():
                if _is_link_or_junction(candidate):
                    raise LocalModelUnavailable(
                        "Faster-whisper model entries cannot be links or "
                        f"junctions: {candidate}"
                    )
                if candidate.is_dir():
                    pending_directories.append(candidate)
                elif candidate.is_file():
                    files.append(candidate)
                    if len(files) > _MAX_FASTER_MODEL_FILES:
                        raise LocalModelUnavailable(
                            "Faster-whisper model directory exceeds the "
                            f"{_MAX_FASTER_MODEL_FILES}-file safety limit: {resolved}"
                        )
                else:
                    raise LocalModelUnavailable(
                        f"Faster-whisper model entry is not regular: {candidate}"
                    )
        files.sort(key=lambda candidate: candidate.relative_to(resolved).as_posix())
    except LocalModelUnavailable:
        raise
    except OSError as exc:
        raise LocalModelUnavailable(
            f"Could not enumerate faster-whisper model directory {path}: {exc}"
        ) from exc

    missing = [
        filename
        for filename in _FASTER_REQUIRED_FILES
        if not _nonempty_file(resolved / filename)
    ]
    if missing:
        raise LocalModelUnavailable(
            "Incomplete faster-whisper model directory; missing non-empty files: "
            + ", ".join(missing)
        )
    if not files or len(files) > _MAX_FASTER_MODEL_FILES:
        raise LocalModelUnavailable(
            f"Faster-whisper model directory must contain between 1 and "
            f"{_MAX_FASTER_MODEL_FILES} regular files: {resolved}"
        )

    digest = hashlib.sha256()
    digest.update(_FASTER_DIGEST_DOMAIN)
    for candidate in files:
        try:
            if candidate.is_symlink():
                raise LocalModelUnavailable(
                    f"Faster-whisper model files cannot be symlinks: {candidate}"
                )
            candidate.resolve(strict=True).relative_to(resolved)
            relative = candidate.relative_to(resolved).as_posix().encode("utf-8")
            before = candidate.stat()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(before.st_size.to_bytes(8, "big"))
            with candidate.open("rb") as model_file:
                for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
                    digest.update(chunk)
            after = candidate.stat()
        except LocalModelUnavailable:
            raise
        except (OSError, ValueError) as exc:
            raise LocalModelUnavailable(
                f"Could not hash faster-whisper model file {candidate}: {exc}"
            ) from exc
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise LocalModelUnavailable(
                f"Faster-whisper model file changed while it was hashed: {candidate}"
            )
    return digest.hexdigest()


def _verified_faster_directory(
    path: Path, expected_sha256: str, variable_name: str
) -> Path:
    if _is_link_or_junction(path):
        raise LocalModelUnavailable(
            f"Faster-whisper model root cannot be a link or junction: {path}"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LocalModelUnavailable(
            f"Could not resolve faster-whisper model directory {path}: {exc}"
        ) from exc
    normalized = validate_sha256(expected_sha256, variable_name)
    actual = faster_whisper_directory_sha256(path)
    if not hmac.compare_digest(actual, normalized):
        raise LocalModelUnavailable(
            f"SHA-256 mismatch for faster-whisper directory {resolved}. Refusing "
            f"to load it because its complete contents do not match {variable_name}."
        )
    return resolved


def _default_huggingface_cache_roots() -> list[Path]:
    roots: list[Path] = []
    if value := os.getenv("HF_HUB_CACHE", "").strip():
        roots.append(_expanded_path(value))
    if value := os.getenv("HF_HOME", "").strip():
        roots.append(_expanded_path(value) / "hub")
    if value := os.getenv("XDG_CACHE_HOME", "").strip():
        roots.append(_expanded_path(value) / "huggingface" / "hub")
    if value := os.getenv("LOCALAPPDATA", "").strip():
        roots.append(_expanded_path(value) / "huggingface" / "hub")
    roots.append(Path.home() / ".cache" / "huggingface" / "hub")
    return roots


def resolve_faster_whisper_model(
    model_spec: str,
    expected_sha256: str,
    *,
    digest_variable: str = "WHISPER_MODEL_SHA256",
    cache_roots: Optional[Iterable[Path]] = None,
) -> Path:
    """Resolve a local model and verify every file with one directory digest."""
    validate_sha256(expected_sha256, digest_variable)
    spec = (model_spec or "").strip()
    if not spec:
        raise LocalModelUnavailable(
            "No faster-whisper model is configured. Select a verified local "
            "model directory first."
        )

    explicit = _expanded_path(spec)
    if _valid_faster_directory(explicit):
        return _verified_faster_directory(
            explicit, expected_sha256, digest_variable
        )
    if _looks_like_path(spec):
        raise LocalModelUnavailable(
            f"The configured faster-whisper model directory is missing or "
            f"incomplete: {explicit}. Required files: "
            + ", ".join(_FASTER_REQUIRED_FILES)
        )
    if not _SAFE_MODEL_NAME.fullmatch(spec):
        raise LocalModelUnavailable(
            "The faster-whisper model must be a safe alias or explicit local path."
        )

    roots = list(cache_roots) if cache_roots is not None else _default_huggingface_cache_roots()
    repo_name = f"models--Systran--faster-whisper-{spec}"
    candidates: list[Path] = []
    for root in roots:
        root = Path(root)
        if _valid_faster_directory(root):
            candidates.append(root)
            continue
        repo = root / repo_name
        ref = repo / "refs" / "main"
        if ref.is_file():
            try:
                revision = ref.read_text(encoding="utf-8").strip()
            except OSError:
                revision = ""
            if revision and _SAFE_MODEL_NAME.fullmatch(revision):
                referenced = repo / "snapshots" / revision
                if _valid_faster_directory(referenced):
                    return _verified_faster_directory(
                        referenced, expected_sha256, digest_variable
                    )
        snapshots = repo / "snapshots"
        if snapshots.is_dir():
            candidates.extend(
                item for item in snapshots.iterdir() if _valid_faster_directory(item)
            )

    unique_by_resolved: dict[Path, Path] = {}
    for candidate in candidates:
        if _is_link_or_junction(candidate):
            raise LocalModelUnavailable(
                f"Faster-whisper model root cannot be a link or junction: {candidate}"
            )
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except OSError as exc:
            raise LocalModelUnavailable(
                f"Could not resolve faster-whisper candidate {candidate}: {exc}"
            ) from exc
        unique_by_resolved.setdefault(resolved_candidate, candidate)
    unique = sorted(unique_by_resolved.values(), key=str)
    if len(unique) == 1:
        return _verified_faster_directory(
            unique[0], expected_sha256, digest_variable
        )
    if len(unique) > 1:
        raise LocalModelUnavailable(
            f"Multiple cached snapshots exist for {spec!r}. Select the exact "
            "verified snapshot directory."
        )
    raise LocalModelUnavailable(
        f"No complete local faster-whisper model was found for {spec!r}. "
        "Clicky will not download it. Provision the model separately."
    )


def _default_whisper_cpp_cache_dirs() -> list[Path]:
    directories: list[Path] = []
    if value := os.getenv("WHISPERCPP_MODEL_DIR", "").strip():
        directories.append(_expanded_path(value))
    if value := os.getenv("XDG_CACHE_HOME", "").strip():
        directories.extend(
            (_expanded_path(value) / "whisper.cpp", _expanded_path(value) / "pywhispercpp")
        )
    if value := os.getenv("LOCALAPPDATA", "").strip():
        directories.extend(
            (_expanded_path(value) / "whisper.cpp", _expanded_path(value) / "pywhispercpp" / "models")
        )
    directories.extend(
        (Path.home() / ".cache" / "whisper.cpp", Path.home() / ".cache" / "pywhispercpp")
    )
    return directories


def _verified_whisper_cpp_file(path: Path, expected_sha256: str) -> Path:
    resolved = path.resolve()
    require_file_sha256(
        resolved, expected_sha256, "WHISPERCPP_MODEL_SHA256"
    )
    return resolved


def resolve_whisper_cpp_model(
    model_spec: str,
    expected_sha256: str,
    *,
    cache_dirs: Optional[Iterable[Path]] = None,
) -> Path:
    """Resolve one local GGML/GGUF file and verify its immutable identity."""
    validate_sha256(expected_sha256, "WHISPERCPP_MODEL_SHA256")
    spec = (model_spec or "").strip()
    if not spec:
        raise LocalModelUnavailable(
            "No whisper.cpp model is configured. Select a verified local "
            "GGML/GGUF model file first."
        )

    explicit = _expanded_path(spec)
    if _nonempty_file(explicit):
        return _verified_whisper_cpp_file(explicit, expected_sha256)
    if _looks_like_path(spec):
        raise LocalModelUnavailable(
            f"The configured whisper.cpp model file does not exist or is empty: {explicit}"
        )
    if not _SAFE_MODEL_NAME.fullmatch(spec):
        raise LocalModelUnavailable(
            "The whisper.cpp model must be a safe alias or explicit local path."
        )

    filenames = (f"ggml-{spec}.bin", f"{spec}.bin", f"ggml-{spec}.gguf", f"{spec}.gguf")
    directories = list(cache_dirs) if cache_dirs is not None else _default_whisper_cpp_cache_dirs()
    matches = sorted(
        {
            candidate.resolve()
            for directory in directories
            for filename in filenames
            if _nonempty_file(candidate := Path(directory) / filename)
        },
        key=str,
    )
    if len(matches) == 1:
        return _verified_whisper_cpp_file(matches[0], expected_sha256)
    if len(matches) > 1:
        raise LocalModelUnavailable(
            f"Multiple cached whisper.cpp models match {spec!r}. Select the "
            "exact verified model file."
        )
    raise LocalModelUnavailable(
        f"No local whisper.cpp model was found for {spec!r}. Clicky will not "
        "download it. Provision a verified GGML/GGUF model separately."
    )


def _main(argv: Optional[list[str]] = None) -> int:
    """Print the reviewed digest used for a faster-whisper directory."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Compute Clicky's complete faster-whisper directory digest."
    )
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        print(faster_whisper_directory_sha256(args.directory))
    except LocalModelUnavailable as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
