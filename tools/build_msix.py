"""Create and validate an unsigned Store-submission MSIX from one frozen onedir.

This tool never signs, installs, submits, uploads, or rebuilds the application.
It requires an exact reviewed MakeAppx.exe hash and preserves the complete
staging directory used to produce the package.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from PIL import Image

from assets.make_icon import make_frame


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "packaging" / "AppxManifest.xml.in"
STORE_MARKER_TEMPLATE = (
    ROOT / "packaging" / "UNSIGNED-STORE-SUBMISSION-INPUT.txt"
)
VALIDATION_IDENTITY = "th3nolo.Clicky.Validation"
VALIDATION_PUBLISHER = "CN=Clicky Local Validation"
VALIDATION_PUBLISHER_DISPLAY = "Manuel Parra"
MAX_FILES = 100_000
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
_IDENTITY_NAME = re.compile(r"^[A-Za-z0-9.-]{3,50}$")
_VERSION = re.compile(
    r"^(0|[1-9][0-9]{0,4})\."
    r"(0|[1-9][0-9]{0,4})\."
    r"(0|[1-9][0-9]{0,4})\."
    r"(0|[1-9][0-9]{0,4})$"
)
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_ASSET_SIZES = {
    "StoreLogo.png": (50, 50),
    "Square44x44Logo.png": (44, 44),
    "Square71x71Logo.png": (71, 71),
    "Square150x150Logo.png": (150, 150),
    "Wide310x150Logo.png": (310, 150),
    "Square310x310Logo.png": (310, 310),
}


class MsixPackagingError(RuntimeError):
    """The candidate could not be packaged without weakening a gate."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def _validate_output_boundaries(
    *,
    distribution: Path,
    staging: Path,
    output: Path,
    report: Path,
) -> None:
    writable = (staging, output, report)
    if any(
        _is_within(path, distribution) or _is_within(distribution, path)
        for path in writable
    ):
        raise MsixPackagingError(
            "distribution and packaging outputs must not contain one another"
        )
    if output == report:
        raise MsixPackagingError("MSIX output and report paths must differ")
    if _is_within(output, staging) or _is_within(report, staging):
        raise MsixPackagingError(
            "MSIX output and report must remain outside preserved staging"
        )


def _require_regular_file(path: Path) -> os.stat_result:
    details = path.lstat()
    attributes = getattr(details, "st_file_attributes", 0)
    if path.is_symlink() or attributes & 0x400:
        raise MsixPackagingError(f"reparse points are not allowed: {path}")
    if not stat.S_ISREG(details.st_mode):
        raise MsixPackagingError(f"non-regular package input: {path}")
    if details.st_nlink != 1:
        raise MsixPackagingError(f"hard-linked package input: {path}")
    if os.name == "nt":
        from tools.windows_runtime_validation import _alternate_stream_names

        unexpected = [
            name
            for name in _alternate_stream_names(path)
            if name.casefold() != "::$data"
        ]
        if unexpected:
            raise MsixPackagingError(
                f"alternate data stream in package input: {path}"
            )
    return details


def validated_files(directory: Path) -> tuple[Path, ...]:
    if not directory.is_dir() or directory.is_symlink():
        raise MsixPackagingError(f"package input is not a real directory: {directory}")
    files = []
    total_bytes = 0
    for current_name, directories, names in os.walk(
        directory,
        topdown=True,
        followlinks=False,
    ):
        current = Path(current_name)
        current_details = current.lstat()
        if current.is_symlink() or getattr(
            current_details, "st_file_attributes", 0
        ) & 0x400:
            raise MsixPackagingError(f"reparse directory is not allowed: {current}")
        directories.sort()
        names.sort()
        for name in directories:
            child = current / name
            if child.is_symlink() or getattr(
                child.lstat(), "st_file_attributes", 0
            ) & 0x400:
                raise MsixPackagingError(
                    f"reparse directory is not allowed: {child}"
                )
        for name in names:
            path = current / name
            details = _require_regular_file(path)
            total_bytes += details.st_size
            files.append(path)
            if len(files) > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                raise MsixPackagingError(
                    "package input exceeds the reviewed file or byte bound"
                )
    return tuple(
        sorted(files, key=lambda path: path.relative_to(directory).as_posix())
    )


def tree_identity(directory: Path) -> dict[str, int | str]:
    files = validated_files(directory)
    digest = hashlib.sha256()
    digest.update(b"clicky-msix-input-v1\0")
    total_bytes = 0
    for path in files:
        details = _require_regular_file(path)
        relative = path.relative_to(directory).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(details.st_size.to_bytes(8, "big"))
        total_bytes += details.st_size
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return {
        "scheme": "clicky-msix-input-v1",
        "tree_sha256": digest.hexdigest(),
        "file_count": len(files),
        "total_bytes": total_bytes,
    }


def validate_identity(
    identity_name: str,
    publisher: str,
    publisher_display_name: str,
    version: str,
) -> None:
    if not _IDENTITY_NAME.fullmatch(identity_name):
        raise MsixPackagingError("invalid Partner Center package identity name")
    if (
        not _VERSION.fullmatch(version)
        or any(int(part) > 65535 for part in version.split("."))
    ):
        raise MsixPackagingError("MSIX version must be four bounded integers")
    if (
        not publisher.startswith("CN=")
        or not 1 <= len(publisher) <= 8192
        or any(value in publisher for value in ("\r", "\n", "{{", "}}"))
    ):
        raise MsixPackagingError("invalid Partner Center publisher DN")
    if (
        not publisher_display_name.strip()
        or len(publisher_display_name) > 256
        or any(value in publisher_display_name for value in ("\r", "\n", "{{", "}}"))
    ):
        raise MsixPackagingError("invalid Partner Center publisher display name")


def resolve_identity(
    *,
    validation_only: bool,
    partner_center_confirmed: bool,
    identity_name: str | None,
    publisher: str | None,
    publisher_display_name: str | None,
) -> tuple[str, str, str]:
    if validation_only:
        if any(
            (
                identity_name,
                publisher,
                publisher_display_name,
                partner_center_confirmed,
            )
        ):
            raise MsixPackagingError(
                "validation-only mode uses fixed non-Store identity values"
            )
        return (
            VALIDATION_IDENTITY,
            VALIDATION_PUBLISHER,
            VALIDATION_PUBLISHER_DISPLAY,
        )
    if (
        not partner_center_confirmed
        or not identity_name
        or not publisher
        or not publisher_display_name
    ):
        raise MsixPackagingError(
            "copy all three Product identity values from Partner Center "
            "and pass --partner-center-confirmed"
        )
    return identity_name, publisher, publisher_display_name


def render_manifest(
    *,
    identity_name: str,
    publisher: str,
    publisher_display_name: str,
    version: str,
) -> bytes:
    validate_identity(
        identity_name,
        publisher,
        publisher_display_name,
        version,
    )
    text = TEMPLATE.read_text(encoding="utf-8")
    replacements = {
        "{{IDENTITY_NAME}}": identity_name,
        "{{PUBLISHER}}": publisher,
        "{{PUBLISHER_DISPLAY_NAME}}": publisher_display_name,
        "{{VERSION}}": version,
    }
    for token, value in replacements.items():
        text = text.replace(token, html.escape(value, quote=True))
    if "{{" in text or "}}" in text:
        raise MsixPackagingError("unresolved MSIX manifest placeholder")
    encoded = text.encode("utf-8")
    ElementTree.fromstring(encoded)
    return encoded


def _write_assets(directory: Path) -> None:
    directory.mkdir()
    for name, (width, height) in _ASSET_SIZES.items():
        side = min(width, height)
        icon = make_frame(side)
        canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        canvas.alpha_composite(
            icon,
            ((width - side) // 2, (height - side) // 2),
        )
        canvas.save(directory / name, format="PNG", compress_level=9)


def _copy_distribution(source: Path, target: Path) -> dict[str, int | str]:
    source_identity = tree_identity(source)
    target.mkdir()
    for source_file in validated_files(source):
        relative = source_file.relative_to(source)
        target_file = target / relative
        target_file.parent.mkdir(parents=True, exist_ok=True)
        with source_file.open("rb") as input_handle, target_file.open("xb") as output:
            shutil.copyfileobj(input_handle, output, length=1024 * 1024)
    copied_identity = tree_identity(target)
    if copied_identity != source_identity:
        raise MsixPackagingError("staged Clicky directory differs from onedir input")
    return source_identity


def prepare_staging(
    *,
    distribution: Path,
    staging: Path,
    identity_name: str,
    publisher: str,
    publisher_display_name: str,
    version: str,
    source_commit: str,
    validation_only: bool,
    makeappx_sha256: str,
) -> dict[str, object]:
    if staging.exists() or not staging.parent.is_dir():
        raise MsixPackagingError("MSIX staging path must be new with an existing parent")
    if not _COMMIT.fullmatch(source_commit):
        raise MsixPackagingError("source commit must be a lowercase 40-hex Git ID")
    commit_file = distribution / "SOURCE-COMMIT.txt"
    if (
        not commit_file.is_file()
        or commit_file.read_text(encoding="ascii").strip() != source_commit
    ):
        raise MsixPackagingError("onedir source commit does not match the request")
    local_marker = distribution / "UNSIGNED-LOCAL-TEST-ONLY.txt"
    store_marker = distribution / "UNSIGNED-STORE-SUBMISSION-INPUT.txt"
    if validation_only:
        if not local_marker.is_file() and not store_marker.is_file():
            raise MsixPackagingError("unsigned input marker is missing")
    elif not store_marker.is_file() or local_marker.exists():
        raise MsixPackagingError(
            "Store packaging requires the dedicated unsigned Store input"
        )
    elif store_marker.read_bytes() != STORE_MARKER_TEMPLATE.read_bytes():
        raise MsixPackagingError("Store input marker differs from the reviewed text")

    staging.mkdir()
    input_identity = _copy_distribution(distribution, staging / "Clicky")
    _write_assets(staging / "Assets")
    manifest = render_manifest(
        identity_name=identity_name,
        publisher=publisher,
        publisher_display_name=publisher_display_name,
        version=version,
    )
    (staging / "AppxManifest.xml").write_bytes(manifest)
    if validation_only:
        (staging / "UNSIGNED-VALIDATION-ONLY.txt").write_text(
            "UNSIGNED VALIDATION PACKAGE. DO NOT SUBMIT OR DISTRIBUTE.\n",
            encoding="utf-8",
            newline="\n",
        )
    metadata = {
        "brand": "th3nolo",
        "legal_publisher": "Manuel Parra",
        "source_commit": source_commit,
        "package_identity_name": identity_name,
        "publisher": publisher,
        "publisher_display_name": publisher_display_name,
        "version": version,
        "validation_only": validation_only,
        "makeappx_sha256": makeappx_sha256,
        "application_input": input_identity,
        "clicky_exe_sha256": sha256_file(distribution / "Clicky.exe"),
    }
    (staging / "MSIX-INPUT-IDENTITY.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return metadata


def _run_makeappx(
    makeappx: Path,
    expected_sha256: str,
    arguments: list[str],
) -> None:
    if sha256_file(makeappx) != expected_sha256:
        raise MsixPackagingError("MakeAppx.exe changed before execution")
    result = subprocess.run(
        [str(makeappx), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode:
        output = (result.stdout + "\n" + result.stderr).strip()
        raise MsixPackagingError(
            f"MakeAppx failed with exit {result.returncode}: {output[-4000:]}"
        )
    if sha256_file(makeappx) != expected_sha256:
        raise MsixPackagingError("MakeAppx.exe changed during execution")


def validate_package(
    *,
    makeappx: Path,
    package: Path,
    staging: Path,
    expected_manifest: bytes,
    makeappx_sha256: str,
) -> dict[str, object]:
    if not package.is_file():
        raise MsixPackagingError("MakeAppx produced no package")
    with zipfile.ZipFile(package) as archive:
        names = set(archive.namelist())
        if "AppxSignature.p7x" in names:
            raise MsixPackagingError("unsigned Store input unexpectedly has a signature")
        if archive.read("AppxManifest.xml") != expected_manifest:
            raise MsixPackagingError("packaged manifest differs from staging")
    with tempfile.TemporaryDirectory(prefix="clicky-msix-unpack-") as temporary:
        unpacked = Path(temporary)
        _run_makeappx(
            makeappx,
            makeappx_sha256,
            ["unpack", "/v", "/p", str(package), "/d", str(unpacked)],
        )
        if (unpacked / "AppxManifest.xml").read_bytes() != expected_manifest:
            raise MsixPackagingError("unpacked manifest differs from staging")
        if tree_identity(unpacked / "Clicky") != tree_identity(staging / "Clicky"):
            raise MsixPackagingError("packaged Clicky tree differs from staging")
        for name, expected_size in _ASSET_SIZES.items():
            with Image.open(unpacked / "Assets" / name) as image:
                if image.size != expected_size or image.format != "PNG":
                    raise MsixPackagingError(f"invalid packaged asset: {name}")
    return {
        "msix_sha256": sha256_file(package),
        "msix_bytes": package.stat().st_size,
        "staging_identity": tree_identity(staging),
        "signed": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--distribution", type=Path, required=True)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--version", default="1.2.0.0")
    parser.add_argument("--makeappx", type=Path, required=True)
    parser.add_argument("--makeappx-sha256", required=True)
    parser.add_argument("--validation-only", action="store_true")
    parser.add_argument("--identity-name")
    parser.add_argument("--publisher")
    parser.add_argument("--publisher-display-name")
    parser.add_argument("--partner-center-confirmed", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.name != "nt":
        raise MsixPackagingError("MSIX packaging requires Windows")
    makeappx = args.makeappx.resolve()
    distribution = args.distribution.resolve()
    staging = args.staging.resolve()
    output = args.output.resolve()
    report_path = args.report.resolve()
    if not makeappx.is_file() or not _SHA256.fullmatch(
        args.makeappx_sha256
    ):
        raise MsixPackagingError("reviewed MakeAppx path and SHA-256 are required")
    actual_makeappx = sha256_file(makeappx)
    if actual_makeappx.casefold() != args.makeappx_sha256.casefold():
        raise MsixPackagingError("MakeAppx.exe does not match the reviewed SHA-256")
    if output.exists() or report_path.exists():
        raise MsixPackagingError("MSIX output and report paths must be new")
    if not output.parent.is_dir() or not report_path.parent.is_dir():
        raise MsixPackagingError("MSIX output and report parents must exist")
    if output.suffix.casefold() != ".msix":
        raise MsixPackagingError("MSIX output must use the .msix extension")
    _validate_output_boundaries(
        distribution=distribution,
        staging=staging,
        output=output,
        report=report_path,
    )
    identity_name, publisher, publisher_display_name = resolve_identity(
        validation_only=args.validation_only,
        partner_center_confirmed=args.partner_center_confirmed,
        identity_name=args.identity_name,
        publisher=args.publisher,
        publisher_display_name=args.publisher_display_name,
    )

    metadata = prepare_staging(
        distribution=distribution,
        staging=staging,
        identity_name=identity_name,
        publisher=publisher,
        publisher_display_name=publisher_display_name,
        version=args.version,
        source_commit=args.source_commit,
        validation_only=args.validation_only,
        makeappx_sha256=actual_makeappx,
    )
    manifest = (staging / "AppxManifest.xml").read_bytes()
    _run_makeappx(
        makeappx,
        actual_makeappx,
        [
            "pack",
            "/v",
            "/h",
            "SHA256",
            "/d",
            str(staging),
            "/p",
            str(output),
        ],
    )
    package = validate_package(
        makeappx=makeappx,
        package=output,
        staging=staging,
        expected_manifest=manifest,
        makeappx_sha256=actual_makeappx,
    )
    report = {
        **metadata,
        **package,
        "store_submission_complete": False,
        "store_certification_complete": False,
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
