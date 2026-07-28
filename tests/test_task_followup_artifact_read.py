"""Exact adopted-artifact byte reads for selected follow-up sources."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from tasks.artifacts import (
    ArtifactAdoptionError,
    _artifact_filename,
    _run_directory_name,
    read_adopted_artifact,
)
from tasks.models import Artifact


CONTENT = b"verified UTF-8 source\n"


def artifact() -> Artifact:
    return Artifact(
        artifact_id="selected-source",
        run_id="parent-run",
        source_call_id="source-call",
        name="selected.txt",
        media_type="text/plain",
        byte_count=len(CONTENT),
        sha256=hashlib.sha256(CONTENT).hexdigest(),
        verification_result_id="verification-result",
        verification_evidence_digest="e" * 64,
    )


def write_adopted(root: Path, item: Artifact) -> Path:
    directory = root / _run_directory_name(item.run_id)
    directory.mkdir(parents=True)
    path = directory / _artifact_filename(item.artifact_id)
    path.write_bytes(CONTENT)
    return path


class TaskFollowupArtifactReadTests(unittest.TestCase):
    def test_exact_regular_adopted_bytes_are_returned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "adopted"
            item = artifact()
            write_adopted(root, item)

            self.assertEqual(
                read_adopted_artifact(item, adoption_root=root),
                CONTENT,
            )

    def test_changed_and_unadopted_artifacts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "adopted"
            item = artifact()
            path = write_adopted(root, item)
            path.write_bytes(CONTENT + b"changed")
            with self.assertRaisesRegex(
                ArtifactAdoptionError,
                "integrity",
            ):
                read_adopted_artifact(item, adoption_root=root)

            unadopted = Artifact(
                artifact_id="pending-source",
                run_id="parent-run",
                source_call_id="source-call",
                name="pending.txt",
                media_type="text/plain",
                byte_count=len(CONTENT),
                sha256=hashlib.sha256(CONTENT).hexdigest(),
            )
            with self.assertRaisesRegex(
                ArtifactAdoptionError,
                "Only adopted",
            ):
                read_adopted_artifact(unadopted, adoption_root=root)

    def test_linked_artifact_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "adopted"
            item = artifact()
            path = write_adopted(root, item)
            target = path.with_name("target.artifact")
            target.write_bytes(CONTENT)
            path.unlink()
            try:
                path.symlink_to(target)
            except OSError:
                self.skipTest("symlinks are unavailable")
            with self.assertRaisesRegex(
                ArtifactAdoptionError,
                "identity",
            ):
                read_adopted_artifact(item, adoption_root=root)

    def test_hardlinked_artifact_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "adopted"
            item = artifact()
            path = write_adopted(root, item)
            target = path.with_name("target.artifact")
            path.replace(target)
            try:
                os.link(target, path)
            except OSError:
                self.skipTest("hard links are unavailable")
            with self.assertRaisesRegex(
                ArtifactAdoptionError,
                "integrity",
            ):
                read_adopted_artifact(item, adoption_root=root)


if __name__ == "__main__":
    unittest.main()
