"""Public filesystem ownership and native-call contracts using inert doubles."""

import ast
import ctypes
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

from security import filesystem as boundary


class FakePath:
    def __init__(self, name, mode=stat.S_IFREG, *, link=False, attributes=0, error=None):
        self.name = name
        self.info = types.SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
        self.link = link
        self.error = error
        self.chmod = mock.Mock()

    def __str__(self):
        return self.name

    def lstat(self):
        if self.error:
            raise self.error
        return self.info

    def is_symlink(self):
        return self.link


class FilesystemBoundaryTests(unittest.TestCase):
    def test_metadata_and_path_predicates_keep_missing_and_error_behavior(self):
        for attributes, expected in ((0, False), (0x400, True), (0x800, False), (0xC00, True)):
            with self.subTest(attributes=attributes):
                path = FakePath("item", attributes=attributes)
                self.assertEqual(boundary.metadata_is_reparse(path.info), expected)
                self.assertEqual(boundary.is_link_or_reparse(path), expected)
        self.assertFalse(boundary.metadata_is_reparse(types.SimpleNamespace()))
        self.assertTrue(boundary.is_link_or_reparse(FakePath("link", link=True)))
        self.assertFalse(boundary.is_link_or_reparse(FakePath("missing", error=FileNotFoundError())))
        self.assertFalse(boundary.is_link_or_reparse(FakePath("denied", error=PermissionError())))

    def removal(self, root, paths, children, *, exists=True, failure=None):
        events = []

        def operation(name, path):
            events.append((name, str(path)))
            if failure is not None and failure[:2] == (name, str(path)):
                raise failure[2]

        def scan(path):
            operation("scandir", path)
            return [types.SimpleNamespace(path=child) for child in children.get(str(path), ())]

        fake_os = types.SimpleNamespace(
            path=types.SimpleNamespace(lexists=lambda path: exists),
            rmdir=lambda path: operation("rmdir", path),
            unlink=lambda path: operation("unlink", path),
            scandir=scan,
        )
        with mock.patch.object(boundary, "os", fake_os), mock.patch.object(boundary, "Path", side_effect=paths.__getitem__):
            boundary.remove_tree_without_following_links(root)
        return events

    def test_missing_path_never_inspects_or_removes(self):
        root = FakePath("missing", error=AssertionError("must not inspect"))
        self.assertEqual(self.removal(root, {}, {}, exists=False), [])

    def test_links_and_reparse_points_are_removed_as_leaves(self):
        for root, expected in (
            (FakePath("broken-file-link", link=True), "unlink"),
            (FakePath("directory-link", stat.S_IFDIR, link=True), "rmdir"),
            (FakePath("junction", stat.S_IFDIR, attributes=0x400), "rmdir"),
            (FakePath("reparse-file", attributes=0x400), "unlink"),
            (FakePath("plain-file"), "unlink"),
        ):
            with self.subTest(path=root.name):
                self.assertEqual(self.removal(root, {}, {}), [(expected, root.name)])

    def test_directory_children_are_removed_before_their_parents(self):
        paths = {"root": FakePath("root", stat.S_IFDIR),
                 "nested": FakePath("nested", stat.S_IFDIR), "leaf": FakePath("leaf")}
        self.assertEqual(self.removal(paths["root"], paths, {"root": ["nested"], "nested": ["leaf"]}),
                         [("scandir", "root"), ("scandir", "nested"), ("unlink", "leaf"),
                          ("rmdir", "nested"), ("rmdir", "root")])

    def test_cleanup_errors_propagate_without_wrapping_or_suppression(self):
        error = OSError("original filesystem failure")
        with self.assertRaises(OSError) as caught:
            self.removal(FakePath("root", error=error), {}, {})
        self.assertIs(caught.exception, error)
        for operation, target in (("scandir", "root"), ("unlink", "leaf"), ("rmdir", "root")):
            with self.subTest(operation=operation):
                paths = {"root": FakePath("root", stat.S_IFDIR), "leaf": FakePath("leaf")}
                with self.assertRaises(OSError) as caught:
                    self.removal(paths["root"], paths, {"root": ["leaf"]}, failure=(operation, target, error))
                self.assertIs(caught.exception, error)

    def test_non_windows_protection_retains_private_mode(self):
        path = FakePath("directory")
        with mock.patch.object(boundary, "os", types.SimpleNamespace(name="posix")):
            boundary.protect_directory(path)
        path.chmod.assert_called_once_with(0o700)

    def test_windows_acl_and_descriptor_cleanup_order(self):
        for convert_ok, set_ok in ((True, True), (False, True), (True, False)):
            with self.subTest(convert=convert_ok, set=set_ok):
                events = []
                error = OSError("synthetic native failure")
                convert = mock.Mock(side_effect=lambda *args: events.append(("convert", args)) or convert_ok)
                set_security = mock.Mock(side_effect=lambda *args: events.append(("set", args)) or set_ok)
                free = mock.Mock(side_effect=lambda *args: events.append(("free", args)))
                dll = types.SimpleNamespace(
                    advapi32=types.SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=convert,
                                                  SetFileSecurityW=set_security),
                    kernel32=types.SimpleNamespace(LocalFree=free),
                )
                with mock.patch.object(boundary, "os", types.SimpleNamespace(name="nt")), \
                     mock.patch.object(ctypes, "windll", dll, create=True), \
                     mock.patch.object(ctypes, "WinError", return_value=error, create=True):
                    if convert_ok and set_ok:
                        boundary.protect_directory(FakePath("directory"))
                    else:
                        with self.assertRaises(OSError) as caught:
                            boundary.protect_directory(FakePath("directory"))
                        self.assertIs(caught.exception, error)
                self.assertEqual([event[0] for event in events], ["convert", "set", "free"] if convert_ok else ["convert"])
                self.assertEqual(convert.call_args.args[:2], ("D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)", 1))
                self.assertEqual(len(convert.argtypes), 4)
                self.assertIs(convert.restype, ctypes.wintypes.BOOL)
                if convert_ok:
                    self.assertEqual(set_security.call_args.args[:2], ("directory", 0x00000004 | 0x80000000))
                    self.assertIs(set_security.call_args.args[2], free.call_args.args[0])
                    self.assertEqual(len(set_security.argtypes), 3)
                    self.assertIs(set_security.restype, ctypes.wintypes.BOOL)

    def test_public_helpers_have_one_owner_and_callers_use_its_interface(self):
        root = Path(__file__).resolve().parents[1]
        names = {"metadata_is_reparse", "is_link_or_reparse", "protect_directory", "remove_tree_without_following_links"}
        for filename in ("tasks/coordinator.py", "tasks/artifacts.py", "workspace_coding/adoption.py"):
            tree = ast.parse((root / filename).read_text(encoding="utf-8"))
            imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                        and node.module == "security.filesystem" for alias in node.names}
            self.assertTrue(names - {"metadata_is_reparse"} <= imported)
            self.assertFalse({node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)} & names)
            self.assertFalse({alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                              and node.module == "tasks.coordinator" for alias in node.names} & {"_" + name for name in names})
        tree = ast.parse((root / "security/filesystem.py").read_text(encoding="utf-8"))
        imports = {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        imports.update(alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertTrue(imports <= {"os", "stat", "pathlib", "ctypes"})
        self.assertEqual({node.name for node in tree.body if isinstance(node, ast.FunctionDef)}, names)
