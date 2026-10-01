"""Packaging safety checks; real ISA regression checks live in tests/ghidra/."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_extension", ROOT / "scripts/build_extension.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ExtensionInstallTests(unittest.TestCase):
    def test_refuses_unowned_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stage = base / "stage"
            stage.mkdir()
            target = base / "Ghidra/Extensions/jayMT_Analyzer"
            target.mkdir(parents=True)
            (target / "user-file").write_text("keep")
            with self.assertRaises(ValueError):
                builder.install_extension(stage, base)
            self.assertEqual((target / "user-file").read_text(), "keep")

    def test_upgrade_keeps_rollback_outside_discovered_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stage = base / "stage"
            stage.mkdir()
            (stage / "jaymt-build.json").write_text(json.dumps({"name": builder.NAME}))
            (stage / "payload").write_text("first")
            target = builder.install_extension(stage, base)
            (stage / "payload").write_text("second")
            builder.install_extension(stage, base)
            self.assertEqual((target / "payload").read_text(), "second")
            backups = list((base / ".jaymt-backups").iterdir())
            self.assertEqual(len(backups), 1)
            self.assertEqual((backups[0] / "payload").read_text(), "first")
            self.assertEqual(len(list((base / "Ghidra/Extensions").iterdir())), 1)

    def test_refuses_symlink_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            stage = base / "stage"
            stage.mkdir()
            extensions = base / "Ghidra/Extensions"
            extensions.mkdir(parents=True)
            (extensions / builder.NAME).symlink_to(stage, target_is_directory=True)
            with self.assertRaises(ValueError):
                builder.install_extension(stage, base)


if __name__ == "__main__":
    unittest.main()
