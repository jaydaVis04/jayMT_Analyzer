import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from jaymt import cli


class CliTests(unittest.TestCase):
    def test_launch_preserves_paths_and_full_analysis_and_worker_override(self):
        with tempfile.TemporaryDirectory(prefix="jay mt ") as temporary:
            root = Path(temporary)
            (root / "support").mkdir()
            (root / "support" / ("launch.bat" if cli.os.name == "nt" else "launch.sh")).touch()
            command = cli.headless_command(root, root / "my projects", "md1", root / "md1rom",
                                           root / "symbols with spaces.csv", root / "report.json",
                                           root, 24, "8G")
            self.assertIn("-Dcpu.core.override=24 -Djava.awt.headless=true", command)
            self.assertEqual(command[1:5], ["fg", "jdk", "jayMT_Analyzer", "8G"])
            self.assertEqual(command[command.index("-max-cpu") + 1], "24")
            self.assertIn(str(root / "symbols with spaces.csv"), command)
            self.assertIn("-noanalysis", command)
            self.assertEqual(command[command.index("-postScript") + 1], str(cli.ROOT / "ghidra_scripts/JayMTAnalyze.java"))
            self.assertNotIn("--no-bruteforce", command)
            self.assertFalse(any("ParallelGCThreads=" in part for part in command))

    def test_invalid_resource_flags_fail_early(self):
        for arguments in (("--threads", "0"), ("--threads", "-2"), ("--stack-threads", "0"), ("--heap", "0G"), ("--heap", "8G -Xbad")):
            with self.subTest(arguments=arguments), mock.patch("sys.stderr"), self.assertRaises(SystemExit):
                cli.parser().parse_args(["analyze", "input", *arguments])

    def test_stack_workers_cannot_exceed_global_worker_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "support").mkdir()
            (root / "support" / ("launch.bat" if cli.os.name == "nt" else "launch.sh")).touch()
            command = cli.headless_command(root, root, "md1", root / "md1rom", root / "symbols.csv",
                                           root / "report.json", root, 4, "4G", stack_threads=12)
            self.assertEqual(command[-1], "--stack-threads=4")

    def test_headless_zero_exit_without_report_is_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "ghidra"
            (runtime / "Ghidra").mkdir(parents=True)
            (runtime / "Ghidra/application.properties").write_text("application.version=11.4.2\n")
            (runtime / "support").mkdir()
            (runtime / "support" / ("launch.bat" if cli.os.name == "nt" else "launch.sh")).touch()
            prepared = root / "prepared"
            prepared.mkdir()
            (prepared / "md1rom").write_bytes(b"\0" * 64)
            (prepared / "md1_dbginfo.csv").write_text("name addr size mode type\n")
            args = cli.parser().parse_args(["analyze", str(prepared), "--ghidra", str(runtime)])
            with mock.patch.object(cli.subprocess, "run", return_value=mock.Mock(returncode=0)):
                with self.assertRaisesRegex(ValueError, "did not produce an analysis report"):
                    cli.run_analysis(args)

    def test_existing_project_is_never_reimported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Ghidra").mkdir()
            (root / "Ghidra/application.properties").write_text("application.version=11.4.2\n")
            (root / "support").mkdir()
            (root / "support" / ("launch.bat" if cli.os.name == "nt" else "launch.sh")).touch()
            (root / "projects").mkdir()
            (root / "projects/md1.gpr").write_text("keep")
            args = cli.parser().parse_args(["analyze", str(root), "--ghidra", str(root), "--workspace", str(root)])
            with mock.patch.object(cli.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "project already exists"):
                    cli.run_analysis(args)
                run.assert_not_called()
            self.assertEqual((root / "projects/md1.gpr").read_text(), "keep")

    def test_invalid_java_home_does_not_extract_or_create_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = cli.parser().parse_args(["analyze", str(root / "input.img"), "--java-home", str(root / "missing")])
            with mock.patch.object(cli, "ghidra_path", return_value=root), mock.patch.object(cli, "extract_image") as extract:
                with self.assertRaisesRegex(ValueError, "bin/java"):
                    cli.run_analysis(args)
                extract.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
