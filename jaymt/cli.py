"""Small command line entry point; Ghidra owns the analysis database."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

from . import __version__
from .firmware import FirmwareError, extract_image

ROOT = Path(__file__).resolve().parent.parent
LANGUAGE = "MIPS:LE:32:jaymt"


def say(message):
    prefix = "jayMT_Analyzer"
    if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
        prefix = "\033[92m" + prefix + "\033[0m"
    print("[{}] {}".format(prefix, message), flush=True)


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def heap_size(value):
    if not re.fullmatch(r"[1-9][0-9]*[mMgG]", value):
        raise argparse.ArgumentTypeError("use a positive heap size such as 4G or 8192M")
    return value.upper()


def ghidra_path(value):
    if not value:
        raise ValueError("set --ghidra or GHIDRA_INSTALL_DIR to an extracted Ghidra installation")
    path = Path(value).expanduser().resolve()
    properties = path / "Ghidra/application.properties"
    if not properties.is_file():
        raise ValueError("not a Ghidra installation: {}".format(path))
    version = re.search(r"(?m)^application.version=(\d+)\.(\d+)(?:\.(\d+))?", properties.read_text(encoding="utf-8"))
    if version is None or tuple(int(part or 0) for part in version.groups()) < (11, 4, 2):
        raise ValueError("Ghidra 11.4.2 or later is required; the compact extension replaces the legacy fork")
    launcher_path(path)
    return path


def launcher_path(ghidra):
    launch = ghidra / "support" / ("launch.bat" if os.name == "nt" else "launch.sh")
    if not launch.is_file():
        raise ValueError("Ghidra launcher is missing: {}".format(launch))
    return launch


def java_environment(java_home_option):
    environment = os.environ.copy()
    if java_home_option:
        java_home = Path(java_home_option).expanduser().resolve()
        if not (java_home / "bin" / ("java.exe" if os.name == "nt" else "java")).is_file():
            raise ValueError("--java-home does not contain bin/java")
        environment["JAVA_HOME"] = str(java_home)
        environment["PATH"] = str(java_home / "bin") + os.pathsep + environment.get("PATH", "")
    return environment


def headless_command(ghidra, project_dir, project, rom, csv, report, logs,
                     threads, heap, no_bruteforce=False, verbose=False):
    """Use the supported launcher without analyzeHeadless's hardcoded 2 GB/2 GC threads."""
    launch = launcher_path(ghidra)
    vmargs = "-Dcpu.core.override={} -Djava.awt.headless=true".format(threads)
    command = [str(launch), "fg", "jdk", "jayMT_Analyzer", heap, vmargs,
               "ghidra.app.util.headless.AnalyzeHeadless", str(project_dir), project,
               "-import", str(rom), "-loader", "BinaryLoader", "-processor", LANGUAGE,
               "-cspec", "default", "-noanalysis", "-max-cpu", str(threads),
               "-scriptPath", str(ROOT / "ghidra_scripts"),
               "-log", str(logs / "ghidra.log"),
               "-scriptlog", str(logs / "script.log"),
               "-postScript", "JayMTAnalyze.java", str(csv), str(report)]
    if no_bruteforce:
        command.append("--no-bruteforce")
    if verbose:
        command.append("--verbose")
    return command


def run_analysis(args):
    started = time.perf_counter()
    runtime = ghidra_path(args.ghidra)
    environment = java_environment(args.java_home)
    image = Path(args.image).expanduser().resolve()
    if not image.exists():
        raise ValueError("input does not exist: {}".format(image))
    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else image.parent / (image.stem + "_jaymt")
    project_dir = workspace / "projects"
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", args.project):
        raise ValueError("project name must contain only letters, numbers, dots, underscores, and hyphens")
    if (project_dir / (args.project + ".gpr")).exists() or (project_dir / (args.project + ".rep")).exists():
        raise ValueError("project already exists; select a new --project name or --workspace")
    prepared = image if image.is_dir() else workspace / "extracted"
    if image.is_file():
        extract_image(image, prepared, progress=say)
    rom, csv = prepared / "md1rom", prepared / "md1_dbginfo.csv"
    if not rom.is_file() or not csv.is_file():
        raise ValueError("analysis needs md1rom and md1_dbginfo.csv; extraction alone supports images without debug symbols")
    logs = workspace / "logs" / args.project
    for path in (project_dir, logs):
        path.mkdir(parents=True, exist_ok=True)
    # Exclusive report name prevents an earlier successful run masking a failed script.
    report = workspace / ("analysis-{}-{}.json".format(time.time_ns(), os.getpid()))
    command = headless_command(runtime, project_dir, args.project, rom, csv, report,
                               logs, args.threads, args.heap,
                               args.no_bruteforce, args.verbose)
    say("MIPS/MIPS16e analysis | {} workers | {} heap | {}".format(args.threads, args.heap, args.project))
    say("Ghidra reports stage progress below; individual database edits remain serial.")
    (workspace / "invocation.json").write_text(json.dumps({
        "tool_version": __version__, "command": command,
        "threads": args.threads, "heap": args.heap,
    }, indent=2) + "\n", encoding="utf-8")
    # Some native analyzers emit nothing for minutes; keep elapsed time visible.
    finished = threading.Event()

    def heartbeat():
        while not finished.wait(30):
            elapsed = int(time.perf_counter() - started)
            say("Ghidra process running | elapsed {:02d}:{:02d} | logs: {}".format(
                elapsed // 60, elapsed % 60, workspace / "logs"))

    ticker = threading.Thread(target=heartbeat, daemon=True)
    ticker.start()
    try:
        result = subprocess.run(command, env=environment, check=False)
    finally:
        finished.set()
        ticker.join()
    if result.returncode:
        raise ValueError("Ghidra exited with code {}; see {}".format(result.returncode, workspace / "logs"))
    if not report.is_file():
        raise ValueError("Ghidra did not produce an analysis report; check logs and install the extension with 'setup'")
    summary = json.loads(report.read_text(encoding="utf-8"))
    if summary.get("status") not in ("completed", "completed_with_warnings"):
        raise ValueError("analysis did not complete: {}; see {}".format(summary.get("status"), report))
    if not (project_dir / (args.project + ".gpr")).is_file():
        raise ValueError("analysis finished but the Ghidra project was not saved; see logs")
    log_file = logs / "ghidra.log"
    if not log_file.is_file() or "REPORT: Save succeeded for: /md1rom" not in log_file.read_text(encoding="utf-8", errors="replace"):
        raise ValueError("analysis finished but Ghidra did not confirm saving md1rom; see {}".format(logs))
    say("{} in {:.1f}s. Report: {}".format(summary["status"], time.perf_counter() - started, report))
    say("Open project: {}".format(project_dir / (args.project + ".gpr")))
    return 0


def parser():
    cli = argparse.ArgumentParser(prog="jayMT_Analyzer", description="Prepare md1img and analyze MediaTek MIPS firmware in Ghidra.")
    cli.add_argument("--version", action="version", version=__version__)
    commands = cli.add_subparsers(dest="command", required=True)
    unpack = commands.add_parser("unpack", help="extract md1rom and debug symbols from md1img (or legacy CP archives)")
    unpack.add_argument("image")
    unpack.add_argument("-o", "--output")
    unpack.add_argument("--all-sections", action="store_true", help="also export DSP/debug/other sections")
    setup = commands.add_parser("setup", help="build and install the small MediaTek processor extension")
    setup.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"))
    setup.add_argument("--java-home", help="JDK directory (bin/java and bin/javac)")
    run = commands.add_parser("analyze", help="extract and run full headless analysis; accepts an existing extraction directory")
    run.add_argument("image")
    run.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"))
    run.add_argument("--java-home", help="JDK directory")
    run.add_argument("--workspace", help="output directory; default: <input stem>_jaymt")
    run.add_argument("--project", default="md1", help="Ghidra project name (must be new)")
    run.add_argument("--threads", type=positive, default=getattr(os, "process_cpu_count", os.cpu_count)() or 1)
    run.add_argument("--heap", type=heap_size, default="4G", help="Java heap cap; default 4G, increase if RAM permits")
    run.add_argument("--no-bruteforce", action="store_true", help="skip uncertain final mode guesses (less coverage)")
    run.add_argument("--verbose", action="store_true")
    return cli


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "unpack":
            result = extract_image(args.image, args.output, all_sections=args.all_sections, progress=say)
            say("Prepared firmware: {}".format(result["output_dir"]))
            return 0
        if args.command == "setup":
            runtime = ghidra_path(args.ghidra)
            command = [sys.executable, str(ROOT / "scripts/build_extension.py"), "--ghidra", str(runtime), "--install"]
            if args.java_home:
                command += ["--java-home", args.java_home]
            return subprocess.run(command, check=False).returncode
        return run_analysis(args)
    except KeyboardInterrupt:
        print("\n[jayMT_Analyzer] Cancelled; partial output is not a completed analysis.", file=sys.stderr)
        return 130
    except (FirmwareError, ValueError, OSError) as error:
        print("[jayMT_Analyzer] {}".format(error), file=sys.stderr)
        return 1
