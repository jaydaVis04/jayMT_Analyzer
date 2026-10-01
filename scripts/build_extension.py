#!/usr/bin/env python3
"""Build the small jayMT processor extension with an installed Ghidra and JDK."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NAME = "jayMT_Analyzer"


def read_properties(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def java_tool(name: str) -> str:
    suffix = ".exe" if os.name == "nt" else ""
    home = os.environ.get("JAVA_HOME")
    if home:
        path = Path(home) / "bin" / (name + suffix)
        if path.is_file():
            return str(path)
    path = shutil.which(name)
    if not path:
        raise ValueError("A JDK is required; set JAVA_HOME to your Ghidra-compatible JDK")
    return path


def install_extension(staging: Path, ghidra: Path) -> Path:
    """Atomically install; keep the previous tool version as a rollback backup."""
    extensions = ghidra / "Ghidra" / "Extensions"
    extensions.mkdir(parents=True, exist_ok=True)
    target = extensions / NAME
    if target.is_symlink():
        raise ValueError("Refusing to replace a symlink: " + str(target))
    if target.exists():
        marker = target / "jaymt-build.json"
        if not marker.is_file() or json.loads(marker.read_text()).get("name") != NAME:
            raise ValueError("Existing extension is not owned by this builder: " + str(target))
    with tempfile.TemporaryDirectory(prefix=".jaymt-install-", dir=extensions) as temporary:
        fresh = Path(temporary) / NAME
        shutil.copytree(staging, fresh)
        backup = None
        if target.exists():
            backups = ghidra / ".jaymt-backups"
            backups.mkdir(exist_ok=True)
            backup = backups / (NAME + "-" + os.urandom(6).hex())
            target.rename(backup)
        try:
            fresh.rename(target)
        except OSError:
            if backup is not None:
                backup.rename(target)
            raise
    return target


def build(ghidra: Path, output: Path, install: bool = False) -> Path:
    ghidra = ghidra.expanduser().resolve()
    properties = ghidra / "Ghidra" / "application.properties"
    if not properties.is_file():
        raise ValueError("Not a Ghidra installation: " + str(ghidra))
    props = read_properties(properties)
    version = props["application.version"]
    numbers = tuple(int(n) for n in re.findall(r"\d+", version)[:3])
    if numbers < (11, 4, 2):
        raise ValueError("Ghidra 11.4.2 or later is required (validated with 11.4.2)")
    java, javac = java_tool("java"), java_tool("javac")
    jars = sorted((ghidra / "Ghidra").glob("**/*.jar"))
    # Exclude extensions and rollback copies; they must not affect the compiler classpath.
    jars = [p for p in jars if "Extensions" not in p.relative_to(ghidra / "Ghidra").parts]
    if not jars:
        raise ValueError("No runtime JARs in Ghidra installation")
    classpath = os.pathsep.join(str(p) for p in jars)
    output = output.expanduser().resolve()
    archive = output if output.suffix.lower() == ".zip" else output / ("ghidra_" + version + "_" + NAME + ".zip")
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="jaymt-build-") as temporary:
        stage = Path(temporary) / NAME
        shutil.copytree(ROOT / "extension", stage)
        # Keep one canonical copy in source control while retaining licensing and
        # the complete usage guide in every separately distributed extension.
        for filename in ("LICENSE", "NOTICE", "README.md"):
            shutil.copyfile(ROOT / filename, stage / filename)
        if (ROOT / "assets").is_dir():
            shutil.copytree(ROOT / "assets", stage / "assets")
        langs = stage / "data" / "languages"
        print("[jayMT] Compiling MediaTek MIPS32/MIPS16e2 language", flush=True)
        subprocess.run([java, "-Djava.awt.headless=true", "-cp", classpath,
                        "ghidra.pcodeCPort.slgh_compile.SleighCompile",
                        str(langs / "mips32le.slaspec"), str(langs / "mips32le.sla")], check=True)
        classes = Path(temporary) / "classes"
        classes.mkdir()
        print("[jayMT] Compiling instruction analyzer", flush=True)
        sources = sorted((stage / "src").glob("**/*.java"))
        release = props.get("application.java.compiler", props.get("application.java.min", "21"))
        subprocess.run([javac, "--release", release, "-proc:none", "-encoding", "UTF-8", "-cp", classpath,
                        "-d", str(classes), *map(str, sources)], check=True)
        print("[jayMT] Checking native analysis script compatibility", flush=True)
        script_sources = sorted((ROOT / "ghidra_scripts").glob("*.java"))
        if script_sources:
            subprocess.run([javac, "--release", release, "-proc:none", "-encoding", "UTF-8", "-cp", classpath,
                            "-d", str(Path(temporary) / "script-check"), *map(str, script_sources)], check=True)
        lib = stage / "lib"
        lib.mkdir(exist_ok=True)
        with zipfile.ZipFile(lib / "jayMT_Analyzer.jar", "w", zipfile.ZIP_DEFLATED) as jar:
            for path in sorted(classes.rglob("*.class")):
                jar.write(path, path.relative_to(classes).as_posix())
        # Make the complete modified source available in every distributable.
        with zipfile.ZipFile(lib / "jayMT_Analyzer-src.zip", "w", zipfile.ZIP_DEFLATED) as source_zip:
            for path in sorted((stage / "src").rglob("*.java")):
                source_zip.write(path, path.relative_to(stage).as_posix())
        shutil.rmtree(stage / "src")
        extension_props = stage / "extension.properties"
        extension_props.write_text(extension_props.read_text().replace("@GHIDRA_VERSION@", version))
        scripts = ROOT / "ghidra_scripts"
        if scripts.exists():
            shutil.copytree(scripts, stage / "ghidra_scripts",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.class", ".DS_Store"))
        hashes = {p.relative_to(stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(stage.rglob("*")) if p.is_file()}
        (stage / "jaymt-build.json").write_text(json.dumps({"name": NAME,
            "ghidra_version": version, "sha256": hashes}, indent=2) + "\n")
        temporary_archive = Path(temporary) / "extension.zip"
        with zipfile.ZipFile(temporary_archive, "w", zipfile.ZIP_DEFLATED) as zipped:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    zipped.write(path, NAME + "/" + path.relative_to(stage).as_posix())
        shutil.copyfile(temporary_archive, archive)
        if install:
            print("[jayMT] Installed " + str(install_extension(stage, ghidra)), flush=True)
    print("[jayMT] Built " + str(archive) + " (" + str(archive.stat().st_size) + " bytes)", flush=True)
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--java-home", type=Path, help="Ghidra-compatible JDK (otherwise JAVA_HOME/PATH)")
    parser.add_argument("--output", type=Path, default=ROOT / "dist", help="ZIP filename or output directory")
    parser.add_argument("--install", action="store_true", help="Install into this Ghidra, keeping an upgrade backup")
    args = parser.parse_args(argv)
    if args.java_home:
        os.environ["JAVA_HOME"] = str(args.java_home.expanduser().resolve())
    try:
        build(args.ghidra, args.output, args.install)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print("[jayMT] Build failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
