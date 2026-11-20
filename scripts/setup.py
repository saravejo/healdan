#!/usr/bin/env python3
"""Bootstrap a non-editable, external controller; keep credentials out of Git."""
from pathlib import Path
import os
import subprocess
import sys
import venv

if sys.version_info < (3, 12):
    raise SystemExit("Python 3.12+ is required")

root = Path(__file__).resolve().parent.parent
installation = Path.home() / ".local/share/healdan/controller-1.0"
if installation.resolve().is_relative_to(root):
    raise SystemExit("Controller installation must be outside the vault")
if not (installation / "pyvenv.cfg").exists():
    venv.EnvBuilder(with_pip=True).create(installation)
binary = installation / ("Scripts" if os.name == "nt" else "bin")
python = binary / ("python.exe" if os.name == "nt" else "python")
subprocess.run([str(python), "-m", "pip", "install", "--upgrade", str(root)], check=True)
command = [str(python), "-m", "healdan", "--vault", str(root), "setup"]
if sys.stdin.isatty():
    command.append("--interactive")
subprocess.run(command, check=True)
print("Add this controller directory to PATH: " + str(binary))
