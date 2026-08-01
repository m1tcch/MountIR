#!/usr/bin/env python3
"""MountIR dependency bootstrapping.

Single source of truth for MountIR's runtime dependencies and the logic that
pulls them in.  Two layers of dependencies are managed:

* **Python packages** - declared in ``requirements.txt`` (pinned) and installed
  into a project-local **virtual environment** (``.venv/``).  They are never
  installed into the system interpreter, so running MountIR as root does not
  pollute the OS Python and side-steps PEP 668 ("externally-managed-
  environment") errors on modern Debian/Ubuntu.
* **System forensic tools** - the external binaries each format handler shells
  out to (``ewfmount``, ``qemu-nbd``, ``affuse`` ...), installed with ``apt`` on
  Debian/Ubuntu-based systems.

On the very first run MountIR:

1. creates ``.venv`` and installs the pinned Python deps into it,
2. **re-launches itself inside that venv** (so ``colorama`` & friends import
   from the venv, not the root site-packages),
3. installs any missing system forensic tools, and
4. drops a marker file so the system-tool step is not repeated.

``mountir setup`` re-runs the whole thing on demand.  Set
``MOUNTIR_NO_BOOTSTRAP=1`` (or pass ``--no-setup``) to opt out entirely and run
against the current interpreter.
"""

import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils import logger, tool_exists, SCRIPT_DIR

# ---------------------------------------------------------------------------
# Dependency declarations
# ---------------------------------------------------------------------------
REQUIREMENTS_FILE = SCRIPT_DIR / "requirements.txt"

# Project-local virtual environment that holds MountIR's Python dependencies.
VENV_DIR = SCRIPT_DIR / ".venv"

# Map an external tool -> the apt package that provides it.
# Tools shipped by util-linux/coreutils are present on virtually every Linux
# install and are listed for documentation/completeness.
SYSTEM_PACKAGES: Dict[str, str] = {
    # Format handlers
    "ewfmount": "ewf-tools",        # E01/L01 baseline; apt is the 2014 legacy
                                    # line -> build_libewf adds EWF2 (Ex01/Lx01)
    "qemu-nbd": "qemu-utils",       # VMDK, VHD/VHDX, QCOW2, VDI (primary)
    "affuse": "afflib-tools",       # AFF
    "vmdkmount": "libvmdk-utils",   # VMDK (fallback)
    "vhdimount": "libvhdi-utils",   # VHD/VHDX (fallback)
    # Partition / filesystem support
    "kpartx": "kpartx",             # partition device mapping
    "pvs": "lvm2",                  # LVM detection/activation
    "fusermount": "fuse",           # FUSE unmounting
    "ntfs-3g": "ntfs-3g",           # NTFS mounting
    "mmls": "sleuthkit",            # partition layout (fallback to fdisk)
    # Extended filesystem drivers (broad forensic FS coverage)
    "mount.exfat-fuse": "exfat-fuse",  # exFAT FUSE fallback (kernel handles 5.4+)
    "fsck.exfat": "exfatprogs",        # exFAT userland (label/fsck)
    "fsck.hfsplus": "hfsprogs",        # macOS HFS+ fsck/label helpers
    "vmfs-fuse": "vmfs-tools",         # VMware ESXi VMFS3/5 datastores
    "vmfs6-fuse": "vmfs6-tools",        # VMware ESXi 6.5+ VMFS6 datastores
    "zpool": "zfsutils-linux",         # ZFS pool import (also needs kernel module)
    # UFS (FreeBSD/NetScaler/pfSense) uses the in-kernel ufs driver - no package.
    # APFS (apfs-fuse) is not in apt; it is built from source (see build_apfs_fuse).
    # Built-ins (util-linux / file) - listed for completeness
    "fdisk": "fdisk",
    "blkid": "util-linux",
    "losetup": "util-linux",
    "file": "file",
}

# apfs-fuse is the only maintained read-only APFS driver for Linux and is not
# packaged for apt, so it is built from source on demand.
APFS_FUSE_REPO = "https://github.com/sgan81/apfs-fuse.git"
APFS_FUSE_BUILD_DEPS = [
    "git", "cmake", "g++", "libfuse3-dev", "libbz2-dev",
    "zlib1g-dev", "libattr1-dev",
]
_SOURCE_BUILD_ROOT = Path("/var/lib/mountir/src")

# UFS (FreeBSD/pfSense/NetScaler) normally mounts through the in-kernel ``ufs``
# driver, but that driver is optional: Ubuntu ships it in
# linux-modules-extra-$(uname -r), and the Microsoft WSL2 kernel omits it
# entirely while shipping no loadable modules at all. ``fuse-ufs`` is the
# userspace driver that covers those hosts.
#
# It is a Rust crate, so building it needs a cargo toolchain. That is a heavy,
# opinionated dependency to pull in behind the user's back, so this build is
# **opt-in** (`mountir setup --ufs`) and never installs a toolchain
# itself -- it uses cargo if cargo is already there and explains how to get one
# if it isn't.
FUSE_UFS_CRATE = "fuse-ufs"
FUSE_UFS_REPO = "https://github.com/asomers/fuse-ufs"
FUSE_UFS_BUILD_DEPS = ["pkg-config", "libfuse3-dev", "gcc"]

# The *current* fuse-ufs release pulls in dependencies built for the 2024 Rust
# edition (fuser 0.16, bincode 2.x), which need Rust 1.85+. Ubuntu 24.04's apt
# ``cargo`` is 1.75, so on a stock distro toolchain that build fails deep in the
# dependency graph with an error naming a crate the user never asked for.
#
# 0.4.4 is the newest release whose dependency set still compiles on 1.75
# (verified on Ubuntu 24.04 / cargo 1.75.0), so an older toolchain gets that
# instead of a doomed build. Pinned deliberately: a forensic tool should install
# a known-good version rather than whatever resolves today.
FUSE_UFS_MODERN_RUST = (1, 85)
FUSE_UFS_LEGACY_VERSION = "0.4.4"

# cargo is usually installed per-user by rustup, and ``sudo`` resets PATH to
# secure_path -- so the invoking user's cargo is invisible to a plain PATH
# lookup. Check the usual rustup locations for both root and $SUDO_USER.
_CARGO_CANDIDATE_DIRS = [
    "/usr/local/cargo/bin",
    "/root/.cargo/bin",
    "/usr/local/bin",
    "/usr/bin",
]

# The apt ``ewf-tools`` package ships the frozen 2014 *legacy* libewf line
# (version 20140807), which cannot read EWF2 (Ex01/Lx01) EnCase v7 containers.
# MountIR builds the maintained libyal release from source so a newer
# ``ewfmount`` in /usr/local/bin shadows the apt one and adds Ex01/Lx01 support.
#
# Pinned for forensic reproducibility (you want to know exactly which tool
# version touched the evidence).  Override with the ``MOUNTIR_LIBEWF_VERSION``
# env var and rebuild with ``mountir setup --force`` -- a newer upstream release
# may change behaviour, so bumping is deliberate, not automatic.
LIBEWF_VERSION = "20240506"
LIBEWF_RELEASE_URL = (
    "https://github.com/libyal/libewf/releases/download/"
    "{version}/libewf-experimental-{version}.tar.gz"
)
# The release tarball ships a pre-generated ``configure`` (no autotools needed).
LIBEWF_BUILD_DEPS = [
    "gcc", "make", "pkg-config", "zlib1g-dev", "libbz2-dev",
    "libssl-dev", "libfuse-dev",
]

# Marker written once first-run bootstrap (system tools) has completed.
_MARKER_CANDIDATES = [
    Path("/var/lib/mountir/.bootstrapped"),
    SCRIPT_DIR / ".mountir_bootstrapped",
]

# Opt out of automatic first-run bootstrapping (venv + system tools).
_OPT_OUT_ENV = "MOUNTIR_NO_BOOTSTRAP"
# Set on the child process after re-exec, to detect "already inside the venv".
_IN_VENV_ENV = "MOUNTIR_IN_VENV"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _opted_out() -> bool:
    """True when the user has disabled automatic bootstrapping."""
    return bool(os.environ.get(_OPT_OUT_ENV))


def is_root() -> bool:
    """True when running as root on a POSIX system (no-op elsewhere)."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def _ensure_console_logger() -> None:
    """Attach a minimal stderr logger if none is configured yet.

    Bootstrap may run before ``setup_logging`` (we re-exec into the venv before
    full logging is set up), so progress messages would otherwise be dropped.
    Only the pre-exec process hits this; the re-exec'd process configures
    logging normally.
    """
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(handler)


def missing_system_tools() -> List[str]:
    """Return the list of declared tools that are not on PATH."""
    return [tool for tool in SYSTEM_PACKAGES if not tool_exists(tool)]


def missing_system_packages() -> List[str]:
    """Return the apt packages needed to satisfy the missing tools."""
    return sorted({SYSTEM_PACKAGES[t] for t in missing_system_tools()})


def _marker_path() -> Path:
    """Pick a writable marker location, preferring the system path."""
    for candidate in _MARKER_CANDIDATES:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            return candidate
        except OSError:
            continue
    return _MARKER_CANDIDATES[-1]


def already_bootstrapped() -> bool:
    """True if a bootstrap marker exists in any known location."""
    return any(p.exists() for p in _MARKER_CANDIDATES)


def _write_marker() -> None:
    try:
        _marker_path().write_text("ok\n", encoding="utf-8")
    except OSError as e:
        logger.debug("Could not write bootstrap marker: %s", e)


# ---------------------------------------------------------------------------
# Virtual environment management
# ---------------------------------------------------------------------------
def venv_python() -> Path:
    """Path to the Python interpreter inside the project venv."""
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def venv_exists() -> bool:
    """True if the project venv has been created."""
    return venv_python().exists()


def in_project_venv() -> bool:
    """True if the current interpreter is the project venv's interpreter."""
    if os.environ.get(_IN_VENV_ENV):
        return True
    try:
        return Path(sys.executable).resolve() == venv_python().resolve()
    except OSError:
        return False


def _run_venv_module() -> bool:
    """Create the venv with the current interpreter's ``venv`` module."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "venv", str(VENV_DIR)],
            text=True, timeout=180,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug("venv module invocation failed: %s", e)
        return False


def create_venv() -> bool:
    """Create the project virtual environment.

    On Debian/Ubuntu the ``venv``/``ensurepip`` machinery lives in a separate
    ``python3-venv`` package; if creation fails we try to install it and retry
    once.
    """
    logger.info("Creating Python virtual environment at %s", VENV_DIR)
    if _run_venv_module():
        return True

    logger.warning("venv creation failed - attempting to install python3-venv")
    if install_system_deps(["python3-venv"]) and _run_venv_module():
        return True

    logger.error(
        "Could not create a virtual environment. Install 'python3-venv' "
        "(Debian/Ubuntu) and retry, or run with --no-setup to use the system "
        "interpreter.",
    )
    return False


def install_python_deps(python_exe: Optional[Path] = None) -> bool:
    """Install/upgrade the pinned Python dependencies into the venv.

    Returns True on success.
    """
    if not REQUIREMENTS_FILE.exists():
        logger.warning("requirements.txt not found at %s", REQUIREMENTS_FILE)
        return False

    py = str(python_exe or venv_python())
    logger.info("Installing pinned Python dependencies into the venv")
    try:
        result = subprocess.run(
            [py, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)],
            text=True, timeout=300,
        )
        if result.returncode == 0:
            logger.info("Python dependencies are satisfied")
            return True
        logger.warning("pip exited with code %d", result.returncode)
        return False
    except FileNotFoundError:
        logger.error("pip not available for interpreter %s", py)
        return False
    except subprocess.TimeoutExpired:
        logger.error("pip install timed out")
        return False


def ensure_venv_ready(force_install: bool = False) -> bool:
    """Make sure the venv exists with the pinned deps installed.

    The deps are installed when the venv is first created, or whenever
    ``force_install`` is set (e.g. ``mountir setup``).  On subsequent runs an
    existing venv is reused without re-running pip.
    """
    created = False
    if not venv_exists():
        if not create_venv():
            return False
        created = True
    if created or force_install:
        install_python_deps(venv_python())
    return venv_exists()


def reexec_into_venv() -> None:
    """Re-run the current MountIR command using the venv interpreter.

    Implemented with ``subprocess`` (rather than ``os.exec*``) so behaviour is
    identical on Linux and Windows and stdio/exit codes propagate cleanly: the
    child inherits stdin/stdout/stderr, so ``--json`` output and the banner go
    to the right streams.  Exits the current process with the child's return
    code; returns only if the venv interpreter is missing.
    """
    py = venv_python()
    if not py.exists():
        logger.error(
            "Virtual environment python missing at %s; continuing with the "
            "system interpreter", py,
        )
        return

    env = os.environ.copy()
    env[_IN_VENV_ENV] = "1"
    script = SCRIPT_DIR / "mountir.py"
    argv = [str(py), str(script)] + sys.argv[1:]

    logger.info("Re-launching MountIR inside the virtual environment")
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        result = subprocess.run(argv, env=env)
    except KeyboardInterrupt:
        sys.exit(130)
    sys.exit(result.returncode)


# ---------------------------------------------------------------------------
# System package install
# ---------------------------------------------------------------------------
def _priv_prefix() -> Optional[List[str]]:
    """Privilege-escalation prefix for system-modifying commands.

    Returns ``[]`` when already root, ``["sudo"]`` when sudo is available, or
    ``None`` when neither (caller must abort the privileged action).
    """
    if is_root():
        return []
    if tool_exists("sudo"):
        return ["sudo"]
    return None


def _run(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 300) -> bool:
    """Run a build/install command, returning True on success.  Never raises."""
    try:
        result = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            logger.warning("command failed (%d): %s", result.returncode, " ".join(cmd))
            return False
        return True
    except FileNotFoundError:
        logger.warning("command not found: %s", cmd[0])
        return False
    except subprocess.TimeoutExpired:
        logger.warning("command timed out: %s", " ".join(cmd))
        return False


def install_system_deps(packages: List[str]) -> bool:
    """Install the given apt packages.  Requires root (or sudo)."""
    if not packages:
        logger.info("All required system tools are already installed")
        return True

    # Choose a privilege escalation strategy.
    prefix = _priv_prefix()
    if prefix is None:
        logger.error(
            "Cannot install system packages without root. Run as root or "
            "install manually: apt install %s", " ".join(packages),
        )
        return False

    logger.info("Installing system packages: %s", " ".join(packages))
    try:
        subprocess.run(prefix + ["apt-get", "update", "-qq"],
                       text=True, timeout=180)
        result = subprocess.run(
            prefix + ["apt-get", "install", "-y"] + packages,
            text=True, timeout=600,
        )
        if result.returncode == 0:
            logger.info("System packages installed successfully")
            return True
        # The batch failed -- often a single package is unavailable on this
        # distro (e.g. vmfs6-tools isn't in every apt repo). Retry each package
        # individually so one missing package doesn't block all the others.
        logger.warning(
            "Batch install failed; retrying packages individually "
            "(some may be unavailable on this distro)")
        failed = []
        for pkg in packages:
            r = subprocess.run(prefix + ["apt-get", "install", "-y", pkg],
                               text=True, timeout=300)
            if r.returncode != 0:
                failed.append(pkg)
        if failed:
            logger.warning("Could not install: %s", " ".join(failed))
            return False
        logger.info("System packages installed successfully (individually)")
        return True
    except FileNotFoundError:
        logger.error(
            "apt-get not found. MountIR auto-install targets Debian/Ubuntu. "
            "Install manually: %s", " ".join(packages),
        )
        return False
    except subprocess.TimeoutExpired:
        logger.error("System package installation timed out")
        return False


def build_apfs_fuse(force: bool = False) -> bool:
    """Build and install apfs-fuse from source (it isn't packaged for apt).

    Read-only APFS support on Linux comes from ``apfs-fuse``
    (github.com/sgan81/apfs-fuse).  Best-effort: installs the build
    dependencies, clones the repo with submodules, runs ``cmake`` + ``make``,
    and installs the binaries into ``/usr/local/bin``.  Never raises; returns
    True only when an ``apfs-fuse`` binary ends up on PATH.
    """
    if not force and tool_exists("apfs-fuse"):
        logger.debug("apfs-fuse already installed")
        return True

    prefix = _priv_prefix()
    if prefix is None:
        logger.error(
            "Cannot build apfs-fuse without root. Run as root/sudo, or build "
            "manually from %s", APFS_FUSE_REPO,
        )
        return False

    logger.info("Building apfs-fuse from source (no apt package available)")
    if not install_system_deps(APFS_FUSE_BUILD_DEPS):
        logger.warning("Could not install apfs-fuse build dependencies")
        return False

    src = _SOURCE_BUILD_ROOT / "apfs-fuse"
    build = src / "build"
    try:
        _SOURCE_BUILD_ROOT.mkdir(parents=True, exist_ok=True)
        if not (src / ".git").exists():
            if not _run(["git", "clone", "--recursive", APFS_FUSE_REPO, str(src)],
                        timeout=600):
                return False
        build.mkdir(parents=True, exist_ok=True)
        if not _run(["cmake", ".."], cwd=build, timeout=300):
            return False
        if not _run(["make", "-j"], cwd=build, timeout=1800):
            return False
        for name in ("apfs-fuse", "apfsutil", "apfs-dump", "apfs-dump-quick"):
            binary = build / name
            if binary.exists():
                _run(prefix + ["install", "-m", "0755", str(binary), "/usr/local/bin/"],
                     timeout=60)
    except OSError as e:
        logger.warning("apfs-fuse build failed: %s", e)
        return False

    if _tool_on_path("apfs-fuse"):
        logger.info("apfs-fuse installed to /usr/local/bin")
        return True
    logger.warning("apfs-fuse build finished but the binary isn't on PATH")
    return False


def _tool_on_path(name: str) -> bool:
    """PATH lookup that bypasses ``tool_exists``' cache.

    ``tool_exists`` memoises its answer, so a tool probed *before* a build has
    already been cached as missing and would still read as missing afterwards.
    Post-install verification has to ask PATH again.
    """
    import shutil
    return shutil.which(name) is not None


def find_cargo() -> Optional[str]:
    """Path to a usable ``cargo``, or None.

    ``shutil.which`` alone isn't enough: rustup installs cargo into the user's
    ``~/.cargo/bin``, and under ``sudo`` the reset ``secure_path`` hides it. We
    also look under ``$SUDO_USER``'s home so ``sudo mountir setup`` finds the
    toolchain the user actually installed.
    """
    import shutil

    found = shutil.which("cargo")
    if found:
        return found

    # $SUDO_USER first: under sudo, $HOME is usually /root, while the toolchain
    # the user actually installed lives in their own home.
    candidates: List[str] = []
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        candidates.append(f"/home/{sudo_user}/.cargo/bin")
    home = os.environ.get("HOME")
    if home:
        candidates.append(str(Path(home) / ".cargo" / "bin"))
    candidates.extend(_CARGO_CANDIDATE_DIRS)

    for directory in candidates:
        candidate = Path(directory) / "cargo"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def cargo_version(cargo: str) -> Optional[Tuple[int, int]]:
    """``(major, minor)`` reported by ``cargo --version``, or None.

    Used to pick a fuse-ufs release this toolchain can actually build, rather
    than starting a compile that dies minutes later inside a transitive crate.
    """
    try:
        result = subprocess.run([cargo, "--version"], capture_output=True,
                                text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"cargo\s+(\d+)\.(\d+)", result.stdout or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def build_fuse_ufs(force: bool = False) -> bool:
    """Install the ``fuse-ufs`` userspace UFS driver with cargo (opt-in).

    Gives FreeBSD/pfSense/NetScaler UFS volumes a driver on hosts whose kernel
    has none -- notably WSL2, which ships neither the ``ufs`` module nor any way
    to load one. Installs into ``/usr/local`` so the binary lands in
    ``/usr/local/bin/fuse-ufs``, where :mod:`partition` picks it up
    automatically as the UFS fallback mounter.

    Best-effort and never raises. Returns True only when a ``fuse-ufs`` binary
    ends up on PATH. A missing cargo is reported with how to get one rather than
    installing a Rust toolchain unprompted.
    """
    if not force and tool_exists("fuse-ufs"):
        logger.debug("fuse-ufs already installed")
        return True

    prefix = _priv_prefix()
    if prefix is None:
        logger.error(
            "Cannot install fuse-ufs without root. Run as root/sudo, or install "
            "it yourself with 'cargo install %s'", FUSE_UFS_CRATE,
        )
        return False

    cargo = find_cargo()
    if not cargo:
        logger.warning(
            "fuse-ufs needs a Rust toolchain and no 'cargo' was found. Install "
            "one (apt install cargo, or rustup from https://rustup.rs) and "
            "re-run 'mountir setup --ufs'. Source: %s", FUSE_UFS_REPO,
        )
        return False

    logger.info("Installing fuse-ufs with %s (userspace UFS driver)", cargo)
    if not install_system_deps(FUSE_UFS_BUILD_DEPS):
        logger.warning("Could not install fuse-ufs build dependencies")
        return False

    # --root /usr/local puts the binary in /usr/local/bin, matching where the
    # other source-built drivers land. --force lets a rebuild replace it.
    #
    # --locked is not optional: without it cargo re-resolves the whole dependency
    # graph to the newest semver-compatible releases, so an install that worked
    # yesterday breaks the moment some transitive crate raises its MSRV. Locked
    # installs the dependency set the author released and tested.
    cmd = prefix + [cargo, "install", FUSE_UFS_CRATE, "--locked",
                    "--root", "/usr/local"]

    version = cargo_version(cargo)
    if version and version < FUSE_UFS_MODERN_RUST:
        logger.info(
            "cargo %d.%d is older than the %d.%d the current fuse-ufs needs - "
            "installing the pinned %s instead. For the latest, install a newer "
            "toolchain with rustup (https://rustup.rs) and re-run with --force.",
            version[0], version[1], FUSE_UFS_MODERN_RUST[0],
            FUSE_UFS_MODERN_RUST[1], FUSE_UFS_LEGACY_VERSION,
        )
        cmd += ["--version", FUSE_UFS_LEGACY_VERSION]

    if force:
        cmd.append("--force")
    if not _run(cmd, timeout=1800):
        logger.warning(
            "cargo install %s failed. If it stopped on a dependency needing a "
            "newer rustc, install an up-to-date toolchain with rustup "
            "(https://rustup.rs) - Ubuntu's apt cargo lags well behind.",
            FUSE_UFS_CRATE,
        )
        return False

    if _tool_on_path("fuse-ufs"):
        logger.info("fuse-ufs installed to /usr/local/bin")
        return True
    logger.warning("cargo reported success but fuse-ufs isn't on PATH")
    return False


def ewfmount_version_of(binary: str) -> Optional[str]:
    """Return the ``YYYYMMDD`` version reported by a specific ewfmount binary.

    libewf tools print ``ewfmount YYYYMMDD`` as the first line of ``-V`` output
    (to stdout, though we read stderr too defensively).  Returns None when the
    binary is missing or doesn't report a parseable version.
    """
    try:
        result = subprocess.run(
            [binary, "-V"], capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    match = re.search(
        r"ewfmount\s+(\d{8})", (result.stdout or "") + (result.stderr or ""),
    )
    return match.group(1) if match else None


# Locations a source-built (modern) ewfmount typically lands in, plus the apt
# one.  Scanned in addition to PATH so MountIR finds a newer build even when the
# caller's PATH (or sudo's ``secure_path``) would resolve the legacy one first.
_EWFMOUNT_CANDIDATE_DIRS = ["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin"]


def _candidate_ewfmount_paths() -> List[str]:
    """All distinct ewfmount binaries on PATH and in the known install dirs.

    ``shutil.which`` only returns the *first* hit on PATH; under ``sudo`` the
    reset ``secure_path`` can put the frozen apt build (/usr/bin) ahead of a
    source-built modern one (/usr/local/bin).  We gather every candidate so the
    newest can be chosen explicitly rather than relying on PATH ordering.
    """
    seen: Dict[str, None] = {}
    paths: List[str] = []

    def _add(p: Optional[str]) -> None:
        if not p:
            return
        try:
            real = str(Path(p).resolve())
        except OSError:
            real = p
        if real not in seen and Path(p).exists():
            seen[real] = None
            paths.append(p)

    import shutil
    _add(shutil.which("ewfmount"))
    for d in _EWFMOUNT_CANDIDATE_DIRS:
        _add(str(Path(d) / "ewfmount"))
    return paths


def best_ewfmount(minimum: str = LIBEWF_VERSION) -> Optional[str]:
    """Path to the newest ewfmount available, preferring an EWF2-capable build.

    Scans every ewfmount on PATH and in the standard install dirs, reads each
    one's version, and returns the highest.  This guarantees MountIR uses a
    modern (Ex01/Lx01-capable) ewfmount when one is installed, regardless of how
    PATH or ``sudo``'s ``secure_path`` is ordered.  Returns None when no
    ewfmount is found at all.
    """
    best_path: Optional[str] = None
    best_ver = -1
    for path in _candidate_ewfmount_paths():
        ver = ewfmount_version_of(path)
        try:
            ver_int = int(ver) if ver else 0
        except ValueError:
            ver_int = 0
        if ver_int > best_ver:
            best_ver, best_path = ver_int, path
    # Fall back to a bare "ewfmount" (resolved via PATH at exec time) only when
    # nothing concrete was found but the name is on PATH.
    if best_path is None and tool_exists("ewfmount"):
        return "ewfmount"
    return best_path


def installed_ewfmount_version() -> Optional[str]:
    """Return the version of the *newest* ewfmount available (``YYYYMMDD``).

    Considers every candidate (not just the first on PATH) so the reported
    version reflects the build MountIR will actually use to mount.
    """
    best_ver: Optional[str] = None
    for path in _candidate_ewfmount_paths():
        ver = ewfmount_version_of(path)
        if ver and (best_ver is None or int(ver) > int(best_ver)):
            best_ver = ver
    return best_ver


def have_modern_libewf(minimum: str = LIBEWF_VERSION) -> bool:
    """True when the installed ``ewfmount`` is new enough for EWF2 (Ex01/Lx01).

    The apt ``ewf-tools`` package is the 2014 legacy line (20140807) and reports
    a version below the pinned modern release; a source-built libewf reports
    ``minimum`` or newer.  Versions are ``YYYYMMDD`` integers, so a numeric
    compare orders them correctly.
    """
    version = installed_ewfmount_version()
    if not version:
        return False
    try:
        return int(version) >= int(minimum)
    except ValueError:
        return False


def _download(url: str, dest: Path, timeout: int = 180) -> bool:
    """Download ``url`` to ``dest`` with urllib (follows redirects).  No raise."""
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # nosec B310 - https only
            data = resp.read()
        dest.write_bytes(data)
        return dest.stat().st_size > 0
    except (urllib.error.URLError, OSError, ValueError) as e:
        logger.warning("download failed for %s: %s", url, e)
        return False


def _extract_tarball(tarball: Path, dest: Path) -> Optional[Path]:
    """Extract a ``.tar.gz`` into ``dest``; return the top-level extracted dir."""
    import tarfile
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            names = tf.getnames()
            try:
                tf.extractall(dest, filter="data")  # safe extraction (py3.12+)
            except TypeError:
                tf.extractall(dest)  # older Python without the filter kwarg
    except (tarfile.TarError, OSError) as e:
        logger.warning("could not extract %s: %s", tarball.name, e)
        return None
    tops = {n.split("/", 1)[0] for n in names if n and not n.startswith("/")}
    return dest / next(iter(tops)) if len(tops) == 1 else dest


def ewfmount_has_fuse(binary: Optional[str] = None) -> bool:
    """True when *binary* (default: the resolved ewfmount) links a FUSE library.

    A libewf build without FUSE produces an ewfmount that reports a modern
    version but fails every mount with "No sub system to mount EWF format", so a
    version check alone is not enough. Inspecting the dynamic dependencies is a
    cheap, reliable capability probe.
    """
    binary = binary or best_ewfmount() or "ewfmount"
    try:
        result = subprocess.run(
            ["ldd", binary], capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    return "libfuse" in (result.stdout or "").lower()


def _make_fuse2_pkgconfig_wrapper() -> Optional[str]:
    """Create a pkg-config shim that hides fuse3 so libewf builds against fuse2.

    libewf 20240506's configure prefers fuse3 and reports success with it, but
    the resulting ewfmount links no FUSE subsystem and cannot mount. The fuse2
    path works. This shim makes any ``fuse3`` pkg-config query fail while passing
    everything else through to the real pkg-config, so configure falls back to
    fuse2 -- without uninstalling the system's libfuse3-dev. Returns the shim
    path, or None when pkg-config isn't available.
    """
    import shutil
    real = shutil.which("pkg-config")
    if not real:
        return None
    wrapper = _SOURCE_BUILD_ROOT / "pkgconfig-no-fuse3.sh"
    try:
        _SOURCE_BUILD_ROOT.mkdir(parents=True, exist_ok=True)
        script = (
            "#!/bin/sh\n"
            "# MountIR: hide fuse3 so libewf builds against the reliable fuse2.\n"
            'for arg in "$@"; do\n'
            '  case "$arg" in *fuse3*) exit 1 ;; esac\n'
            "done\n"
            f'exec "{real}" "$@"\n'
        )
        wrapper.write_text(script, encoding="utf-8")
        wrapper.chmod(0o755)
    except OSError as e:
        logger.debug("could not create pkg-config fuse2 shim: %s", e)
        return None
    return str(wrapper)


def build_libewf(force: bool = False, version: str = "") -> bool:
    """Build and install modern libewf from source for EWF2 (Ex01/Lx01) support.

    The apt ``ewf-tools`` package is frozen at the 2014 legacy line (20140807),
    which cannot read EnCase v7 EWF2 (Ex01/Lx01) images.  This downloads the
    maintained libyal release (pinned to :data:`LIBEWF_VERSION`, overridable via
    the ``MOUNTIR_LIBEWF_VERSION`` env var), runs its bundled
    ``./configure && make && make install`` into ``/usr/local``, and refreshes
    the dynamic linker cache so the freshly built ``ewfmount`` shadows the apt
    one.  Best-effort: never raises; returns True only when a modern ``ewfmount``
    ends up on PATH.

    ``force`` rebuilds even when a modern libewf is already installed (used by
    ``mountir setup --force`` to pull a newer pinned/override version).
    """
    version = version or os.environ.get("MOUNTIR_LIBEWF_VERSION") or LIBEWF_VERSION
    if not force and have_modern_libewf() and ewfmount_has_fuse():
        logger.debug("modern, FUSE-capable libewf already installed")
        return True

    url = LIBEWF_RELEASE_URL.format(version=version)
    prefix = _priv_prefix()
    if prefix is None:
        logger.error(
            "Cannot build libewf without root. Run as root/sudo, or build "
            "manually from %s", url,
        )
        return False

    logger.info(
        "Building libewf %s from source (apt ewf-tools is the 2014 legacy "
        "line; this adds EWF2 Ex01/Lx01 support)", version,
    )
    if not install_system_deps(LIBEWF_BUILD_DEPS):
        logger.warning("Could not install libewf build dependencies")
        return False

    tarball = _SOURCE_BUILD_ROOT / f"libewf-{version}.tar.gz"
    src_dir = _SOURCE_BUILD_ROOT / f"libewf-{version}"
    try:
        _SOURCE_BUILD_ROOT.mkdir(parents=True, exist_ok=True)
        if not _download(url, tarball):
            logger.warning("Could not download libewf source from %s", url)
            return False
        # Always build from a pristine tree. Rebuilding over stale objects (e.g.
        # after installing FUSE headers) silently keeps the previous, possibly
        # mount-incapable, ewfmount instead of recompiling against the new deps.
        if src_dir.exists():
            import shutil
            shutil.rmtree(src_dir, ignore_errors=True)
        src = _extract_tarball(tarball, _SOURCE_BUILD_ROOT)
        if src is None:
            return False
        # Force the reliable fuse2 build path: libewf 20240506 auto-detects
        # fuse3 and reports success, but the ewfmount it produces links no FUSE
        # subsystem and fails every mount ("No sub system to mount EWF format").
        configure_cmd = ["./configure"]
        pc_wrapper = _make_fuse2_pkgconfig_wrapper()
        if pc_wrapper:
            configure_cmd.append("PKG_CONFIG=" + pc_wrapper)
        if not _run(configure_cmd, cwd=src, timeout=600):
            return False
        if not _run(["make", "-j"], cwd=src, timeout=1800):
            return False
        if not _run(prefix + ["make", "install"], cwd=src, timeout=300):
            return False
        _run(prefix + ["ldconfig"], timeout=60)  # register /usr/local/lib
    except OSError as e:
        logger.warning("libewf build failed: %s", e)
        return False

    # A version check alone isn't enough: verify the built ewfmount can actually
    # mount (links a FUSE library), or the tool would report success over a
    # binary that fails every mount.
    if not have_modern_libewf(version):
        logger.warning("libewf build finished but a modern ewfmount isn't on PATH")
        return False
    if not ewfmount_has_fuse():
        logger.error(
            "Built ewfmount (%s) has no FUSE support and cannot mount images. "
            "Install FUSE headers and rebuild: 'sudo apt-get install libfuse-dev' "
            "then 'sudo mountir setup --force'.",
            best_ewfmount() or "ewfmount",
        )
        return False
    logger.info(
        "libewf %s installed to /usr/local (Ex01/Lx01, FUSE-capable)", version)
    return True


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def ensure_venv_runtime() -> None:
    """Ensure MountIR runs inside the project venv (call early in ``main``).

    On first run this creates the venv, installs the pinned Python deps, and
    re-execs the current command with the venv interpreter.  It is a no-op once
    inside the venv or when bootstrapping is opted out, and never raises - a
    failed venv bootstrap must not stop the user from running a command.
    """
    if _opted_out():
        return
    if in_project_venv():
        return

    _ensure_console_logger()
    if not venv_exists():
        logger.info("First run detected - setting up MountIR virtual environment")
    try:
        if ensure_venv_ready():
            reexec_into_venv()  # replaces the process; only returns on failure
    except Exception as e:  # never let bootstrap crash the CLI
        logger.warning("venv bootstrap encountered an error: %s", e)


def ensure_system_bootstrap() -> None:
    """Install missing system forensic tools once (call after venv re-exec)."""
    if _opted_out():
        return
    if already_bootstrapped():
        return
    logger.info("First run - installing missing system forensic tools")
    try:
        install_system_deps(missing_system_packages())
    except Exception as e:  # never let bootstrap crash the CLI
        logger.warning("System tool bootstrap encountered an error: %s", e)
    if not tool_exists("apfs-fuse"):
        logger.info(
            "APFS images need apfs-fuse (built from source) - run "
            "'mountir setup' to build it.")
    if not have_modern_libewf():
        logger.info(
            "EnCase v7 EWF2 (Ex01/Lx01) images need modern libewf (built from "
            "source) - run 'mountir setup' to build it.")
    _write_marker()


def run_bootstrap(force: bool = False, with_fuse_ufs: bool = False) -> bool:
    """Full dependency install for ``mountir setup``.

    Creates/refreshes the venv with the pinned Python deps and installs any
    missing system forensic tools.  Does not re-exec (the caller is performing
    setup, not a mount operation).

    *with_fuse_ufs* additionally installs the ``fuse-ufs`` UFS driver via cargo.
    It is opt-in because it needs a Rust toolchain, which is too heavy a
    dependency to pull in unasked -- see :func:`build_fuse_ufs`.
    """
    logger.info("Bootstrapping MountIR dependencies...")
    venv_ok = ensure_venv_ready(force_install=True)

    packages = missing_system_packages()
    if packages:
        logger.info("Missing system tools require: %s", " ".join(packages))
    sys_ok = install_system_deps(packages)

    # APFS has no apt package; build the FUSE driver from source on demand.
    # A failed optional build is reported but doesn't fail the whole setup.
    if not build_apfs_fuse(force=force):
        logger.warning(
            "apfs-fuse is unavailable - APFS images won't mount until it builds "
            "(needs a compiler + network). Re-run 'mountir setup' to retry.")

    # apt ewf-tools is the 2014 legacy line; build modern libewf for EWF2.
    if not build_libewf(force=force):
        logger.warning(
            "Modern libewf is unavailable - EnCase v7 EWF2 (Ex01/Lx01) images "
            "won't mount until it builds (needs a compiler + network). Re-run "
            "'mountir setup' to retry.")

    # UFS: opt-in, because it needs a Rust toolchain. Skipping it only costs
    # UFS support, and only on hosts whose kernel lacks the ufs driver.
    if with_fuse_ufs:
        if not build_fuse_ufs(force=force):
            logger.warning(
                "fuse-ufs is unavailable - FreeBSD/pfSense/NetScaler UFS volumes "
                "won't mount on a kernel without the 'ufs' driver. Re-run "
                "'mountir setup --ufs' once cargo is installed.")
    elif not _tool_on_path("fuse-ufs"):
        logger.info(
            "UFS uses the in-kernel driver. If this kernel lacks it (WSL2 does), "
            "add the userspace driver with 'mountir setup --ufs'.")

    _write_marker()

    if venv_ok and sys_ok:
        logger.info("Bootstrap complete - MountIR is ready")
        logger.info("Python dependencies live in %s", VENV_DIR)
    else:
        logger.warning(
            "Bootstrap finished with warnings. Run 'mountir check' to review "
            "remaining gaps.",
        )
    return venv_ok and sys_ok
