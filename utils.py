#!/usr/bin/env python3
"""MountIR shared utilities: logging, subprocess, tool checks, NBD helpers."""

import logging
import os
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("MountIR")


def setup_logging(verbose: bool) -> Optional[Path]:
    """Configure dual logging: file (DEBUG) + console (INFO or DEBUG)."""
    log_file = None
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for candidate in [SCRIPT_DIR.parent / "logs", SCRIPT_DIR / "logs", Path("/tmp")]:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            log_file = candidate / f"mountir_{timestamp}.log"
            break
        except OSError:
            continue

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler: always DEBUG (skip if no writable log dir)
    if log_file:
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except OSError:
            log_file = None

    # Console handler
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return log_file


# ---------------------------------------------------------------------------
# Subprocess wrapper
# ---------------------------------------------------------------------------
def run_command(
    cmd: List[str],
    check: bool = True,
    timeout: int = 300,
    capture: bool = True,
    log_cmd: Optional[List[str]] = None,
) -> subprocess.CompletedProcess:
    """Run an external command with logging.

    Logs the command at DEBUG, captures output, logs stderr on failure,
    raises subprocess.CalledProcessError on non-zero if check=True.

    When *capture* is False, stdout and stderr are redirected to DEVNULL
    so the subprocess output doesn't leak to the console and no memory is
    wasted buffering it.

    *log_cmd* substitutes what gets written to the log. Callers that pass a
    secret on the command line (BitLocker credentials) use it to keep the secret
    out of the on-disk log; it does not change what is executed.
    """
    logger.debug("Running: %s", " ".join(log_cmd or cmd))
    try:
        if capture:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        else:
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
            )
    except FileNotFoundError:
        logger.error("Command not found: %s", cmd[0])
        raise
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %ds: %s", timeout,
                     " ".join(log_cmd or cmd))
        raise

    if result.returncode != 0:
        logger.debug("Command exited with code %d", result.returncode)
        if capture and result.stderr:
            for line in result.stderr.strip().splitlines():
                logger.debug("  stderr: %s", line)
        if check:
            raise subprocess.CalledProcessError(
                result.returncode, cmd,
                output=getattr(result, 'stdout', None),
                stderr=getattr(result, 'stderr', None),
            )
    return result


# ---------------------------------------------------------------------------
# Tool existence checking (cached)
# ---------------------------------------------------------------------------
_tool_cache: dict = {}


def tool_exists(name: str) -> bool:
    """Check if a tool is available on PATH (result is cached)."""
    if name not in _tool_cache:
        _tool_cache[name] = shutil.which(name) is not None
    return _tool_cache[name]


def check_root() -> bool:
    """Check if running as root (Linux: euid == 0)."""
    return os.geteuid() == 0


# ---------------------------------------------------------------------------
# Mount point helpers
# ---------------------------------------------------------------------------
MOUNT_ID_RANDOM_LEN = 6
_MOUNT_ID_ALPHABET = string.ascii_lowercase + string.digits


def generate_mount_id(case_id: Optional[str] = None,
                      image_name: str = "",
                      random_len: int = MOUNT_ID_RANDOM_LEN) -> str:
    """Generate a mount point directory name.

    Format: {case_id}_{image_stem}_{random6}  or  EV_{random6}

    The suffix is random, not unique -- use :func:`claim_mount_dir` when the
    name has to be free, since only creating the directory can settle that.
    """
    rand = "".join(random.choices(_MOUNT_ID_ALPHABET, k=random_len))
    # Sanitize inputs
    safe_case = re.sub(r"[^a-zA-Z0-9_-]", "", case_id or "")
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "", image_name)

    parts = []
    if safe_case:
        parts.append(safe_case)
    if safe_name:
        parts.append(safe_name)
    parts.append(rand)

    if parts[0] == rand:
        return f"EV_{rand}"
    return "_".join(parts)


def claim_mount_dir(mount_base: Path, case_id: str = "",
                    image_name: str = "") -> Tuple[str, Path]:
    """Reserve a free mount directory under *mount_base*; return (id, path).

    ``mkdir`` **is** the claim: it fails with ``FileExistsError`` if the name is
    taken, so two MountIR processes racing on the same base cannot both win the
    same id and mount into each other's tree. A generated id is 6 random
    characters, so a collision means either bad luck or a very busy mount base;
    the suffix is widened as attempts fail so the search converges instead of
    retrying at the same odds.

    Raises OSError if no free name could be claimed.
    """
    mount_base.mkdir(parents=True, exist_ok=True)
    for attempt in range(9):
        mount_id = generate_mount_id(
            case_id, image_name,
            random_len=MOUNT_ID_RANDOM_LEN + 2 * (attempt // 3),
        )
        path = mount_base / mount_id
        try:
            path.mkdir()
        except FileExistsError:
            logger.debug("Mount id %s is already in use, retrying", mount_id)
            continue
        return mount_id, path
    raise OSError(f"Could not claim a free mount directory under {mount_base}")


def ensure_mount_dir(path: Path) -> Path:
    """Create a directory for mounting, ensuring it exists and is empty."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def _rmdir_empty_tree(path: Path) -> None:
    """Recursively rmdir empty directories under *path*, never entering a mount.

    A still-mounted evidence volume under *path* must not be descended into: it
    can hold millions of files, and walking it just to discover we cannot remove
    anything costs minutes of I/O against the image. ``os.path.ismount`` prunes
    those subtrees; symlinks are never followed.
    """
    try:
        children = list(path.iterdir())
    except OSError:
        return
    for child in children:
        if not child.is_dir() or child.is_symlink() or os.path.ismount(child):
            continue
        _rmdir_empty_tree(child)
        try:
            child.rmdir()
        except OSError:
            pass


def cleanup_mount_dir(path: Path) -> None:
    """Remove an empty mount point directory tree."""
    try:
        if path.is_dir():
            _rmdir_empty_tree(path)
            try:
                path.rmdir()
                logger.debug("Removed mount directory: %s", path)
            except OSError:
                logger.debug("Directory not empty, skipping removal: %s", path)
    except Exception as e:
        logger.warning("Failed to clean up %s: %s", path, e)


# ---------------------------------------------------------------------------
# Scratch space for formats that must be materialised on disk
# ---------------------------------------------------------------------------
# Prefix for every temp dir MountIR creates, so `clean` can recognise its own
# scratch and nothing else.
SCRATCH_PREFIX = "mountir_"


def make_scratch_dir(kind: str) -> Path:
    """Create a scratch directory for a format that must be written out.

    DMG conversion, OVA/XVA extraction and split-raw concatenation all
    materialise a full-size copy of the evidence.  ``/tmp`` is a tmpfs (RAM) on
    many hosts, so the default would OOM the box on any real image; honour
    ``MOUNTIR_TMPDIR`` (then ``TMPDIR``) so the analyst can point the scratch at
    a disk with room for it.
    """
    base = os.environ.get("MOUNTIR_TMPDIR") or None
    if base:
        Path(base).mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f"{SCRATCH_PREFIX}{kind}_", dir=base))


def is_scratch_dir(path: Path) -> bool:
    """True when *path* is a MountIR scratch directory we may delete."""
    return path.is_dir() and path.name.startswith(SCRATCH_PREFIX)


def safe_extractall(tf, dest: Path) -> None:
    """Extract a tarfile using the ``data`` filter (path-traversal safe).

    Evidence containers (OVA/XVA) are untrusted input: a member named
    ``../../etc/cron.d/x`` would otherwise be written outside *dest* by a tool
    that runs as root.  Python 3.12+ implements this as ``filter="data"``;
    older interpreters get an equivalent manual check.
    """
    try:
        tf.extractall(dest, filter="data")
        return
    except TypeError:
        pass  # Python < 3.12 (pre-backport): no filter kwarg

    dest_resolved = dest.resolve()

    def _inside(path: Path) -> bool:
        resolved = Path(path).resolve()
        return resolved == dest_resolved or dest_resolved in resolved.parents

    for member in tf.getmembers():
        target = dest / member.name
        if not _inside(target):
            raise ValueError(f"unsafe path in archive: {member.name}")
        if not (member.issym() or member.islnk()):
            continue
        # A link that points outside *dest* is as dangerous as a bad path: a
        # later member named "<link>/file" passes the check above and is then
        # written through the link. Hardlink targets are archive-root relative,
        # symlink targets are relative to the link's own directory.
        link = member.linkname
        base = dest if member.islnk() else target.parent
        if Path(link).is_absolute() or not _inside(base / link):
            raise ValueError(
                f"unsafe link in archive: {member.name} -> {link}")
    tf.extractall(dest)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def format_bytes(n: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ---------------------------------------------------------------------------
# NBD (Network Block Device) helpers
# ---------------------------------------------------------------------------
def ensure_nbd_module(max_part: int = 16) -> bool:
    """Load the nbd kernel module if not already loaded.

    Returns True if module is loaded (or was already loaded).
    """
    # Check if already loaded
    try:
        result = run_command(["lsmod"], check=False)
        if "nbd" in result.stdout:
            logger.debug("nbd module already loaded")
            return True
    except Exception:
        pass

    logger.info("Loading nbd kernel module (max_part=%d)", max_part)
    try:
        run_command(["modprobe", "nbd", f"max_part={max_part}"], capture=False)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to load nbd module: %s", e)
        return False


NBD_MAX_DEVICES = 16


def free_nbd_devices(max_devices: int = NBD_MAX_DEVICES) -> List[str]:
    """Unused /dev/nbdN devices, in order.

    Checks /sys/block/nbdN/size -- a size of 0 means unused. This is a snapshot,
    not a reservation: see :func:`nbd_attach`.
    """
    devices = []
    for i in range(max_devices):
        size_file = Path(f"/sys/block/nbd{i}/size")
        if not size_file.exists():
            continue
        try:
            if int(size_file.read_text().strip()) == 0:
                devices.append(f"/dev/nbd{i}")
        except (ValueError, OSError):
            continue
    return devices


def nbd_attach(image_path: Path, read_only: bool = True,
               format_hint: Optional[str] = None,
               max_devices: int = NBD_MAX_DEVICES) -> Optional[str]:
    """Attach *image_path* to a free NBD device; return the device, or None.

    Picking a free device and then attaching to it is a race: two MountIR runs
    scanning at the same time both see ``/dev/nbd0`` idle. Rather than guard it
    with a lock -- which could not exclude other tools on the box anyway -- the
    attach itself is the claim: ``qemu-nbd -c`` fails on a device that is
    already connected, so a lost race just moves us to the next candidate.
    Loading the nbd module is handled here too, since every caller needs it.
    """
    if not ensure_nbd_module():
        logger.error("Failed to load nbd kernel module")
        return None

    candidates = free_nbd_devices(max_devices)
    if not candidates:
        logger.error("No free NBD devices available")
        return None

    for device in candidates:
        if nbd_connect(image_path, device, read_only=read_only,
                       format_hint=format_hint):
            return device
        logger.debug("%s was not available for %s, trying the next device",
                     device, image_path.name)

    logger.error(
        "Could not attach %s to any of the %d free NBD device(s) tried - "
        "another process may have taken them, or the image format was rejected "
        "(check 'qemu-img info %s')",
        image_path.name, len(candidates), image_path,
    )
    return None


def nbd_connect(image_path: Path, nbd_device: str,
                read_only: bool = True,
                format_hint: Optional[str] = None) -> bool:
    """Connect an image to an NBD device via qemu-nbd.

    Args:
        image_path: Path to the disk image.
        nbd_device: Target NBD device (e.g., /dev/nbd0).
        read_only: Mount read-only (default True).
        format_hint: Image format ('vmdk', 'vpc', 'vhdx', 'qcow2').

    Returns True on success. A failure is logged at DEBUG, not ERROR: callers
    such as :func:`nbd_attach` try several devices in turn, and a device another
    process claimed first is an expected miss rather than a problem to report.
    """
    cmd = ["qemu-nbd", f"--connect={nbd_device}"]
    if read_only:
        cmd.append("--read-only")
    if format_hint:
        cmd.extend(["--format", format_hint])
    cmd.append(str(image_path))

    try:
        run_command(cmd, capture=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.debug("qemu-nbd connect to %s failed: %s", nbd_device, e)
        return False

    # Wait for the device to become available
    for _ in range(10):
        size_file = Path(f"/sys/block/{Path(nbd_device).name}/size")
        try:
            size = int(size_file.read_text().strip())
            if size > 0:
                logger.debug("NBD device %s is ready (size=%d)", nbd_device, size)
                return True
        except (ValueError, OSError):
            pass
        time.sleep(0.5)

    logger.warning("NBD device %s may not be ready yet", nbd_device)
    return True  # Proceed anyway; mount attempt will reveal issues


def nbd_disconnect(nbd_device: str) -> bool:
    """Disconnect an NBD device."""
    try:
        run_command(["qemu-nbd", "--disconnect", nbd_device], capture=False)
        logger.debug("Disconnected NBD device: %s", nbd_device)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to disconnect %s: %s", nbd_device, e)
        return False


# ---------------------------------------------------------------------------
# FUSE helpers
# ---------------------------------------------------------------------------
def find_mounts_under(base: Path, proc_mounts: Optional[str] = None) -> List[str]:
    """Return mountpoints at or under *base*, deepest first.

    Reads /proc/mounts (or *proc_mounts* text when provided, for testing).
    Deepest-first ordering lets callers unmount children before their parents.
    """
    base_str = str(base).replace("\\", "/").rstrip("/")
    if proc_mounts is None:
        try:
            proc_mounts = Path("/proc/mounts").read_text()
        except OSError:
            return []

    found = []
    for line in proc_mounts.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        # /proc/mounts escapes spaces as \040
        mp = parts[1].replace("\\040", " ")
        if mp == base_str or mp.startswith(base_str + "/"):
            found.append(mp)

    found.sort(key=lambda p: p.count("/"), reverse=True)
    return found


def loop_devices_backing(base: Path, losetup_output: Optional[str] = None) -> List[str]:
    """Return loop devices whose backing file lives under *base*.

    Loops stacked on one of those loops are included too, transitively: an LVM
    logical volume is exposed as an offset loop over its PV's loop device, so
    its backing "file" is ``/dev/loopN`` rather than a path under *base*.

    Parses `losetup -a` (or *losetup_output* when provided, for testing).
    """
    base_str = str(base).replace("\\", "/").rstrip("/")
    devices = []
    if losetup_output is None:
        try:
            result = run_command(["losetup", "-a"], check=False, timeout=15)
            if result.returncode != 0:
                return []
            losetup_output = result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    # e.g.  /dev/loop3: [2049]:131 (/mnt/mountir/<id>/container/ewf1)
    # Offset loops add a suffix:  ... (/path/ewf1), offset 1048576, sizelimit N
    backing = {}
    for line in losetup_output.splitlines():
        m = re.match(r"^(/dev/loop\d+):\s.*?\((.+?)\)\s*(?:,.*)?$", line.strip())
        if m:
            backing[m.group(1)] = m.group(2)
    for dev, backfile in backing.items():
        if backfile == base_str or backfile.startswith(base_str + "/"):
            devices.append(dev)
    # Each pass adds one layer of stacking; stop when a pass adds nothing.
    found = set(devices)
    while True:
        stacked = [dev for dev, backfile in backing.items()
                   if backfile in found and dev not in found]
        if not stacked:
            return devices
        devices.extend(stacked)
        found.update(stacked)


# A FUSE mount is visible only to the UID that created it unless ``allow_other``
# is set. MountIR mounts as root, so without it the analyst's own shell gets
# EACCES on the whole evidence tree and every ``ls`` needs sudo -- while kernel
# mounts (vfat, ext4) in the same tree are readable, which makes the failure look
# arbitrary. ntfs-3g and fuse-exfat set allow_other themselves when run as root;
# ewfmount, affuse, vmdkmount, vhdimount, apfs-fuse and fuse-ufs do not.
#
# The libyal tools (ewfmount/vmdkmount/vhdimount) forward FUSE options with -X;
# everything else uses the conventional -o.
FUSE_ACCESS_OPTS_LIBYAL = ["-X", "allow_other"]
FUSE_ACCESS_OPTS = ["-o", "allow_other"]


def run_fuse_mount(cmd: List[str], access_opts: List[str],
                   insert_at: int = 1, capture: bool = False):
    """Run a FUSE mount command with ``allow_other``, retrying without it.

    Not every build accepts the option (and a locked-down ``/etc/fuse.conf`` can
    refuse it), so a rejection falls back to the plain command: a mount only root
    can read still beats no mount at all. The retry is logged, not hidden.
    """
    with_access = cmd[:insert_at] + access_opts + cmd[insert_at:]
    try:
        return run_command(with_access, capture=capture)
    except Exception as e:
        logger.debug("FUSE mount with %s failed (%s); retrying without it",
                     " ".join(access_opts), e)
        return run_command(cmd, capture=capture)


def fuse_unmount(mount_point: Path) -> bool:
    """Unmount a FUSE filesystem.

    Tries a clean unmount first (fusermount/umount); if the mount is busy,
    falls back to a lazy unmount so cleanup still succeeds. Lazy unmounts are
    safe here because all MountIR mounts are read-only.
    """
    mp = str(mount_point)
    attempts = (
        (["fusermount", "-u", mp], False),
        (["umount", mp], False),
        (["fusermount", "-u", "-z", mp], True),   # lazy fallback
        (["umount", "-l", mp], True),             # lazy fallback
    )
    for cmd, lazy in attempts:
        try:
            run_command(cmd, capture=False)
            if lazy:
                logger.warning("Lazy-unmounted busy FUSE mount: %s", mount_point)
            else:
                logger.debug("FUSE unmounted: %s", mount_point)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    logger.error(
        "Failed to FUSE-unmount %s - something is using it. "
        "'cd' out of the mount (or check 'fuser -m %s') and try again.",
        mount_point, mount_point,
    )
    return False
