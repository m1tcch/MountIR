#!/usr/bin/env python3
"""Mount state tracking with JSON persistence."""

import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Iterator, List, Optional

from utils import logger, SCRIPT_DIR

try:
    import fcntl  # POSIX only; MountIR's target platform
except ImportError:  # pragma: no cover - Windows dev/test hosts
    fcntl = None


@dataclass
class MountedPartition:
    """State for a single mounted partition."""
    device: str
    number: int
    filesystem: str = ""
    mount_point: str = ""
    label: str = ""
    size_bytes: int = 0
    mounted: bool = False


@dataclass
class MountedImage:
    """State for a single mounted disk image."""
    mount_id: str           # e.g., "EV_a3f2b1"
    image_path: str
    image_type: str         # ImageType value
    case_id: str = ""
    mount_base: str = ""    # base directory
    container_mount: str = ""  # FUSE mount point or empty
    block_device: str = ""  # /dev/nbd0 or /dev/loop0 or empty
    loop_device: str = ""   # primary loop device (raw handler)
    partition_loops: List[str] = field(default_factory=list)  # per-partition offset loops
    fuse_mounts: List[str] = field(default_factory=list)  # nested FUSE views (BitLocker/VSS)
    raw_image_path: str = ""  # path to raw image exposed by FUSE, or scratch dir
    partitions: List[MountedPartition] = field(default_factory=list)
    lvm_vg_names: List[str] = field(default_factory=list)  # display / legacy entries
    # One record per evidence VG: {"name", "uuid", "pv_devices", "activated_lvs"}.
    # The UUID and devices are what make teardown safe when the analyst's host
    # has a VG of the same name.
    lvm_vgs: List[dict] = field(default_factory=list)
    lvm_dm_devices: List[str] = field(default_factory=list)  # dm tables MountIR built
    zfs_pools: List[str] = field(default_factory=list)  # imported ZFS pools to export on unmount
    mounted_at: str = ""    # ISO 8601 timestamp
    handler_class: str = "" # e.g., "EwfHandler"


@dataclass
class MountState:
    """Global state tracking all mounted images."""
    mounted_images: List[MountedImage] = field(default_factory=list)
    version: str = "1"


def _known_fields(cls, data: dict) -> dict:
    """Drop keys *cls* has no field for, so state survives a version skew.

    A state file written by a newer MountIR (or one carrying a field since
    retired) must not make the whole file unreadable -- that would strand every
    live mount recorded in it.
    """
    allowed = {f.name for f in fields(cls)}
    unknown = set(data) - allowed
    if unknown:
        logger.debug("Ignoring unknown state field(s) %s for %s",
                     sorted(unknown), cls.__name__)
    return {k: v for k, v in data.items() if k in allowed}


class StateManager:
    """Read/write mount state from/to JSON file.

    Maintains an in-memory cache of the state to avoid re-reading
    the JSON file on every operation.  Disk writes use an atomic
    temp-file + rename pattern to prevent corruption.

    Every mutation (:meth:`add_mount`, :meth:`remove_mount`, :meth:`save`) runs
    under an exclusive ``flock`` on a sidecar lock file and re-reads the file
    inside the lock, so two MountIR processes mounting different images at the
    same time cannot lose each other's entry to a read-modify-write race.
    """

    def __init__(self, state_file: Optional[Path] = None):
        self.state_file = state_file or self._resolve_state_path()
        self._cache: Optional[MountState] = None

    # -- locking -----------------------------------------------------------
    @property
    def lock_file(self) -> Path:
        """Sidecar lock file guarding read-modify-write of the state file.

        Locking a separate file (rather than the state file itself) keeps the
        lock valid across the atomic temp-file + rename in :meth:`_write`, which
        replaces the state file's inode and would drop a lock held on it.
        """
        return self.state_file.with_name(self.state_file.name + ".lock")

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Hold an exclusive lock for the duration of the block.

        Degrades to no locking when ``fcntl`` is unavailable (non-POSIX dev
        hosts) or the lock file cannot be created -- a serialised write is
        better than none, but an unwritable lock directory must not stop an
        analyst unmounting evidence.

        The lock is an open file descriptor, so it is released by the kernel if
        the holder is killed; a crashed run cannot wedge the next one.
        """
        if fcntl is None:
            yield
            return
        try:
            self.lock_file.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.lock_file), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as e:
            logger.debug("state lock unavailable (%s) - proceeding unlocked", e)
            yield
            return
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                logger.info("Waiting for the mount-state lock (%s)",
                            self.lock_file)
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _resolve_state_path(self) -> Path:
        """Determine the state file location.

        Prefers /var/lib/mountir/ (system-level, since tool runs as root).
        Falls back to script directory.
        """
        system_dir = Path("/var/lib/mountir")
        try:
            system_dir.mkdir(parents=True, exist_ok=True)
            return system_dir / "mountir_state.json"
        except PermissionError:
            return SCRIPT_DIR / "mountir_state.json"

    def load(self, refresh: bool = False) -> MountState:
        """Load state from JSON file (returns cached copy when available).

        *refresh* discards the cache and re-reads the file; mutations use it so
        they modify whatever another process has just written rather than a
        snapshot taken before the lock was held.
        """
        if refresh:
            self._cache = None
        if self._cache is not None:
            return self._cache

        if not self.state_file.exists():
            self._cache = MountState()
            return self._cache

        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            state = MountState(version=data.get("version", "1"))

            for img_data in data.get("mounted_images", []):
                partitions = [
                    MountedPartition(**_known_fields(MountedPartition, p))
                    for p in img_data.pop("partitions", [])
                ]
                state.mounted_images.append(
                    MountedImage(partitions=partitions,
                                 **_known_fields(MountedImage, img_data))
                )
            self._cache = state
            return self._cache

        except PermissionError:
            # The state file is created root-owned by mount/unmount; the
            # read-only `list`/`check` commands may run unprivileged and can't
            # read it. Degrade to an empty view with an actionable hint rather
            # than crashing.
            logger.warning(
                "Cannot read state file %s without privileges - run with sudo "
                "to see tracked mounts.", self.state_file,
            )
            self._cache = MountState()
            return self._cache

        except (json.JSONDecodeError, TypeError, KeyError, OSError) as e:
            logger.warning("Failed to parse state file: %s", e)
            self._cache = MountState()
            return self._cache

    def save(self, state: MountState) -> None:
        """Replace the state file with *state*, atomically and under the lock."""
        with self._exclusive():
            self._write(state)

    def _write(self, state: MountState) -> None:
        """Write *state* atomically (temp + rename). Caller holds the lock."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": state.version,
            "mounted_images": [asdict(img) for img in state.mounted_images],
        }
        # Atomic write: write to temp file then rename
        tmp_name = None
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="w",
                dir=str(self.state_file.parent),
                suffix=".tmp",
                delete=False,
            )
            tmp_name = tmp.name
            json.dump(data, tmp, default=str)
            tmp.close()
            os.replace(tmp_name, str(self.state_file))
        except Exception:
            # Clean up temp file on failure, then re-raise
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            raise
        self._cache = state
        logger.debug("State saved to %s", self.state_file)

    def add_mount(self, mounted: MountedImage) -> None:
        """Add a mounted image to the state and save (read-modify-write)."""
        with self._exclusive():
            state = self.load(refresh=True)
            state.mounted_images.append(mounted)
            self._write(state)

    def remove_mount(self, mount_id: str) -> None:
        """Remove a mounted image from the state and save (read-modify-write)."""
        with self._exclusive():
            state = self.load(refresh=True)
            state.mounted_images = [
                img for img in state.mounted_images
                if img.mount_id != mount_id
            ]
            self._write(state)

    def find_by_mount_id(self, mount_id: str) -> Optional[MountedImage]:
        """Find a mounted image by its mount ID."""
        state = self.load()
        for img in state.mounted_images:
            if img.mount_id == mount_id:
                return img
        return None

    def find_by_path(self, path: str) -> Optional[MountedImage]:
        """Find a mounted image by its image path or mount base path."""
        state = self.load()
        norm_path = path.rstrip("/").rstrip("\\")
        for img in state.mounted_images:
            if img.image_path == path:
                return img
            # Also match by mount directory (normalize separators)
            mount_dir = f"{img.mount_base.rstrip('/')}/{img.mount_id}"
            if norm_path == mount_dir or norm_path == mount_dir.rstrip("/"):
                return img
        return None

    def verify_mounts(self) -> List[MountedImage]:
        """Check which recorded mounts are still actually mounted.

        Reads /proc/mounts to verify. Returns list of stale entries.

        Fields are compared exactly rather than by substring: ``/dev/loop1`` is
        a substring of ``/dev/loop12``, and one mount id can be a prefix of
        another, so a substring test reports live mounts for images that are
        long gone.
        """
        state = self.load()
        stale = []

        try:
            proc_mounts = Path("/proc/mounts").read_text()
        except OSError:
            return stale

        mounted_sources = set()
        mounted_points = set()
        for line in proc_mounts.splitlines():
            columns = line.split()
            if len(columns) < 2:
                continue
            mounted_sources.add(columns[0])
            # /proc/mounts escapes spaces as \040
            mounted_points.add(columns[1].replace("\\040", " "))

        for img in state.mounted_images:
            paths = {img.container_mount}
            paths.update(p.mount_point for p in img.partitions if p.mount_point)
            is_active = bool(paths & mounted_points)

            # Also check if the block device is still backing a mount.
            if not is_active and img.block_device:
                is_active = img.block_device in mounted_sources

            if not is_active:
                stale.append(img)

        return stale
