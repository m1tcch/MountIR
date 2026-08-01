#!/usr/bin/env python3
"""Mount state tracking with JSON persistence."""

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from utils import logger, SCRIPT_DIR


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
    secondary_loop: str = ""  # secondary loop for FUSE raw images
    partition_loops: List[str] = field(default_factory=list)  # per-partition offset loops
    raw_image_path: str = ""  # path to raw image exposed by FUSE
    partitions: List[MountedPartition] = field(default_factory=list)
    lvm_vg_names: List[str] = field(default_factory=list)
    zfs_pools: List[str] = field(default_factory=list)  # imported ZFS pools to export on unmount
    mounted_at: str = ""    # ISO 8601 timestamp
    handler_class: str = "" # e.g., "EwfHandler"


@dataclass
class MountState:
    """Global state tracking all mounted images."""
    mounted_images: List[MountedImage] = field(default_factory=list)
    version: str = "1"


class StateManager:
    """Read/write mount state from/to JSON file.

    Maintains an in-memory cache of the state to avoid re-reading
    the JSON file on every operation.  Disk writes use an atomic
    temp-file + rename pattern to prevent corruption.
    """

    def __init__(self, state_file: Optional[Path] = None):
        self.state_file = state_file or self._resolve_state_path()
        self._cache: Optional[MountState] = None

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

    def load(self) -> MountState:
        """Load state from JSON file (returns cached copy when available)."""
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
                    MountedPartition(**p)
                    for p in img_data.pop("partitions", [])
                ]
                state.mounted_images.append(
                    MountedImage(partitions=partitions, **img_data)
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
        """Save state to JSON file atomically (temp + rename)."""
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
        """Add a mounted image to the state and save."""
        state = self.load()
        state.mounted_images.append(mounted)
        self.save(state)

    def remove_mount(self, mount_id: str) -> None:
        """Remove a mounted image from the state and save."""
        state = self.load()
        state.mounted_images = [
            img for img in state.mounted_images
            if img.mount_id != mount_id
        ]
        self.save(state)

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
        """
        state = self.load()
        stale = []

        try:
            proc_mounts = Path("/proc/mounts").read_text()
        except OSError:
            return stale

        for img in state.mounted_images:
            # Check if any of the image's mount points appear in /proc/mounts
            is_active = False
            paths_to_check = [img.container_mount]
            for part in img.partitions:
                if part.mount_point:
                    paths_to_check.append(part.mount_point)

            for mount_path in paths_to_check:
                if mount_path and mount_path in proc_mounts:
                    is_active = True
                    break

            # Also check if block device is still in use
            if not is_active and img.block_device:
                if img.block_device in proc_mounts:
                    is_active = True

            if not is_active:
                stale.append(img)

        return stale
