#!/usr/bin/env python3
"""Abstract base class for disk image format handlers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from utils import logger, tool_exists


@dataclass
class MountResult:
    """Result of a container mount operation."""
    success: bool
    mount_point: Optional[Path] = None
    block_device: Optional[str] = None   # e.g., /dev/nbd0, /dev/loop0
    loop_device: Optional[str] = None    # secondary loop for FUSE raw images
    raw_image_path: Optional[Path] = None  # path to raw image after FUSE mount
    error: Optional[str] = None


class BaseHandler(ABC):
    """Abstract base class for disk image format handlers."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Human-readable format name (e.g., 'E01/EWF')."""

    @property
    @abstractmethod
    def required_tools(self) -> List[str]:
        """List of primary external tools required."""

    @property
    def fallback_tools(self) -> List[str]:
        """Optional fallback tools if primary is unavailable."""
        return []

    def check_tools(self) -> Dict:
        """Check which required/fallback tools are installed.

        Returns:
            {"available": [...], "missing": [...], "usable": bool}
        """
        available = [t for t in self.required_tools if tool_exists(t)]
        missing = [t for t in self.required_tools if not tool_exists(t)]

        # If primary tools are missing, check fallbacks
        usable = len(missing) == 0
        fallback_available = []
        if not usable and self.fallback_tools:
            fallback_available = [t for t in self.fallback_tools if tool_exists(t)]
            if fallback_available:
                usable = True
                logger.debug(
                    "%s: primary tools missing %s, using fallback %s",
                    self.format_name, missing, fallback_available,
                )

        return {
            "available": available + fallback_available,
            "missing": [t for t in missing if t not in fallback_available],
            "usable": usable,
            "fallback_in_use": bool(fallback_available),
        }

    @abstractmethod
    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount the container image.

        This mounts the FORMAT container (E01->raw, VMDK->block, etc.).
        Partition detection is handled separately by partition.py.

        Args:
            image_path: Path to the disk image file.
            mount_point: Directory to mount the container into.

        Returns:
            MountResult with success status and mount details.
        """

    @abstractmethod
    def unmount(self, mount_result: MountResult) -> bool:
        """Unmount and clean up the container mount.

        Args:
            mount_result: The MountResult from a previous mount() call.

        Returns:
            True on success, False on failure.
        """
