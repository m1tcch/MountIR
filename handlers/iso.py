#!/usr/bin/env python3
"""Handler for ISO 9660 disk images."""

from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import logger, run_command


class IsoHandler(BaseHandler):
    """Mount ISO images directly via mount -o loop.

    ISO images contain a filesystem directly (no partition table),
    so partition detection should be skipped for this format.
    """

    @property
    def format_name(self) -> str:
        return "ISO"

    @property
    def required_tools(self) -> List[str]:
        return ["mount"]  # always available on Linux

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount ISO image read-only via loop device.

        Uses: mount -o loop,ro,noatime,noexec <image> <mount_point>
        """
        try:
            run_command([
                "mount",
                "-o", "loop,ro,noatime,noexec",
                str(image_path),
                str(mount_point),
            ], capture=False)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        logger.info("Mounted %s -> %s", image_path.name, mount_point)
        return MountResult(
            success=True,
            mount_point=mount_point,
        )

    def unmount(self, mount_result: MountResult) -> bool:
        """Unmount the ISO."""
        if not mount_result.mount_point:
            return True
        try:
            run_command(["umount", str(mount_result.mount_point)], capture=False)
            logger.info("Unmounted ISO: %s", mount_result.mount_point)
            return True
        except Exception as e:
            logger.error("Failed to unmount %s: %s", mount_result.mount_point, e)
            return False
