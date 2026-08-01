#!/usr/bin/env python3
"""Handler for DD/Raw/IMG disk images using losetup."""

from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import logger, run_command


class RawHandler(BaseHandler):
    """Mount raw disk images (DD, raw, img, bin) via losetup."""

    @property
    def format_name(self) -> str:
        return "DD/Raw"

    @property
    def required_tools(self) -> List[str]:
        return ["losetup"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Attach raw image as a loop device with partition scanning.

        Uses: losetup --find --show --read-only --partscan <image>
        The --partscan flag creates /dev/loopNpX for each partition.
        """
        try:
            result = run_command([
                "losetup",
                "--find", "--show",
                "--read-only",
                "--partscan",
                str(image_path),
            ])
            loop_device = result.stdout.strip()
            if not loop_device:
                return MountResult(
                    success=False,
                    error="losetup returned empty device path",
                )

            logger.info("Attached %s as %s", image_path.name, loop_device)
            return MountResult(
                success=True,
                block_device=loop_device,
                loop_device=loop_device,
            )

        except Exception as e:
            return MountResult(success=False, error=str(e))

    def unmount(self, mount_result: MountResult) -> bool:
        """Detach the loop device."""
        if not mount_result.loop_device:
            logger.warning("No loop device to detach")
            return True

        try:
            run_command(["losetup", "-d", mount_result.loop_device], capture=False)
            logger.info("Detached loop device: %s", mount_result.loop_device)
            return True
        except Exception as e:
            logger.error("Failed to detach %s: %s", mount_result.loop_device, e)
            return False
