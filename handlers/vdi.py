#!/usr/bin/env python3
"""Handler for VDI (VirtualBox Disk Image) using qemu-nbd."""

from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import (
    logger,
    nbd_attach, nbd_disconnect,
)


class VdiHandler(BaseHandler):
    """Mount VDI images via qemu-nbd."""

    @property
    def format_name(self) -> str:
        return "VDI"

    @property
    def required_tools(self) -> List[str]:
        return ["qemu-nbd"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount VDI image via qemu-nbd -> /dev/nbdN."""
        device = nbd_attach(image_path, format_hint="vdi")
        if not device:
            return MountResult(
                success=False,
                error=f"Could not attach {image_path.name} to an NBD device",
            )

        logger.info("Mounted %s via qemu-nbd -> %s", image_path.name, device)
        return MountResult(success=True, block_device=device)

    def unmount(self, mount_result: MountResult) -> bool:
        """Disconnect the NBD device."""
        if mount_result.block_device:
            return nbd_disconnect(mount_result.block_device)
        return True
