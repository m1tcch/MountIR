#!/usr/bin/env python3
"""Handler for QCOW2 (QEMU Copy-On-Write) disk images using qemu-nbd."""

from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import (
    logger,
    ensure_nbd_module, find_free_nbd_device, nbd_connect, nbd_disconnect,
)


class QcowHandler(BaseHandler):
    """Mount QCOW2 images via qemu-nbd."""

    @property
    def format_name(self) -> str:
        return "QCOW2"

    @property
    def required_tools(self) -> List[str]:
        return ["qemu-nbd"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount QCOW2 image via qemu-nbd -> /dev/nbdN."""
        if not ensure_nbd_module():
            return MountResult(
                success=False,
                error="Failed to load nbd kernel module",
            )

        device = find_free_nbd_device()
        if not device:
            return MountResult(
                success=False,
                error="No free NBD device available",
            )

        if not nbd_connect(image_path, device, format_hint="qcow2"):
            return MountResult(
                success=False,
                error=f"Failed to connect {image_path.name} to {device}",
            )

        logger.info("Mounted %s via qemu-nbd -> %s", image_path.name, device)
        return MountResult(success=True, block_device=device)

    def unmount(self, mount_result: MountResult) -> bool:
        """Disconnect the NBD device."""
        if mount_result.block_device:
            return nbd_disconnect(mount_result.block_device)
        return True
