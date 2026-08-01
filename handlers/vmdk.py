#!/usr/bin/env python3
"""Handler for VMDK (VMware) disk images using qemu-nbd."""

from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import (
    logger, run_command, fuse_unmount,
    ensure_nbd_module, find_free_nbd_device, nbd_connect, nbd_disconnect,
    tool_exists,
)


class VmdkHandler(BaseHandler):
    """Mount VMDK images via qemu-nbd, with vmdkmount as fallback."""

    @property
    def format_name(self) -> str:
        return "VMDK"

    @property
    def required_tools(self) -> List[str]:
        return ["qemu-nbd"]

    @property
    def fallback_tools(self) -> List[str]:
        return ["vmdkmount"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount VMDK image.

        Primary: qemu-nbd -> /dev/nbdN block device.
        Fallback: vmdkmount -> FUSE raw image.
        """
        if tool_exists("qemu-nbd"):
            return self._mount_nbd(image_path)
        return self._mount_fuse(image_path, mount_point)

    def _mount_nbd(self, image_path: Path) -> MountResult:
        """Mount via qemu-nbd."""
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

        if not nbd_connect(image_path, device, format_hint="vmdk"):
            return MountResult(
                success=False,
                error=f"Failed to connect {image_path.name} to {device}",
            )

        logger.info("Mounted %s via qemu-nbd -> %s", image_path.name, device)
        return MountResult(success=True, block_device=device)

    def _mount_fuse(self, image_path: Path, mount_point: Path) -> MountResult:
        """Fallback: mount via vmdkmount (FUSE)."""
        try:
            run_command(["vmdkmount", str(image_path), str(mount_point)], capture=False)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        # vmdkmount exposes raw image as vmdk1
        raw_path = mount_point / "vmdk1"
        if not raw_path.exists():
            candidates = list(mount_point.iterdir())
            raw_path = candidates[0] if candidates else None

        if not raw_path:
            return MountResult(
                success=False,
                mount_point=mount_point,
                error="vmdkmount succeeded but no raw image found",
            )

        logger.info("Mounted %s via vmdkmount -> %s", image_path.name, raw_path)
        return MountResult(
            success=True,
            mount_point=mount_point,
            raw_image_path=raw_path,
        )

    def unmount(self, mount_result: MountResult) -> bool:
        """Unmount VMDK: disconnect NBD or FUSE-unmount."""
        if mount_result.block_device:
            return nbd_disconnect(mount_result.block_device)
        if mount_result.mount_point:
            return fuse_unmount(mount_result.mount_point)
        return True
