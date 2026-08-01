#!/usr/bin/env python3
"""Handler for VHD/VHDX (Microsoft) disk images using qemu-nbd."""

from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import (
    logger, run_command, fuse_unmount,
    ensure_nbd_module, find_free_nbd_device, nbd_connect, nbd_disconnect,
    tool_exists,
)


class VhdHandler(BaseHandler):
    """Mount VHD/VHDX images via qemu-nbd, with vhdimount as fallback (VHD only)."""

    def __init__(self, is_vhdx: bool = False):
        self._is_vhdx = is_vhdx

    @property
    def format_name(self) -> str:
        return "VHDX" if self._is_vhdx else "VHD"

    @property
    def required_tools(self) -> List[str]:
        return ["qemu-nbd"]

    @property
    def fallback_tools(self) -> List[str]:
        # vhdimount only supports VHD, not VHDX
        return [] if self._is_vhdx else ["vhdimount"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount VHD/VHDX image.

        Primary: qemu-nbd -> /dev/nbdN (format='vpc' for VHD, 'vhdx' for VHDX).
        Fallback (VHD only): vhdimount -> FUSE raw image.
        """
        if tool_exists("qemu-nbd"):
            return self._mount_nbd(image_path)
        if not self._is_vhdx:
            return self._mount_fuse(image_path, mount_point)
        return MountResult(
            success=False,
            error="qemu-nbd required for VHDX (not available)",
        )

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

        # VHD uses 'vpc' format in qemu, VHDX uses 'vhdx'
        fmt = "vhdx" if self._is_vhdx else "vpc"
        if not nbd_connect(image_path, device, format_hint=fmt):
            return MountResult(
                success=False,
                error=f"Failed to connect {image_path.name} to {device}",
            )

        logger.info("Mounted %s via qemu-nbd -> %s", image_path.name, device)
        return MountResult(success=True, block_device=device)

    def _mount_fuse(self, image_path: Path, mount_point: Path) -> MountResult:
        """Fallback: mount VHD via vhdimount (FUSE)."""
        try:
            run_command(["vhdimount", str(image_path), str(mount_point)], capture=False)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        # vhdimount exposes raw image as vhdi1
        raw_path = mount_point / "vhdi1"
        if not raw_path.exists():
            candidates = list(mount_point.iterdir())
            raw_path = candidates[0] if candidates else None

        if not raw_path:
            return MountResult(
                success=False,
                mount_point=mount_point,
                error="vhdimount succeeded but no raw image found",
            )

        logger.info("Mounted %s via vhdimount -> %s", image_path.name, raw_path)
        return MountResult(
            success=True,
            mount_point=mount_point,
            raw_image_path=raw_path,
        )

    def unmount(self, mount_result: MountResult) -> bool:
        """Unmount VHD/VHDX: disconnect NBD or FUSE-unmount."""
        if mount_result.block_device:
            return nbd_disconnect(mount_result.block_device)
        if mount_result.mount_point:
            return fuse_unmount(mount_result.mount_point)
        return True
