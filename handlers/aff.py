#!/usr/bin/env python3
"""Handler for AFF (Advanced Forensic Format) disk images using affuse."""

from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import (
    logger, run_command, fuse_unmount, run_fuse_mount, FUSE_ACCESS_OPTS,
)


class AffHandler(BaseHandler):
    """Mount AFF images via affuse (FUSE).

    affuse creates a FUSE mount point containing a raw image file
    that represents the uncompressed disk data.
    """

    @property
    def format_name(self) -> str:
        return "AFF"

    @property
    def required_tools(self) -> List[str]:
        return ["affuse"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount AFF image via affuse.

        Creates a FUSE mount exposing the raw image at
        <mount_point>/<image_name>.raw
        """
        try:
            run_fuse_mount(["affuse", str(image_path), str(mount_point)],
                           FUSE_ACCESS_OPTS)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        # affuse creates <image_name>.raw in the mount point
        expected_raw = mount_point / f"{image_path.stem}.raw"
        raw_path = None

        if expected_raw.exists():
            raw_path = expected_raw
        else:
            # Search for any file in the mount point
            candidates = list(mount_point.iterdir())
            if candidates:
                raw_path = candidates[0]
                logger.debug("AFF raw image at non-standard path: %s", raw_path)

        if not raw_path:
            return MountResult(
                success=False,
                mount_point=mount_point,
                error="affuse succeeded but no raw image found",
            )

        logger.info(
            "Mounted %s -> %s (raw: %s)",
            image_path.name, mount_point, raw_path.name,
        )
        return MountResult(
            success=True,
            mount_point=mount_point,
            raw_image_path=raw_path,
        )

    def unmount(self, mount_result: MountResult) -> bool:
        """Unmount the affuse FUSE filesystem."""
        if mount_result.mount_point:
            return fuse_unmount(mount_result.mount_point)
        return True
