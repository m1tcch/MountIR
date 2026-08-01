#!/usr/bin/env python3
"""Handler for AFF4 (Advanced Forensic Format 4) disk images using aff4imager."""

from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import logger, run_command, fuse_unmount, tool_exists


class Aff4Handler(BaseHandler):
    """Mount AFF4 images via aff4imager (FUSE export).

    aff4imager -V creates a FUSE mount point containing a raw image file
    that represents the uncompressed disk data.
    """

    @property
    def format_name(self) -> str:
        return "AFF4"

    @property
    def required_tools(self) -> List[str]:
        return ["aff4imager"]

    @property
    def fallback_tools(self) -> List[str]:
        return ["pyaff4"]

    def check_tools(self):
        """Check for aff4imager or pyaff4 Python module."""
        result = super().check_tools()

        # If aff4imager is missing, check for pyaff4 module
        if not result["usable"]:
            try:
                import importlib
                importlib.import_module("pyaff4")
                result["available"].append("pyaff4")
                result["usable"] = True
                result["fallback_in_use"] = True
                logger.debug(
                    "%s: primary tools missing, pyaff4 module available",
                    self.format_name,
                )
            except ImportError:
                pass

        return result

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount AFF4 image via aff4imager FUSE export.

        Creates a FUSE mount exposing the raw image at
        <mount_point>/<image_name>.raw
        """
        try:
            run_command([
                "aff4imager",
                "-V", str(image_path),
                str(mount_point),
            ], capture=False)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        # aff4imager exposes raw image in the mount point
        expected_raw = mount_point / f"{image_path.stem}.raw"
        raw_path = None

        if expected_raw.exists():
            raw_path = expected_raw
        else:
            # Search for any file in the mount point
            candidates = list(mount_point.iterdir())
            if candidates:
                raw_path = candidates[0]
                logger.debug("AFF4 raw image at non-standard path: %s", raw_path)

        if not raw_path:
            return MountResult(
                success=False,
                mount_point=mount_point,
                error="aff4imager succeeded but no raw image found",
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
        """Unmount the aff4imager FUSE filesystem."""
        if mount_result.mount_point:
            return fuse_unmount(mount_result.mount_point)
        return True
