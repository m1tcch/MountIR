#!/usr/bin/env python3
"""Handler for macOS DMG (Apple Disk Image) files."""

import platform
import tempfile
from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import logger, run_command, tool_exists


class DmgHandler(BaseHandler):
    """Mount DMG images by converting to raw with dmg2img, then loop-mounting.

    On macOS, uses hdiutil as an alternative.
    On Linux, uses dmg2img to convert to a raw image, then losetup.
    """

    @property
    def format_name(self) -> str:
        return "DMG"

    @property
    def required_tools(self) -> List[str]:
        return ["dmg2img"]

    @property
    def fallback_tools(self) -> List[str]:
        return ["hdiutil"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount DMG image.

        Primary (Linux): dmg2img -> raw file -> losetup.
        Fallback (macOS): hdiutil attach.
        """
        if platform.system() == "Darwin" and tool_exists("hdiutil"):
            return self._mount_hdiutil(image_path, mount_point)
        if tool_exists("dmg2img"):
            return self._mount_dmg2img(image_path, mount_point)
        return MountResult(
            success=False,
            error="Neither dmg2img nor hdiutil available",
        )

    def _mount_dmg2img(self, image_path: Path, mount_point: Path) -> MountResult:
        """Convert DMG to raw with dmg2img, then attach via losetup."""
        temp_dir = Path(tempfile.mkdtemp(prefix="mountir_dmg_"))
        raw_path = temp_dir / f"{image_path.stem}.raw"

        try:
            run_command([
                "dmg2img",
                str(image_path),
                str(raw_path),
            ], capture=False)
        except Exception as e:
            raw_path.unlink(missing_ok=True)
            temp_dir.rmdir()
            return MountResult(
                success=False,
                error=f"dmg2img conversion failed: {e}",
            )

        if not raw_path.exists():
            temp_dir.rmdir()
            return MountResult(
                success=False,
                error="dmg2img produced no output file",
            )

        logger.info("Converted %s -> %s", image_path.name, raw_path)

        # Attach the raw image via losetup
        try:
            result = run_command([
                "losetup",
                "--find", "--show",
                "--read-only",
                "--partscan",
                str(raw_path),
            ])
            loop_device = result.stdout.strip()
            if not loop_device:
                raw_path.unlink(missing_ok=True)
                temp_dir.rmdir()
                return MountResult(
                    success=False,
                    error="losetup returned empty device path",
                )

            logger.info("Attached %s as %s", raw_path.name, loop_device)
            return MountResult(
                success=True,
                block_device=loop_device,
                loop_device=loop_device,
                raw_image_path=raw_path,
            )

        except Exception as e:
            raw_path.unlink(missing_ok=True)
            temp_dir.rmdir()
            return MountResult(success=False, error=str(e))

    def _mount_hdiutil(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount DMG on macOS using hdiutil."""
        try:
            run_command([
                "hdiutil", "attach",
                str(image_path),
                "-mountpoint", str(mount_point),
                "-readonly",
                "-nobrowse",
            ], capture=False)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        logger.info("Mounted %s via hdiutil -> %s", image_path.name, mount_point)
        return MountResult(
            success=True,
            mount_point=mount_point,
        )

    def unmount(self, mount_result: MountResult) -> bool:
        """Detach loop device and clean up raw file, or hdiutil detach."""
        success = True

        # macOS hdiutil path
        if (mount_result.mount_point
                and not mount_result.loop_device
                and platform.system() == "Darwin"):
            try:
                run_command([
                    "hdiutil", "detach",
                    str(mount_result.mount_point),
                ], capture=False)
                logger.info(
                    "Detached hdiutil mount: %s", mount_result.mount_point,
                )
                return True
            except Exception as e:
                logger.error(
                    "Failed to detach hdiutil mount %s: %s",
                    mount_result.mount_point, e,
                )
                return False

        # Linux dmg2img path: detach loop, then clean up raw file
        if mount_result.loop_device:
            try:
                run_command(["losetup", "-d", mount_result.loop_device], capture=False)
                logger.info(
                    "Detached loop device: %s", mount_result.loop_device,
                )
            except Exception as e:
                logger.error(
                    "Failed to detach %s: %s", mount_result.loop_device, e,
                )
                success = False

        # Clean up the temporary raw file
        if mount_result.raw_image_path and mount_result.raw_image_path.exists():
            try:
                temp_dir = mount_result.raw_image_path.parent
                mount_result.raw_image_path.unlink()
                logger.debug(
                    "Removed converted raw image: %s",
                    mount_result.raw_image_path,
                )
                if temp_dir.exists() and not any(temp_dir.iterdir()):
                    temp_dir.rmdir()
                    logger.debug("Removed temp directory: %s", temp_dir)
            except Exception as e:
                logger.warning(
                    "Failed to clean up temp file %s: %s",
                    mount_result.raw_image_path, e,
                )

        return success
