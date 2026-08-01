#!/usr/bin/env python3
"""Handler for macOS sparse images (.sparseimage / .sparsebundle)."""

import tempfile
from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import logger, run_command, fuse_unmount, tool_exists


class SparseImageHandler(BaseHandler):
    """Mount macOS sparse images.

    For .sparsebundle: use sparsebundlefs (FUSE), then loop-mount the raw.
    For .sparseimage: use dmg2img to convert, then loop-mount.
    """

    @property
    def format_name(self) -> str:
        return "macOS Sparse Image"

    @property
    def required_tools(self) -> List[str]:
        return ["sparsebundlefs"]

    @property
    def fallback_tools(self) -> List[str]:
        return ["dmg2img"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount sparse image based on type.

        .sparsebundle -> sparsebundlefs (FUSE) -> losetup
        .sparseimage  -> dmg2img -> losetup
        """
        suffix = image_path.suffix.lower()

        if suffix == ".sparsebundle" and tool_exists("sparsebundlefs"):
            return self._mount_sparsebundle(image_path, mount_point)
        if tool_exists("dmg2img"):
            return self._mount_dmg2img(image_path, mount_point)

        return MountResult(
            success=False,
            error="Neither sparsebundlefs nor dmg2img available",
        )

    def _mount_sparsebundle(
        self, image_path: Path, mount_point: Path,
    ) -> MountResult:
        """Mount .sparsebundle via sparsebundlefs FUSE, then loop-mount."""
        # sparsebundlefs mounts the bundle as a single raw block device image
        try:
            run_command([
                "sparsebundlefs",
                str(image_path),
                str(mount_point),
            ], capture=False)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        # sparsebundlefs exposes a single raw image file in the mount point
        candidates = list(mount_point.iterdir())
        if not candidates:
            return MountResult(
                success=False,
                mount_point=mount_point,
                error="sparsebundlefs succeeded but no raw image found",
            )

        raw_path = candidates[0]
        logger.debug("sparsebundlefs exposed raw image: %s", raw_path)

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
                return MountResult(
                    success=False,
                    mount_point=mount_point,
                    raw_image_path=raw_path,
                    error="losetup returned empty device path",
                )

            logger.info(
                "Mounted %s via sparsebundlefs+losetup -> %s",
                image_path.name, loop_device,
            )
            return MountResult(
                success=True,
                mount_point=mount_point,
                block_device=loop_device,
                loop_device=loop_device,
                raw_image_path=raw_path,
            )

        except Exception as e:
            # Try to clean up the FUSE mount
            fuse_unmount(mount_point)
            return MountResult(success=False, error=str(e))

    def _mount_dmg2img(
        self, image_path: Path, mount_point: Path,
    ) -> MountResult:
        """Convert sparse image to raw with dmg2img, then loop-mount."""
        temp_dir = Path(tempfile.mkdtemp(prefix="mountir_sparse_"))
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

        # Attach via losetup
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

    def unmount(self, mount_result: MountResult) -> bool:
        """Unmount sparse image: detach loop, FUSE-unmount, clean up temp files."""
        success = True

        # Detach loop device first
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

        # Unmount FUSE (sparsebundlefs)
        if mount_result.mount_point:
            if not fuse_unmount(mount_result.mount_point):
                success = False

        # Clean up temporary raw file (dmg2img path)
        if mount_result.raw_image_path and mount_result.raw_image_path.exists():
            try:
                temp_dir = mount_result.raw_image_path.parent
                # Only clean up if it's a temp file (not from FUSE mount)
                if "mountir_sparse_" in str(temp_dir):
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
