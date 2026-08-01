#!/usr/bin/env python3
"""Handler for split raw disk images (.001/.002/.003 segments)."""

import shutil
import tempfile
from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from handlers.raw import RawHandler
from utils import logger, run_command


COPY_BUFFER = 4 * 1024 * 1024  # 4 MB — large buffer for disk image I/O


class SplitRawHandler(BaseHandler):
    """Mount split raw images by reassembling segments, then delegating to RawHandler.

    Split raw images consist of numbered segments (image.001, image.002, etc.)
    that must be concatenated to reconstruct the original raw disk image.
    After reassembly, the combined image is mounted via RawHandler (losetup).
    """

    @property
    def format_name(self) -> str:
        return "Split Raw"

    @property
    def required_tools(self) -> List[str]:
        return ["losetup"]

    def _find_segments(self, image_path: Path) -> List[Path]:
        """Find all split raw segments in order.

        Starting from image_path (e.g., image.001), find .002, .003, etc.
        """
        stem = image_path.stem
        parent = image_path.parent
        segments = []
        idx = 1

        while True:
            segment = parent / f"{stem}.{idx:03d}"
            if segment.exists():
                segments.append(segment)
                idx += 1
            else:
                break

        return segments

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Reassemble split segments into a single raw image, then loop-mount.

        Creates a temporary combined raw file by concatenating all segments,
        then delegates to RawHandler for the actual mount.
        """
        segments = self._find_segments(image_path)
        if not segments:
            return MountResult(
                success=False,
                error=f"No segments found for {image_path.name}",
            )

        if len(segments) == 1:
            logger.info(
                "Only one segment found for %s, delegating to RawHandler",
                image_path.name,
            )
            raw_handler = RawHandler()
            return raw_handler.mount(image_path, mount_point)

        logger.info(
            "Reassembling %d segments for %s",
            len(segments), image_path.name,
        )

        # Create a temporary directory for the combined file
        temp_dir = Path(tempfile.mkdtemp(prefix="mountir_split_"))
        combined_path = temp_dir / f"{image_path.stem}.raw"

        try:
            with open(combined_path, "wb") as outfile:
                for segment in segments:
                    logger.debug("  Concatenating segment: %s", segment.name)
                    with open(segment, "rb") as infile:
                        shutil.copyfileobj(infile, outfile, length=COPY_BUFFER)

            logger.info(
                "Reassembled %d segments -> %s",
                len(segments), combined_path,
            )

            # Delegate to RawHandler
            raw_handler = RawHandler()
            result = raw_handler.mount(combined_path, mount_point)

            if result.success:
                # Store the raw image path so unmount can clean it up
                result.raw_image_path = combined_path
            else:
                # Clean up on failure
                combined_path.unlink(missing_ok=True)
                temp_dir.rmdir()

            return result

        except Exception as e:
            # Clean up on error
            combined_path.unlink(missing_ok=True)
            temp_dir.rmdir()
            return MountResult(success=False, error=str(e))

    def unmount(self, mount_result: MountResult) -> bool:
        """Detach loop device and clean up the reassembled temporary file."""
        success = True

        # Detach the loop device
        if mount_result.loop_device:
            try:
                run_command(["losetup", "-d", mount_result.loop_device], capture=False)
                logger.info("Detached loop device: %s", mount_result.loop_device)
            except Exception as e:
                logger.error(
                    "Failed to detach %s: %s", mount_result.loop_device, e
                )
                success = False

        # Clean up the temporary combined raw file
        if mount_result.raw_image_path and mount_result.raw_image_path.exists():
            try:
                temp_dir = mount_result.raw_image_path.parent
                mount_result.raw_image_path.unlink()
                logger.debug(
                    "Removed temporary combined image: %s",
                    mount_result.raw_image_path,
                )
                # Remove the temp directory if empty
                if temp_dir.exists() and not any(temp_dir.iterdir()):
                    temp_dir.rmdir()
                    logger.debug("Removed temp directory: %s", temp_dir)
            except Exception as e:
                logger.warning(
                    "Failed to clean up temp file %s: %s",
                    mount_result.raw_image_path, e,
                )

        return success
