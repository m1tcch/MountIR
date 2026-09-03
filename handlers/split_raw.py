#!/usr/bin/env python3
"""Handler for split raw disk images (.001/.002/.003 segments).

Preferred path is ``affuse``, which presents the whole segment set as a single
virtual raw file without copying a byte -- the same approach EverReady's
``er2.sh`` takes.  Concatenating the segments into a scratch file (the fallback
when afflib-tools isn't installed) needs as much free disk as the evidence and
takes as long as a full copy, so it is only used when there is no alternative.
"""

import shutil
from pathlib import Path
from typing import List, Optional

from handlers.base import BaseHandler, MountResult
from handlers.raw import RawHandler
from utils import (
    logger, run_command, tool_exists, fuse_unmount, run_fuse_mount,
    FUSE_ACCESS_OPTS, make_scratch_dir,
)


COPY_BUFFER = 4 * 1024 * 1024  # 4 MB — large buffer for disk image I/O


class SplitRawHandler(BaseHandler):
    """Mount split raw images (image.001, image.002, ...).

    ``affuse`` exposes the set as one raw file through FUSE (no copy); without
    it the segments are concatenated into a scratch file and loop-mounted via
    :class:`RawHandler`.
    """

    @property
    def format_name(self) -> str:
        return "Split Raw"

    @property
    def required_tools(self) -> List[str]:
        return ["losetup"]

    @property
    def fallback_tools(self) -> List[str]:
        return ["affuse"]

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
        """Expose the segment set as one raw image, then hand it downstream."""
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
            return RawHandler().mount(image_path, mount_point)

        if tool_exists("affuse"):
            result = self._mount_affuse(image_path, mount_point, len(segments))
            if result.success:
                return result
            logger.warning(
                "affuse could not expose %s (%s); falling back to "
                "concatenation", image_path.name, result.error,
            )

        return self._mount_concatenated(image_path, mount_point, segments)

    def _mount_affuse(self, image_path: Path, mount_point: Path,
                      count: int) -> MountResult:
        """Expose the whole set as one virtual raw file via affuse (no copy)."""
        try:
            run_fuse_mount(["affuse", str(image_path), str(mount_point)],
                           FUSE_ACCESS_OPTS)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        raw_path = self._affuse_raw_file(image_path, mount_point)
        if not raw_path:
            fuse_unmount(mount_point)
            return MountResult(
                success=False,
                error="affuse succeeded but exposed no raw image",
            )

        logger.info(
            "Exposed %d segments of %s via affuse -> %s (no copy)",
            count, image_path.name, raw_path,
        )
        return MountResult(
            success=True,
            mount_point=mount_point,
            raw_image_path=raw_path,
        )

    @staticmethod
    def _affuse_raw_file(image_path: Path, mount_point: Path) -> Optional[Path]:
        """Locate the raw file affuse exposed (naming varies by version)."""
        for candidate in (mount_point / f"{image_path.name}.raw",
                          mount_point / f"{image_path.stem}.raw"):
            if candidate.exists():
                return candidate
        try:
            files = [p for p in mount_point.iterdir() if p.is_file()]
        except OSError:
            return None
        return files[0] if files else None

    def _mount_concatenated(self, image_path: Path, mount_point: Path,
                            segments: List[Path]) -> MountResult:
        """Fallback: concatenate the segments into scratch, then loop-mount.

        This writes a full-size copy of the evidence; set ``MOUNTIR_TMPDIR`` to
        a volume with room for it (``/tmp`` is a RAM-backed tmpfs on many
        hosts).
        """
        total = sum(s.stat().st_size for s in segments)
        logger.warning(
            "affuse is unavailable - reassembling %d segments of %s (%d bytes) "
            "into scratch space. Install afflib-tools to mount without copying.",
            len(segments), image_path.name, total,
        )

        temp_dir = make_scratch_dir("split")
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

            result = RawHandler().mount(combined_path, mount_point)
            if result.success:
                # Remembered so unmount can delete the reassembled copy.
                result.raw_image_path = combined_path
            else:
                shutil.rmtree(temp_dir, ignore_errors=True)
            return result

        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return MountResult(success=False, error=str(e))

    def unmount(self, mount_result: MountResult) -> bool:
        """Release the segment set: detach the loop or drop the FUSE mount."""
        # Concatenated (or single-segment) path: a loop device backs the mount.
        if mount_result.loop_device:
            success = True
            try:
                run_command(["losetup", "-d", mount_result.loop_device], capture=False)
                logger.info("Detached loop device: %s", mount_result.loop_device)
            except Exception as e:
                logger.error(
                    "Failed to detach %s: %s", mount_result.loop_device, e
                )
                success = False
            self._remove_reassembled(mount_result.raw_image_path)
            return success

        # affuse path: the raw image is a FUSE view, nothing was copied.
        if mount_result.mount_point:
            return fuse_unmount(mount_result.mount_point)
        return True

    @staticmethod
    def _remove_reassembled(raw_image_path: Optional[Path]) -> None:
        """Delete the concatenated scratch copy (and its dir) if we made one."""
        if not raw_image_path or not raw_image_path.exists():
            return
        temp_dir = raw_image_path.parent
        try:
            raw_image_path.unlink()
            logger.debug("Removed temporary combined image: %s", raw_image_path)
            if temp_dir.exists() and not any(temp_dir.iterdir()):
                temp_dir.rmdir()
                logger.debug("Removed temp directory: %s", temp_dir)
        except Exception as e:
            logger.warning(
                "Failed to clean up temp file %s: %s", raw_image_path, e,
            )
